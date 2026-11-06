// ============================================================
// NetVarRepeaterService - usluga Windows (tryb konsolowy: --console)
//
// Przechwytuje (WinDivert, warstwa NETWORK, tryb SNIFF) przychodzace
// datagramy UDP i przekazuje ich tresc (payload) wedlug regul z config.txt.
// Tryb SNIFF = kopia pakietu; oryginal trafia normalnie do systemu, wiec
// port nasluchu NIE jest blokowany ani zajmowany (nie robimy bind()).
// ============================================================

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <sddl.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "adapters.h"
#include "common.h"
#include "config.h"

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif

// ------------------------------------------------------------
// Ustawienia (z config.txt) i stan globalny
// ------------------------------------------------------------
static std::atomic<uint32_t> g_maxPps(2000);
static std::atomic<uint32_t> g_logMaxMb(1);
static NvrSettingsFile       g_settings;   // zmieniane tylko gdy relay stoi (LoadRules)

static CRITICAL_SECTION g_logCs;    // log
static CRITICAL_SECTION g_dataCs;   // g_rules (podmiana), g_cfgMessage, g_startTime, g_ifTable
static CRITICAL_SECTION g_ctlCs;    // serializuje Start/Stop/Reset/auto-ponowienie

static bool g_console = false;

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS        g_serviceStatus;
static HANDLE                g_stopEvent = nullptr;

static const int NUM_PIPE_THREADS = 3;   // status odpowiada nawet gdy trwa Start/Reset
static HANDLE g_pipeThreads[NUM_PIPE_THREADS] = { nullptr, nullptr, nullptr };
static HANDLE g_supervisor = nullptr;

static uint64_t NowFileTime()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// ------------------------------------------------------------
// Pomocnicze: UTF-8, opis bledow
// ------------------------------------------------------------
static std::string Utf8(const std::wstring& w)
{
    if (w.empty())
        return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                nullptr, 0, nullptr, nullptr);
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                        &s[0], n, nullptr, nullptr);
    return s;
}

static std::string ErrStr(DWORD code)
{
    if (code == NVR_ERR_NO_RULES)
        return "brak poprawnych reguł w konfiguracji";
    if (code == NVR_ERR_ADAPTER_DISABLED)
        return "trasa prowadzi przez kartę wyłączoną w konfiguracji (zakładka Karty sieciowe)";

    wchar_t buf[512];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, buf, 512, nullptr);
    std::string s = "kod " + std::to_string(code);
    if (n > 0)
    {
        while (n > 0 && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' || buf[n - 1] == L' '))
            --n;
        s += " (" + Utf8(std::wstring(buf, n)) + ")";
    }
    return s;
}

static std::string ErrHint(DWORD code)
{
    switch (code)
    {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:     return "brak WinDivert64.sys obok pliku exe?";
        case ERROR_ACCESS_DENIED:      return "wymagane uprawnienia administratora / SYSTEM";
        case ERROR_INVALID_IMAGE_HASH: return "sterownik zablokowany (podpis / Secure Boot / antywirus)";
        case 1275:                     return "sterownik zablokowany przez system (ERROR_DRIVER_BLOCKED)";
        case ERROR_INVALID_PARAMETER:  return "niepoprawny filtr WinDivert";
        case ERROR_SERVICE_DOES_NOT_EXIST: return "sterownik WinDivert nie zainstalowany";
        default: return std::string();
    }
}

// ------------------------------------------------------------
// Log z ograniczeniem wielkosci (rotacja do pliku .1)
// Maksymalne zajecie dysku = ok. 2 x log_max_kb.
// ------------------------------------------------------------
static void Log(const char* fmt, ...)
{
    char msg[1500];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);

    char line[1600];
    const int len = std::snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d  %s\r\n",
                                  st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, msg);
    if (len <= 0)
        return;

    EnterCriticalSection(&g_logCs);

    if (g_console)
    {
        std::fwrite(line, 1, static_cast<size_t>(len), stdout);
        std::fflush(stdout);
    }

    const std::wstring path = NvrLogPath();
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        LARGE_INTEGER size;
        const unsigned long long limit = static_cast<unsigned long long>(g_logMaxMb.load()) * 1024ull * 1024ull;

        if (GetFileSizeEx(h, &size) && static_cast<unsigned long long>(size.QuadPart) > limit)
        {
            CloseHandle(h);
            MoveFileExW(path.c_str(), (path + L".1").c_str(), MOVEFILE_REPLACE_EXISTING);
            h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }

        if (h != INVALID_HANDLE_VALUE)
        {
            DWORD w = 0;
            WriteFile(h, line, static_cast<DWORD>(len), &w, nullptr);
            CloseHandle(h);
        }
    }

    LeaveCriticalSection(&g_logCs);
}

// ------------------------------------------------------------
// WinDivert (ladowany dynamicznie z katalogu exe)
// ------------------------------------------------------------
static const int      WD_LAYER_NETWORK = 0;
static const UINT64   WD_FLAG_SNIFF    = 0x0001;
static const UINT64   WD_FLAG_RECV_ONLY = 0x0004;
static const int      WD_SHUTDOWN_RECV = 0x1;

// Uklad WINDIVERT_ADDRESS z WinDivert 2.x (80 bajtow)
struct DivertAddress
{
    int64_t  timestamp;
    uint32_t flags;
    uint32_t reserved2;
    uint32_t ifIdx;        // WINDIVERT_DATA_NETWORK.IfIdx  <- interfejs, na ktorym odebrano pakiet
    uint32_t subIfIdx;
    uint8_t  reserved3[56];
};
static_assert(sizeof(DivertAddress) == 80, "WINDIVERT_ADDRESS must be 80 bytes");

typedef HANDLE (WINAPI *FnWinDivertOpen)(const char*, int, INT16, UINT64);
typedef BOOL   (WINAPI *FnWinDivertRecv)(HANDLE, void*, UINT, UINT*, void*);
typedef BOOL   (WINAPI *FnWinDivertClose)(HANDLE);
typedef BOOL   (WINAPI *FnWinDivertShutdown)(HANDLE, int);

static HMODULE             g_dll = nullptr;
static FnWinDivertOpen     g_wdOpen = nullptr;
static FnWinDivertRecv     g_wdRecv = nullptr;
static FnWinDivertClose    g_wdClose = nullptr;
static FnWinDivertShutdown g_wdShutdown = nullptr;

static std::wstring ExeDir()
{
    wchar_t path[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH * 2);
    std::wstring p(path, n);
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

static std::atomic<uint32_t> g_lastError(0);

static bool LoadWinDivert()
{
    if (g_dll)
        return true;

    const std::wstring dll = ExeDir() + L"\\WinDivert.dll";
    g_dll = LoadLibraryExW(dll.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);

    if (!g_dll)
    {
        const DWORD e = GetLastError();
        g_lastError.store(e);
        Log("BŁĄD: nie można załadować WinDivert.dll z '%s': %s", Utf8(dll).c_str(), ErrStr(e).c_str());
        return false;
    }

    g_wdOpen = reinterpret_cast<FnWinDivertOpen>(GetProcAddress(g_dll, "WinDivertOpen"));
    g_wdRecv = reinterpret_cast<FnWinDivertRecv>(GetProcAddress(g_dll, "WinDivertRecv"));
    g_wdClose = reinterpret_cast<FnWinDivertClose>(GetProcAddress(g_dll, "WinDivertClose"));
    g_wdShutdown = reinterpret_cast<FnWinDivertShutdown>(GetProcAddress(g_dll, "WinDivertShutdown"));

    if (!g_wdOpen || !g_wdRecv || !g_wdClose || !g_wdShutdown)
    {
        g_lastError.store(ERROR_PROC_NOT_FOUND);
        Log("BŁĄD: WinDivert.dll nie zawiera wymaganych funkcji (wymagana wersja 2.x)");
        FreeLibrary(g_dll);
        g_dll = nullptr;
        return false;
    }

    return true;
}

// ------------------------------------------------------------
// Regula + liczniki
// ------------------------------------------------------------
struct OutSock
{
    SOCKET   s;
    uint32_t ifIdx;
};

struct Rule
{
    NvrRuleCfg  cfg;
    sockaddr_in dst;
    bool        directedBcast;      // adres docelowy to broadcast kierowany
    uint32_t    noOutError;         // kod bledu, gdy regula nie ma zadnego wyjscia
    std::vector<OutSock> outs;      // tylko watek relay (lub Start/Stop gdy relay stoi)

    // dane tylko dla watku relay
    bool       failed;              // ostatnia wysylka sie nie powiodla -> odtworz gniazda
    double     tokens;
    ULONGLONG  tokTick;
    ULONGLONG  lastLogTick;

    std::atomic<uint32_t> outMode;
    std::atomic<uint32_t> outIfIdx;
    std::atomic<uint32_t> outCount;
    std::atomic<uint32_t> lastRxIf;
    std::atomic<uint32_t> txIf[NVR_MAX_TX_SHOW];
    std::atomic<uint32_t> lastError;
    std::atomic<uint64_t> received;
    std::atomic<uint64_t> forwarded;
    std::atomic<uint64_t> errors;
    std::atomic<uint64_t> skipped;
    std::atomic<uint64_t> bytesRx;
    std::atomic<uint64_t> bytesTx;

    explicit Rule(const NvrRuleCfg& c)
        : cfg(c), directedBcast(false), noOutError(ERROR_NETWORK_UNREACHABLE), failed(false), tokens(0), tokTick(0), lastLogTick(0),
          outMode(NVR_OUT_OS), outIfIdx(0), outCount(0), lastRxIf(0), lastError(0),
          received(0), forwarded(0), errors(0), skipped(0), bytesRx(0), bytesTx(0)
    {
        for (uint32_t i = 0; i < NVR_MAX_TX_SHOW; ++i)
            txIf[i].store(0);
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(c.dstPort);
        dst.sin_addr.s_addr = htonl(c.dstIp);
    }

    void PublishTx()
    {
        const uint32_t n = static_cast<uint32_t>(outs.size());
        for (uint32_t i = 0; i < NVR_MAX_TX_SHOW; ++i)
            txIf[i].store(i < n ? outs[i].ifIdx : 0);
        outCount.store(n);
    }

    void CloseSockets()
    {
        for (size_t i = 0; i < outs.size(); ++i)
            if (outs[i].s != INVALID_SOCKET)
                closesocket(outs[i].s);
        outs.clear();
        PublishTx();
    }

    // czy wolno zapisac wpis do logu (max raz na 60 s na regule)
    bool LogOk()
    {
        const ULONGLONG now = GetTickCount64();
        if (lastLogTick != 0 && now - lastLogTick < 60000)
            return false;
        lastLogTick = now;
        return true;
    }

    ~Rule() { CloseSockets(); }
};

typedef std::vector<std::unique_ptr<Rule> > RuleList;

static RuleList     g_rules;
static std::string  g_cfgMessage;
static uint32_t     g_cfgErrorCount = 0;
static uint64_t     g_startTime = 0;

static HANDLE                g_relayThread = nullptr;
static HANDLE                g_divert = INVALID_HANDLE_VALUE;
static std::atomic<bool>     g_active(false);
static std::atomic<bool>     g_relayStop(false);
static std::atomic<bool>     g_userStopped(false);
static std::atomic<uint64_t> g_nextRetryTick(0);
static std::atomic<uint64_t> g_totalSeen(0);
static std::atomic<uint64_t> g_totalIgnored(0);
static std::atomic<uint64_t> g_totalLoop(0);

static std::string RuleName(const NvrRuleCfg& c)
{
    return NvrIpToString(c.srcIp) + ":" + std::to_string(c.listenPort) + " -> " +
           NvrIpToString(c.dstIp) + ":" + std::to_string(c.dstPort);
}

// ------------------------------------------------------------
// Identyfikacja interfejsow sieciowych
// ------------------------------------------------------------
struct IfAddr
{
    uint32_t ifIdx;
    uint32_t ip;          // host order
    uint32_t mask;        // host order
    bool     isVirtual;   // heurystyka (tylko informacyjnie)
    bool     rxAllowed;   // karta zaznaczona w oknie konfiguracji: odbior
    bool     txAllowed;   // karta zaznaczona w oknie konfiguracji: wysylanie
    std::wstring name;
};

static std::vector<IfAddr> g_ifTable;   // ostatnio wyliczone interfejsy (pod g_dataCs)

// Karty Up z IPv4. Wybor odbioru/wysylania pochodzi z settings.ini;
// karta bez wpisu: fizyczna = wlaczona, wirtualna = wylaczona.
static std::vector<IfAddr> EnumInterfaces()
{
    std::vector<IfAddr> result;
    const std::vector<NvrAdapter> ads = NvrEnumAdapters(false);

    for (size_t i = 0; i < ads.size(); ++i)
    {
        const bool def = !ads[i].isVirtual;
        const bool rx = NvrAdapterAllowed(g_settings, ads[i].guid, def, false);
        const bool tx = NvrAdapterAllowed(g_settings, ads[i].guid, def, true);

        for (size_t k = 0; k < ads[i].addrs.size(); ++k)
        {
            IfAddr ia;
            ia.ifIdx = ads[i].ifIdx;
            ia.ip = ads[i].addrs[k].ip;
            ia.mask = ads[i].addrs[k].mask;
            ia.isVirtual = ads[i].isVirtual;
            ia.rxAllowed = rx;
            ia.txAllowed = tx;
            ia.name = ads[i].name;
            result.push_back(ia);
        }
    }

    return result;
}

static uint64_t IfSignature(const std::vector<IfAddr>& v)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < v.size(); ++i)
    {
        const uint32_t parts[4] = { v[i].ifIdx, v[i].ip, v[i].mask,
                                    (v[i].rxAllowed ? 1u : 0u) | (v[i].txAllowed ? 2u : 0u) | (v[i].isVirtual ? 4u : 0u) };
        for (int k = 0; k < 4; ++k)
        {
            h ^= parts[k];
            h *= 1099511628211ull;
        }
    }
    return h;
}

static const IfAddr* FindIf(const std::vector<IfAddr>& v, uint32_t ifIdx)
{
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].ifIdx == ifIdx)
            return &v[i];
    return nullptr;
}

static bool IsLocalIp(const std::vector<IfAddr>& v, uint32_t ip)
{
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i].ip == ip)
            return true;
    return false;
}

static SOCKET MakeOutSocket(uint32_t bindIp, uint32_t ifIdx)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET)
        return s;

    BOOL on = TRUE;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&on), sizeof(on));

    if (ifIdx != 0)
    {
        DWORD v = htonl(ifIdx);     // IP_UNICAST_IF: indeks w network byte order
        setsockopt(s, IPPROTO_IP, IP_UNICAST_IF, reinterpret_cast<const char*>(&v), sizeof(v));
    }

    if (bindIp != 0)
    {
        sockaddr_in a;
        std::memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(bindIp);
        a.sin_port = 0;

        if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
        {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    return s;
}

static void AddOut(Rule& r, const IfAddr& ia)
{
    SOCKET s = MakeOutSocket(ia.ip, ia.ifIdx);
    if (s == INVALID_SOCKET)
        return;
    OutSock o = { s, ia.ifIdx };
    r.outs.push_back(o);
}

// Wybiera interfejs/gniazda wyjsciowe dla reguly (patrz README: "Identyfikacja interfejsow").
static void BuildOutputs(Rule& r, const std::vector<IfAddr>& all)
{
    r.CloseSockets();
    r.outMode.store(NVR_OUT_OS);
    r.outIfIdx.store(0);
    r.directedBcast = false;
    r.failed = false;

    r.noOutError = ERROR_NETWORK_UNREACHABLE;

    // tylko karty z zaznaczonym "Wysylanie" w oknie konfiguracji
    std::vector<IfAddr> ifs;
    for (size_t i = 0; i < all.size(); ++i)
        if (all[i].txAllowed)
            ifs.push_back(all[i]);

    const uint32_t dst = r.cfg.dstIp;

    // 1) broadcast ograniczony -> po jednym gniezdzie na interfejs
    if (dst == 0xFFFFFFFFu)
    {
        std::set<uint32_t> seen;
        for (size_t i = 0; i < ifs.size(); ++i)
            if (seen.insert(ifs[i].ifIdx).second)
                AddOut(r, ifs[i]);

        r.outMode.store(NVR_OUT_BCAST_ALL);
        r.PublishTx();
        return;
    }

    // 2) broadcast kierowany -> interfejs z ta podsiecia
    for (size_t i = 0; i < ifs.size(); ++i)
    {
        const IfAddr& ia = ifs[i];
        if (ia.mask == 0xFFFFFFFFu || ia.mask == 0xFFFFFFFEu || ia.mask == 0)
            continue;

        if (dst == (ia.ip | ~ia.mask))
        {
            r.directedBcast = true;
            AddOut(r, ia);
            if (!r.outs.empty())
            {
                r.outMode.store(NVR_OUT_BOUND);
                r.outIfIdx.store(ia.ifIdx);
                r.PublishTx();
                return;
            }
        }
    }

    // 3) unicast -> interfejs wskazany przez tablice routingu
    DWORD bestIf = 0;
    if (GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&r.dst), &bestIf) == NO_ERROR)
    {
        for (size_t i = 0; i < ifs.size(); ++i)
        {
            if (ifs[i].ifIdx != bestIf)
                continue;

            AddOut(r, ifs[i]);
            if (!r.outs.empty())
            {
                r.outMode.store(NVR_OUT_BOUND);
                r.outIfIdx.store(ifs[i].ifIdx);
                r.PublishTx();
                return;
            }
        }
    }

    // 4) trasa prowadzi przez znana karte, ale wylaczona w konfiguracji -> nie wysylamy
    //    (inaczej ruch wyciekalby przez karte, ktorej uzytkownik nie chce uzywac)
    if (bestIf != 0)
    {
        for (size_t i = 0; i < all.size(); ++i)
        {
            if (all[i].ifIdx == bestIf && !all[i].txAllowed)
            {
                r.noOutError = NVR_ERR_ADAPTER_DISABLED;
                Log("Reguła %s: trasa do celu prowadzi przez kartę '%s', która ma wyłączone wysyłanie - pakiety będą odrzucane",
                    RuleName(r.cfg).c_str(), Utf8(all[i].name).c_str());
                r.PublishTx();
                return;
            }
        }
    }

    // 5) adres lokalny / loopback / nieznany interfejs -> decyduje system
    SOCKET s = MakeOutSocket(0, 0);
    if (s != INVALID_SOCKET)
    {
        OutSock o = { s, 0 };
        r.outs.push_back(o);
    }
    r.PublishTx();
}

static void LogInterfaces(const std::vector<IfAddr>& v)
{
    if (v.empty())
        Log("Interfejsy: brak aktywnych kart IPv4");

    for (size_t i = 0; i < v.size(); ++i)
        Log("Interfejs [if %u] '%s' %s/%u %s odbiór=%s wysyłanie=%s", v[i].ifIdx, Utf8(v[i].name).c_str(),
            NvrIpToString(v[i].ip).c_str(),
            32 - (v[i].mask == 0 ? 32u : static_cast<unsigned>(__builtin_ctz(v[i].mask))),
            v[i].isVirtual ? "[wirtualna]" : "[fizyczna]",
            v[i].rxAllowed ? "TAK" : "nie", v[i].txAllowed ? "TAK" : "nie");
}

static void LogOutputs(const Rule& r)
{
    std::string list;
    for (size_t i = 0; i < r.outs.size(); ++i)
        list += (i ? ", if " : "if ") + std::to_string(r.outs[i].ifIdx);

    const uint32_t mode = r.outMode.load();
    Log("Reguła %s: wyjście = %s%s", RuleName(r.cfg).c_str(),
        mode == NVR_OUT_BCAST_ALL ? "broadcast na kartach: " :
        mode == NVR_OUT_BOUND     ? "karta: " : "wybór systemu ",
        list.c_str());
}

// Przebudowuje wyjscia wszystkich regul i publikuje tabele interfejsow.
static void ApplyInterfaces(const std::vector<IfAddr>& ifs, bool logIt)
{
    EnterCriticalSection(&g_dataCs);
    g_ifTable = ifs;
    LeaveCriticalSection(&g_dataCs);

    if (logIt)
        LogInterfaces(ifs);

    for (size_t i = 0; i < g_rules.size(); ++i)
    {
        BuildOutputs(*g_rules[i], ifs);
        if (logIt)
            LogOutputs(*g_rules[i]);
    }
}

// ------------------------------------------------------------
// Parsowanie pakietu IPv4/UDP
// ------------------------------------------------------------
static bool ParseUdp(const unsigned char* p, UINT len,
                     uint32_t& srcIp, uint16_t& dstPort,
                     const unsigned char*& payload, UINT& payloadLen)
{
    if (len < 20)
        return false;

    const unsigned ver = p[0] >> 4;
    const unsigned ihl = (p[0] & 0x0Fu) * 4u;

    if (ver != 4 || ihl < 20 || len < ihl + 8 || p[9] != IPPROTO_UDP)
        return false;

    const unsigned total = (static_cast<unsigned>(p[2]) << 8) | p[3];
    if (total < ihl + 8 || total > len)
        return false;

    const unsigned frag = (static_cast<unsigned>(p[6]) << 8) | p[7];
    if ((frag & 0x3FFFu) != 0)          // fragmenty IP nie sa skladane
        return false;

    srcIp = (static_cast<uint32_t>(p[12]) << 24) | (static_cast<uint32_t>(p[13]) << 16) |
            (static_cast<uint32_t>(p[14]) << 8)  |  static_cast<uint32_t>(p[15]);

    const unsigned char* udp = p + ihl;
    dstPort = static_cast<uint16_t>((udp[2] << 8) | udp[3]);

    const unsigned udpLen = (static_cast<unsigned>(udp[4]) << 8) | udp[5];
    if (udpLen < 8 || udpLen > total - ihl)
        return false;

    payload = udp + 8;
    payloadLen = udpLen - 8;
    return true;
}

// ------------------------------------------------------------
// Przekazywanie jednego pakietu
//
// Liczniki reguly (spojne): received = forwarded + errors + skipped
//   forwarded - wyslano poprawnie na wszystkie wyjscia
//   errors    - przynajmniej jedna wysylka sie nie powiodla / brak wyjscia
//   skipped   - celowo pominiety (limit pps, ochrona przed petla)
//   bytesTx   - suma bajtow faktycznie wyslanych (po kazdym wyjsciu)
// ------------------------------------------------------------
static void ForwardOne(Rule& r, const unsigned char* payload, UINT plen,
                       uint32_t rxIfIdx, bool& needRefresh)
{
    // Ochrona przed petla / burza: limit pakietow na sekunde na regule (token bucket)
    const uint32_t maxPps = g_maxPps.load();
    if (maxPps > 0)
    {
        const ULONGLONG now = GetTickCount64();
        if (r.tokTick == 0)
        {
            r.tokens = maxPps;
            r.tokTick = now;
        }
        else
        {
            r.tokens += static_cast<double>(now - r.tokTick) * maxPps / 1000.0;
            if (r.tokens > maxPps) r.tokens = maxPps;
            r.tokTick = now;
        }

        if (r.tokens < 1.0)
        {
            r.skipped.fetch_add(1);
            if (r.LogOk())
                Log("OSTRZEŻENIE: reguła %s przekroczyła limit %u pakietów/s - pakiety pomijane (możliwa pętla)",
                    RuleName(r.cfg).c_str(), maxPps);
            return;
        }
        r.tokens -= 1.0;
    }

    int attempted = 0, failed = 0;

    for (size_t i = 0; i < r.outs.size(); ++i)
    {
        const OutSock& o = r.outs[i];

        // broadcast: nie odsylamy na interfejs, z ktorego pakiet przyszedl
        if (r.outMode.load() == NVR_OUT_BCAST_ALL && o.ifIdx == rxIfIdx)
            continue;

        // broadcast kierowany na te sama siec i ten sam port = ping-pong z drugim repeaterem
        if (r.directedBcast && o.ifIdx == rxIfIdx && r.cfg.dstPort == r.cfg.listenPort)
            continue;

        ++attempted;

        const int sent = sendto(o.s, reinterpret_cast<const char*>(payload),
                                static_cast<int>(plen), 0,
                                reinterpret_cast<const sockaddr*>(&r.dst), sizeof(r.dst));

        if (sent == static_cast<int>(plen))
        {
            r.bytesTx.fetch_add(plen);
        }
        else
        {
            ++failed;
            const DWORD e = static_cast<DWORD>(WSAGetLastError());
            r.lastError.store(e);
            if (r.LogOk())
                Log("BŁĄD wysyłania (reguła %s, karta if %u): %s", RuleName(r.cfg).c_str(),
                    o.ifIdx, ErrStr(e).c_str());
        }
    }

    if (r.outs.empty())
    {
        r.errors.fetch_add(1);
        r.lastError.store(r.noOutError);
        r.failed = (r.noOutError != NVR_ERR_ADAPTER_DISABLED);
        needRefresh = needRefresh || r.failed;
        if (r.LogOk())
            Log("BŁĄD: reguła %s nie ma żadnego interfejsu wyjściowego: %s",
                RuleName(r.cfg).c_str(), ErrStr(r.noOutError).c_str());
        return;
    }

    if (attempted == 0)
    {
        r.skipped.fetch_add(1);     // jedyny dostepny interfejs to odbiorczy (ochrona przed petla)
        return;
    }

    if (failed > 0)
    {
        r.errors.fetch_add(1);
        r.failed = true;
        needRefresh = true;
        return;
    }

    r.forwarded.fetch_add(1);
}

// Sprawdza, czy zmienila sie lista interfejsow; gniazda sa odtwarzane tylko gdy tak.
static void CheckInterfaces(std::vector<IfAddr>& ifs, uint64_t& sig, bool& needRefresh)
{
    const std::vector<IfAddr> cur = EnumInterfaces();
    const uint64_t s2 = IfSignature(cur);

    if (s2 != sig)
    {
        Log("Zmiana interfejsów sieciowych - odtwarzam gniazda wyjściowe");
        ifs = cur;
        sig = s2;
        ApplyInterfaces(ifs, true);
        needRefresh = false;
        return;
    }

    if (needRefresh)
    {
        for (size_t i = 0; i < g_rules.size(); ++i)
        {
            Rule& r = *g_rules[i];
            if (r.failed)
            {
                BuildOutputs(r, ifs);
                LogOutputs(r);
            }
        }
        needRefresh = false;
    }
}

static DWORD WINAPI RelayThread(void*)
{
    std::vector<unsigned char> buf(65535);
    DivertAddress addr;

    std::vector<IfAddr> ifs;
    EnterCriticalSection(&g_dataCs);
    ifs = g_ifTable;
    LeaveCriticalSection(&g_dataCs);

    uint64_t sig = IfSignature(ifs);
    ULONGLONG lastCheck = GetTickCount64();
    bool needRefresh = false;

    while (!g_relayStop.load())
    {
        UINT len = 0;

        if (!g_wdRecv(g_divert, buf.data(), static_cast<UINT>(buf.size()), &len, &addr))
        {
            const DWORD e = GetLastError();

            if (g_relayStop.load() || e == ERROR_NO_DATA)   // WinDivertShutdown
                break;

            g_lastError.store(e);
            Log("BŁĄD odbioru WinDivert: %s", ErrStr(e).c_str());

            if (e == ERROR_INVALID_HANDLE)
                break;

            Sleep(10);
            continue;
        }

        g_totalSeen.fetch_add(1);

        const ULONGLONG now = GetTickCount64();
        if (now - lastCheck >= 5000 || (needRefresh && now - lastCheck >= 2000))
        {
            CheckInterfaces(ifs, sig, needRefresh);
            lastCheck = now;
        }

        uint32_t srcIp = 0;
        uint16_t dstPort = 0;
        const unsigned char* payload = nullptr;
        UINT plen = 0;

        if (!ParseUdp(buf.data(), len, srcIp, dstPort, payload, plen))
        {
            g_totalIgnored.fetch_add(1);
            continue;
        }

        // Ochrona przed petla: pakiet z naszym wlasnym adresem zrodlowym
        if (IsLocalIp(ifs, srcIp))
        {
            g_totalLoop.fetch_add(1);
            continue;
        }

        // Pakiety z kart, na ktorych odbior jest wylaczony w oknie konfiguracji.
        // Karta nieznana (jeszcze nie na liscie) jest dopuszczana, a lista odswiezana.
        {
            const IfAddr* rx = FindIf(ifs, addr.ifIdx);
            if (!rx)
                needRefresh = true;
            else if (!rx->rxAllowed)
            {
                g_totalLoop.fetch_add(1);
                continue;
            }
        }

        bool matched = false;

        for (size_t i = 0; i < g_rules.size(); ++i)
        {
            Rule& r = *g_rules[i];

            if (r.cfg.listenPort != dstPort)
                continue;
            if (r.cfg.srcIp != 0 && r.cfg.srcIp != srcIp)
                continue;

            matched = true;
            r.received.fetch_add(1);
            r.bytesRx.fetch_add(plen);
            r.lastRxIf.store(addr.ifIdx);
            ForwardOne(r, payload, plen, addr.ifIdx, needRefresh);
        }

        if (!matched)
            g_totalIgnored.fetch_add(1);
    }

    g_active.store(false);
    return 0;
}

// ------------------------------------------------------------
// Konfiguracja i sterowanie silnikiem (wolane pod g_ctlCs)
// ------------------------------------------------------------
static bool ReadFileUtf8(const std::wstring& path, std::string& out)
{
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;

    out.clear();
    char tmp[4096];
    DWORD n = 0;
    while (ReadFile(h, tmp, sizeof(tmp), &n, nullptr) && n > 0)
        out.append(tmp, n);

    CloseHandle(h);
    return true;
}

static void EnsureDefaultConfig()
{
    CreateDirectoryW(NvrDataDir().c_str(), nullptr);

    const std::wstring path = NvrConfigPath();
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return;

    static const char sample[] =
        "# NetVar repeater - konfiguracja\r\n"
        "# Format reguły: ip_nadawcy port_odbiorczy ip_docelowy port_docelowy\r\n"
        "# ip_nadawcy 0.0.0.0 = dowolny nadawca (również broadcast)\r\n"
        "# ip_docelowy może być broadcast (255.255.255.255 lub np. 192.168.1.255)\r\n"
        "# Komentarze: # lub ;\r\n"
        "#\r\n"
        "# Karty sieciowe, limit logu i limit pakietów/s ustawiasz w oknie konfiguracji\r\n"
        "# (menu ikony -> Edytuj konfigurację -> zakładki Karty sieciowe / Ustawienia).\r\n"
        "#\r\n"
        "# Przykłady reguł:\r\n"
        "# 0.0.0.0   1202 192.168.1.10   1203\r\n"
        "# 10.0.0.1  1203 192.170.10.3   1203\r\n"
        "# 0.0.0.0   1202 192.170.10.4   1202\r\n"
        "# 10.0.0.1  1203 255.255.255.255 1203\r\n";

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD w = 0;
        WriteFile(h, sample, sizeof(sample) - 1, &w, nullptr);
        CloseHandle(h);
    }
}

static void EngineStop()
{
    if (g_relayThread)
    {
        g_relayStop.store(true);

        if (g_divert != INVALID_HANDLE_VALUE && g_wdShutdown)
            g_wdShutdown(g_divert, WD_SHUTDOWN_RECV);

        if (WaitForSingleObject(g_relayThread, 10000) == WAIT_TIMEOUT)
            Log("OSTRZEŻENIE: wątek odbiorczy nie zakończył się w 10 s");

        CloseHandle(g_relayThread);
        g_relayThread = nullptr;
    }

    if (g_divert != INVALID_HANDLE_VALUE)
    {
        g_wdClose(g_divert);
        g_divert = INVALID_HANDLE_VALUE;
    }

    for (size_t i = 0; i < g_rules.size(); ++i)
        g_rules[i]->CloseSockets();

    g_active.store(false);
}

// Wczytuje config.txt i podmienia liste regul (relay MUSI byc zatrzymany).
static void LoadRules(bool keepCounters)
{
    EnsureDefaultConfig();

    std::string text;
    const bool haveFile = ReadFileUtf8(NvrConfigPath(), text);

    NvrConfigResult cfg;
    if (haveFile)
        cfg = NvrParseConfig(text, NVR_MAX_RULES);

    // settings.ini: karty (odbior/wysylanie), limit logu, limit pps
    std::string setText;
    NvrSettingsFile st;
    const bool haveSettings = ReadFileUtf8(NvrSettingsPath(), setText);
    if (haveSettings)
        st = NvrParseSettings(setText);

    g_settings = st;
    g_maxPps.store(st.maxPps);
    g_logMaxMb.store(st.logMaxMb);

    if (!haveSettings)
        Log("Brak settings.ini - ustawienia domyślne (karty fizyczne włączone, wirtualne wyłączone)");
    for (size_t i = 0; i < st.errors.size() && i < 10; ++i)
        Log("  %s", st.errors[i].c_str());

    RuleList fresh;
    for (size_t i = 0; i < cfg.rules.size(); ++i)
    {
        std::unique_ptr<Rule> r(new Rule(cfg.rules[i]));

        if (keepCounters)
        {
            for (size_t j = 0; j < g_rules.size(); ++j)
            {
                const NvrRuleCfg& o = g_rules[j]->cfg;
                if (o.srcIp == r->cfg.srcIp && o.listenPort == r->cfg.listenPort &&
                    o.dstIp == r->cfg.dstIp && o.dstPort == r->cfg.dstPort)
                {
                    const Rule& old = *g_rules[j];
                    r->received.store(old.received.load());
                    r->forwarded.store(old.forwarded.load());
                    r->errors.store(old.errors.load());
                    r->skipped.store(old.skipped.load());
                    r->bytesRx.store(old.bytesRx.load());
                    r->bytesTx.store(old.bytesTx.load());
                    r->lastError.store(old.lastError.load());
                    r->lastRxIf.store(old.lastRxIf.load());
                    break;
                }
            }
        }

        fresh.push_back(std::move(r));
    }

    std::string msg;
    if (!haveFile)
        msg = "Nie można odczytać pliku konfiguracji";
    else if (!cfg.errors.empty())
        msg = cfg.errors[0];
    else if (cfg.rules.empty())
        msg = "Brak reguł w konfiguracji - edytuj konfigurację";

    EnterCriticalSection(&g_dataCs);
    g_rules.swap(fresh);                       // stare reguly zamkna gniazda w destruktorach
    g_cfgErrorCount = static_cast<uint32_t>(cfg.errors.size());
    g_cfgMessage = msg;
    LeaveCriticalSection(&g_dataCs);

    if (!keepCounters)
    {
        g_totalSeen.store(0);
        g_totalIgnored.store(0);
        g_totalLoop.store(0);
    }

    Log("Konfiguracja: %u reguł, %u błędnych linii; ustawienia: max_pps=%u, log_max_mb=%u, kart w settings.ini=%u",
        static_cast<unsigned>(cfg.rules.size()), static_cast<unsigned>(cfg.errors.size()),
        st.maxPps, st.logMaxMb, static_cast<unsigned>(st.adapters.size()));

    for (size_t i = 0; i < cfg.errors.size() && i < 20; ++i)
        Log("  odrzucono: %s", cfg.errors[i].c_str());
}

static std::string BuildFilter()
{
    std::set<uint16_t> ports;
    for (size_t i = 0; i < g_rules.size(); ++i)
        ports.insert(g_rules[i]->cfg.listenPort);

    // Tylko pakiety przychodzace, nie-loopback, IPv4 UDP na portach z regul.
    // (nadawca jest dopasowywany w kodzie - filtr WinDivert ma limit dlugosci)
    std::string f = "inbound and loopback == 0 and ip and udp";

    if (!ports.empty() && ports.size() <= 40)
    {
        f += " and (";
        bool first = true;
        for (std::set<uint16_t>::const_iterator it = ports.begin(); it != ports.end(); ++it)
        {
            if (!first) f += " or ";
            f += "udp.DstPort == " + std::to_string(*it);
            first = false;
        }
        f += ")";
    }

    return f;
}

static DWORD EngineStart(bool keepCounters)
{
    EngineStop();
    LoadRules(keepCounters);

    if (g_rules.empty())
    {
        g_lastError.store(NVR_ERR_NO_RULES);
        return NVR_ERR_NO_RULES;
    }

    if (!LoadWinDivert())
        return g_lastError.load();

    const std::string filter = BuildFilter();

    g_divert = g_wdOpen(filter.c_str(), WD_LAYER_NETWORK, 0, WD_FLAG_SNIFF | WD_FLAG_RECV_ONLY);
    if (g_divert == INVALID_HANDLE_VALUE)
    {
        const DWORD e = GetLastError();
        g_lastError.store(e);
        const std::string hint = ErrHint(e);
        Log("BŁĄD: WinDivertOpen nie powiódł się: %s%s%s", ErrStr(e).c_str(),
            hint.empty() ? "" : " - ", hint.c_str());
        return e;
    }

    Log("WinDivert otwarty, filtr: %s", filter.c_str());

    ApplyInterfaces(EnumInterfaces(), true);

    g_relayStop.store(false);
    g_lastError.store(0);

    EnterCriticalSection(&g_dataCs);
    g_startTime = NowFileTime();
    LeaveCriticalSection(&g_dataCs);

    g_active.store(true);
    g_relayThread = CreateThread(nullptr, 0, RelayThread, nullptr, 0, nullptr);

    if (!g_relayThread)
    {
        const DWORD e = GetLastError();
        g_lastError.store(e);
        Log("BŁĄD: nie można utworzyć wątku odbiorczego: %s", ErrStr(e).c_str());
        EngineStop();
        return e;
    }

    Log("Przekazywanie URUCHOMIONE");
    return NO_ERROR;
}

static DWORD EngineCommand(uint32_t cmd)
{
    DWORD result = NO_ERROR;

    EnterCriticalSection(&g_ctlCs);

    switch (cmd)
    {
        case NVR_CMD_START:
            Log("Polecenie: START");
            g_userStopped.store(false);
            g_nextRetryTick.store(0);
            result = EngineStart(true);
            break;

        case NVR_CMD_STOP:
            Log("Polecenie: STOP");
            g_userStopped.store(true);
            EngineStop();
            Log("Przekazywanie ZATRZYMANE");
            break;

        case NVR_CMD_RESET:
        {
            Log("Polecenie: RESET");
            const bool shouldRun = g_active.load() || !g_userStopped.load();
            EngineStop();
            g_lastError.store(0);
            g_nextRetryTick.store(0);

            if (shouldRun)
            {
                result = EngineStart(false);
            }
            else
            {
                LoadRules(false);
                EnterCriticalSection(&g_dataCs);
                g_startTime = 0;
                LeaveCriticalSection(&g_dataCs);
            }
            break;
        }

        default:
            break;
    }

    LeaveCriticalSection(&g_ctlCs);
    return result;
}

// ------------------------------------------------------------
// Nadzor: ponawianie startu po bledzie (wycofanie 5-10-20-30-60 s)
// ------------------------------------------------------------
static DWORD WINAPI SupervisorThread(void*)
{
    unsigned failures = 0;
    DWORD lastLoggedErr = 0xFFFFFFFFu;
    ULONGLONG lastLoggedTick = 0;

    while (WaitForSingleObject(g_stopEvent, 1000) == WAIT_TIMEOUT)
    {
        if (g_active.load() || g_userStopped.load())
        {
            failures = 0;
            g_nextRetryTick.store(0);
            continue;
        }

        const ULONGLONG now = GetTickCount64();
        uint64_t next = g_nextRetryTick.load();

        if (next == 0)
        {
            static const unsigned delays[] = { 5, 10, 20, 30, 60 };
            const unsigned d = delays[failures < 5 ? failures : 4];
            next = now + static_cast<ULONGLONG>(d) * 1000ull;
            g_nextRetryTick.store(next);
            continue;
        }

        if (now < next)
            continue;

        if (!TryEnterCriticalSection(&g_ctlCs))
            continue;

        if (!g_active.load() && !g_userStopped.load())
        {
            const DWORD e = EngineStart(true);
            if (e == NO_ERROR)
            {
                Log("Automatyczne ponowienie startu: sukces");
                failures = 0;
            }
            else
            {
                ++failures;
                if (e != lastLoggedErr || now - lastLoggedTick > 600000ull)
                {
                    Log("Automatyczne ponowienie startu nie powiodło się: %s (kolejna próba wg harmonogramu)",
                        ErrStr(e).c_str());
                    lastLoggedErr = e;
                    lastLoggedTick = now;
                }
            }
        }

        LeaveCriticalSection(&g_ctlCs);
        g_nextRetryTick.store(0);
    }

    return 0;
}

// ------------------------------------------------------------
// Serwer named pipe (tray <-> usluga), 3 watki
// ------------------------------------------------------------
// Uzupelnia opis interfejsu z tabeli g_ifTable (wolac pod g_dataCs).
static void FillIf(NvrIfInfo& out, uint32_t ifIdx)
{
    std::memset(&out, 0, sizeof(out));
    out.ifIdx = ifIdx;

    if (ifIdx == 0)
        return;

    for (size_t i = 0; i < g_ifTable.size(); ++i)
    {
        if (g_ifTable[i].ifIdx != ifIdx)
            continue;

        out.ip = g_ifTable[i].ip;
        out.flags = g_ifTable[i].isVirtual ? NVR_IF_VIRTUAL : 0;
        const size_t n = g_ifTable[i].name.size() < 39 ? g_ifTable[i].name.size() : 39;
        for (size_t k = 0; k < n; ++k)
            out.name[k] = g_ifTable[i].name[k];
        return;
    }
}

static uint32_t BuildReply(std::vector<unsigned char>& out, DWORD commandResult)
{
    EnterCriticalSection(&g_dataCs);

    size_t n = g_rules.size();
    if (n > NVR_MAX_RULES) n = NVR_MAX_RULES;

    const uint32_t size = static_cast<uint32_t>(sizeof(NvrReplyHeader) + n * sizeof(NvrRuleStatus));
    out.assign(size, 0);

    NvrReplyHeader* h = reinterpret_cast<NvrReplyHeader*>(out.data());
    h->magic = NVR_MAGIC;
    h->commandResult = commandResult;
    h->active = g_active.load() ? 1u : 0u;
    h->lastError = g_lastError.load();
    h->userStopped = g_userStopped.load() ? 1u : 0u;
    h->maxPps = g_maxPps.load();
    h->logMaxMb = g_logMaxMb.load();
    h->nowTime = NowFileTime();
    h->totalSeen = g_totalSeen.load();
    h->totalIgnored = g_totalIgnored.load();
    h->totalLoopDropped = g_totalLoop.load();
    h->configErrorCount = g_cfgErrorCount;
    h->startTime = g_startTime;
    h->ruleCount = static_cast<uint32_t>(n);
    std::strncpy(h->message, g_cfgMessage.c_str(), sizeof(h->message) - 1);

    const uint64_t next = g_nextRetryTick.load();
    const ULONGLONG now = GetTickCount64();
    if (!h->active && !h->userStopped && next > now)
        h->retryInSec = static_cast<uint32_t>((next - now + 999) / 1000);

    NvrRuleStatus* rs = reinterpret_cast<NvrRuleStatus*>(out.data() + sizeof(NvrReplyHeader));

    for (size_t i = 0; i < n; ++i)
    {
        const Rule& r = *g_rules[i];
        rs[i].srcIp = r.cfg.srcIp;
        rs[i].dstIp = r.cfg.dstIp;
        rs[i].listenPort = r.cfg.listenPort;
        rs[i].dstPort = r.cfg.dstPort;
        rs[i].outMode = r.outMode.load();
        rs[i].outIfIdx = r.outIfIdx.load();
        rs[i].outCount = r.outCount.load();
        rs[i].lastError = r.lastError.load();
        rs[i].received = r.received.load();
        rs[i].forwarded = r.forwarded.load();
        rs[i].errors = r.errors.load();
        rs[i].skipped = r.skipped.load();
        rs[i].bytesReceived = r.bytesRx.load();
        rs[i].bytesForwarded = r.bytesTx.load();

        FillIf(rs[i].rxIf, r.lastRxIf.load());

        uint32_t shown = r.outCount.load();
        if (shown > NVR_MAX_TX_SHOW) shown = NVR_MAX_TX_SHOW;
        rs[i].txShown = shown;
        for (uint32_t k = 0; k < shown; ++k)
            FillIf(rs[i].txIf[k], r.txIf[k].load());
    }

    LeaveCriticalSection(&g_dataCs);
    return size;
}

// Czeka na zakonczenie operacji overlapped; false przy timeout/stop/bledzie.
static bool WaitIo(HANDLE pipe, OVERLAPPED& ov, DWORD timeoutMs, DWORD& bytes)
{
    HANDLE h[2] = { ov.hEvent, g_stopEvent };
    const DWORD w = WaitForMultipleObjects(2, h, FALSE, timeoutMs);

    if (w != WAIT_OBJECT_0)
    {
        CancelIo(pipe);
        GetOverlappedResult(pipe, &ov, &bytes, TRUE);
        return false;
    }

    return GetOverlappedResult(pipe, &ov, &bytes, FALSE) != FALSE;
}

static DWORD WINAPI PipeThread(void*)
{
    PSECURITY_DESCRIPTOR sd = nullptr;

    // Uwierzytelnieni uzytkownicy: odczyt + zapis (status i polecenia),
    // administratorzy i SYSTEM: pelny dostep.
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GRGW;;;AU)(A;;GA;;;BA)(A;;GA;;;SY)", SDDL_REVISION_1, &sd, nullptr))
    {
        Log("BŁĄD: nie można utworzyć deskryptora zabezpieczeń pipe: %s", ErrStr(GetLastError()).c_str());
        return 1;
    }

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;

    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<unsigned char> reply;

    while (WaitForSingleObject(g_stopEvent, 0) == WAIT_TIMEOUT)
    {
        HANDLE pipe = CreateNamedPipeW(
            NVR_PIPE_NAME,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            NVR_MAX_REPLY, 256, 0, &sa);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            Sleep(500);
            continue;
        }

        OVERLAPPED ov;
        std::memset(&ov, 0, sizeof(ov));
        ov.hEvent = ev;
        ResetEvent(ev);

        DWORD bytes = 0;
        bool connected = false;

        if (ConnectNamedPipe(pipe, &ov))
            connected = true;
        else
        {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED)
                connected = true;
            else if (e == ERROR_IO_PENDING)
                connected = WaitIo(pipe, ov, INFINITE, bytes);
        }

        if (connected)
        {
            NvrRequest req;
            std::memset(&req, 0, sizeof(req));

            std::memset(&ov, 0, sizeof(ov));
            ov.hEvent = ev;
            ResetEvent(ev);

            bool ok = false;
            if (ReadFile(pipe, &req, sizeof(req), nullptr, &ov) || GetLastError() == ERROR_IO_PENDING)
                ok = WaitIo(pipe, ov, 2000, bytes) && bytes == sizeof(req) && req.magic == NVR_MAGIC;

            if (ok)
            {
                DWORD cmdResult = NO_ERROR;

                if (req.command >= NVR_CMD_START && req.command <= NVR_CMD_RESET)
                    cmdResult = EngineCommand(req.command);

                const uint32_t size = BuildReply(reply, cmdResult);

                std::memset(&ov, 0, sizeof(ov));
                ov.hEvent = ev;
                ResetEvent(ev);

                if (WriteFile(pipe, reply.data(), size, nullptr, &ov) ||
                    GetLastError() == ERROR_IO_PENDING)
                {
                    WaitIo(pipe, ov, 2000, bytes);
                }

                FlushFileBuffers(pipe);
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    CloseHandle(ev);
    LocalFree(sd);
    return 0;
}

// ------------------------------------------------------------
// Wspolny rdzen: tryb uslugi i tryb konsolowy
// ------------------------------------------------------------
static void ReportServiceStatus(DWORD state, DWORD exitCode = NO_ERROR, DWORD waitHint = 0)
{
    if (!g_statusHandle)
        return;

    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;
    g_serviceStatus.dwWin32ExitCode = exitCode;
    g_serviceStatus.dwWaitHint = waitHint;

    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
    {
        g_serviceStatus.dwControlsAccepted = 0;
        g_serviceStatus.dwCheckPoint++;
    }
    else
    {
        g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        g_serviceStatus.dwCheckPoint = 0;
    }

    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

static int RunCore(bool console)
{
    InitializeCriticalSection(&g_logCs);
    InitializeCriticalSection(&g_dataCs);
    InitializeCriticalSection(&g_ctlCs);

    g_console = console;
    CreateDirectoryW(NvrDataDir().c_str(), nullptr);
    SetCurrentDirectoryW(ExeDir().c_str());   // katalog roboczy uslugi to System32

    Log("=== NetVar repeater: start (%s) ===", console ? "tryb konsolowy" : "usługa");

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    WSADATA wsa;
    const int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsa);

    if (!g_stopEvent || wsaRc != 0)
    {
        Log("BŁĄD: inicjalizacja (WSAStartup=%d)", wsaRc);
        return 1;
    }

    for (int i = 0; i < NUM_PIPE_THREADS; ++i)
        g_pipeThreads[i] = CreateThread(nullptr, 0, PipeThread, nullptr, 0, nullptr);

    g_supervisor = CreateThread(nullptr, 0, SupervisorThread, nullptr, 0, nullptr);

    ReportServiceStatus(SERVICE_RUNNING);

    // Automatyczny start przekazywania. Przy bledzie usluga dziala dalej
    // i SupervisorThread ponawia probe (wynik widoczny w trayu i w logu).
    EnterCriticalSection(&g_ctlCs);
    const DWORD startResult = EngineStart(false);
    LeaveCriticalSection(&g_ctlCs);

    if (startResult != NO_ERROR)
        Log("Start nieudany (%s) - usługa próbuje ponownie automatycznie", ErrStr(startResult).c_str());

    WaitForSingleObject(g_stopEvent, INFINITE);

    Log("Zatrzymywanie...");

    for (int i = 0; i < NUM_PIPE_THREADS; ++i)
    {
        if (g_pipeThreads[i])
        {
            WaitForSingleObject(g_pipeThreads[i], 5000);
            CloseHandle(g_pipeThreads[i]);
            g_pipeThreads[i] = nullptr;
        }
    }

    if (g_supervisor)
    {
        WaitForSingleObject(g_supervisor, 15000);
        CloseHandle(g_supervisor);
        g_supervisor = nullptr;
    }

    EnterCriticalSection(&g_ctlCs);
    EngineStop();
    LeaveCriticalSection(&g_ctlCs);

    g_rules.clear();

    if (g_dll)
    {
        FreeLibrary(g_dll);
        g_dll = nullptr;
    }

    WSACleanup();
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;

    Log("=== NetVar repeater: zatrzymany ===");

    DeleteCriticalSection(&g_ctlCs);
    DeleteCriticalSection(&g_dataCs);
    DeleteCriticalSection(&g_logCs);
    return 0;
}

static DWORD WINAPI ServiceHandler(DWORD control, DWORD, void*, void*)
{
    switch (control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30000);
            if (g_stopEvent)
                SetEvent(g_stopEvent);
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(NVR_SERVICE_NAME, ServiceHandler, nullptr);
    if (!g_statusHandle)
        return;

    std::memset(&g_serviceStatus, 0, sizeof(g_serviceStatus));
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    const int rc = RunCore(false);

    ReportServiceStatus(SERVICE_STOPPED, rc == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR);
}

static BOOL WINAPI ConsoleHandler(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT ||
        type == CTRL_SHUTDOWN_EVENT)
    {
        if (g_stopEvent)
            SetEvent(g_stopEvent);
        return TRUE;
    }
    return FALSE;
}

static bool PipeAlreadyExists()
{
    if (WaitNamedPipeW(NVR_PIPE_NAME, 1))
        return true;
    return GetLastError() != ERROR_FILE_NOT_FOUND;
}

int main(int argc, char** argv)
{
    bool console = false;
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--console") == 0 || std::strcmp(argv[i], "-c") == 0)
            console = true;

    if (console)
    {
        SetConsoleOutputCP(CP_UTF8);

        if (PipeAlreadyExists())
        {
            std::fputs("Usługa NetVarRepeater (lub inna instancja) już działa.\n"
                       "Zatrzymaj ją (sc stop NetVarRepeater) przed uruchomieniem w trybie konsolowym.\n", stderr);
            return 2;
        }

        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        std::puts("NetVar repeater - tryb konsolowy (Ctrl+C = zakończ). Wymaga uprawnień administratora.");
        return RunCore(true);
    }

    SERVICE_TABLE_ENTRYW table[] =
    {
        { const_cast<LPWSTR>(NVR_SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table))
    {
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
        {
            std::puts("NetVarRepeaterService.exe jest usługą Windows.\n"
                      "  Instalacja:        install.bat (jako administrator)\n"
                      "  Test w konsoli:    NetVarRepeaterService.exe --console");
        }
        return 1;
    }

    return 0;
}
