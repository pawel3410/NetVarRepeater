// ============================================================
// NetVarRepeaterService - usluga Windows
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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "common.h"
#include "config.h"

#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 31
#endif

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
    uint32_t flags;        // Layer:8 Event:8 Sniffed:1 Outbound:1 Loopback:1 Impostor:1 IPv6:1 ...
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
    NvrRuleCfg cfg;
    sockaddr_in dst;
    std::vector<OutSock> outs;      // tylko watek relay (i Start/Stop gdy relay stoi)

    std::atomic<uint32_t> outMode;
    std::atomic<uint32_t> outIfIdx;
    std::atomic<uint32_t> outCount;
    std::atomic<uint32_t> lastError;
    std::atomic<uint64_t> received;
    std::atomic<uint64_t> forwarded;
    std::atomic<uint64_t> bytes;
    std::atomic<uint64_t> errors;

    explicit Rule(const NvrRuleCfg& c)
        : cfg(c), outMode(NVR_OUT_OS), outIfIdx(0), outCount(0), lastError(0),
          received(0), forwarded(0), bytes(0), errors(0)
    {
        std::memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(c.dstPort);
        dst.sin_addr.s_addr = htonl(c.dstIp);
    }

    void CloseSockets()
    {
        for (size_t i = 0; i < outs.size(); ++i)
            if (outs[i].s != INVALID_SOCKET)
                closesocket(outs[i].s);
        outs.clear();
        outCount.store(0);
    }

    ~Rule() { CloseSockets(); }
};

typedef std::vector<std::unique_ptr<Rule> > RuleList;

// ------------------------------------------------------------
// Stan globalny
// ------------------------------------------------------------
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS        g_serviceStatus;
static HANDLE                g_stopEvent = nullptr;     // zatrzymanie uslugi
static HANDLE                g_pipeThread = nullptr;

static CRITICAL_SECTION g_dataCs;   // chroni g_rules (podmiana), g_cfgMessage, g_startTime
static CRITICAL_SECTION g_ctlCs;    // serializuje Start/Stop/Reset

static RuleList     g_rules;
static std::string  g_cfgMessage;
static uint32_t     g_cfgErrorCount = 0;
static uint64_t     g_startTime = 0;

static HANDLE               g_relayThread = nullptr;
static HANDLE               g_divert = INVALID_HANDLE_VALUE;
static std::atomic<bool>    g_active(false);
static std::atomic<bool>    g_relayStop(false);
static std::atomic<uint32_t> g_lastError(0);
static std::atomic<uint64_t> g_totalSeen(0);
static std::atomic<uint64_t> g_totalIgnored(0);

static uint64_t NowFileTime()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

// ------------------------------------------------------------
// Ladowanie WinDivert
// ------------------------------------------------------------
static std::wstring ExeDir()
{
    wchar_t path[MAX_PATH * 2];
    DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH * 2);
    std::wstring p(path, n);
    size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

static bool LoadWinDivert()
{
    if (g_dll)
        return true;

    // pelna sciezka - katalog roboczy uslugi to System32
    std::wstring dll = ExeDir() + L"\\WinDivert.dll";
    g_dll = LoadLibraryExW(dll.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);

    if (!g_dll)
    {
        g_lastError.store(GetLastError());
        return false;
    }

    g_wdOpen = reinterpret_cast<FnWinDivertOpen>(GetProcAddress(g_dll, "WinDivertOpen"));
    g_wdRecv = reinterpret_cast<FnWinDivertRecv>(GetProcAddress(g_dll, "WinDivertRecv"));
    g_wdClose = reinterpret_cast<FnWinDivertClose>(GetProcAddress(g_dll, "WinDivertClose"));
    g_wdShutdown = reinterpret_cast<FnWinDivertShutdown>(GetProcAddress(g_dll, "WinDivertShutdown"));

    if (!g_wdOpen || !g_wdRecv || !g_wdClose || !g_wdShutdown)
    {
        g_lastError.store(ERROR_PROC_NOT_FOUND);
        FreeLibrary(g_dll);
        g_dll = nullptr;
        return false;
    }

    return true;
}

// ------------------------------------------------------------
// Identyfikacja interfejsow sieciowych
// ------------------------------------------------------------
struct IfAddr
{
    uint32_t ifIdx;
    uint32_t ip;      // host order
    uint32_t mask;    // host order
};

// Lista adresow IPv4 interfejsow, ktore sa UP i nie sa loopbackiem.
static std::vector<IfAddr> EnumInterfaces()
{
    std::vector<IfAddr> result;

    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf;
    ULONG rc;

    for (int attempt = 0; attempt < 4; ++attempt)
    {
        buf.resize(size);
        rc = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
            GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &size);

        if (rc != ERROR_BUFFER_OVERFLOW)
            break;
    }

    if (rc != NO_ERROR)
        return result;

    for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
         a; a = a->Next)
    {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->OperStatus != IfOperStatusUp)
            continue;

        for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u; u = u->Next)
        {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            IfAddr ia;
            ia.ifIdx = a->IfIndex;
            ia.ip = ntohl(sin->sin_addr.s_addr);

            unsigned prefix = u->OnLinkPrefixLength;
            if (prefix > 32) prefix = 32;
            ia.mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));

            if (ia.ip != 0)
                result.push_back(ia);
        }
    }

    return result;
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
        // IP_UNICAST_IF: indeks interfejsu w network byte order (IPv4)
        DWORD v = htonl(ifIdx);
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

// Wybiera interfejs/gniazda wyjsciowe dla reguly (patrz README: "Identyfikacja interfejsow").
static void BuildOutputs(Rule& r, const std::vector<IfAddr>& ifs)
{
    r.CloseSockets();
    r.outMode.store(NVR_OUT_OS);
    r.outIfIdx.store(0);

    const uint32_t dst = r.cfg.dstIp;

    // 1) broadcast ograniczony 255.255.255.255 -> po jednym gnieZdzie na interfejs
    if (dst == 0xFFFFFFFFu)
    {
        std::set<uint32_t> seen;
        for (size_t i = 0; i < ifs.size(); ++i)
        {
            if (!seen.insert(ifs[i].ifIdx).second)
                continue;

            SOCKET s = MakeOutSocket(ifs[i].ip, ifs[i].ifIdx);
            if (s != INVALID_SOCKET)
            {
                OutSock o = { s, ifs[i].ifIdx };
                r.outs.push_back(o);
            }
        }
        r.outMode.store(NVR_OUT_BCAST_ALL);
        r.outCount.store(static_cast<uint32_t>(r.outs.size()));
        return;
    }

    // 2) broadcast kierowany (np. 192.168.1.255) -> interfejs z ta podsiecia
    for (size_t i = 0; i < ifs.size(); ++i)
    {
        const IfAddr& ia = ifs[i];
        if (ia.mask == 0xFFFFFFFFu || ia.mask == 0xFFFFFFFEu || ia.mask == 0)
            continue;

        if (dst == (ia.ip | ~ia.mask))
        {
            SOCKET s = MakeOutSocket(ia.ip, ia.ifIdx);
            if (s != INVALID_SOCKET)
            {
                OutSock o = { s, ia.ifIdx };
                r.outs.push_back(o);
                r.outMode.store(NVR_OUT_BOUND);
                r.outIfIdx.store(ia.ifIdx);
                r.outCount.store(1);
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

            SOCKET s = MakeOutSocket(ifs[i].ip, ifs[i].ifIdx);
            if (s != INVALID_SOCKET)
            {
                OutSock o = { s, ifs[i].ifIdx };
                r.outs.push_back(o);
                r.outMode.store(NVR_OUT_BOUND);
                r.outIfIdx.store(ifs[i].ifIdx);
                r.outCount.store(1);
                return;
            }
        }
    }

    // 4) np. adres lokalny / loopback / brak trasy -> decyduje system
    SOCKET s = MakeOutSocket(0, 0);
    if (s != INVALID_SOCKET)
    {
        OutSock o = { s, 0 };
        r.outs.push_back(o);
    }
    r.outCount.store(static_cast<uint32_t>(r.outs.size()));
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
// Watek odbiorczo-przekazujacy
// ------------------------------------------------------------
static void ForwardOne(Rule& r, const unsigned char* payload, UINT plen,
                       uint32_t rxIfIdx, bool& needRefresh)
{
    int attempted = 0, failed = 0;

    for (size_t i = 0; i < r.outs.size(); ++i)
    {
        const OutSock& o = r.outs[i];

        // broadcast: nie odsylamy na interfejs, z ktorego pakiet przyszedl
        if (r.outMode.load() == NVR_OUT_BCAST_ALL && o.ifIdx == rxIfIdx)
            continue;

        ++attempted;

        const int sent = sendto(o.s, reinterpret_cast<const char*>(payload),
                                static_cast<int>(plen), 0,
                                reinterpret_cast<const sockaddr*>(&r.dst), sizeof(r.dst));

        if (sent != static_cast<int>(plen))
        {
            ++failed;
            r.errors.fetch_add(1);
            r.lastError.store(static_cast<uint32_t>(WSAGetLastError()));
            needRefresh = true;
        }
    }

    if (attempted == 0)
    {
        // brak interfejsu wyjsciowego (np. siec jeszcze nie wstala)
        if (r.outMode.load() != NVR_OUT_BCAST_ALL || r.outs.empty())
        {
            r.errors.fetch_add(1);
            r.lastError.store(ERROR_NETWORK_UNREACHABLE);
            needRefresh = true;
        }
        return;
    }

    if (failed == 0)
    {
        r.forwarded.fetch_add(1);
        r.bytes.fetch_add(plen);
    }
}

static void RefreshOutputs()
{
    const std::vector<IfAddr> ifs = EnumInterfaces();
    for (size_t i = 0; i < g_rules.size(); ++i)
        BuildOutputs(*g_rules[i], ifs);
}

static DWORD WINAPI RelayThread(void*)
{
    std::vector<unsigned char> buf(65535);
    DivertAddress addr;
    ULONGLONG lastRefresh = GetTickCount64();
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
            if (e == ERROR_INVALID_HANDLE)
                break;

            Sleep(10);
            continue;
        }

        g_totalSeen.fetch_add(1);

        uint32_t srcIp = 0;
        uint16_t dstPort = 0;
        const unsigned char* payload = nullptr;
        UINT plen = 0;

        if (!ParseUdp(buf.data(), len, srcIp, dstPort, payload, plen))
        {
            g_totalIgnored.fetch_add(1);
            continue;
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
            ForwardOne(r, payload, plen, addr.ifIdx, needRefresh);
        }

        if (!matched)
            g_totalIgnored.fetch_add(1);

        // Odswiezenie interfejsow: po bledzie wysylki (min. 2 s), a poza tym co 30 s
        const ULONGLONG now = GetTickCount64();
        if ((needRefresh && now - lastRefresh >= 2000) || now - lastRefresh >= 30000)
        {
            RefreshOutputs();
            lastRefresh = now;
            needRefresh = false;
        }
    }

    g_active.store(false);
    return 0;
}

// ------------------------------------------------------------
// Sterowanie silnikiem (wolane pod g_ctlCs)
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
    const std::wstring dir = NvrDataDir();
    CreateDirectoryW(dir.c_str(), nullptr);

    const std::wstring path = NvrConfigPath();
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        return;

    static const char sample[] =
        "# NetVarRepeater - konfiguracja\r\n"
        "# Format: ip_nadawcy port_odbiorczy ip_docelowy port_docelowy\r\n"
        "# ip_nadawcy 0.0.0.0 = dowolny nadawca (rowniez broadcast)\r\n"
        "# ip_docelowy moze byc broadcast (255.255.255.255 lub np. 192.168.1.255)\r\n"
        "# Komentarze: # lub ;\r\n"
        "#\r\n"
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

        WaitForSingleObject(g_relayThread, 10000);
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
                    r->received.store(g_rules[j]->received.load());
                    r->forwarded.store(g_rules[j]->forwarded.load());
                    r->bytes.store(g_rules[j]->bytes.load());
                    r->errors.store(g_rules[j]->errors.load());
                    r->lastError.store(g_rules[j]->lastError.load());
                    break;
                }
            }
        }

        fresh.push_back(std::move(r));
    }

    std::string msg;
    if (!haveFile)
        msg = "Nie mozna odczytac pliku konfiguracji";
    else if (!cfg.errors.empty())
        msg = cfg.errors[0];

    EnterCriticalSection(&g_dataCs);
    g_rules.swap(fresh);                       // stare reguly zamkna gniazda w destruktorach
    g_cfgErrorCount = static_cast<uint32_t>(cfg.errors.size());
    g_cfgMessage = msg;
    LeaveCriticalSection(&g_dataCs);

    if (!keepCounters)
    {
        g_totalSeen.store(0);
        g_totalIgnored.store(0);
    }
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
        g_lastError.store(ERROR_BAD_CONFIGURATION);
        return ERROR_BAD_CONFIGURATION;
    }

    if (!LoadWinDivert())
        return g_lastError.load();

    const std::string filter = BuildFilter();

    g_divert = g_wdOpen(filter.c_str(), WD_LAYER_NETWORK, 0, WD_FLAG_SNIFF | WD_FLAG_RECV_ONLY);
    if (g_divert == INVALID_HANDLE_VALUE)
    {
        const DWORD e = GetLastError();
        g_lastError.store(e);
        return e;
    }

    RefreshOutputs();

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
        EngineStop();
        return e;
    }

    return NO_ERROR;
}

static DWORD EngineCommand(uint32_t cmd)
{
    DWORD result = NO_ERROR;

    EnterCriticalSection(&g_ctlCs);

    switch (cmd)
    {
        case NVR_CMD_START:
            result = EngineStart(true);
            break;

        case NVR_CMD_STOP:
            EngineStop();
            break;

        case NVR_CMD_RESET:
        {
            const bool wasActive = g_active.load();
            EngineStop();
            g_lastError.store(0);

            if (wasActive)
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
// Serwer named pipe (tray <-> usluga)
// ------------------------------------------------------------
static uint32_t BuildReply(std::vector<unsigned char>& out, DWORD commandResult)
{
    out.assign(NVR_MAX_REPLY, 0);

    NvrReplyHeader* h = reinterpret_cast<NvrReplyHeader*>(out.data());
    h->magic = NVR_MAGIC;
    h->commandResult = commandResult;
    h->active = g_active.load() ? 1u : 0u;
    h->lastError = g_lastError.load();
    h->nowTime = NowFileTime();
    h->totalSeen = g_totalSeen.load();
    h->totalIgnored = g_totalIgnored.load();

    EnterCriticalSection(&g_dataCs);

    h->configErrorCount = g_cfgErrorCount;
    h->startTime = g_startTime;
    std::strncpy(h->message, g_cfgMessage.c_str(), sizeof(h->message) - 1);

    NvrRuleStatus* rs = reinterpret_cast<NvrRuleStatus*>(out.data() + sizeof(NvrReplyHeader));
    uint32_t n = 0;

    for (size_t i = 0; i < g_rules.size() && n < NVR_MAX_RULES; ++i, ++n)
    {
        const Rule& r = *g_rules[i];
        rs[n].srcIp = r.cfg.srcIp;
        rs[n].dstIp = r.cfg.dstIp;
        rs[n].listenPort = r.cfg.listenPort;
        rs[n].dstPort = r.cfg.dstPort;
        rs[n].outMode = r.outMode.load();
        rs[n].outIfIdx = r.outIfIdx.load();
        rs[n].outCount = r.outCount.load();
        rs[n].lastError = r.lastError.load();
        rs[n].received = r.received.load();
        rs[n].forwarded = r.forwarded.load();
        rs[n].bytesForwarded = r.bytes.load();
        rs[n].errors = r.errors.load();
    }

    LeaveCriticalSection(&g_dataCs);

    h->ruleCount = n;
    return static_cast<uint32_t>(sizeof(NvrReplyHeader) + n * sizeof(NvrRuleStatus));
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
        g_lastError.store(GetLastError());
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
// Usluga Windows
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

static DWORD WINAPI ServiceHandler(DWORD control, DWORD, void*, void*)
{
    switch (control)
    {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
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

    // katalog roboczy uslugi to System32 - przenosimy do katalogu exe
    SetCurrentDirectoryW(ExeDir().c_str());

    InitializeCriticalSection(&g_dataCs);
    InitializeCriticalSection(&g_ctlCs);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    WSADATA wsa;
    const int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsa);

    if (!g_stopEvent || wsaRc != 0)
    {
        ReportServiceStatus(SERVICE_STOPPED, wsaRc ? static_cast<DWORD>(wsaRc) : GetLastError());
        return;
    }

    g_pipeThread = CreateThread(nullptr, 0, PipeThread, nullptr, 0, nullptr);

    ReportServiceStatus(SERVICE_RUNNING);

    // Automatyczny start przekazywania (wynik widoczny w trayu; usluga dziala dalej nawet przy bledzie)
    EnterCriticalSection(&g_ctlCs);
    EngineStart(false);
    LeaveCriticalSection(&g_ctlCs);

    WaitForSingleObject(g_stopEvent, INFINITE);

    if (g_pipeThread)
    {
        WaitForSingleObject(g_pipeThread, 5000);
        CloseHandle(g_pipeThread);
        g_pipeThread = nullptr;
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

    DeleteCriticalSection(&g_dataCs);
    DeleteCriticalSection(&g_ctlCs);

    ReportServiceStatus(SERVICE_STOPPED);
}

int main()
{
    SERVICE_TABLE_ENTRYW table[] =
    {
        { const_cast<LPWSTR>(NVR_SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table))
    {
        MessageBoxW(nullptr,
                    L"Ten program jest uslugą Windows. Zainstaluj ją przez install.bat.",
                    L"NetVarRepeaterService", MB_OK | MB_ICONINFORMATION);
        return 1;
    }

    return 0;
}
