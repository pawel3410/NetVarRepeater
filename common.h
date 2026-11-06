// ============================================================
// NetVar repeater - wspolne definicje (usluga <-> tray)
// ============================================================
#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

#define NVR_SERVICE_NAME L"NetVarRepeater"
#define NVR_PIPE_NAME    L"\\\\.\\pipe\\NetVarRepeater"

static const uint32_t NVR_MAGIC     = 0x3352564E;  // "NVR3" (zmiana wersji protokolu)
static const uint32_t NVR_MAX_RULES = 256;
static const uint32_t NVR_MAX_TX_SHOW = 4;   // ile interfejsow wysylajacych raportujemy na regule

// Wlasne kody bledow (bit 29 = kod klienta, nie koliduje z Win32)
static const uint32_t NVR_ERR_NO_RULES = 0xE0000001u;   // brak poprawnych regul w konfiguracji
static const uint32_t NVR_ERR_ADAPTER_DISABLED = 0xE0000002u;   // trasa prowadzi przez karte wylaczona w konfiguracji

enum NvrCommand : uint32_t
{
    NVR_CMD_STATUS = 1,  // tylko odczyt stanu
    NVR_CMD_START  = 2,  // wczytaj konfiguracje i (re)start przekazywania
    NVR_CMD_STOP   = 3,  // zatrzymaj przekazywanie (usluga dziala dalej)
    NVR_CMD_RESET  = 4   // wczytaj konfiguracje, wyzeruj liczniki, zachowaj stan
};

// Tryb wyboru interfejsu wyjsciowego dla reguly
enum NvrOutMode : uint32_t
{
    NVR_OUT_OS        = 0,  // interfejs wybiera system (trasa domyslna)
    NVR_OUT_BOUND     = 1,  // wymuszony jeden interfejs (wg trasy / podsieci)
    NVR_OUT_BCAST_ALL = 2   // broadcast ograniczony: wszystkie interfejsy poza odbiorczym
};

static const uint32_t NVR_IF_VIRTUAL = 1;   // NvrIfInfo.flags: karta wirtualna

#pragma pack(push, 1)

struct NvrRequest
{
    uint32_t magic;
    uint32_t command;
};

struct NvrReplyHeader
{
    uint32_t magic;
    uint32_t commandResult;     // kod bledu wyniku polecenia (0 = OK)
    uint32_t active;            // 1 = przekazywanie dziala
    uint32_t lastError;         // ostatni blad globalny (Win32 / WinSock / NVR_ERR_*)
    uint32_t configErrorCount;  // liczba odrzuconych linii konfiguracji
    uint32_t ruleCount;         // liczba struktur NvrRuleStatus za naglowkiem
    uint32_t userStopped;       // 1 = zatrzymane przez uzytkownika (bez auto-ponawiania)
    uint32_t retryInSec;        // za ile sekund automatyczna proba startu (0 = brak)
    uint32_t reserved1;
    uint32_t maxPps;            // ustawienie: limit pakietow/s na regule
    uint32_t logMaxMb;          // ustawienie: maks. rozmiar logu w MB
    uint32_t reserved2;
    uint64_t startTime;         // FILETIME UTC rozpoczecia pracy (0 = nie startowano)
    uint64_t nowTime;           // FILETIME UTC w chwili odpowiedzi
    uint64_t totalSeen;         // pakiety przechwycone przez filtr WinDivert
    uint64_t totalIgnored;      // przechwycone, ale bez pasujacej reguly / uszkodzone
    uint64_t totalLoopDropped;  // odrzucone jako petla (nadawca = wlasny adres) lub z karty wirtualnej
    char     message[192];      // opis stanu / pierwszy blad konfiguracji (UTF-8)
};

struct NvrIfInfo
{
    uint32_t ifIdx;             // indeks interfejsu (0 = nieznany / brak)
    uint32_t ip;                // pierwszy adres IPv4 interfejsu, host order (0 = brak)
    uint32_t flags;             // NVR_IF_*
    wchar_t  name[40];          // nazwa karty (FriendlyName), np. "Ethernet 2"
};

struct NvrRuleStatus
{
    uint32_t srcIp;             // host order, 0 = dowolny nadawca
    uint32_t dstIp;             // host order
    uint16_t listenPort;
    uint16_t dstPort;
    uint32_t outMode;           // NvrOutMode
    uint32_t outIfIdx;          // indeks interfejsu (gdy NVR_OUT_BOUND)
    uint32_t outCount;          // ile gniazd wyjsciowych jest aktywnych
    uint32_t lastError;         // ostatni blad wysylki tej reguly
    uint64_t received;          // pakiety dopasowane do reguly
    uint64_t forwarded;         // pakiety wyslane poprawnie na wszystkie wyjscia
    uint64_t errors;            // pakiety, przy ktorych wysylka sie nie powiodla
    uint64_t skipped;           // pakiety celowo nie wyslane (limit pps, ochrona przed petla)
    uint64_t bytesReceived;     // suma payloadu pakietow dopasowanych
    uint64_t bytesForwarded;    // suma payloadu faktycznie wyslanego (po kazdym wyjsciu)
    NvrIfInfo rxIf;             // interfejs, na ktorym ostatnio odebrano pakiet tej reguly
    uint32_t  txShown;          // ile pozycji txIf jest wypelnionych
    NvrIfInfo txIf[NVR_MAX_TX_SHOW];   // interfejsy wysylajace
};

#pragma pack(pop)

static const uint32_t NVR_MAX_REPLY =
    sizeof(NvrReplyHeader) + NVR_MAX_RULES * sizeof(NvrRuleStatus);

inline std::wstring NvrDataDir()
{
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring dir = (n > 0 && n < MAX_PATH) ? std::wstring(buf)
                                               : std::wstring(L"C:\\ProgramData");
    return dir + L"\\NetVarRepeater";
}

inline std::wstring NvrConfigPath() { return NvrDataDir() + L"\\config.txt"; }
inline std::wstring NvrLogPath()    { return NvrDataDir() + L"\\netvarrepeater.log"; }
inline std::wstring NvrSettingsPath() { return NvrDataDir() + L"\\settings.ini"; }
