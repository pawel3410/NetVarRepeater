// ============================================================
// NetVarRepeater - wspolne definicje (usluga <-> tray)
// ============================================================
#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

#define NVR_SERVICE_NAME L"NetVarRepeater"
#define NVR_PIPE_NAME    L"\\\\.\\pipe\\NetVarRepeater"

static const uint32_t NVR_MAGIC     = 0x3152564E;  // "NVR1"
static const uint32_t NVR_MAX_RULES = 256;
static const uint32_t NVR_MAX_TX_SHOW = 4;   // ile interfejsow wysylajacych raportujemy na regule

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

#pragma pack(push, 1)

struct NvrRequest
{
    uint32_t magic;
    uint32_t command;
};

struct NvrReplyHeader
{
    uint32_t magic;
    uint32_t commandResult;     // kod Win32 wyniku polecenia (0 = OK)
    uint32_t active;            // 1 = przekazywanie dziala
    uint32_t lastError;         // ostatni blad globalny (Win32 / WinSock)
    uint32_t configErrorCount;  // liczba odrzuconych linii konfiguracji
    uint32_t ruleCount;         // liczba struktur NvrRuleStatus za naglowkiem
    uint64_t startTime;         // FILETIME UTC rozpoczecia pracy (0 = nie startowano)
    uint64_t nowTime;           // FILETIME UTC w chwili odpowiedzi
    uint64_t totalSeen;         // pakiety przechwycone przez filtr WinDivert
    uint64_t totalIgnored;      // przechwycone, ale bez pasujacej reguly / uszkodzone
    char     message[192];      // opis stanu / pierwszy blad konfiguracji (UTF-8 lub ASCII)
};

struct NvrIfInfo
{
    uint32_t ifIdx;             // indeks interfejsu (0 = nieznany / brak)
    uint32_t ip;                // pierwszy adres IPv4 interfejsu, host order (0 = brak)
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
    uint64_t received;
    uint64_t forwarded;
    uint64_t bytesForwarded;
    uint64_t errors;
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

inline std::wstring NvrConfigPath()
{
    return NvrDataDir() + L"\\config.txt";
}
