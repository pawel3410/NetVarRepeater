// ============================================================
// NetVarRepeaterTray - ikona w zasobniku (klient uslugi)
//
//  - najechanie kursorem: zwarte okienko ze statystykami,
//  - klikniecie ikony:    okno statusu (tabela regul, przyciski),
//  - prawy przycisk:      menu (konfiguracja, edycja, Start / Stop / Reset),
//  - komunikacja z usluga przez named pipe (common.h).
// ============================================================

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef _WIN32_IE
#define _WIN32_IE 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include "adapters.h"

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <shellapi.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <vector>

#include "common.h"
#include "config.h"

#ifndef NIN_SELECT
#define NIN_SELECT     (WM_USER + 0)
#endif
#ifndef NIN_KEYSELECT
#define NIN_KEYSELECT  (WM_USER + 1)
#endif
#ifndef NIN_POPUPOPEN
#define NIN_POPUPOPEN  (WM_USER + 6)
#endif
#ifndef NIN_POPUPCLOSE
#define NIN_POPUPCLOSE (WM_USER + 7)
#endif
#ifndef NOTIFYICON_VERSION_4
#define NOTIFYICON_VERSION_4 4
#endif

static const UINT WM_TRAY      = WM_APP + 1;
static const UINT WM_CMD_DONE  = WM_APP + 2;
static const UINT_PTR ID_TIMER = 1;
static const UINT_PTR ID_PROMO = 2;

static const UINT ID_STATUSWIN = 2000;
static const UINT ID_EDIT      = 2001;
static const UINT ID_START     = 2002;
static const UINT ID_STOP      = 2003;
static const UINT ID_RESET     = 2004;
static const UINT ID_EXIT      = 2005;
static const UINT ID_LOG       = 2006;
static const UINT ID_LOGDIR    = 2007;
static const UINT ID_RULE_BASE = 3000;

static const wchar_t* APP_TITLE = L"NetVar repeater";

// ------------------------------------------------------------
// Stan
// ------------------------------------------------------------
struct Snapshot
{
    bool ok;
    DWORD cmdResult;
    NvrReplyHeader h;
    std::vector<NvrRuleStatus> rules;

    Snapshot() : ok(false), cmdResult(0) { std::memset(&h, 0, sizeof(h)); }
};

static HINSTANCE g_inst = nullptr;
static HWND g_window = nullptr;
static HWND g_popup = nullptr;
static HFONT g_uiFont = nullptr;
static HFONT g_monoFont = nullptr;
static NOTIFYICONDATAW g_nid;
static UINT g_msgTaskbarCreated = 0;
static HICON g_icons[4] = { nullptr, nullptr, nullptr, nullptr };
static int g_iconState = -1;
static Snapshot g_snap;
static int g_failCount = 0;
static POINT g_anchor = { 0, 0 };
static bool g_popupVisible = false;
static bool g_cmdBusy = false;
static int g_promoTries = 0;

// okna
static HWND g_editor = nullptr, g_editCtl = nullptr, g_edHelp = nullptr, g_edInfo = nullptr, g_edTab = nullptr;
static HWND g_edSave = nullptr, g_edApply = nullptr, g_edNext = nullptr, g_edClose = nullptr;
static HWND g_adHelp = nullptr, g_adList = nullptr, g_adBtn[4] = { nullptr, nullptr, nullptr, nullptr };
static HWND g_setHelp = nullptr, g_setLogLabel = nullptr, g_setLogEdit = nullptr;
static HWND g_setPpsLabel = nullptr, g_setPpsEdit = nullptr, g_setOpenLog = nullptr;

static HWND g_stWin = nullptr, g_stLabel = nullptr, g_stList = nullptr;
static HWND g_stBtn[4] = { nullptr, nullptr, nullptr, nullptr };
static std::wstring g_stLabelText;
static std::vector<std::vector<std::wstring> > g_stCache;

static void OpenEditor();
static void PopupShow();
static void OpenStatusWindow();
static void UpdateStatusWindow();
static void StartCommand(uint32_t cmd);

// ------------------------------------------------------------
// Pomocnicze
// ------------------------------------------------------------
static std::wstring W(const std::string& s)
{
    std::wstring w;
    for (size_t i = 0; i < s.size(); ++i)
        w += static_cast<wchar_t>(static_cast<unsigned char>(s[i]));
    return w;
}

static std::wstring Num(unsigned long long v) { return std::to_wstring(v); }

static std::string WideToUtf8(const std::wstring& w)
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

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty())
        return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &w[0], n);
    return w;
}

static std::wstring ErrText(DWORD code)
{
    if (code == NVR_ERR_NO_RULES)
        return L"brak poprawnych reguł w konfiguracji";
    if (code == NVR_ERR_ADAPTER_DISABLED)
        return L"trasa prowadzi przez kartę wyłączoną w konfiguracji (zakładka Karty sieciowe)";

    wchar_t buf[512];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                             nullptr, code, 0, buf, 512, nullptr);
    std::wstring s = L"kod " + Num(code);
    if (n > 0)
    {
        while (n > 0 && (buf[n - 1] == L'\r' || buf[n - 1] == L'\n' || buf[n - 1] == L' '))
            --n;
        s += L" (" + std::wstring(buf, n) + L")";
    }
    return s;
}

static std::wstring FormatTime(uint64_t ft64)
{
    if (ft64 == 0)
        return L"-";

    FILETIME utc, local;
    utc.dwLowDateTime = static_cast<DWORD>(ft64 & 0xFFFFFFFFu);
    utc.dwHighDateTime = static_cast<DWORD>(ft64 >> 32);
    FileTimeToLocalFileTime(&utc, &local);

    SYSTEMTIME st;
    FileTimeToSystemTime(&local, &st);

    wchar_t b[64];
    wsprintfW(b, L"%04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
              st.wHour, st.wMinute, st.wSecond);
    return b;
}

static std::wstring FormatDuration(uint64_t ft100ns)
{
    uint64_t s = ft100ns / 10000000ull;
    const unsigned d = static_cast<unsigned>(s / 86400);
    s %= 86400;

    wchar_t b[64];
    if (d > 0)
        wsprintfW(b, L"%ud %02u:%02u:%02u", d, static_cast<unsigned>(s / 3600),
                  static_cast<unsigned>((s / 60) % 60), static_cast<unsigned>(s % 60));
    else
        wsprintfW(b, L"%02u:%02u:%02u", static_cast<unsigned>(s / 3600),
                  static_cast<unsigned>((s / 60) % 60), static_cast<unsigned>(s % 60));
    return b;
}

static std::wstring FormatBytes(uint64_t b)
{
    if (b < 1024)
        return Num(b) + L" B";

    static const wchar_t* units[] = { L"KB", L"MB", L"GB", L"TB" };
    double v = static_cast<double>(b);
    int i = -1;
    do { v /= 1024.0; ++i; } while (v >= 1024.0 && i < 3);

    const unsigned long long whole = static_cast<unsigned long long>(v);
    const unsigned long long frac = static_cast<unsigned long long>((v - static_cast<double>(whole)) * 10.0);
    return Num(whole) + L"." + Num(frac) + L" " + units[i];
}

static std::wstring RuleText(uint32_t src, uint16_t lport, uint32_t dst, uint16_t dport)
{
    return W(NvrIpToString(src)) + L":" + Num(lport) + L"  ->  " +
           W(NvrIpToString(dst)) + L":" + Num(dport);
}

static std::wstring IfText(const NvrIfInfo& i, bool withIdx)
{
    if (i.ifIdx == 0)
        return L"-";

    wchar_t nm[40];
    for (int k = 0; k < 40; ++k)
        nm[k] = i.name[k];
    nm[39] = 0;

    std::wstring s = nm[0] ? std::wstring(nm) : std::wstring(L"interfejs");
    if (i.ip != 0)
        s += L" (" + W(NvrIpToString(i.ip)) + L")";
    if (i.flags & NVR_IF_VIRTUAL)
        s += L" [wirt.]";
    if (withIdx)
        s += L" [if " + Num(i.ifIdx) + L"]";
    return s;
}

static std::wstring TxText(const NvrRuleStatus& r, bool withIdx)
{
    if (r.outMode == NVR_OUT_OS || r.txShown == 0)
        return L"wybór systemu";

    std::wstring t;
    for (uint32_t k = 0; k < r.txShown; ++k)
    {
        if (k) t += L", ";
        t += IfText(r.txIf[k], withIdx);
    }
    if (r.outCount > r.txShown)
        t += L" +" + Num(r.outCount - r.txShown);
    return t;
}

static std::wstring StateText(const Snapshot& s)
{
    if (!s.ok)
        return L"USŁUGA NIEDOSTĘPNA";
    if (s.h.active)
        return L"AKTYWNY";
    if (s.h.userStopped)
        return L"ZATRZYMANY";

    std::wstring t = L"NIE DZIAŁA";
    if (s.h.retryInSec > 0)
        t += L" (ponowna próba za " + Num(s.h.retryInSec) + L" s)";
    return t;
}

static bool ReadConfigFile(std::string& out)
{
    HANDLE h = CreateFileW(NvrConfigPath().c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
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

// ------------------------------------------------------------
// Komunikacja z usluga (bezpieczna dla watkow)
// ------------------------------------------------------------
static bool Transact(uint32_t cmd, Snapshot& out, DWORD timeoutMs)
{
    std::vector<unsigned char> buf(NVR_MAX_REPLY);

    NvrRequest req;
    req.magic = NVR_MAGIC;
    req.command = cmd;

    DWORD got = 0;
    const BOOL ok = CallNamedPipeW(NVR_PIPE_NAME, &req, sizeof(req),
                                   buf.data(), static_cast<DWORD>(buf.size()), &got, timeoutMs);

    Snapshot s;
    if (ok && got >= sizeof(NvrReplyHeader))
    {
        std::memcpy(&s.h, buf.data(), sizeof(NvrReplyHeader));

        if (s.h.magic == NVR_MAGIC)
        {
            uint32_t n = s.h.ruleCount;
            const uint32_t maxN = (got - sizeof(NvrReplyHeader)) / sizeof(NvrRuleStatus);
            if (n > maxN) n = maxN;

            s.rules.resize(n);
            if (n)
                std::memcpy(&s.rules[0], buf.data() + sizeof(NvrReplyHeader),
                            n * sizeof(NvrRuleStatus));

            s.cmdResult = s.h.commandResult;
            s.ok = true;
        }
    }

    out = s;
    return s.ok;
}

// Polecenia (Start/Stop/Reset) w osobnym watku - interfejs sie nie blokuje.
struct CmdJob
{
    uint32_t cmd;
    bool ok;
    Snapshot snap;
};

static DWORD WINAPI CmdThread(void* p)
{
    CmdJob* j = static_cast<CmdJob*>(p);
    j->ok = Transact(j->cmd, j->snap, 5000);
    PostMessageW(g_window, WM_CMD_DONE, 0, reinterpret_cast<LPARAM>(j));
    return 0;
}

static void StartCommand(uint32_t cmd)
{
    if (g_cmdBusy)
        return;

    CmdJob* j = new CmdJob();
    j->cmd = cmd;
    j->ok = false;

    HANDLE h = CreateThread(nullptr, 0, CmdThread, j, 0, nullptr);
    if (!h)
    {
        delete j;
        return;
    }

    g_cmdBusy = true;
    CloseHandle(h);
}

// ------------------------------------------------------------
// Ikony - kolorowe tlo z napisem "NV"
// ------------------------------------------------------------
static HICON MakeIcon(COLORREF color)
{
    const int sz = GetSystemMetrics(SM_CXSMICON);
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmpColor = CreateCompatibleBitmap(screen, sz, sz);
    HBITMAP bmpMask = CreateBitmap(sz, sz, 1, 1, nullptr);

    HGDIOBJ old = SelectObject(mem, bmpColor);
    RECT rc = { 0, 0, sz, sz };

    HBRUSH bg = CreateSolidBrush(color);
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HBRUSH frame = CreateSolidBrush(RGB(25, 25, 25));
    FrameRect(mem, &rc, frame);
    DeleteObject(frame);

    // Na ikonie 16x16 miesci sie tylko skrot "NV"; pelna nazwa "NetVar repeater"
    // jest w tooltipie, oknie statystyk i tytulach okien.
    HFONT font = CreateFontW(-(sz * 11 / 16), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HGDIOBJ oldFont = SelectObject(mem, font);
    SetBkMode(mem, TRANSPARENT);
    SetTextColor(mem, RGB(255, 255, 255));
    DrawTextW(mem, L"NV", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(mem, oldFont);
    DeleteObject(font);

    SelectObject(mem, bmpMask);
    PatBlt(mem, 0, 0, sz, sz, BLACKNESS);                  // 0 = cala ikona widoczna
    SelectObject(mem, old);

    ICONINFO ii;
    ii.fIcon = TRUE;
    ii.xHotspot = 0;
    ii.yHotspot = 0;
    ii.hbmMask = bmpMask;
    ii.hbmColor = bmpColor;
    HICON icon = CreateIconIndirect(&ii);

    DeleteObject(bmpColor);
    DeleteObject(bmpMask);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return icon;
}

// 0 = szara (usluga niedostepna lub przekazywanie nie dziala), 1 = zielona (dziala)
// Bledy wysylania NIE zmieniaja koloru - widac je w oknie przy najechaniu i w oknie statusu.
static int StateOf(const Snapshot& s)
{
    return (s.ok && s.h.active) ? 1 : 0;
}

static void ApplyIconState(bool force)
{
    const int st = StateOf(g_snap);

    const wchar_t* tip = !g_snap.ok          ? L"NetVar repeater - usługa niedostępna"
                       : !g_snap.h.active    ? L"NetVar repeater - zatrzymany"
                       :                       L"NetVar repeater - aktywny";

    if (!force && st == g_iconState && std::wcscmp(tip, g_nid.szTip) == 0)
        return;

    g_iconState = st;
    g_nid.hIcon = g_icons[st];
    std::wcsncpy(g_nid.szTip, tip, 127);
    g_nid.szTip[127] = 0;

    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

static void AddTrayIcon()
{
    std::memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_window;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAY;
    g_nid.hIcon = g_icons[g_iconState < 0 ? 0 : g_iconState];
    std::wcscpy(g_nid.szTip, L"NetVar repeater");

    Shell_NotifyIconW(NIM_ADD, &g_nid);

    // Wersja 4: powiadomienia NIN_POPUPOPEN/CLOSE przy najechaniu kursorem
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

// Windows 11: ikona domyslnie trafia do ukrytych ("przepelnienie").
// Ustawiamy IsPromoted=1 w HKCU\Control Panel\NotifyIconSettings\<id> (wpis tworzy Explorer
// po pierwszym dodaniu ikony), co pokazuje ikone na pasku zadan. Zwraca true, gdy nic wiecej
// nie ma do zrobienia (ustawiono albo klucz nie istnieje - Windows 10).
static bool PromoteIcon()
{
    HKEY root = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\NotifyIconSettings", 0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_READ, &root) != ERROR_SUCCESS)
        return true;

    static const wchar_t suffix[] = L"\\netvarrepeatertray.exe";
    const size_t suffixLen = sizeof(suffix) / sizeof(wchar_t) - 1;

    bool done = false;

    for (DWORD i = 0; !done; ++i)
    {
        wchar_t name[256];
        DWORD nameLen = 256;
        if (RegEnumKeyExW(root, i, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        HKEY sub = nullptr;
        if (RegOpenKeyExW(root, name, 0, KEY_READ | KEY_SET_VALUE, &sub) != ERROR_SUCCESS)
            continue;

        wchar_t path[1024];
        DWORD size = sizeof(path) - sizeof(wchar_t), type = 0;
        if (RegQueryValueExW(sub, L"ExecutablePath", nullptr, &type,
                             reinterpret_cast<LPBYTE>(path), &size) == ERROR_SUCCESS && type == REG_SZ)
        {
            path[size / sizeof(wchar_t)] = 0;
            std::wstring p = path;
            for (size_t k = 0; k < p.size(); ++k)
                p[k] = static_cast<wchar_t>(std::towlower(p[k]));

            if (p.size() >= suffixLen && p.compare(p.size() - suffixLen, suffixLen, suffix) == 0)
            {
                const DWORD one = 1;
                if (RegSetValueExW(sub, L"IsPromoted", 0, REG_DWORD,
                                   reinterpret_cast<const BYTE*>(&one), sizeof(one)) == ERROR_SUCCESS)
                    done = true;
            }
        }
        RegCloseKey(sub);
    }

    RegCloseKey(root);
    return done;
}

// ------------------------------------------------------------
// Odswiezanie stanu
// ------------------------------------------------------------
static void UpdateAllViews()
{
    ApplyIconState(false);
    if (g_popupVisible)
        PopupShow();
    UpdateStatusWindow();
}

static void RefreshStatus(DWORD timeoutMs)
{
    Snapshot s;
    if (Transact(NVR_CMD_STATUS, s, timeoutMs))
    {
        g_snap = s;
        g_failCount = 0;
    }
    else if (++g_failCount >= 3)       // chwilowe zacięcia nie zmieniają ikony na szarą
    {
        g_snap = Snapshot();
    }

    UpdateAllViews();
}

// ------------------------------------------------------------
// Zwarte okienko przy najechaniu (podwojne buforowanie)
// ------------------------------------------------------------
static std::wstring BuildPopupText()
{
    const Snapshot& s = g_snap;

    if (!s.ok)
        return L"NetVar repeater\r\nUsługa nie odpowiada (zatrzymana lub niezainstalowana).";

    std::wstring t = L"NetVar repeater - " + StateText(s) + L"\r\n";

    if (s.h.startTime != 0)
    {
        t += L"Start: " + FormatTime(s.h.startTime);
        if (s.h.active && s.h.nowTime > s.h.startTime)
            t += L"    Czas pracy: " + FormatDuration(s.h.nowTime - s.h.startTime);
        t += L"\r\n";
    }

    if (s.h.lastError != 0)
        t += L"Błąd: " + ErrText(s.h.lastError) + L"\r\n";

    if (s.h.configErrorCount != 0)
        t += L"Odrzucone linie konfiguracji: " + Num(s.h.configErrorCount) + L" (" +
             Utf8ToWide(s.h.message) + L")\r\n";
    else if (!s.h.active && s.h.message[0])
        t += Utf8ToWide(s.h.message) + L"\r\n";

    t += L"Przechwycone: " + Num(s.h.totalSeen) + L"   bez reguły: " + Num(s.h.totalIgnored) +
         L"   pętla/wirtualne: " + Num(s.h.totalLoopDropped);

    const size_t maxShow = 12;
    for (size_t i = 0; i < s.rules.size() && i < maxShow; ++i)
    {
        const NvrRuleStatus& r = s.rules[i];

        t += L"\r\n#" + Num(i + 1) + L"  " + RuleText(r.srcIp, r.listenPort, r.dstIp, r.dstPort) +
             L"   odebr. " + Num(r.received) + L" (" + FormatBytes(r.bytesReceived) + L")" +
             L" · przek. " + Num(r.forwarded) + L" (" + FormatBytes(r.bytesForwarded) + L")" +
             L" · błędy " + Num(r.errors) + L" · pomin. " + Num(r.skipped);

        t += L"\r\n      " + (r.rxIf.ifIdx ? IfText(r.rxIf, false) : std::wstring(L"(brak pakietów)")) +
             L"  →  " + TxText(r, false);
    }

    if (s.rules.empty())
        t += L"\r\n(brak reguł)";
    if (s.rules.size() > maxShow)
        t += L"\r\n... i " + Num(s.rules.size() - maxShow) + L" więcej (kliknij ikonę, by zobaczyć wszystkie)";

    return t;
}

static LRESULT CALLBACK PopupProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_PAINT)
    {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        HDC mem = CreateCompatibleDC(dc);
        HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
        HGDIOBJ oldBmp = SelectObject(mem, bmp);

        FillRect(mem, &rc, GetSysColorBrush(COLOR_INFOBK));
        SetBkMode(mem, TRANSPARENT);
        SetTextColor(mem, GetSysColor(COLOR_INFOTEXT));
        HGDIOBJ oldFont = SelectObject(mem, g_uiFont);

        RECT tr = { 8, 6, rc.right - 8, rc.bottom - 6 };
        const std::wstring text = BuildPopupText();
        DrawTextW(mem, text.c_str(), -1, &tr, DT_LEFT | DT_NOPREFIX | DT_EXPANDTABS);

        SelectObject(mem, oldFont);
        BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
        SelectObject(mem, oldBmp);
        DeleteObject(bmp);
        DeleteDC(mem);
        EndPaint(hwnd, &ps);
        return 0;
    }

    if (msg == WM_ERASEBKGND)
        return 1;

    if (msg == WM_NCHITTEST)
        return HTTRANSPARENT;

    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void PopupShow()
{
    if (!g_popup)
        return;

    const std::wstring text = BuildPopupText();

    HDC dc = GetDC(g_popup);
    HGDIOBJ old = SelectObject(dc, g_uiFont);
    RECT rc = { 0, 0, 900, 0 };
    DrawTextW(dc, text.c_str(), -1, &rc, DT_CALCRECT | DT_LEFT | DT_NOPREFIX | DT_EXPANDTABS);
    SelectObject(dc, old);
    ReleaseDC(g_popup, dc);

    const int w = rc.right + 16;
    const int h = rc.bottom + 12;

    MONITORINFO mi;
    mi.cbSize = sizeof(mi);
    GetMonitorInfoW(MonitorFromPoint(g_anchor, MONITOR_DEFAULTTONEAREST), &mi);
    const RECT wa = mi.rcWork;

    int x = g_anchor.x - w / 2;
    int y = g_anchor.y - h - 8;

    if (y < wa.top)                       // pasek zadan u gory
        y = g_anchor.y + 24;
    if (y + h > wa.bottom) y = wa.bottom - h;
    if (x + w > wa.right)  x = wa.right - w;
    if (x < wa.left)       x = wa.left;

    SetWindowPos(g_popup, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE | SWP_SHOWWINDOW);
    InvalidateRect(g_popup, nullptr, FALSE);
    g_popupVisible = true;
}

static void PopupHide()
{
    if (g_popup)
        ShowWindow(g_popup, SW_HIDE);
    g_popupVisible = false;
}

// ------------------------------------------------------------
// Okno statusu: tabela regul + przyciski
// ------------------------------------------------------------
static const int ID_ST_START = 5001, ID_ST_STOP = 5002, ID_ST_RESET = 5003, ID_ST_EDIT = 5004;

struct ColDef { const wchar_t* title; int width; bool right; };
static const ColDef kCols[] =
{
    { L"#",                30,  false }, { L"Nadawca",         100, false }, { L"Port odb.",  65, true },
    { L"Cel",             110,  false }, { L"Port cel.",        65, true  }, { L"Odebrane",   75, true },
    { L"Przekazane",       80,  true  }, { L"Błędy",            55, true  }, { L"Pominięte",  70, true },
    { L"Odebrano (dane)",  95,  true  }, { L"Wysłano (dane)",   95, true  },
    { L"Karta odbiorcza", 210,  false }, { L"Karta wysyłająca", 280, false }
};
static const int NCOLS = sizeof(kCols) / sizeof(kCols[0]);

static std::wstring BuildStatusHeader()
{
    const Snapshot& s = g_snap;

    if (!s.ok)
        return L"Usługa NetVar repeater nie odpowiada (zatrzymana lub niezainstalowana).\r\n"
               L"Sprawdź services.msc lub uruchom install.bat jako administrator.";

    std::wstring t = L"Stan: " + StateText(s);
    if (s.h.startTime != 0)
    {
        t += L"     Start: " + FormatTime(s.h.startTime);
        if (s.h.active && s.h.nowTime > s.h.startTime)
            t += L"     Czas pracy: " + FormatDuration(s.h.nowTime - s.h.startTime);
    }
    t += L"\r\nPrzechwycone pakiety: " + Num(s.h.totalSeen) + L"     bez pasującej reguły: " +
         Num(s.h.totalIgnored) + L"     odrzucone (pętla / karty wirtualne): " + Num(s.h.totalLoopDropped);
    t += L"\r\nUstawienia: limit: " +
         (s.h.maxPps ? Num(s.h.maxPps) + L" pakietów/s na regułę" : std::wstring(L"brak")) +
         L"     log: do " + Num(s.h.logMaxMb) + L" MB (" + NvrLogPath() + L")";

    if (s.h.lastError != 0)
        t += L"\r\nBłąd: " + ErrText(s.h.lastError);
    if (s.h.configErrorCount != 0)
        t += L"\r\nOdrzucone linie konfiguracji: " + Num(s.h.configErrorCount) + L" (" + Utf8ToWide(s.h.message) + L")";
    else if (!s.h.active && s.h.message[0])
        t += L"\r\n" + Utf8ToWide(s.h.message);

    return t;
}

static std::vector<std::wstring> RowTexts(size_t i, const NvrRuleStatus& r)
{
    std::vector<std::wstring> v;
    v.push_back(Num(i + 1));
    v.push_back(r.srcIp == 0 ? L"0.0.0.0 (dowolny)" : W(NvrIpToString(r.srcIp)));
    v.push_back(Num(r.listenPort));
    v.push_back(W(NvrIpToString(r.dstIp)));
    v.push_back(Num(r.dstPort));
    v.push_back(Num(r.received));
    v.push_back(Num(r.forwarded));
    v.push_back(Num(r.errors) + ((r.errors > 0 && r.lastError != 0) ? L" (" + Num(r.lastError) + L")" : std::wstring()));
    v.push_back(Num(r.skipped));
    v.push_back(FormatBytes(r.bytesReceived));
    v.push_back(FormatBytes(r.bytesForwarded));
    v.push_back(r.rxIf.ifIdx ? IfText(r.rxIf, true) : std::wstring(L"(jeszcze brak pakietów)"));
    v.push_back(TxText(r, true));
    return v;
}

static void UpdateStatusWindow()
{
    if (!g_stWin)
        return;

    const std::wstring header = BuildStatusHeader();
    if (header != g_stLabelText)
    {
        g_stLabelText = header;
        SetWindowTextW(g_stLabel, header.c_str());
    }

    const size_t n = g_snap.rules.size();
    int cnt = ListView_GetItemCount(g_stList);

    while (cnt < static_cast<int>(n))
    {
        LVITEM it;
        std::memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = cnt;
        it.pszText = const_cast<LPWSTR>(L"");
        ListView_InsertItem(g_stList, &it);
        ++cnt;
        g_stCache.push_back(std::vector<std::wstring>(NCOLS));
    }
    while (cnt > static_cast<int>(n))
    {
        ListView_DeleteItem(g_stList, --cnt);
        g_stCache.pop_back();
    }

    for (size_t i = 0; i < n; ++i)
    {
        const std::vector<std::wstring> row = RowTexts(i, g_snap.rules[i]);
        for (int c = 0; c < NCOLS; ++c)
        {
            if (g_stCache[i][c] != row[c])
            {
                g_stCache[i][c] = row[c];
                ListView_SetItemText(g_stList, static_cast<int>(i), c, const_cast<LPWSTR>(row[c].c_str()));
            }
        }
    }

    const bool avail = g_snap.ok && !g_cmdBusy;
    EnableWindow(g_stBtn[0], avail);
    EnableWindow(g_stBtn[1], avail && g_snap.h.active);
    EnableWindow(g_stBtn[2], avail);
}

static void LayoutStatus(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    MoveWindow(g_stLabel, 10, 8, w - 20, 92, TRUE);
    MoveWindow(g_stList, 8, 104, w - 16, h - 104 - 46, TRUE);
    MoveWindow(g_stBtn[0], 8, h - 38, 90, 30, TRUE);
    MoveWindow(g_stBtn[1], 104, h - 38, 90, 30, TRUE);
    MoveWindow(g_stBtn[2], 200, h - 38, 90, 30, TRUE);
    MoveWindow(g_stBtn[3], w - 188, h - 38, 180, 30, TRUE);
}

static LRESULT CALLBACK StatusProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            g_stLabel = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX,
                0, 0, 0, 0, hwnd, nullptr, g_inst, nullptr);

            g_stList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                0, 0, 0, 0, hwnd, nullptr, g_inst, nullptr);
            ListView_SetExtendedListViewStyle(g_stList,
                LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

            for (int c = 0; c < NCOLS; ++c)
            {
                LVCOLUMN col;
                std::memset(&col, 0, sizeof(col));
                col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
                col.fmt = kCols[c].right ? LVCFMT_RIGHT : LVCFMT_LEFT;
                col.cx = kCols[c].width;
                col.pszText = const_cast<LPWSTR>(kCols[c].title);
                ListView_InsertColumn(g_stList, c, &col);
            }

            const wchar_t* names[4] = { L"Start", L"Stop", L"Reset", L"Edytuj konfigurację..." };
            const int ids[4] = { ID_ST_START, ID_ST_STOP, ID_ST_RESET, ID_ST_EDIT };
            for (int i = 0; i < 4; ++i)
            {
                g_stBtn[i] = CreateWindowExW(0, L"BUTTON", names[i], WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                    0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ids[i])), g_inst, nullptr);
                SendMessageW(g_stBtn[i], WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            }
            SendMessageW(g_stLabel, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            SendMessageW(g_stList, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            return 0;
        }

        case WM_SIZE:
            LayoutStatus(hwnd);
            return 0;

        case WM_GETMINMAXINFO:
        {
            MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 640;
            mmi->ptMinTrackSize.y = 300;
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case ID_ST_START: StartCommand(NVR_CMD_START); return 0;
                case ID_ST_STOP:  StartCommand(NVR_CMD_STOP);  return 0;
                case ID_ST_RESET: StartCommand(NVR_CMD_RESET); return 0;
                case ID_ST_EDIT:  OpenEditor();                return 0;
                case IDCANCEL:    DestroyWindow(hwnd);         return 0;
            }
            break;

        case WM_CLOSE:
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            g_stWin = nullptr;
            g_stList = nullptr;
            g_stLabel = nullptr;
            g_stLabelText.clear();
            g_stCache.clear();
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void OpenStatusWindow()
{
    if (g_stWin)
    {
        ShowWindow(g_stWin, SW_RESTORE);
        SetForegroundWindow(g_stWin);
        return;
    }

    g_stWin = CreateWindowExW(0, L"NvrStatus", L"NetVar repeater - status", WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT, 1060, 420, nullptr, nullptr, g_inst, nullptr);
    if (!g_stWin)
        return;

    ShowWindow(g_stWin, SW_SHOW);
    SetForegroundWindow(g_stWin);
    RefreshStatus(300);
}

// ------------------------------------------------------------
// Otwieranie logu
// ------------------------------------------------------------
static void OpenLog()
{
    const std::wstring path = NvrLogPath();
    if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        MessageBoxW(g_window, (L"Plik logu jeszcze nie istnieje:\n" + path).c_str(), APP_TITLE,
                    MB_OK | MB_ICONINFORMATION);
        return;
    }
    ShellExecuteW(nullptr, L"open", L"notepad.exe", (L"\"" + path + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
}

static void OpenLogFolder()
{
    const std::wstring path = NvrLogPath();
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
        ShellExecuteW(nullptr, L"open", L"explorer.exe", (L"/select,\"" + path + L"\"").c_str(), nullptr, SW_SHOWNORMAL);
    else
        ShellExecuteW(nullptr, L"open", NvrDataDir().c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

// ------------------------------------------------------------
// Okno konfiguracji: zakladki Reguly / Karty sieciowe / Ustawienia
// ------------------------------------------------------------
static const int ID_ED_SAVE = 4001, ID_ED_APPLY = 4002, ID_ED_NEXT = 4003, ID_ED_CLOSE = 4004;
static const int ID_AD_RX = 4010, ID_AD_TX = 4011, ID_AD_DEF = 4012, ID_AD_REFRESH = 4013;
static const int ID_SET_OPENLOG = 4020;
static const int ID_CTL_TAB = 6000, ID_CTL_RULES = 6001, ID_CTL_LOGMB = 6002, ID_CTL_PPS = 6003, ID_CTL_ADLIST = 6004;
static const UINT_PTR ID_ED_TIMER = 1;

struct AdRow
{
    std::string  guid;
    std::wstring name, ip, state, type;
    bool isVirtual, present, rx, tx;
};

static std::vector<AdRow> g_adRows;
static NvrConfigResult g_edResult;
static std::vector<int> g_edErrLines;
static bool g_edDirty = false;     // zmieniono tekst regul (do ponownej walidacji)
static bool g_setDirty = false;    // zmieniono karty / ustawienia
static int  g_curTab = 0;

static bool ReadSettingsFile(NvrSettingsFile& st)
{
    HANDLE h = CreateFileW(NvrSettingsPath().c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        st = NvrSettingsFile();
        return false;
    }

    std::string raw;
    char tmp[4096];
    DWORD n = 0;
    while (ReadFile(h, tmp, sizeof(tmp), &n, nullptr) && n > 0)
        raw.append(tmp, n);
    CloseHandle(h);

    st = NvrParseSettings(raw);
    return true;
}

static bool WriteTextFile(const std::wstring& path, const std::string& data)
{
    CreateDirectoryW(NvrDataDir().c_str(), nullptr);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        const std::wstring msg = L"Nie można zapisać pliku:\n" + path + L"\n" + ErrText(GetLastError()) +
                                 L"\n\nUruchom ponownie install.bat (nadaje prawa zapisu) lub edytuj plik jako administrator.";
        MessageBoxW(g_editor, msg.c_str(), APP_TITLE, MB_OK | MB_ICONERROR);
        return false;
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
    CloseHandle(h);

    if (!ok || written != data.size())
    {
        MessageBoxW(g_editor, (L"Zapis pliku nie powiódł się:\n" + path).c_str(), APP_TITLE, MB_OK | MB_ICONERROR);
        return false;
    }
    return true;
}

// ---- zakladka: Reguly ----
static std::wstring LoadConfigForEditor()
{
    std::string raw;
    std::wstring w;

    if (ReadConfigFile(raw))
    {
        if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
            static_cast<unsigned char>(raw[1]) == 0xBB && static_cast<unsigned char>(raw[2]) == 0xBF)
            raw.erase(0, 3);
        w = Utf8ToWide(raw);
    }
    else
    {
        w = L"# ip_nadawcy port_odbiorczy ip_docelowy port_docelowy\n";
    }

    std::wstring out;
    for (size_t i = 0; i < w.size(); ++i)
    {
        if (w[i] == L'\r') continue;
        if (w[i] == L'\n') out += L"\r\n"; else out += w[i];
    }
    return out;
}

static std::string EditorTextUtf8()
{
    const int len = GetWindowTextLengthW(g_editCtl);
    std::wstring w(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(g_editCtl, &w[0], len + 1);
    w.resize(static_cast<size_t>(len));
    return WideToUtf8(w);
}

static void EditorRevalidate()
{
    g_edResult = NvrParseConfig(EditorTextUtf8(), NVR_MAX_RULES);
    g_edErrLines.clear();

    for (size_t i = 0; i < g_edResult.errors.size(); ++i)
    {
        int line = 0;
        if (std::sscanf(g_edResult.errors[i].c_str(), "linia %d", &line) == 1)
            g_edErrLines.push_back(line);
    }
}

static void EditorUpdateInfo()
{
    std::wstring t;

    if (g_curTab == 0)
    {
        DWORD start = 0, end = 0;
        SendMessageW(g_editCtl, EM_GETSEL, reinterpret_cast<WPARAM>(&start), reinterpret_cast<LPARAM>(&end));
        const int line = static_cast<int>(SendMessageW(g_editCtl, EM_LINEFROMCHAR, start, 0)) + 1;
        const int col = static_cast<int>(start) -
                        static_cast<int>(SendMessageW(g_editCtl, EM_LINEINDEX, static_cast<WPARAM>(-1), 0)) + 1;

        t = L"Wiersz " + Num(line) + L", kolumna " + Num(col) + L"   |   Reguły: " +
            Num(g_edResult.rules.size()) + L"   |   ";

        if (g_edResult.errors.empty())
            t += L"brak błędów";
        else
            t += L"BŁĘDY: " + Num(g_edResult.errors.size()) + L" - " + W(g_edResult.errors[0]);
    }
    else if (g_curTab == 1)
    {
        t = L"Kliknij ☑/☐ w kolumnie Odbiór lub Wysyłanie (albo użyj przycisków). Zmiany zapisz przyciskiem Zapisz.";
    }
    else
    {
        t = L"Zmiany zapisz przyciskiem Zapisz; zastosuj je przez Start (lub Zapisz i zastosuj).";
    }

    wchar_t cur[600];
    GetWindowTextW(g_edInfo, cur, 600);
    if (t != cur)
        SetWindowTextW(g_edInfo, t.c_str());

    EnableWindow(g_edNext, !g_edErrLines.empty());
}

static void EditorGotoLine(int line1)
{
    const LRESULT idx = SendMessageW(g_editCtl, EM_LINEINDEX, static_cast<WPARAM>(line1 - 1), 0);
    if (idx < 0)
        return;
    const LRESULT len = SendMessageW(g_editCtl, EM_LINELENGTH, static_cast<WPARAM>(idx), 0);
    SendMessageW(g_editCtl, EM_SETSEL, static_cast<WPARAM>(idx), static_cast<LPARAM>(idx + len));
    SendMessageW(g_editCtl, EM_SCROLLCARET, 0, 0);
    SetFocus(g_editCtl);
}

static void EditorNextError()
{
    if (g_edErrLines.empty())
        return;

    DWORD start = 0, end = 0;
    SendMessageW(g_editCtl, EM_GETSEL, reinterpret_cast<WPARAM>(&start), reinterpret_cast<LPARAM>(&end));
    const int cur = static_cast<int>(SendMessageW(g_editCtl, EM_LINEFROMCHAR, start, 0)) + 1;

    int target = g_edErrLines[0];
    for (size_t i = 0; i < g_edErrLines.size(); ++i)
        if (g_edErrLines[i] > cur) { target = g_edErrLines[i]; break; }

    EditorGotoLine(target);
}

// ---- zakladka: Karty sieciowe ----
static const int NADCOLS = 7;
static const ColDef kAdCols[NADCOLS] =
{
    { L"Odbiór", 60, false }, { L"Wysyłanie", 80, false }, { L"Karta", 210, false },
    { L"Adres IPv4", 130, false }, { L"Stan", 90, false }, { L"Typ", 200, false }, { L"GUID", 290, false }
};

static std::wstring AdCell(const AdRow& r, int c)
{
    switch (c)
    {
        case 0: return r.rx ? L"☑" : L"☐";
        case 1: return r.tx ? L"☑" : L"☐";
        case 2: return r.name;
        case 3: return r.ip;
        case 4: return r.state;
        case 5: return r.type;
        default: return W(r.guid);
    }
}

static void LoadAdapterRows()
{
    NvrSettingsFile st;
    ReadSettingsFile(st);

    const std::vector<NvrAdapter> ads = NvrEnumAdapters(true);
    g_adRows.clear();

    for (size_t i = 0; i < ads.size(); ++i)
    {
        AdRow r;
        r.guid = ads[i].guid;
        r.name = ads[i].name;
        r.ip = ads[i].addrs.empty() ? std::wstring(L"-") : W(NvrIpToString(ads[i].addrs[0].ip));
        if (ads[i].addrs.size() > 1)
            r.ip += L" (+" + Num(ads[i].addrs.size() - 1) + L")";
        r.state = ads[i].up ? L"aktywna" : L"nieaktywna";
        r.isVirtual = ads[i].isVirtual;
        r.type = ads[i].isVirtual ? L"wirtualna (rozpoznana automatycznie)" : L"fizyczna";
        r.present = true;
        const bool def = !ads[i].isVirtual;
        r.rx = NvrAdapterAllowed(st, ads[i].guid, def, false);
        r.tx = NvrAdapterAllowed(st, ads[i].guid, def, true);
        g_adRows.push_back(r);
    }

    // karty zapisane w settings.ini, ktorych teraz nie ma (odlaczone) - zeby mozna je ustawic z gory
    for (size_t k = 0; k < st.adapters.size(); ++k)
    {
        bool found = false;
        for (size_t i = 0; i < g_adRows.size(); ++i)
            if (NvrLower(g_adRows[i].guid) == NvrLower(st.adapters[k].guid)) { found = true; break; }
        if (found)
            continue;

        AdRow r;
        r.guid = st.adapters[k].guid;
        r.name = st.adapters[k].name.empty() ? W(st.adapters[k].guid) : Utf8ToWide(st.adapters[k].name);
        r.ip = L"-";
        r.state = L"nieobecna";
        r.type = L"-";
        r.isVirtual = false;
        r.present = false;
        r.rx = st.adapters[k].rx;
        r.tx = st.adapters[k].tx;
        g_adRows.push_back(r);
    }
}

static void FillAdapterList()
{
    const int sel = ListView_GetNextItem(g_adList, -1, LVNI_SELECTED);

    SendMessageW(g_adList, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_adList);

    for (size_t i = 0; i < g_adRows.size(); ++i)
    {
        LVITEM it;
        std::memset(&it, 0, sizeof(it));
        it.mask = LVIF_TEXT;
        it.iItem = static_cast<int>(i);
        const std::wstring c0 = AdCell(g_adRows[i], 0);
        it.pszText = const_cast<LPWSTR>(c0.c_str());
        ListView_InsertItem(g_adList, &it);

        for (int c = 1; c < NADCOLS; ++c)
        {
            const std::wstring t = AdCell(g_adRows[i], c);
            ListView_SetItemText(g_adList, static_cast<int>(i), c, const_cast<LPWSTR>(t.c_str()));
        }
    }

    if (sel >= 0 && sel < static_cast<int>(g_adRows.size()))
        ListView_SetItemState(g_adList, sel, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);

    SendMessageW(g_adList, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_adList, nullptr, TRUE);
}

static void ToggleAdapter(int item, bool tx)
{
    if (item < 0 || item >= static_cast<int>(g_adRows.size()))
        return;

    AdRow& r = g_adRows[static_cast<size_t>(item)];
    if (tx) r.tx = !r.tx; else r.rx = !r.rx;

    const int col = tx ? 1 : 0;
    const std::wstring t = AdCell(r, col);
    ListView_SetItemText(g_adList, item, col, const_cast<LPWSTR>(t.c_str()));
    g_setDirty = true;
}

static void AdaptersDefaults()
{
    for (size_t i = 0; i < g_adRows.size(); ++i)
    {
        if (!g_adRows[i].present)
            continue;
        g_adRows[i].rx = !g_adRows[i].isVirtual;
        g_adRows[i].tx = !g_adRows[i].isVirtual;
    }
    FillAdapterList();
    g_setDirty = true;
}

// ---- zakladka: Ustawienia + zapis ----
static bool CollectSettings(NvrSettingsFile& out, std::wstring& err)
{
    wchar_t b[32];

    GetWindowTextW(g_setLogEdit, b, 32);
    if (!NvrParseUInt(NvrTrim(WideToUtf8(b)), 1, 1024, out.logMaxMb))
    {
        err = L"Maksymalny rozmiar logu: podaj liczbę całkowitą MB od 1 do 1024.";
        return false;
    }

    GetWindowTextW(g_setPpsEdit, b, 32);
    if (!NvrParseUInt(NvrTrim(WideToUtf8(b)), 0, 1000000, out.maxPps))
    {
        err = L"Limit pakietów/s: podaj liczbę od 0 do 1000000 (0 = bez limitu).";
        return false;
    }

    out.adapters.clear();
    for (size_t i = 0; i < g_adRows.size(); ++i)
    {
        NvrAdapterSel a;
        a.guid = g_adRows[i].guid;
        a.rx = g_adRows[i].rx;
        a.tx = g_adRows[i].tx;
        a.name = WideToUtf8(g_adRows[i].name);
        for (size_t k = 0; k < a.name.size(); ++k)
            if (a.name[k] == '|' || a.name[k] == '\r' || a.name[k] == '\n') a.name[k] = '/';
        out.adapters.push_back(a);
    }
    return true;
}

static void ShowTab(int t);

static bool SaveAll()
{
    const std::string rulesUtf8 = EditorTextUtf8();

    NvrConfigResult res = NvrParseConfig(rulesUtf8, NVR_MAX_RULES);
    if (!res.errors.empty())
    {
        std::wstring msg = L"W regułach są błędy (" + Num(res.errors.size()) + L"):\n\n";
        for (size_t i = 0; i < res.errors.size() && i < 10; ++i)
            msg += W(res.errors[i]) + L"\n";
        msg += L"\nBłędne linie zostaną pominięte przez usługę. Zapisać mimo to?";

        if (MessageBoxW(g_editor, msg.c_str(), APP_TITLE, MB_YESNO | MB_ICONWARNING) != IDYES)
            return false;
    }

    NvrSettingsFile st;
    std::wstring err;
    if (!CollectSettings(st, err))
    {
        ShowTab(2);
        MessageBoxW(g_editor, err.c_str(), APP_TITLE, MB_OK | MB_ICONWARNING);
        return false;
    }

    bool anyRx = false, anyTx = false;
    for (size_t i = 0; i < g_adRows.size(); ++i)
    {
        anyRx = anyRx || g_adRows[i].rx;
        anyTx = anyTx || g_adRows[i].tx;
    }
    if (!anyRx || !anyTx)
    {
        const std::wstring msg = std::wstring(L"Żadna karta nie ma włączonego ") +
                                 (!anyRx ? L"odbioru" : L"wysyłania") +
                                 L" - nic nie będzie przekazywane.\nZapisać mimo to?";
        if (MessageBoxW(g_editor, msg.c_str(), APP_TITLE, MB_YESNO | MB_ICONWARNING) != IDYES)
        {
            ShowTab(1);
            return false;
        }
    }

    if (!WriteTextFile(NvrConfigPath(), rulesUtf8))
        return false;
    if (!WriteTextFile(NvrSettingsPath(), NvrFormatSettings(st)))
        return false;

    SendMessageW(g_editCtl, EM_SETMODIFY, FALSE, 0);
    g_setDirty = false;
    return true;
}

// ---- okno ----
static void ShowTab(int t)
{
    g_curTab = t;
    TabCtrl_SetCurSel(g_edTab, t);

    const int r = (t == 0) ? SW_SHOW : SW_HIDE;
    const int a = (t == 1) ? SW_SHOW : SW_HIDE;
    const int s = (t == 2) ? SW_SHOW : SW_HIDE;

    ShowWindow(g_edHelp, r);
    ShowWindow(g_editCtl, r);
    ShowWindow(g_edNext, r);

    ShowWindow(g_adHelp, a);
    ShowWindow(g_adList, a);
    for (int i = 0; i < 4; ++i)
        ShowWindow(g_adBtn[i], a);

    ShowWindow(g_setHelp, s);
    ShowWindow(g_setLogLabel, s);
    ShowWindow(g_setLogEdit, s);
    ShowWindow(g_setPpsLabel, s);
    ShowWindow(g_setPpsEdit, s);
    ShowWindow(g_setOpenLog, s);

    SetFocus(t == 0 ? g_editCtl : t == 1 ? g_adList : g_setLogEdit);
    EditorUpdateInfo();
}

static void LayoutEditor(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    MoveWindow(g_edTab, 8, 6, w - 16, h - 6 - 74, TRUE);

    RECT pg = { 8, 6, w - 8, h - 74 + 6 };
    TabCtrl_AdjustRect(g_edTab, FALSE, &pg);

    const int x0 = pg.left + 6, y0 = pg.top + 6;
    const int pw = (pg.right - 6) - x0, ph = (pg.bottom - 6) - y0;

    // Reguly
    MoveWindow(g_edHelp, x0, y0, pw, 34, TRUE);
    MoveWindow(g_editCtl, x0, y0 + 38, pw, ph - 38, TRUE);

    // Karty
    MoveWindow(g_adHelp, x0, y0, pw, 34, TRUE);
    MoveWindow(g_adList, x0, y0 + 38, pw, ph - 38 - 36, TRUE);
    const int by = y0 + ph - 30;
    MoveWindow(g_adBtn[0], x0, by, 150, 28, TRUE);
    MoveWindow(g_adBtn[1], x0 + 156, by, 160, 28, TRUE);
    MoveWindow(g_adBtn[2], x0 + 322, by, 170, 28, TRUE);
    MoveWindow(g_adBtn[3], x0 + 498, by, 130, 28, TRUE);

    // Ustawienia
    MoveWindow(g_setHelp, x0, y0, pw, 34, TRUE);
    MoveWindow(g_setLogLabel, x0, y0 + 52, 330, 22, TRUE);
    MoveWindow(g_setLogEdit, x0 + 340, y0 + 48, 80, 24, TRUE);
    MoveWindow(g_setPpsLabel, x0, y0 + 90, 330, 22, TRUE);
    MoveWindow(g_setPpsEdit, x0 + 340, y0 + 86, 80, 24, TRUE);
    MoveWindow(g_setOpenLog, x0, y0 + 132, 150, 28, TRUE);

    MoveWindow(g_edInfo, 8, h - 68, w - 16, 20, TRUE);
    MoveWindow(g_edSave,  8, h - 38, 100, 30, TRUE);
    MoveWindow(g_edApply, 114, h - 38, 190, 30, TRUE);
    MoveWindow(g_edNext,  310, h - 38, 130, 30, TRUE);
    MoveWindow(g_edClose, w - 108, h - 38, 100, 30, TRUE);
}

static HWND MakeChild(HWND parent, const wchar_t* cls, const wchar_t* text, DWORD style, DWORD exStyle, int id, HFONT font)
{
    HWND c = CreateWindowExW(exStyle, cls, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, parent,
                             reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), g_inst, nullptr);
    if (c)
        SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return c;
}

static LRESULT CALLBACK EditorProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            g_edTab = MakeChild(hwnd, WC_TABCONTROLW, L"", WS_CLIPSIBLINGS | WS_TABSTOP, 0, ID_CTL_TAB, g_uiFont);
            const wchar_t* tabs[3] = { L"Reguły", L"Karty sieciowe", L"Ustawienia" };
            for (int i = 0; i < 3; ++i)
            {
                TCITEM ti;
                std::memset(&ti, 0, sizeof(ti));
                ti.mask = TCIF_TEXT;
                ti.pszText = const_cast<LPWSTR>(tabs[i]);
                TabCtrl_InsertItem(g_edTab, i, &ti);
            }

            // Reguly
            g_edHelp = MakeChild(hwnd, L"STATIC",
                L"Reguła: ip_nadawcy port_odbiorczy ip_docelowy port_docelowy   (0.0.0.0 = dowolny nadawca, "
                L"ip docelowy może być broadcast, # = komentarz).  Skróty: Ctrl+S zapisz, Ctrl+A zaznacz wszystko, "
                L"Esc zamknij, Ctrl+Tab do przycisków.",
                SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_editCtl = MakeChild(hwnd, L"EDIT", L"",
                WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
                ES_WANTRETURN | ES_NOHIDESEL, WS_EX_CLIENTEDGE, ID_CTL_RULES, g_monoFont);

            // Karty
            g_adHelp = MakeChild(hwnd, L"STATIC",
                L"Zaznacz karty, na których program ma ODBIERAĆ pakiety i/lub z których ma je WYSYŁAĆ. "
                L"Nowa karta bez wpisu: fizyczna = włączona, wirtualna = wyłączona. Karty nieobecne (odłączone) można ustawić z góry.",
                SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_adList = MakeChild(hwnd, WC_LISTVIEWW, L"",
                WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, WS_EX_CLIENTEDGE, ID_CTL_ADLIST, g_uiFont);
            ListView_SetExtendedListViewStyle(g_adList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
            for (int c = 0; c < NADCOLS; ++c)
            {
                LVCOLUMN col;
                std::memset(&col, 0, sizeof(col));
                col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
                col.fmt = LVCFMT_LEFT;
                col.cx = kAdCols[c].width;
                col.pszText = const_cast<LPWSTR>(kAdCols[c].title);
                ListView_InsertColumn(g_adList, c, &col);
            }
            g_adBtn[0] = MakeChild(hwnd, L"BUTTON", L"Odbiór: przełącz", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_AD_RX, g_uiFont);
            g_adBtn[1] = MakeChild(hwnd, L"BUTTON", L"Wysyłanie: przełącz", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_AD_TX, g_uiFont);
            g_adBtn[2] = MakeChild(hwnd, L"BUTTON", L"Domyślne (fizyczne)", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_AD_DEF, g_uiFont);
            g_adBtn[3] = MakeChild(hwnd, L"BUTTON", L"Odśwież listę", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_AD_REFRESH, g_uiFont);

            // Ustawienia
            g_setHelp = MakeChild(hwnd, L"STATIC",
                L"Plik logu po przekroczeniu limitu jest przenoszony do .log.1 (poprzedni .log.1 jest nadpisywany), "
                L"więc log zajmie najwyżej ok. 2 x limit.", SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_setLogLabel = MakeChild(hwnd, L"STATIC", L"Maksymalny rozmiar pliku logu [MB, 1-1024]:", SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_setLogEdit = MakeChild(hwnd, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_CTL_LOGMB, g_uiFont);
            g_setPpsLabel = MakeChild(hwnd, L"STATIC", L"Limit pakietów/s na regułę (ochrona przed pętlą, 0 = bez limitu):", SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_setPpsEdit = MakeChild(hwnd, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_CTL_PPS, g_uiFont);
            g_setOpenLog = MakeChild(hwnd, L"BUTTON", L"Otwórz log", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_SET_OPENLOG, g_uiFont);
            SendMessageW(g_setLogEdit, EM_SETLIMITTEXT, 4, 0);
            SendMessageW(g_setPpsEdit, EM_SETLIMITTEXT, 7, 0);

            // Wspolne
            g_edInfo = MakeChild(hwnd, L"STATIC", L"", SS_LEFT | SS_NOPREFIX, 0, 0, g_uiFont);
            g_edSave = MakeChild(hwnd, L"BUTTON", L"Zapisz", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_ED_SAVE, g_uiFont);
            g_edApply = MakeChild(hwnd, L"BUTTON", L"Zapisz i zastosuj (Start)", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_ED_APPLY, g_uiFont);
            g_edNext = MakeChild(hwnd, L"BUTTON", L"Następny błąd", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_ED_NEXT, g_uiFont);
            g_edClose = MakeChild(hwnd, L"BUTTON", L"Zamknij", WS_TABSTOP | BS_PUSHBUTTON, 0, ID_ED_CLOSE, g_uiFont);

            // dane
            SendMessageW(g_editCtl, EM_SETLIMITTEXT, 1024 * 1024, 0);
            SetWindowTextW(g_editCtl, LoadConfigForEditor().c_str());
            SendMessageW(g_editCtl, EM_SETMODIFY, FALSE, 0);

            NvrSettingsFile st;
            ReadSettingsFile(st);
            SetWindowTextW(g_setLogEdit, Num(st.logMaxMb).c_str());
            SetWindowTextW(g_setPpsEdit, Num(st.maxPps).c_str());

            LoadAdapterRows();
            FillAdapterList();

            EditorRevalidate();
            g_curTab = 0;
            LayoutEditor(hwnd);
            ShowTab(0);
            g_setDirty = false;
            g_edDirty = false;
            SetTimer(hwnd, ID_ED_TIMER, 300, nullptr);
            return 0;
        }

        case WM_SIZE:
            LayoutEditor(hwnd);
            return 0;

        case WM_GETMINMAXINFO:
        {
            MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lp);
            mmi->ptMinTrackSize.x = 700;
            mmi->ptMinTrackSize.y = 380;
            return 0;
        }

        case WM_SETFOCUS:
            SetFocus(g_curTab == 0 ? g_editCtl : g_curTab == 1 ? g_adList : g_setLogEdit);
            return 0;

        case WM_TIMER:
            if (wp == ID_ED_TIMER)
            {
                if (g_edDirty)
                {
                    g_edDirty = false;
                    EditorRevalidate();
                }
                EditorUpdateInfo();
            }
            return 0;

        case WM_NOTIFY:
        {
            NMHDR* nh = reinterpret_cast<NMHDR*>(lp);

            if (nh->hwndFrom == g_edTab && nh->code == TCN_SELCHANGE)
            {
                ShowTab(TabCtrl_GetCurSel(g_edTab));
            }
            else if (nh->hwndFrom == g_adList && nh->code == NM_CLICK)
            {
                NMITEMACTIVATE* ia = reinterpret_cast<NMITEMACTIVATE*>(lp);
                LVHITTESTINFO ht;
                std::memset(&ht, 0, sizeof(ht));
                ht.pt = ia->ptAction;
                ListView_SubItemHitTest(g_adList, &ht);
                if (ht.iItem >= 0)
                {
                    if (ht.iSubItem == 0) ToggleAdapter(ht.iItem, false);
                    else if (ht.iSubItem == 1) ToggleAdapter(ht.iItem, true);
                }
            }
            else if (nh->hwndFrom == g_adList && nh->code == LVN_KEYDOWN)
            {
                NMLVKEYDOWN* kd = reinterpret_cast<NMLVKEYDOWN*>(lp);
                const int sel = ListView_GetNextItem(g_adList, -1, LVNI_SELECTED);
                if (sel >= 0)
                {
                    if (kd->wVKey == VK_SPACE || kd->wVKey == 'R' || kd->wVKey == 'O')
                        ToggleAdapter(sel, false);
                    else if (kd->wVKey == 'W' || kd->wVKey == 'T')
                        ToggleAdapter(sel, true);
                }
            }
            return 0;
        }

        case WM_COMMAND:
            if (lp != 0 && reinterpret_cast<HWND>(lp) == g_editCtl)
            {
                if (HIWORD(wp) == EN_CHANGE)
                    g_edDirty = true;
                return 0;
            }
            if (lp != 0 && (reinterpret_cast<HWND>(lp) == g_setLogEdit || reinterpret_cast<HWND>(lp) == g_setPpsEdit))
            {
                if (HIWORD(wp) == EN_CHANGE)
                    g_setDirty = true;
                return 0;
            }

            switch (LOWORD(wp))
            {
                case ID_ED_SAVE:
                    SaveAll();
                    return 0;

                case ID_ED_APPLY:
                    if (SaveAll())
                        StartCommand(NVR_CMD_START);
                    return 0;

                case ID_ED_NEXT:
                    EditorRevalidate();
                    EditorNextError();
                    return 0;

                case ID_AD_RX:
                    ToggleAdapter(ListView_GetNextItem(g_adList, -1, LVNI_SELECTED), false);
                    return 0;

                case ID_AD_TX:
                    ToggleAdapter(ListView_GetNextItem(g_adList, -1, LVNI_SELECTED), true);
                    return 0;

                case ID_AD_DEF:
                    AdaptersDefaults();
                    return 0;

                case ID_AD_REFRESH:
                {
                    // zachowaj biezace wybory uzytkownika dla kart, ktore juz sa na liscie
                    std::vector<AdRow> old = g_adRows;
                    LoadAdapterRows();
                    for (size_t i = 0; i < g_adRows.size(); ++i)
                        for (size_t k = 0; k < old.size(); ++k)
                            if (NvrLower(old[k].guid) == NvrLower(g_adRows[i].guid))
                            {
                                g_adRows[i].rx = old[k].rx;
                                g_adRows[i].tx = old[k].tx;
                            }
                    FillAdapterList();
                    return 0;
                }

                case ID_SET_OPENLOG:
                    OpenLog();
                    return 0;

                case ID_ED_CLOSE:
                case IDCANCEL:
                    SendMessageW(hwnd, WM_CLOSE, 0, 0);
                    return 0;
            }
            break;

        case WM_CLOSE:
            if (SendMessageW(g_editCtl, EM_GETMODIFY, 0, 0) || g_setDirty)
            {
                const int r = MessageBoxW(hwnd, L"Zapisać zmiany w konfiguracji?", APP_TITLE,
                                          MB_YESNOCANCEL | MB_ICONQUESTION);
                if (r == IDCANCEL)
                    return 0;
                if (r == IDYES && !SaveAll())
                    return 0;
            }
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, ID_ED_TIMER);
            g_editor = nullptr;
            g_editCtl = nullptr;
            g_adList = nullptr;
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void OpenEditor()
{
    if (g_editor)
    {
        ShowWindow(g_editor, SW_RESTORE);
        SetForegroundWindow(g_editor);
        return;
    }

    g_editor = CreateWindowExW(0, L"NvrEditor", L"NetVar repeater - konfiguracja",
                               WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 860, 560,
                               nullptr, nullptr, g_inst, nullptr);
    if (g_editor)
    {
        ShowWindow(g_editor, SW_SHOW);
        SetForegroundWindow(g_editor);
    }
}

// Skroty klawiszowe okien konfiguracji i statusu (wolane z petli komunikatow).
static bool HandleKeys(MSG& m)
{
    if (g_editor && (m.hwnd == g_editor || IsChild(g_editor, m.hwnd)))
    {
        if (m.message == WM_KEYDOWN)
        {
            const bool ctrl = GetKeyState(VK_CONTROL) < 0;

            if (m.wParam == VK_ESCAPE)
            {
                PostMessageW(g_editor, WM_CLOSE, 0, 0);
                return true;
            }
            if (ctrl && m.wParam == 'S')
            {
                PostMessageW(g_editor, WM_COMMAND, ID_ED_SAVE, 0);
                return true;
            }
            if (ctrl && m.wParam == 'A')
            {
                wchar_t cls[16];
                GetClassNameW(m.hwnd, cls, 16);
                if (_wcsicmp(cls, L"Edit") == 0)
                {
                    SendMessageW(m.hwnd, EM_SETSEL, 0, static_cast<LPARAM>(-1));
                    return true;
                }
            }
            if (ctrl && m.wParam == VK_TAB)
            {
                SetFocus(g_edSave);
                return true;
            }
        }

        if (m.hwnd != g_editCtl && IsDialogMessageW(g_editor, &m))
            return true;
    }

    if (g_stWin && (m.hwnd == g_stWin || IsChild(g_stWin, m.hwnd)))
    {
        if (m.message == WM_KEYDOWN && m.wParam == VK_ESCAPE)
        {
            DestroyWindow(g_stWin);
            return true;
        }
        if (IsDialogMessageW(g_stWin, &m))
            return true;
    }

    return false;
}

// ------------------------------------------------------------
// Menu
// ------------------------------------------------------------
static void ShowMenu(POINT pt)
{
    PopupHide();
    RefreshStatus(300);

    HMENU menu = CreatePopupMenu();
    if (!menu)
        return;

    const bool avail = g_snap.ok && !g_cmdBusy;
    const bool active = g_snap.ok && g_snap.h.active;

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, (L"Stan: " + StateText(g_snap)).c_str());
    AppendMenuW(menu, MF_STRING, ID_STATUSWIN, L"Pokaż status...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    std::string raw;
    NvrConfigResult cfg;
    if (ReadConfigFile(raw))
        cfg = NvrParseConfig(raw, NVR_MAX_RULES);

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"Konfiguracja (kliknij, aby edytować):");

    for (size_t i = 0; i < cfg.rules.size() && i < 25; ++i)
    {
        const NvrRuleCfg& r = cfg.rules[i];
        AppendMenuW(menu, MF_STRING, ID_RULE_BASE + static_cast<UINT>(i),
                    RuleText(r.srcIp, r.listenPort, r.dstIp, r.dstPort).c_str());
    }

    if (cfg.rules.empty())
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"   (brak reguł)");
    else if (cfg.rules.size() > 25)
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0,
                    (L"   ... i " + Num(cfg.rules.size() - 25) + L" więcej").c_str());

    if (!cfg.errors.empty())
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0,
                    (L"   błędne linie: " + Num(cfg.errors.size())).c_str());

    AppendMenuW(menu, MF_STRING, ID_EDIT, L"Edytuj konfigurację (reguły, karty, ustawienia)...");
    AppendMenuW(menu, MF_STRING, ID_LOG, L"Otwórz log");
    AppendMenuW(menu, MF_STRING, ID_LOGDIR, L"Otwórz folder logu");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(menu, MF_STRING | (avail ? 0 : MF_GRAYED), ID_START, L"Start (wczytaj konfigurację)");
    AppendMenuW(menu, MF_STRING | ((avail && active) ? 0 : MF_GRAYED), ID_STOP, L"Stop");
    AppendMenuW(menu, MF_STRING | (avail ? 0 : MF_GRAYED), ID_RESET, L"Reset (wczytaj konfigurację i zeruj liczniki)");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_EXIT, L"Zamknij ikonę");

    SetForegroundWindow(g_window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_window, nullptr);
    PostMessageW(g_window, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

// ------------------------------------------------------------
// Wynik polecenia (w watku interfejsu)
// ------------------------------------------------------------
static void OnCommandDone(CmdJob* j)
{
    g_cmdBusy = false;

    if (!j->ok)
    {
        g_snap = Snapshot();
        UpdateAllViews();
        MessageBoxW(g_window,
                    L"Usługa NetVar repeater nie odpowiada.\n"
                    L"Sprawdź, czy jest zainstalowana i uruchomiona (services.msc).",
                    APP_TITLE, MB_OK | MB_ICONWARNING);
        delete j;
        return;
    }

    g_snap = j->snap;
    g_failCount = 0;
    UpdateAllViews();

    const DWORD res = j->snap.cmdResult;

    if (res != NO_ERROR)
    {
        std::wstring msg;
        if (res == NVR_ERR_NO_RULES)
        {
            msg = L"Brak poprawnych reguł w konfiguracji.";
            if (j->snap.h.message[0])
                msg += L"\n" + Utf8ToWide(j->snap.h.message);
            msg += L"\n\nUsługa spróbuje ponownie automatycznie po poprawieniu konfiguracji.";
        }
        else if (res == ERROR_MOD_NOT_FOUND || res == ERROR_FILE_NOT_FOUND || res == ERROR_PATH_NOT_FOUND)
        {
            msg = L"Nie można załadować WinDivert (brak WinDivert.dll / WinDivert64.sys obok usługi?).\n" + ErrText(res);
        }
        else if (res == ERROR_ACCESS_DENIED)
        {
            msg = L"WinDivert odmówił dostępu - usługa musi działać jako SYSTEM / administrator.";
        }
        else
        {
            msg = L"Polecenie zakończone błędem: " + ErrText(res) + L"\nSzczegóły: " + NvrLogPath();
        }

        MessageBoxW(g_window, msg.c_str(), APP_TITLE, MB_OK | MB_ICONERROR);
    }
    else if (j->snap.h.configErrorCount > 0)
    {
        const std::wstring msg = L"Konfiguracja wczytana, ale " + Num(j->snap.h.configErrorCount) +
                                 L" linii zostało odrzuconych.\nPierwszy błąd: " + Utf8ToWide(j->snap.h.message);
        MessageBoxW(g_window, msg.c_str(), APP_TITLE, MB_OK | MB_ICONWARNING);
    }

    delete j;
}

// ------------------------------------------------------------
// Okno glowne (ukryte)
// ------------------------------------------------------------
static LRESULT CALLBACK MainProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (g_msgTaskbarCreated && msg == g_msgTaskbarCreated)
    {
        AddTrayIcon();
        ApplyIconState(true);
        g_promoTries = 0;
        SetTimer(hwnd, ID_PROMO, 3000, nullptr);
        return 0;
    }

    switch (msg)
    {
        case WM_CREATE:
            g_window = hwnd;
            AddTrayIcon();
            RefreshStatus(300);
            ApplyIconState(true);
            SetTimer(hwnd, ID_TIMER, 2000, nullptr);
            SetTimer(hwnd, ID_PROMO, 3000, nullptr);
            return 0;

        case WM_TIMER:
            if (wp == ID_TIMER)
            {
                RefreshStatus(300);
            }
            else if (wp == ID_PROMO)
            {
                if (PromoteIcon() || ++g_promoTries >= 8)
                    KillTimer(hwnd, ID_PROMO);
            }
            return 0;

        case WM_CMD_DONE:
            OnCommandDone(reinterpret_cast<CmdJob*>(lp));
            return 0;

        case WM_TRAY:
        {
            const UINT ev = LOWORD(lp);
            const POINT pt = { GET_X_LPARAM(wp), GET_Y_LPARAM(wp) };

            switch (ev)
            {
                case NIN_POPUPOPEN:
                    g_anchor = pt;
                    RefreshStatus(300);
                    PopupShow();
                    break;

                case NIN_POPUPCLOSE:
                    PopupHide();
                    break;

                case NIN_SELECT:
                case NIN_KEYSELECT:
                    PopupHide();
                    OpenStatusWindow();
                    break;

                case WM_CONTEXTMENU:        // tylko to zdarzenie - bez WM_RBUTTONUP (podwojne menu)
                    ShowMenu(pt);
                    break;
            }
            return 0;
        }

        case WM_COMMAND:
        {
            const UINT id = LOWORD(wp);

            if (id >= ID_RULE_BASE && id < ID_RULE_BASE + 100)
            {
                OpenEditor();
                return 0;
            }

            switch (id)
            {
                case ID_STATUSWIN: OpenStatusWindow();         return 0;
                case ID_EDIT:      OpenEditor();               return 0;
                case ID_LOG:       OpenLog();                  return 0;
                case ID_LOGDIR:    OpenLogFolder();            return 0;
                case ID_START:     StartCommand(NVR_CMD_START); return 0;
                case ID_STOP:      StartCommand(NVR_CMD_STOP);  return 0;
                case ID_RESET:     StartCommand(NVR_CMD_RESET); return 0;
                case ID_EXIT:      DestroyWindow(hwnd);        return 0;
            }
            break;
        }

        case WM_DESTROY:
            KillTimer(hwnd, ID_TIMER);
            KillTimer(hwnd, ID_PROMO);
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            if (g_editor)
                DestroyWindow(g_editor);
            if (g_stWin)
                DestroyWindow(g_stWin);
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int)
{
    g_inst = inst;

    // jedna instancja na sesje uzytkownika
    HANDLE mutex = CreateMutexW(nullptr, TRUE, L"NetVarRepeaterTray_SingleInstance");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
        return 0;

    INITCOMMONCONTROLSEX icc;
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_TAB_CLASSES;
    InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm;
    std::memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_uiFont = CreateFontIndirectW(&ncm.lfMessageFont);
    g_monoFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");

    g_icons[0] = MakeIcon(RGB(110, 110, 110));   // szara: usluga niedostepna / nie dziala
    g_icons[1] = MakeIcon(RGB(25, 135, 50));     // zielona: dziala

    g_msgTaskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSW wc;
    std::memset(&wc, 0, sizeof(wc));
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);

    wc.lpfnWndProc = MainProc;
    wc.lpszClassName = L"NetVarRepeaterTrayWindow";
    if (!RegisterClassW(&wc))
        return 1;

    wc.lpfnWndProc = PopupProc;
    wc.lpszClassName = L"NvrPopup";
    wc.style = CS_DROPSHADOW;
    RegisterClassW(&wc);

    wc.style = 0;
    wc.hbrBackground = reinterpret_cast<HBRUSH>(static_cast<INT_PTR>(COLOR_BTNFACE + 1));

    wc.lpfnWndProc = EditorProc;
    wc.lpszClassName = L"NvrEditor";
    RegisterClassW(&wc);

    wc.lpfnWndProc = StatusProc;
    wc.lpszClassName = L"NvrStatus";
    RegisterClassW(&wc);

    g_popup = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_TOPMOST | WS_EX_NOACTIVATE,
                              L"NvrPopup", L"", WS_POPUP | WS_BORDER,
                              0, 0, 10, 10, nullptr, nullptr, inst, nullptr);

    HWND main = CreateWindowExW(0, L"NetVarRepeaterTrayWindow", APP_TITLE, 0,
                                0, 0, 0, 0, nullptr, nullptr, inst, nullptr);
    if (!main)
        return 2;

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0)
    {
        if (HandleKeys(m))
            continue;

        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    for (int i = 0; i < 4; ++i)
        if (g_icons[i]) DestroyIcon(g_icons[i]);

    if (mutex) CloseHandle(mutex);
    return static_cast<int>(m.wParam);
}
