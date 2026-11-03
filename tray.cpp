// ============================================================
// NetVarRepeaterTray - ikona w zasobniku systemowym (klient uslugi)
//
//  - najechanie kursorem: okienko ze statystykami kazdej reguly,
//    czasem rozpoczecia i czasem dzialania,
//  - prawy przycisk: menu (konfiguracja, edycja, Start / Stop / Reset),
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

#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>

#include <cstdint>
#include <cwchar>
#include <cstring>
#include <string>
#include <vector>

#include "common.h"
#include "config.h"

#ifndef NIN_POPUPOPEN
#define NIN_POPUPOPEN  (WM_USER + 6)
#endif
#ifndef NIN_POPUPCLOSE
#define NIN_POPUPCLOSE (WM_USER + 7)
#endif
#ifndef NOTIFYICON_VERSION_4
#define NOTIFYICON_VERSION_4 4
#endif
#ifndef NIF_SHOWTIP
#define NIF_SHOWTIP 0x00000080
#endif

static const UINT WM_TRAY       = WM_APP + 1;
static const UINT_PTR ID_TIMER  = 1;
static const UINT ID_EDIT       = 2001;
static const UINT ID_START      = 2002;
static const UINT ID_STOP       = 2003;
static const UINT ID_RESET      = 2004;
static const UINT ID_EXIT       = 2005;
static const UINT ID_RULE_BASE  = 3000;

static const wchar_t* APP_TITLE = L"NetVarRepeater";

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
static HWND g_editor = nullptr;
static HWND g_editCtl = nullptr;
static HFONT g_uiFont = nullptr;
static HFONT g_monoFont = nullptr;
static NOTIFYICONDATAW g_nid;
static UINT g_msgTaskbarCreated = 0;
static HICON g_icons[4] = { nullptr, nullptr, nullptr, nullptr };
static int g_iconState = -1;
static Snapshot g_snap;
static POINT g_anchor = { 0, 0 };
static bool g_popupVisible = false;

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

static std::wstring ErrText(DWORD code)
{
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

static std::wstring RuleText(uint32_t src, uint16_t lport, uint32_t dst, uint16_t dport)
{
    return W(NvrIpToString(src)) + L":" + Num(lport) + L"  ->  " +
           W(NvrIpToString(dst)) + L":" + Num(dport);
}

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
// Komunikacja z usluga
// ------------------------------------------------------------
static bool Transact(uint32_t cmd, Snapshot& out, DWORD timeoutMs)
{
    static std::vector<unsigned char> buf(NVR_MAX_REPLY);

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

// ------------------------------------------------------------
// Ikony (kolorowe kropki generowane w locie)
// ------------------------------------------------------------
static HICON MakeIcon(COLORREF color)
{
    const int sz = GetSystemMetrics(SM_CXSMICON);
    HDC screen = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(screen);
    HBITMAP bmpColor = CreateCompatibleBitmap(screen, sz, sz);
    HBITMAP bmpMask = CreateBitmap(sz, sz, 1, 1, nullptr);

    HGDIOBJ old = SelectObject(mem, bmpColor);
    HBRUSH bg = CreateSolidBrush(RGB(0, 0, 0));
    RECT rc = { 0, 0, sz, sz };
    FillRect(mem, &rc, bg);
    DeleteObject(bg);

    HBRUSH fg = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, RGB(40, 40, 40));
    HGDIOBJ ob = SelectObject(mem, fg);
    HGDIOBJ op = SelectObject(mem, pen);
    Ellipse(mem, 1, 1, sz - 1, sz - 1);
    SelectObject(mem, ob);
    SelectObject(mem, op);
    DeleteObject(fg);
    DeleteObject(pen);

    SelectObject(mem, bmpMask);
    PatBlt(mem, 0, 0, sz, sz, WHITENESS);                  // 1 = przezroczyste
    HGDIOBJ ob2 = SelectObject(mem, GetStockObject(BLACK_BRUSH));
    HGDIOBJ op2 = SelectObject(mem, GetStockObject(NULL_PEN));
    Ellipse(mem, 1, 1, sz, sz);                            // 0 = widoczne
    SelectObject(mem, ob2);
    SelectObject(mem, op2);

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

// 0 = usluga niedostepna, 1 = zatrzymane, 2 = aktywne, 3 = aktywne z bledami
static int StateOf(const Snapshot& s)
{
    if (!s.ok) return 0;
    if (!s.h.active) return 1;
    for (size_t i = 0; i < s.rules.size(); ++i)
        if (s.rules[i].errors > 0) return 3;
    return 2;
}

static void ApplyIconState(bool force)
{
    const int st = StateOf(g_snap);
    if (!force && st == g_iconState)
        return;

    g_iconState = st;
    g_nid.hIcon = g_icons[st];

    const wchar_t* tip = st == 0 ? L"NetVarRepeater - usluga niedostepna"
                       : st == 1 ? L"NetVarRepeater - zatrzymany"
                       :           L"NetVarRepeater - aktywny";
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
    std::wcscpy(g_nid.szTip, L"NetVarRepeater");

    Shell_NotifyIconW(NIM_ADD, &g_nid);

    // Wersja 4: powiadomienia NIN_POPUPOPEN/CLOSE przy najechaniu kursorem
    // (standardowy, 128-znakowy tooltip jest wtedy wylaczony).
    g_nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &g_nid);
}

// ------------------------------------------------------------
// Okienko ze statystykami (zamiast tooltipa)
// ------------------------------------------------------------
static std::wstring BuildPopupText()
{
    const Snapshot& s = g_snap;

    if (!s.ok)
        return L"NetVarRepeater\r\nUsluga nie odpowiada (zatrzymana lub niezainstalowana).";

    std::wstring t = L"NetVarRepeater - ";
    t += s.h.active ? L"AKTYWNY" : L"ZATRZYMANY";
    t += L"\r\n";

    if (s.h.startTime != 0)
    {
        t += L"Start: " + FormatTime(s.h.startTime);
        if (s.h.active && s.h.nowTime > s.h.startTime)
            t += L"    Czas pracy: " + FormatDuration(s.h.nowTime - s.h.startTime);
        t += L"\r\n";
    }

    if (s.h.lastError != 0)
        t += L"Ostatni blad: " + ErrText(s.h.lastError) + L"\r\n";

    if (s.h.configErrorCount != 0)
        t += L"Bledne linie konfiguracji: " + Num(s.h.configErrorCount) + L" (np. " +
             Utf8ToWide(s.h.message) + L")\r\n";

    t += L"Przechwycone: " + Num(s.h.totalSeen) + L", bez reguly: " + Num(s.h.totalIgnored) + L"\r\n";

    if (s.rules.empty())
        t += L"\r\n(brak regul)";

    const size_t maxShow = 20;
    for (size_t i = 0; i < s.rules.size() && i < maxShow; ++i)
    {
        const NvrRuleStatus& r = s.rules[i];

        t += L"\r\n#" + Num(i + 1) + L"  " + RuleText(r.srcIp, r.listenPort, r.dstIp, r.dstPort) + L"\r\n";
        t += L"     odebrane: " + Num(r.received) + L"   przekazane: " + Num(r.forwarded) +
             L"   bledy wysylania: " + Num(r.errors);

        if (r.errors > 0 && r.lastError != 0)
            t += L" (" + Num(r.lastError) + L")";

        t += L"\r\n     wyjscie: ";
        if (r.outMode == NVR_OUT_BOUND)
            t += L"interfejs " + Num(r.outIfIdx);
        else if (r.outMode == NVR_OUT_BCAST_ALL)
            t += L"broadcast na " + Num(r.outCount) + L" interf. (bez odbiorczego)";
        else
            t += L"wybor systemu";
    }

    if (s.rules.size() > maxShow)
        t += L"\r\n... i " + Num(s.rules.size() - maxShow) + L" wiecej";

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

        FillRect(dc, &rc, GetSysColorBrush(COLOR_INFOBK));
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, GetSysColor(COLOR_INFOTEXT));
        HGDIOBJ old = SelectObject(dc, g_uiFont);

        RECT tr = { 8, 6, rc.right - 8, rc.bottom - 6 };
        const std::wstring text = BuildPopupText();
        DrawTextW(dc, text.c_str(), -1, &tr, DT_LEFT | DT_NOPREFIX | DT_EXPANDTABS);

        SelectObject(dc, old);
        EndPaint(hwnd, &ps);
        return 0;
    }

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
    RECT rc = { 0, 0, 700, 0 };
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
    InvalidateRect(g_popup, nullptr, TRUE);
    g_popupVisible = true;
}

static void PopupHide()
{
    if (g_popup)
        ShowWindow(g_popup, SW_HIDE);
    g_popupVisible = false;
}

// ------------------------------------------------------------
// Polecenia
// ------------------------------------------------------------
static void RefreshStatus(DWORD timeoutMs)
{
    Transact(NVR_CMD_STATUS, g_snap, timeoutMs);
    ApplyIconState(false);

    if (g_popupVisible)
        PopupShow();
}

static void DoCommand(uint32_t cmd)
{
    HCURSOR oldCursor = SetCursor(LoadCursorW(nullptr, IDC_WAIT));

    Snapshot s;
    const bool ok = Transact(cmd, s, 5000);
    SetCursor(oldCursor);

    if (!ok)
    {
        g_snap = Snapshot();
        ApplyIconState(false);
        MessageBoxW(g_window,
                    L"Usluga NetVarRepeater nie odpowiada.\n"
                    L"Sprawdz, czy jest zainstalowana i uruchomiona (services.msc).",
                    APP_TITLE, MB_OK | MB_ICONWARNING);
        return;
    }

    g_snap = s;
    ApplyIconState(false);

    if (s.cmdResult != NO_ERROR)
    {
        std::wstring msg;
        if (s.cmdResult == ERROR_BAD_CONFIGURATION)
        {
            msg = L"Brak poprawnych regul w konfiguracji.";
            if (s.h.message[0])
                msg += L"\n" + Utf8ToWide(s.h.message);
        }
        else if (s.cmdResult == ERROR_MOD_NOT_FOUND || s.cmdResult == ERROR_FILE_NOT_FOUND)
        {
            msg = L"Nie mozna zaladowac WinDivert (brak WinDivert.dll / WinDivert64.sys obok uslugi?).\n" +
                  ErrText(s.cmdResult);
        }
        else if (s.cmdResult == ERROR_ACCESS_DENIED)
        {
            msg = L"WinDivert odmowil dostepu - usluga musi dzialac jako SYSTEM / administrator.";
        }
        else
        {
            msg = L"Polecenie zakonczone bledem: " + ErrText(s.cmdResult);
        }

        MessageBoxW(g_window, msg.c_str(), APP_TITLE, MB_OK | MB_ICONERROR);
    }
    else if (s.h.configErrorCount > 0)
    {
        std::wstring msg = L"Konfiguracja wczytana, ale " + Num(s.h.configErrorCount) +
                           L" linii zostalo odrzuconych.\nPierwszy blad: " + Utf8ToWide(s.h.message);
        MessageBoxW(g_window, msg.c_str(), APP_TITLE, MB_OK | MB_ICONWARNING);
    }
}

// ------------------------------------------------------------
// Edytor konfiguracji
// ------------------------------------------------------------
static const int ID_ED_SAVE = 4001, ID_ED_APPLY = 4002, ID_ED_CLOSE = 4003;
static HWND g_edLabel = nullptr, g_edSave = nullptr, g_edApply = nullptr, g_edClose = nullptr;

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

    // normalizacja konca linii dla kontrolki EDIT
    std::wstring out;
    for (size_t i = 0; i < w.size(); ++i)
    {
        if (w[i] == L'\r') continue;
        if (w[i] == L'\n') out += L"\r\n"; else out += w[i];
    }
    return out;
}

static bool SaveConfigFromEditor()
{
    const int len = GetWindowTextLengthW(g_editCtl);
    std::wstring w(static_cast<size_t>(len) + 1, L'\0');
    GetWindowTextW(g_editCtl, &w[0], len + 1);
    w.resize(static_cast<size_t>(len));

    const std::string utf8 = WideToUtf8(w);

    NvrConfigResult res = NvrParseConfig(utf8, NVR_MAX_RULES);
    if (!res.errors.empty())
    {
        std::wstring msg = L"W konfiguracji sa bledy (" + Num(res.errors.size()) + L"):\n\n";
        for (size_t i = 0; i < res.errors.size() && i < 10; ++i)
            msg += W(res.errors[i]) + L"\n";
        msg += L"\nBledne linie zostana pominiete przez usluge. Zapisac mimo to?";

        if (MessageBoxW(g_editor, msg.c_str(), APP_TITLE, MB_YESNO | MB_ICONWARNING) != IDYES)
            return false;
    }

    CreateDirectoryW(NvrDataDir().c_str(), nullptr);

    HANDLE h = CreateFileW(NvrConfigPath().c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        const std::wstring msg = L"Nie mozna zapisac pliku:\n" + NvrConfigPath() + L"\n" +
                                 ErrText(GetLastError()) +
                                 L"\n\nUruchom ponownie install.bat (nadaje prawa zapisu) lub edytuj plik jako administrator.";
        MessageBoxW(g_editor, msg.c_str(), APP_TITLE, MB_OK | MB_ICONERROR);
        return false;
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(h, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    CloseHandle(h);

    if (!ok || written != utf8.size())
    {
        MessageBoxW(g_editor, L"Zapis pliku nie powiodl sie.", APP_TITLE, MB_OK | MB_ICONERROR);
        return false;
    }

    SendMessageW(g_editCtl, EM_SETMODIFY, FALSE, 0);
    return true;
}

static void LayoutEditor(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    MoveWindow(g_edLabel, 8, 6, w - 16, 34, TRUE);
    MoveWindow(g_editCtl, 8, 44, w - 16, h - 44 - 46, TRUE);
    MoveWindow(g_edSave,  8, h - 38, 110, 30, TRUE);
    MoveWindow(g_edApply, 126, h - 38, 200, 30, TRUE);
    MoveWindow(g_edClose, w - 118, h - 38, 110, 30, TRUE);
}

static LRESULT CALLBACK EditorProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
        case WM_CREATE:
        {
            g_edLabel = CreateWindowExW(0, L"STATIC",
                L"Format linii: ip_nadawcy port_odbiorczy ip_docelowy port_docelowy   "
                L"(0.0.0.0 = dowolny nadawca, ip docelowy moze byc broadcast, # = komentarz)",
                WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, nullptr, g_inst, nullptr);

            g_editCtl = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE |
                ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
                0, 0, 0, 0, hwnd, nullptr, g_inst, nullptr);

            g_edSave = CreateWindowExW(0, L"BUTTON", L"Zapisz", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_ED_SAVE)), g_inst, nullptr);
            g_edApply = CreateWindowExW(0, L"BUTTON", L"Zapisz i zastosuj (Start)", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_ED_APPLY)), g_inst, nullptr);
            g_edClose = CreateWindowExW(0, L"BUTTON", L"Zamknij", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(ID_ED_CLOSE)), g_inst, nullptr);

            SendMessageW(g_edLabel, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            SendMessageW(g_editCtl, WM_SETFONT, reinterpret_cast<WPARAM>(g_monoFont), TRUE);
            SendMessageW(g_edSave, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            SendMessageW(g_edApply, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);
            SendMessageW(g_edClose, WM_SETFONT, reinterpret_cast<WPARAM>(g_uiFont), TRUE);

            SendMessageW(g_editCtl, EM_SETLIMITTEXT, 1024 * 1024, 0);
            SetWindowTextW(g_editCtl, LoadConfigForEditor().c_str());
            SendMessageW(g_editCtl, EM_SETMODIFY, FALSE, 0);
            return 0;
        }

        case WM_SIZE:
            LayoutEditor(hwnd);
            return 0;

        case WM_SETFOCUS:
            SetFocus(g_editCtl);
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wp))
            {
                case ID_ED_SAVE:
                    SaveConfigFromEditor();
                    return 0;

                case ID_ED_APPLY:
                    if (SaveConfigFromEditor())
                        DoCommand(NVR_CMD_START);
                    return 0;

                case ID_ED_CLOSE:
                    SendMessageW(hwnd, WM_CLOSE, 0, 0);
                    return 0;
            }
            break;

        case WM_CLOSE:
            if (SendMessageW(g_editCtl, EM_GETMODIFY, 0, 0))
            {
                const int r = MessageBoxW(hwnd, L"Zapisac zmiany w konfiguracji?", APP_TITLE,
                                          MB_YESNOCANCEL | MB_ICONQUESTION);
                if (r == IDCANCEL)
                    return 0;
                if (r == IDYES && !SaveConfigFromEditor())
                    return 0;
            }
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            g_editor = nullptr;
            g_editCtl = nullptr;
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

    g_editor = CreateWindowExW(0, L"NvrEditor", L"NetVarRepeater - konfiguracja",
                               WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 760, 480,
                               nullptr, nullptr, g_inst, nullptr);
    if (g_editor)
    {
        ShowWindow(g_editor, SW_SHOW);
        SetForegroundWindow(g_editor);
    }
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

    const bool avail = g_snap.ok;
    const bool active = avail && g_snap.h.active;

    const wchar_t* state = !avail ? L"Stan: usluga niedostepna"
                         : active ? L"Stan: AKTYWNY" : L"Stan: ZATRZYMANY";
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, state);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // Konfiguracja (z pliku) - klikniecie otwiera edytor
    std::string raw;
    NvrConfigResult cfg;
    if (ReadConfigFile(raw))
        cfg = NvrParseConfig(raw, NVR_MAX_RULES);

    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"Konfiguracja (kliknij, aby edytowac):");

    for (size_t i = 0; i < cfg.rules.size() && i < 25; ++i)
    {
        const NvrRuleCfg& r = cfg.rules[i];
        AppendMenuW(menu, MF_STRING, ID_RULE_BASE + static_cast<UINT>(i),
                    RuleText(r.srcIp, r.listenPort, r.dstIp, r.dstPort).c_str());
    }

    if (cfg.rules.empty())
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, L"   (brak regul)");
    else if (cfg.rules.size() > 25)
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0,
                    (L"   ... i " + Num(cfg.rules.size() - 25) + L" wiecej").c_str());

    if (!cfg.errors.empty())
        AppendMenuW(menu, MF_STRING | MF_GRAYED, 0,
                    (L"   bledne linie: " + Num(cfg.errors.size())).c_str());

    AppendMenuW(menu, MF_STRING, ID_EDIT, L"Edytuj konfiguracje...");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    AppendMenuW(menu, MF_STRING | (avail ? 0 : MF_GRAYED), ID_START,
                L"Start (wczytaj konfiguracje)");
    AppendMenuW(menu, MF_STRING | (active ? 0 : MF_GRAYED), ID_STOP, L"Stop");
    AppendMenuW(menu, MF_STRING | (avail ? 0 : MF_GRAYED), ID_RESET,
                L"Reset (wczytaj konfiguracje i zeruj liczniki)");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_EXIT, L"Zamknij ikone");

    SetForegroundWindow(g_window);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, 0, g_window, nullptr);
    PostMessageW(g_window, WM_NULL, 0, 0);
    DestroyMenu(menu);
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
            return 0;

        case WM_TIMER:
            if (wp == ID_TIMER)
                RefreshStatus(300);
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

                case WM_CONTEXTMENU:
                case WM_RBUTTONUP:
                    ShowMenu(pt);
                    break;

                case WM_LBUTTONDBLCLK:
                    OpenEditor();
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
                case ID_EDIT:  OpenEditor(); return 0;
                case ID_START: DoCommand(NVR_CMD_START); return 0;
                case ID_STOP:  DoCommand(NVR_CMD_STOP);  return 0;
                case ID_RESET: DoCommand(NVR_CMD_RESET); return 0;
                case ID_EXIT:  DestroyWindow(hwnd);      return 0;
            }
            break;
        }

        case WM_DESTROY:
            KillTimer(hwnd, ID_TIMER);
            Shell_NotifyIconW(NIM_DELETE, &g_nid);
            if (g_editor)
                DestroyWindow(g_editor);
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

    NONCLIENTMETRICSW ncm;
    std::memset(&ncm, 0, sizeof(ncm));
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
    g_uiFont = CreateFontIndirectW(&ncm.lfMessageFont);
    g_monoFont = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                             OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, L"Consolas");

    g_icons[0] = MakeIcon(RGB(140, 140, 140));   // niedostepna
    g_icons[1] = MakeIcon(RGB(240, 160, 30));    // zatrzymana
    g_icons[2] = MakeIcon(RGB(40, 180, 60));     // aktywna
    g_icons[3] = MakeIcon(RGB(215, 45, 45));     // aktywna z bledami

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
    wc.lpfnWndProc = EditorProc;
    wc.lpszClassName = L"NvrEditor";
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
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
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }

    for (int i = 0; i < 4; ++i)
        if (g_icons[i]) DestroyIcon(g_icons[i]);

    if (mutex) CloseHandle(mutex);
    return static_cast<int>(m.wParam);
}
