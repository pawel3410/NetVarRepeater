// ============================================================
// NetVarRepeater - parser pliku konfiguracji (bez zaleznosci od WinAPI)
//
// Format linii:  ip_nadawcy  port_odbiorczy  ip_docelowy  port_docelowy
// Separatory: spacje, tabulatory lub przecinki. Komentarz: # lub ;
//
// Ustawienia (karty sieciowe, limit logu, limit pps) NIE sa juz w tym pliku -
// sa w settings.ini edytowanym w oknie konfiguracji (zakladki Karty / Ustawienia).
// ============================================================
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

struct NvrRuleCfg
{
    uint32_t srcIp;        // 0 = dowolny nadawca
    uint16_t listenPort;
    uint32_t dstIp;
    uint16_t dstPort;
    int      line;
};

struct NvrConfigResult
{
    std::vector<NvrRuleCfg>  rules;
    std::vector<std::string> errors;   // czytelne komunikaty "linia N: ..."
};

inline bool NvrParseIPv4(const std::string& s, uint32_t& out)
{
    uint32_t value = 0;
    int parts = 0;
    size_t i = 0;

    while (i <= s.size())
    {
        if (i == s.size() || s[i] < '0' || s[i] > '9')
            return false;

        uint32_t octet = 0;
        int digits = 0;

        while (i < s.size() && s[i] >= '0' && s[i] <= '9')
        {
            octet = octet * 10 + static_cast<uint32_t>(s[i] - '0');
            if (++digits > 3 || octet > 255)
                return false;
            ++i;
        }

        value = (value << 8) | octet;
        ++parts;

        if (i == s.size())
            break;
        if (s[i] != '.')
            return false;
        ++i;
    }

    if (parts != 4)
        return false;

    out = value;
    return true;
}

inline bool NvrParsePort(const std::string& s, uint16_t& out)
{
    if (s.empty() || s.size() > 5)
        return false;

    uint32_t v = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + static_cast<uint32_t>(s[i] - '0');
    }

    if (v < 1 || v > 65535)
        return false;

    out = static_cast<uint16_t>(v);
    return true;
}

inline bool NvrParseUInt(const std::string& s, uint32_t lo, uint32_t hi, uint32_t& out)
{
    if (s.empty() || s.size() > 9)
        return false;

    uint32_t v = 0;
    for (size_t i = 0; i < s.size(); ++i)
    {
        if (s[i] < '0' || s[i] > '9')
            return false;
        v = v * 10 + static_cast<uint32_t>(s[i] - '0');
    }

    if (v < lo || v > hi)
        return false;

    out = v;
    return true;
}

inline std::string NvrTrim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) --b;
    return s.substr(a, b - a);
}

inline std::string NvrIpToString(uint32_t ip)
{
    char b[32];
    std::snprintf(b, sizeof(b), "%u.%u.%u.%u",
                  (ip >> 24) & 255u, (ip >> 16) & 255u, (ip >> 8) & 255u, ip & 255u);
    return b;
}

inline NvrConfigResult NvrParseConfig(const std::string& text, size_t maxRules = 256)
{
    NvrConfigResult result;

    size_t pos = 0;
    int lineNo = 0;

    // pomin BOM UTF-8
    if (text.size() >= 3 &&
        static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB &&
        static_cast<unsigned char>(text[2]) == 0xBF)
    {
        pos = 3;
    }

    while (pos <= text.size())
    {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos)
            end = text.size();

        std::string line = text.substr(pos, end - pos);
        pos = end + 1;
        ++lineNo;

        // komentarze
        size_t c = line.find_first_of("#;");
        if (c != std::string::npos)
            line.erase(c);

        // ustawienie: klucz = wartosc
        const size_t eq = line.find('=');
        if (eq != std::string::npos)
        {
            std::string key = NvrTrim(line.substr(0, eq));
            const std::string val = NvrTrim(line.substr(eq + 1));
            for (size_t i = 0; i < key.size(); ++i)
                if (key[i] >= 'A' && key[i] <= 'Z') key[i] = static_cast<char>(key[i] - 'A' + 'a');

            const std::string pfx = "linia " + std::to_string(lineNo) + ": ";

            if (key == "exclude_virtual" || key == "max_pps" || key == "log_max_kb")
                result.errors.push_back(pfx + "ustawienie '" + key +
                    "' zostalo przeniesione do okna konfiguracji (zakladki Karty / Ustawienia) - usun te linie");
            else if (!key.empty())
                result.errors.push_back(pfx + "nieznane ustawienie '" + key + "'");
            continue;
        }

        // tokeny: spacje / tab / przecinki / CR
        std::vector<std::string> tok;
        std::string cur;
        for (size_t i = 0; i < line.size(); ++i)
        {
            const char ch = line[i];
            if (ch == ' ' || ch == '\t' || ch == ',' || ch == '\r')
            {
                if (!cur.empty()) { tok.push_back(cur); cur.clear(); }
            }
            else
                cur += ch;
        }
        if (!cur.empty())
            tok.push_back(cur);

        if (tok.empty())
            continue;

        const std::string prefix = "linia " + std::to_string(lineNo) + ": ";

        if (tok.size() != 4)
        {
            result.errors.push_back(prefix + "oczekiwano 4 pol (ip_nadawcy port_odb ip_docelowy port_docel)");
            continue;
        }

        NvrRuleCfg r{};
        r.line = lineNo;

        if (!NvrParseIPv4(tok[0], r.srcIp))
        { result.errors.push_back(prefix + "niepoprawny ip nadawcy '" + tok[0] + "'"); continue; }
        if (!NvrParsePort(tok[1], r.listenPort))
        { result.errors.push_back(prefix + "niepoprawny port odbiorczy '" + tok[1] + "'"); continue; }
        if (!NvrParseIPv4(tok[2], r.dstIp))
        { result.errors.push_back(prefix + "niepoprawny ip docelowy '" + tok[2] + "'"); continue; }
        if (!NvrParsePort(tok[3], r.dstPort))
        { result.errors.push_back(prefix + "niepoprawny port docelowy '" + tok[3] + "'"); continue; }
        if (r.dstIp == 0)
        { result.errors.push_back(prefix + "ip docelowy nie moze byc 0.0.0.0"); continue; }

        bool dup = false;
        for (size_t i = 0; i < result.rules.size(); ++i)
        {
            const NvrRuleCfg& o = result.rules[i];
            if (o.srcIp == r.srcIp && o.listenPort == r.listenPort &&
                o.dstIp == r.dstIp && o.dstPort == r.dstPort)
            { dup = true; break; }
        }
        if (dup)
        { result.errors.push_back(prefix + "duplikat wczesniejszej reguly - pominieto"); continue; }

        if (result.rules.size() >= maxRules)
        { result.errors.push_back(prefix + "przekroczono limit regul - pominieto"); continue; }

        result.rules.push_back(r);
    }

    return result;
}

// ============================================================
// settings.ini - ustawienia zarzadzane przez okno konfiguracji
//
//   log_max_mb = 1
//   max_pps    = 2000
//   adapter    = {GUID}|odbior(0/1)|wysylanie(0/1)|nazwa
//
// Karta nieobecna na liscie uzywa wartosci domyslnej: fizyczna = wlaczona,
// wirtualna = wylaczona (odbior i wysylanie).
// ============================================================
struct NvrAdapterSel
{
    std::string guid;
    bool rx;
    bool tx;
    std::string name;     // UTF-8, tylko do wyswietlania
};

struct NvrSettingsFile
{
    uint32_t logMaxMb;
    uint32_t maxPps;
    std::vector<NvrAdapterSel> adapters;
    std::vector<std::string>   errors;

    NvrSettingsFile() : logMaxMb(1), maxPps(2000) {}
};

inline std::string NvrLower(std::string s)
{
    for (size_t i = 0; i < s.size(); ++i)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] = static_cast<char>(s[i] - 'A' + 'a');
    return s;
}

inline NvrSettingsFile NvrParseSettings(const std::string& text)
{
    NvrSettingsFile st;

    size_t pos = 0;
    int lineNo = 0;

    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF &&
        static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF)
        pos = 3;

    while (pos <= text.size())
    {
        size_t end = text.find('\n', pos);
        if (end == std::string::npos)
            end = text.size();

        const std::string line = NvrTrim(text.substr(pos, end - pos));
        pos = end + 1;
        ++lineNo;

        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;

        const std::string pfx = "settings.ini linia " + std::to_string(lineNo) + ": ";
        const size_t eq = line.find('=');
        if (eq == std::string::npos)
        {
            st.errors.push_back(pfx + "oczekiwano klucz = wartosc");
            continue;
        }

        const std::string key = NvrLower(NvrTrim(line.substr(0, eq)));
        const std::string val = NvrTrim(line.substr(eq + 1));

        if (key == "log_max_mb")
        {
            if (!NvrParseUInt(val, 1, 1024, st.logMaxMb))
                st.errors.push_back(pfx + "log_max_mb oczekuje liczby calkowitej 1..1024");
        }
        else if (key == "max_pps")
        {
            if (!NvrParseUInt(val, 0, 1000000, st.maxPps))
                st.errors.push_back(pfx + "max_pps oczekuje liczby 0..1000000");
        }
        else if (key == "adapter")
        {
            // {GUID}|rx|tx|nazwa
            const size_t p1 = val.find('|');
            const size_t p2 = p1 == std::string::npos ? p1 : val.find('|', p1 + 1);
            const size_t p3 = p2 == std::string::npos ? p2 : val.find('|', p2 + 1);

            if (p1 == std::string::npos || p2 == std::string::npos || val.empty())
            {
                st.errors.push_back(pfx + "adapter oczekuje {GUID}|odbior|wysylanie|nazwa");
                continue;
            }

            NvrAdapterSel a;
            a.guid = NvrTrim(val.substr(0, p1));
            a.rx = val.substr(p1 + 1, p2 - p1 - 1) == "1";
            a.tx = (p3 == std::string::npos ? val.substr(p2 + 1) : val.substr(p2 + 1, p3 - p2 - 1)) == "1";
            a.name = p3 == std::string::npos ? std::string() : val.substr(p3 + 1);
            st.adapters.push_back(a);
        }
        else
        {
            st.errors.push_back(pfx + "nieznane ustawienie '" + key + "'");
        }
    }

    return st;
}

inline std::string NvrFormatSettings(const NvrSettingsFile& st)
{
    std::string o;
    o += "# NetVar repeater - ustawienia (zarzadzane przez okno konfiguracji; reguly sa w config.txt)\r\n";
    o += "log_max_mb = " + std::to_string(st.logMaxMb) + "\r\n";
    o += "max_pps = " + std::to_string(st.maxPps) + "\r\n";
    o += "# adapter = {GUID}|odbior|wysylanie|nazwa\r\n";
    for (size_t i = 0; i < st.adapters.size(); ++i)
        o += "adapter = " + st.adapters[i].guid + "|" + (st.adapters[i].rx ? "1" : "0") + "|" +
             (st.adapters[i].tx ? "1" : "0") + "|" + st.adapters[i].name + "\r\n";
    return o;
}

// Czy karta o danym GUID ma wlaczony odbior (tx=false) lub wysylanie (tx=true).
inline bool NvrAdapterAllowed(const NvrSettingsFile& st, const std::string& guid,
                              bool defaultAllowed, bool tx)
{
    const std::string g = NvrLower(guid);
    for (size_t i = 0; i < st.adapters.size(); ++i)
        if (NvrLower(st.adapters[i].guid) == g)
            return tx ? st.adapters[i].tx : st.adapters[i].rx;
    return defaultAllowed;
}
