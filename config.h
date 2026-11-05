// ============================================================
// NetVarRepeater - parser pliku konfiguracji (bez zaleznosci od WinAPI)
//
// Format linii:  ip_nadawcy  port_odbiorczy  ip_docelowy  port_docelowy
// Separatory: spacje, tabulatory lub przecinki. Komentarz: # lub ;
//
// Ustawienia (linie klucz = wartosc):
//   exclude_virtual = yes|no   pomijaj karty wirtualne (VMware, VirtualBox, Hyper-V, VPN...), domyslnie yes
//   max_pps         = N        limit pakietow/s na regule (ochrona przed petla), 0 = bez limitu, domyslnie 2000
//   log_max_kb      = N        maks. rozmiar pliku logu w KB (16..102400), domyslnie 512
// Adresy IPv4 w "host order" (a.b.c.d -> a<<24|b<<16|c<<8|d).
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

struct NvrSettings
{
    bool     excludeVirtual;
    uint32_t maxPps;
    uint32_t logMaxKb;

    NvrSettings() : excludeVirtual(true), maxPps(2000), logMaxKb(512) {}
};

struct NvrConfigResult
{
    NvrSettings              settings;
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

inline bool NvrParseBool(std::string v, bool& out)
{
    for (size_t i = 0; i < v.size(); ++i)
        if (v[i] >= 'A' && v[i] <= 'Z') v[i] = static_cast<char>(v[i] - 'A' + 'a');

    if (v == "yes" || v == "true" || v == "1" || v == "tak" || v == "on")  { out = true;  return true; }
    if (v == "no"  || v == "false" || v == "0" || v == "nie" || v == "off") { out = false; return true; }
    return false;
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

            if (key == "exclude_virtual")
            {
                if (!NvrParseBool(val, result.settings.excludeVirtual))
                    result.errors.push_back(pfx + "exclude_virtual oczekuje yes/no");
            }
            else if (key == "max_pps")
            {
                if (!NvrParseUInt(val, 0, 1000000, result.settings.maxPps))
                    result.errors.push_back(pfx + "max_pps oczekuje liczby 0..1000000");
            }
            else if (key == "log_max_kb")
            {
                if (!NvrParseUInt(val, 16, 102400, result.settings.logMaxKb))
                    result.errors.push_back(pfx + "log_max_kb oczekuje liczby 16..102400");
            }
            else if (!key.empty())
            {
                result.errors.push_back(pfx + "nieznane ustawienie '" + key + "'");
            }
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
