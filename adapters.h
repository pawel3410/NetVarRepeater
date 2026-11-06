// ============================================================
// NetVar repeater - wspolna enumeracja kart sieciowych (usluga i tray)
// ============================================================
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <cstdint>
#include <cwctype>
#include <string>
#include <vector>

struct NvrAdapterAddr
{
    uint32_t ip;      // host order
    uint32_t mask;    // host order
};

struct NvrAdapter
{
    std::string  guid;        // AdapterName, np. "{3F2A...}" - stabilny klucz karty
    std::wstring name;        // FriendlyName, np. "Ethernet 2"
    std::wstring desc;        // opis sterownika
    uint32_t     ifIdx;       // indeks IPv4 (zmienny miedzy restartami / sterownikami)
    bool         up;
    bool         isVirtual;   // heurystyka (domyslna wartosc wyboru, gdy brak wpisu w settings.ini)
    std::vector<NvrAdapterAddr> addrs;
};

inline bool NvrContainsNoCase(const std::wstring& hay, const wchar_t* needle)
{
    std::wstring h = hay;
    for (size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<wchar_t>(std::towlower(h[i]));

    std::wstring n = needle;
    for (size_t i = 0; i < n.size(); ++i)
        n[i] = static_cast<wchar_t>(std::towlower(n[i]));

    return h.find(n) != std::wstring::npos;
}

// Karta wirtualna: typ interfejsu inny niz fizyczny (Ethernet/Wi-Fi/WWAN),
// znany prefiks MAC (VMware, VirtualBox, Hyper-V, Parallels, QEMU, Xen)
// lub charakterystyczna nazwa/opis (VPN, TAP, WSL, Docker, vEthernet...).
inline bool NvrIsVirtualAdapter(const IP_ADAPTER_ADDRESSES* a)
{
    switch (a->IfType)
    {
        case 6:     // Ethernet
        case 71:    // Wi-Fi
        case 117:   // Gigabit Ethernet
        case 243:   // WWAN
        case 244:   // WWAN
            break;
        default:
            return true;
    }

    if (a->PhysicalAddressLength >= 3)
    {
        const unsigned char* m = a->PhysicalAddress;
        static const unsigned char oui[][3] =
        {
            {0x00,0x05,0x69}, {0x00,0x0C,0x29}, {0x00,0x1C,0x14}, {0x00,0x50,0x56},   // VMware
            {0x08,0x00,0x27}, {0x0A,0x00,0x27},                                       // VirtualBox
            {0x00,0x15,0x5D},                                                         // Hyper-V
            {0x00,0x1C,0x42},                                                         // Parallels
            {0x00,0x16,0x3E},                                                         // Xen
            {0x52,0x54,0x00}                                                          // QEMU/KVM
        };
        for (size_t i = 0; i < sizeof(oui) / sizeof(oui[0]); ++i)
            if (m[0] == oui[i][0] && m[1] == oui[i][1] && m[2] == oui[i][2])
                return true;
    }

    std::wstring text;
    if (a->Description)  text += a->Description;
    text += L" | ";
    if (a->FriendlyName) text += a->FriendlyName;

    static const wchar_t* kw[] =
    {
        L"vmware", L"virtualbox", L"vbox", L"hyper-v", L"vethernet", L"virtual", L"wsl",
        L"docker", L"tap-windows", L"tap-", L"wintun", L"wireguard", L"openvpn", L"tailscale",
        L"zerotier", L"vpn", L"tunnel", L"loopback", L"npcap", L"parallels", L"qemu", L"xen ",
        L"bluetooth", L"host-only", L"anyconnect", L"globalprotect", L"fortinet", L"teredo",
        L"isatap", L"6to4"
    };
    for (size_t i = 0; i < sizeof(kw) / sizeof(kw[0]); ++i)
        if (NvrContainsNoCase(text, kw[i]))
            return true;

    return false;
}

// includeDown=false: tylko karty w stanie Up z adresem IPv4 (uzywane przez usluge)
// includeDown=true : wszystkie karty z IPv4 (lista w oknie konfiguracji)
// Loopback jest zawsze pomijany.
inline std::vector<NvrAdapter> NvrEnumAdapters(bool includeDown)
{
    std::vector<NvrAdapter> result;

    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;

    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt)
    {
        buf.resize(size);
        rc = GetAdaptersAddresses(
            AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
            &size);
    }

    if (rc != NO_ERROR)
        return result;

    for (IP_ADAPTER_ADDRESSES* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
         a; a = a->Next)
    {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK || a->IfIndex == 0)
            continue;

        const bool up = (a->OperStatus == IfOperStatusUp);
        if (!up && !includeDown)
            continue;

        NvrAdapter ad;
        ad.guid = a->AdapterName ? a->AdapterName : "";
        ad.name = a->FriendlyName ? a->FriendlyName : L"";
        ad.desc = a->Description ? a->Description : L"";
        ad.ifIdx = a->IfIndex;
        ad.up = up;
        ad.isVirtual = NvrIsVirtualAdapter(a);

        for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u; u = u->Next)
        {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET)
                continue;

            const sockaddr_in* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            const unsigned char* b = reinterpret_cast<const unsigned char*>(&sin->sin_addr);

            NvrAdapterAddr aa;
            aa.ip = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
                    (static_cast<uint32_t>(b[2]) << 8)  |  static_cast<uint32_t>(b[3]);

            unsigned prefix = u->OnLinkPrefixLength;
            if (prefix > 32) prefix = 32;
            aa.mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));

            if (aa.ip != 0)
                ad.addrs.push_back(aa);
        }

        if (!up || !ad.addrs.empty() || includeDown)
            result.push_back(ad);
    }

    return result;
}
