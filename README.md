# NetVar repeater

Program dla Windows 10/11 (x64), który **kopiuje odebrane datagramy UDP** z wybranego portu odbiorczego i **wysyła ich zawartość** pod inny adres IP i port (także broadcast). Działa jako usługa startująca z systemem; ikona w zasobniku (systray) służy do podglądu statystyk i sterowania.

## Pliki projektu (wszystkie w jednym katalogu)

| Plik | Rola |
|---|---|
| `service.cpp` | Usługa Windows: przechwytywanie (WinDivert), przekazywanie, liczniki, log, nadzór, serwer named pipe; tryb konsolowy `--console` |
| `tray.cpp` | Ikona w zasobniku: okienko przy najechaniu, okno statusu, menu, edytor konfiguracji |
| `common.h` | Protokół usługa ↔ tray, ścieżki plików |
| `config.h` | Parser `config.txt` (reguły i ustawienia) |
| `NetVarRepeater.cbp` | Projekt Code::Blocks (targety `Service`, `Tray`) – wyniki i pliki `.o` trafiają do tego samego katalogu |
| `install.bat` / `uninstall.bat` | Instalacja / usunięcie usługi i autostartu ikony |
| `README.md` | Ta dokumentacja |

Po kompilacji w tym samym katalogu powstają `NetVarRepeaterService.exe` i `NetVarRepeaterTray.exe`; dokładasz do niego `WinDivert.dll` i `WinDivert64.sys`.

## Funkcje

- Reguły UDP: `ip_nadawcy + port odbiorczy → ip docelowy + port docelowy`, do 256 reguł; jeden pakiet może pasować do wielu reguł (każda ma własne liczniki).
- `ip_nadawcy = 0.0.0.0` = **dowolny nadawca** (także broadcast). Cel może być broadcastem ograniczonym (`255.255.255.255`) lub kierowanym (np. `192.168.1.255`).
- **Port nie jest blokowany**: WinDivert w trybie `SNIFF` (kopia pakietu), brak `bind()` na porcie odbiorczym.
- Automatyczny start z systemem; **ponawianie startu po błędzie** (WinDivert niezaładowany, brak reguł, brak sieci...) z narastającym odstępem 5 → 10 → 20 → 30 → 60 s. Nie dotyczy stanu „zatrzymany przez użytkownika”. Usługa restartuje się też po awarii procesu (ustawienia SCM).
- **Pomijanie kart wirtualnych** (domyślnie włączone, `exclude_virtual = yes`): VMware, VirtualBox, Hyper-V/vEthernet, WSL, Docker, VPN/TAP/WireGuard/Tailscale/ZeroTier, Bluetooth PAN, tunele (Teredo, ISATAP, 6to4) i każda karta o typie innym niż Ethernet/Wi-Fi/WWAN. Rozpoznanie: typ interfejsu, prefiks MAC (VMware, VirtualBox, Hyper-V, Parallels, Xen, QEMU) oraz nazwa/opis. Pominięte karty nie są używane do wysyłania ani odbioru.
- **Log** `C:\ProgramData\NetVarRepeater\netvarrepeater.log` z rotacją: po przekroczeniu `log_max_kb` plik jest przenoszony do `.log.1` (nadpisując poprzedni), więc zajęcie dysku to najwyżej ok. 2 × `log_max_kb`. Zapisywane są: start/stop, konfiguracja i odrzucone linie, lista kart i wybrane wyjścia, błędy WinDivert i wysyłki (ograniczone do 1 wpisu/min na regułę), ostrzeżenia o limicie pakietów.
- **Ochrona przed pętlą**: (1) odrzucanie pakietów, których nadawcą jest własny adres, (2) filtr `loopback == 0` i tylko ruch przychodzący, (3) brak odsyłania broadcastu na kartę odbiorczą, (4) pominięcie broadcastu kierowanego na tę samą sieć i ten sam port (ping-pong z drugim repeaterem), (5) limit `max_pps` pakietów/s na regułę (domyślnie 2000, `0` = bez limitu).
- **Tryb konsolowy**: `NetVarRepeaterService.exe --console` – ten sam kod w oknie konsoli, log na ekranie, Ctrl+C kończy. Wymaga administratora; odmawia startu, gdy zainstalowana usługa już działa. Target `Service` w Code::Blocks ma ten parametr ustawiony.

### Ikona, okienka i menu

- Ikona ma napis „NV” (na 16×16 pełna nazwa się nie mieści), pełne „NetVar repeater” jest w tooltipie i tytułach okien. Kolor: szary – usługa niedostępna, pomarańczowy – zatrzymany / nie działa, zielony – aktywny, czerwony – aktywny z błędami wysyłania.
- **Najechanie**: zwarte okienko – stan, start, czas pracy, błędy, liczniki ogólne i po dwie linie na regułę (liczniki + karta odbiorcza → karty wysyłające z adresami IP).
- **Kliknięcie ikony**: okno statusu (tabela wszystkich reguł: odebrane, przekazane, błędy, pominięte, dane odebrane/wysłane, karta odbiorcza i wysyłająca z IP i indeksem) z przyciskami Start/Stop/Reset/Edytuj. Odświeża się co 2 s bez migotania.
- **Prawy przycisk**: status, lista reguł (kliknięcie otwiera edytor), `Edytuj konfigurację...`, **Start** (wczytuje konfigurację), **Stop**, **Reset** (wczytuje konfigurację i zeruje liczniki; stan Start/Stop bez zmian), `Zamknij ikonę`.
- Polecenia wykonują się w tle – okna się nie blokują, a status jest dostępny także podczas Start/Reset (usługa obsługuje pipe w 3 wątkach). Chwilowe braki odpowiedzi nie zmieniają ikony na szarą (dopiero 3 kolejne).
- **Edytor konfiguracji**: Ctrl+A, Ctrl+S, Esc, Ctrl+Tab (do przycisków), na bieżąco liczy reguły i błędy, pokazuje wiersz/kolumnę, przycisk *Następny błąd* skacze do błędnej linii, pyta o zapis przy zamykaniu. *Zapisz i zastosuj* zapisuje i wysyła Start.
- **Ikona nie ma trafiać do ukrytych**: Windows 11 domyślnie chowa nowe ikony. Tray ustawia w `HKCU\Control Panel\NotifyIconSettings\<id>` wartość `IsPromoted = 1` dla własnego pliku exe (kilka prób po starcie, bo wpis tworzy Explorer). To mechanizm nieudokumentowany przez Microsoft – na Windows 10 klucz nie istnieje i ikona jest widoczna, jeśli użytkownik jej sam nie ukryje. Jeśli ręcznie przeniesiesz ikonę do ukrytych, przy następnym starcie tray zostanie przypięta ponownie.

## Konfiguracja

Plik: `C:\ProgramData\NetVarRepeater\config.txt` (tworzony z komentowanym przykładem przy pierwszym starcie; zapisany w UTF-8).

```
# ustawienia
exclude_virtual = yes
max_pps = 2000
log_max_kb = 512

# reguły: ip_nadawcy port_odbiorczy ip_docelowy port_docelowy
0.0.0.0    1202  192.168.1.10     1203
10.0.0.1   1203  192.170.10.3     1203
0.0.0.0    1202  192.170.10.4     1202
10.0.0.1   1203  255.255.255.255  1203
```

- Separatory reguł: spacje, tabulatory lub przecinki. Komentarze: `#` lub `;`. Ustawienia: `klucz = wartość` (`exclude_virtual`: yes/no/tak/nie/true/false/1/0; `max_pps`: 0–1000000; `log_max_kb`: 16–102400).
- Błędne linie (zły adres/port, nie 4 pola, duplikat, nieznane ustawienie) są pomijane i widoczne w statusie, edytorze i logu. Brak poprawnych reguł = usługa nie przekazuje i ponawia próbę (można poprawić plik bez klikania Start).
- Zmiany działają po **Start** lub **Reset** (albo po automatycznym ponowieniu startu).

## Liczniki

Na regułę obowiązuje zależność **odebrane = przekazane + błędy + pominięte**:

- *odebrane* – pakiety dopasowane do reguły,
- *przekazane* – wysłane poprawnie na wszystkie wyjścia,
- *błędy* – wysyłka nie powiodła się choć na jednym wyjściu lub nie ma żadnego wyjścia (w nawiasie kod ostatniego błędu),
- *pominięte* – celowo nie wysłane (limit `max_pps`, ochrona przed pętlą),
- *dane odebrane/wysłane* – suma bajtów payloadu; wysłane liczone po każdym wyjściu, więc broadcast na dwie karty daje dwukrotność.

Liczniki ogólne: *przechwycone* (przez filtr WinDivert), *bez reguły* (uszkodzone, sfragmentowane, bez pasującej reguły), *pętla/wirtualne* (pakiety z własnego adresu i z kart wirtualnych).

## Identyfikacja interfejsów sieciowych

**Odbiór.** WinDivert (warstwa `NETWORK`, `SNIFF`) obejmuje wszystkie interfejsy; filtr: `inbound and loopback == 0 and ip and udp and (udp.DstPort == P1 or ...)`. Każdy pakiet ma indeks interfejsu odbiorczego (`IfIdx`), który program zapisuje w regule i dopasowuje do listy kart (nazwa, IP, flaga wirtualna). Pakiety są widziane przed zaporą, więc port nie musi być otwarty. Nadawca i port są dopasowywane w kodzie.

**Wyjście.** Lista kart (`GetAdaptersAddresses`: IPv4, stan *Up*, bez loopbacku, z prefiksem i flagą wirtualna) jest sprawdzana co 5 s i po błędzie wysyłki. **Gniazda są odtwarzane tylko wtedy, gdy lista kart faktycznie się zmieniła** (albo gdy dana reguła miała błąd wysyłki), więc port źródłowy nie zmienia się bez potrzeby. Tryb wyjścia na regułę:

| Adres docelowy | Wybór |
|---|---|
| `255.255.255.255` | po jednym gnieździe na każdą aktywną, niewykluczoną kartę, **bez karty odbiorczej** |
| broadcast kierowany, np. `192.168.1.255` | karta z tą podsiecią |
| unicast | karta z tablicy routingu (`GetBestInterfaceEx`) |
| inne (adres lokalny, karta wykluczona) | wybiera system |

Gniazdo jest przypięte do karty przez `bind()` na jej adres oraz `IP_UNICAST_IF` (działa też dla broadcastu); `SO_BROADCAST` włączone. Przekazywana jest zawartość datagramu w nowym pakiecie – adres źródłowy to adres karty wyjściowej, port efemeryczny.

## Kompilacja (Code::Blocks + MinGW-w64, 64 bity)

1. Otwórz `NetVarRepeater.cbp`, kompilator GNU GCC (MinGW-w64 x86_64, GCC ≥ 8).
2. Zbuduj **Service** i **Tray** (lub *Build → Select target → All*).

| | Service | Tray |
|---|---|---|
| Kompilator | `-std=c++17 -O2 -Wall -Wextra -Wno-cast-function-type -m64 -D_WIN32_WINNT=0x0601` | to samo + `-DUNICODE -D_UNICODE` |
| Linker | `-static -static-libgcc -static-libstdc++ -s` | to samo + `-mwindows -municode` |
| Biblioteki | `ws2_32 iphlpapi advapi32` | `shell32 user32 gdi32 comctl32 advapi32` |

WinDivert jest ładowany dynamicznie – nie trzeba go linkować.

## Instalacja

1. Pobierz **WinDivert 2.2.x (x64)** z https://reactos.org/windivert.html; `WinDivert.dll` i `WinDivert64.sys` skopiuj do katalogu projektu (obok exe i `.bat`).
2. `install.bat` **jako administrator**: tworzy usługę (auto-start, SYSTEM, restart po awarii), katalog `C:\ProgramData\NetVarRepeater` z prawem zapisu dla użytkowników, autostart ikony (`HKLM\...\Run`) i uruchamia usługę.
3. Nie przenoś katalogu po instalacji – w razie potrzeby uruchom `install.bat` ponownie. Usunięcie: `uninstall.bat`.
4. Test bez instalacji: `sc stop NetVarRepeater`, potem `NetVarRepeaterService.exe --console` w konsoli administratora.

Antywirusy mogą oznaczać `WinDivert64.sys` jako podejrzany – może być potrzebny wyjątek.

## Architektura

```
tray.exe --(named pipe \\.\pipe\NetVarRepeater, 3 wątki serwera)--> service.exe
                                                                       |
                       WinDivert SNIFF (kopia pakietów) <--------------+--> gniazda UDP (bind + IP_UNICAST_IF)
```

Pipe: polecenia `STATUS / START / STOP / RESET`; dostęp: zalogowani użytkownicy (odczyt/zapis), administratorzy i SYSTEM (pełny), klienci zdalni odrzucani. Wątek nadzorczy ponawia start po błędzie.

## Ograniczenia

- Tylko IPv4; sfragmentowane datagramy IP nie są składane.
- Pakiety nadane z tego samego komputera (loopback) nie są przekazywane.
- Każdy zalogowany użytkownik może przez tray zmienić konfigurację i sterować usługą (działa jako SYSTEM). W środowisku wieloużytkownikowym zawęź uprawnienia katalogu `ProgramData\NetVarRepeater` i SDDL pipe'a w `service.cpp`.
- Rozpoznawanie kart wirtualnych jest heurystyczne; nietypowa karta wirtualna bez rozpoznawalnej nazwy/MAC może zostać uznana za fizyczną (i odwrotnie). Wynik widać w logu i oknie statusu (`[wirt.]`).
- Pierwsze pakiety tuż po starcie systemu mogą zakończyć się błędem wysyłki, jeśli sieć nie ma jeszcze adresu IP.
