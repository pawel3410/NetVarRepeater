# NetVarRepeater

Program dla Windows 10/11 (x64), który **kopiuje odebrane datagramy UDP** z wybranego portu odbiorczego i **wysyła ich zawartość** pod inny adres IP i port (także broadcast). Działa jako usługa startująca z systemem; ikona w zasobniku (systray) służy do podglądu statystyk i sterowania.

## Spis plików

| Plik | Rola |
|---|---|
| `service.cpp` | Usługa Windows: przechwytywanie (WinDivert), przekazywanie, liczniki, serwer named pipe |
| `tray.cpp` | Ikona w zasobniku: okno statystyk przy najechaniu, menu, edytor konfiguracji |
| `common.h` | Protokół usługa ↔ tray (struktury, polecenia), ścieżka konfiguracji |
| `config.h` | Parser pliku konfiguracji (wspólny dla usługi i tray) |
| `NetVarRepeater.cbp` | Projekt Code::Blocks (targety `Service`, `Tray`, `ServiceDebug`) |
| `install.bat` / `uninstall.bat` | Instalacja / usunięcie usługi i autostartu ikony |

## Funkcje

- Przekazywanie UDP: `ip_nadawcy + port odbiorczy → ip docelowy + port docelowy`, dowolna liczba reguł (limit 256).
- Jeden pakiet może pasować do wielu reguł (np. port 1202 → dwa różne cele) – każda reguła ma własne liczniki.
- `ip_nadawcy = 0.0.0.0` oznacza **dowolnego nadawcę** (także pakiet broadcast i pakiet z adresem źródłowym 0.0.0.0).
- Adres docelowy może być broadcastem ograniczonym (`255.255.255.255`) lub kierowanym (np. `192.168.1.255`).
- **Port nasłuchu nie jest blokowany**: WinDivert pracuje w trybie `SNIFF` (kopia pakietu), a program nigdy nie wykonuje `bind()` na porcie odbiorczym. Oryginalny pakiet trafia normalnie do innych programów.
- Usługa startuje automatycznie z systemem (`start= auto`, konto SYSTEM) i od razu zaczyna przekazywać pakiety; restartuje się po awarii.
- **Najechanie na ikonę**: okno z informacją o stanie, czasie rozpoczęcia, czasie działania oraz – dla każdej reguły – liczbą pakietów odebranych, przekazanych i błędów wysyłania (plus wybrany interfejs wyjściowy).
- **Prawy przycisk** – menu:
  - lista reguł z pliku konfiguracji (kliknięcie otwiera edytor), `Edytuj konfigurację...`,
  - **Start** – wczytuje konfigurację ponownie i (re)startuje przekazywanie (liczniki niezmienionych reguł są zachowane),
  - **Stop** – zatrzymuje przekazywanie (usługa działa dalej),
  - **Reset** – wczytuje konfigurację, zeruje liczniki i czas startu (stan Start/Stop pozostaje bez zmian),
  - `Zamknij ikonę`.
- Kolor ikony: szary – usługa niedostępna, pomarańczowy – zatrzymany, zielony – aktywny, czerwony – aktywny, ale wystąpiły błędy wysyłania.
- Podwójne kliknięcie ikony otwiera edytor konfiguracji.

## Konfiguracja

Plik: `C:\ProgramData\NetVarRepeater\config.txt` (tworzony z komentowanym przykładem przy pierwszym starcie).

```
# ip_nadawcy  port_odbiorczy  ip_docelowy  port_docelowy
0.0.0.0    1202  192.168.1.10     1203
10.0.0.1   1203  192.170.10.3     1203
0.0.0.0    1202  192.170.10.4     1202
10.0.0.1   1203  255.255.255.255  1203
```

- Separatory: spacje, tabulatory lub przecinki. Komentarze: `#` lub `;`.
- Błędne linie (zły adres, port spoza 1–65535, nie 4 pola, duplikat) są pomijane; ich liczba i pierwszy komunikat są widoczne w oknie statystyk i po Start/Reset.
- Edycja: menu ikony → `Edytuj konfigurację...` (przyciski *Zapisz* i *Zapisz i zastosuj*) albo dowolny edytor. Zmiany działają po **Start** lub **Reset**.

## Identyfikacja interfejsów sieciowych

W konfiguracji nie podaje się interfejsów, więc program wyznacza je sam, osobno dla strony odbiorczej i wyjściowej.

**Odbiór (skąd przyszedł pakiet).**
- WinDivert (warstwa `NETWORK`, `SNIFF`) obejmuje wszystkie interfejsy naraz. Filtr: `inbound and loopback == 0 and ip and udp and (udp.DstPort == P1 or ...)` – porty pochodzą z reguł.
- Do każdego pakietu WinDivert dołącza strukturę adresu z **indeksem interfejsu odbiorczego (`IfIdx`)**. Program zapisuje go dla pakietu i używa przy broadcastach (patrz niżej).
- Pakiety są widziane na warstwie sieciowej, zanim zdecyduje o nich firewall – port nie musi być otwarty ani nasłuchiwany przez żaden program.
- Nadawca (`ip.SrcAddr`) i port są dopasowywane do reguł w kodzie, nie w filtrze (filtr WinDivert ma ograniczoną długość).
- `loopback == 0` + filtr tylko na ruch przychodzący zapobiega pętli: pakiety wysłane przez sam program nie są ponownie przechwytywane.

**Wyjście (którędy wysłać).** Przy starcie, a potem co 30 s i po błędzie wysyłki program wylicza interfejsy (`GetAdaptersAddresses`: tylko IPv4, stan *Up*, bez loopbacku, z długością prefiksu) i dla każdej reguły wybiera tryb:

| Adres docelowy | Wybór |
|---|---|
| `255.255.255.255` | po jednym gnieździe na każdy aktywny interfejs, **z pominięciem interfejsu, na którym pakiet odebrano** (przekazanie „na inny interfejs”, brak odbicia na tę samą sieć) |
| broadcast kierowany, np. `192.168.1.255` | interfejs, którego podsieć ma ten adres rozgłoszeniowy |
| zwykły unicast | interfejs wskazany przez tablicę routingu (`GetBestInterfaceEx`) |
| brak dopasowania (np. adres lokalny) | wybiera system |

Gniazdo wyjściowe jest **przypięte do interfejsu** dwoma mechanizmami naraz: `bind()` na adres IP interfejsu (poprawny adres źródłowy) oraz `IP_UNICAST_IF` (wymuszenie interfejsu także dla broadcastu, gdzie sama trasa byłaby niejednoznaczna). Włączone jest `SO_BROADCAST`. Wybrany tryb i indeks interfejsu widać w oknie statystyk.

Przekazywana jest **zawartość datagramu (payload)** w nowym pakiecie UDP – adres i port źródłowy są inne niż w oryginale (źródło = adres interfejsu wyjściowego, port efemeryczny).

## Kompilacja (Code::Blocks + MinGW-w64, 64 bity)

1. Otwórz `NetVarRepeater.cbp`, kompilator **GNU GCC (MinGW-w64, x86_64)**, najlepiej GCC ≥ 8 (wątki *posix* lub *win32* – oba działają).
2. Zbuduj targety **Service** i **Tray** (Release). Wyniki: `bin/NetVarRepeaterService.exe`, `bin/NetVarRepeaterTray.exe`.

Opcje (są już w projekcie):

| | Service | Tray |
|---|---|---|
| Kompilator | `-std=c++17 -O2 -Wall -Wextra -m64 -D_WIN32_WINNT=0x0601` | to samo + `-DUNICODE -D_UNICODE` |
| Linker | `-static -static-libgcc -static-libstdc++ -s` | to samo + `-mwindows -municode` |
| Biblioteki | `ws2_32 iphlpapi advapi32` | `shell32 user32 gdi32 advapi32` |

WinDivert jest ładowany dynamicznie (`LoadLibrary`), więc nie trzeba go linkować ani mieć nagłówków.

## Instalacja

1. Pobierz **WinDivert 2.2.x** (x64) z https://reactos.org/windivert.html i skopiuj `WinDivert.dll` oraz `WinDivert64.sys` do jednego katalogu z oboma plikami `.exe` i skryptami `.bat`. Pliki muszą pochodzić z tej samej wersji.
2. Uruchom `install.bat` **jako administrator**. Skrypt tworzy usługę (auto-start, SYSTEM), katalog `C:\ProgramData\NetVarRepeater` (z prawem zapisu dla użytkowników – żeby edytor w trayu mógł zapisać konfigurację), wpis autostartu ikony (`HKLM\...\Run`) i uruchamia usługę.
3. Nie przenoś katalogu po instalacji (usługa wskazuje na ścieżkę exe) – w razie potrzeby uruchom ponownie `install.bat`.
4. Usunięcie: `uninstall.bat` (konfiguracja zostaje w ProgramData).

Uwaga: sterownik WinDivert wymaga uprawnień administratora; niektóre programy antywirusowe oznaczają `WinDivert64.sys` jako podejrzany – może być potrzebny wyjątek.

## Architektura

```
tray.exe  --(named pipe \\.\pipe\NetVarRepeater, tryb komunikatów)-->  service.exe
                                                                          |
                                      WinDivert SNIFF (kopia pakietów) <--+--> sockety UDP (bind + IP_UNICAST_IF)
```

- Pipe: polecenia `STATUS / START / STOP / RESET`, odpowiedź = nagłówek + liczniki każdej reguły. Dostęp: zalogowani użytkownicy (odczyt/zapis), administratorzy i SYSTEM (pełny), klienci zdalni odrzucani.
- Liczniki są atomowe; Start/Stop/Reset są serializowane i zatrzymują wątek odbiorczy przez `WinDivertShutdown(RECV)`.

## Ograniczenia

- Tylko IPv4. Sfragmentowane datagramy IP nie są składane (są pomijane i liczone jako „bez reguły”).
- Przy zwykłym unicaście, gdy nikt nie nasłuchuje na porcie, system może odesłać ICMP „port unreachable” – dotyczy oryginalnego pakietu, nie kopii.
- Pierwsze pakiety tuż po starcie systemu mogą zostać odrzucone (błąd wysyłki), jeśli sieć nie ma jeszcze adresu IP; interfejsy odświeżają się po błędzie w ciągu 2 s.
- Przekazywanie na ten sam segment sieci, z którego pakiet przyszedł, przez unicast/broadcast kierowany jest możliwe – uważaj na pętle (np. dwie maszyny z tymi samymi regułami w jednej sieci).
- Każdy zalogowany użytkownik może przez tray zmienić konfigurację i sterować przekazywaniem (usługa działa jako SYSTEM i wysyła UDP według tej konfiguracji). W środowisku wieloużytkownikowym zawęź uprawnienia katalogu `ProgramData\NetVarRepeater` i SDDL pipe'a w `service.cpp`.

## Pytania otwarte / założenia

1. `0.0.0.0` w kolumnie nadawcy potraktowano jako „dowolny nadawca”. Jeśli ma znaczyć wyłącznie broadcast, trzeba dodać warunek na adres docelowy pakietu (`255.255.255.255` / adres rozgłoszeniowy podsieci).
2. W konfiguracji nie ma kolumny z interfejsem. Jeśli potrzebny jest ręczny wybór (np. wymuszony interfejs wyjściowy dla konkretnej reguły), można dodać opcjonalne piąte pole z adresem IP interfejsu.
