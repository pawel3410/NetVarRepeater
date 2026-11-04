@echo off
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    echo Uruchom install.bat jako Administrator.
    pause
    exit /b 1
)

for %%F in (NetVarRepeaterService.exe NetVarRepeaterTray.exe WinDivert.dll WinDivert64.sys) do (
    if not exist "%~dp0%%F" (
        echo Brak pliku %%F w katalogu %~dp0
        pause
        exit /b 1
    )
)

sc.exe stop NetVarRepeater >nul 2>&1
timeout /t 2 /nobreak >nul
sc.exe delete NetVarRepeater >nul 2>&1
timeout /t 1 /nobreak >nul

rem --- katalog konfiguracji; uzytkownicy moga edytowac config.txt z ikony w trayu ---
if not exist "%ProgramData%\NetVarRepeater" mkdir "%ProgramData%\NetVarRepeater"
icacls "%ProgramData%\NetVarRepeater" /grant *S-1-5-32-545:(OI)(CI)M /T >nul

sc.exe create NetVarRepeater binPath= "\"%~dp0NetVarRepeaterService.exe\"" start= auto obj= LocalSystem DisplayName= "NetVarRepeater UDP Relay"
if errorlevel 1 (
    echo Nie udalo sie utworzyc uslugi.
    pause
    exit /b 1
)

sc.exe description NetVarRepeater "Przekazuje kopie pakietow UDP wedlug konfiguracji (WinDivert)."
sc.exe failure NetVarRepeater reset= 86400 actions= restart/5000/restart/5000/restart/30000

rem --- ikona w zasobniku dla kazdego uzytkownika (HKLM\Run) ---
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v NetVarRepeaterTray /t REG_SZ /d "\"%~dp0NetVarRepeaterTray.exe\"" /f

sc.exe start NetVarRepeater

echo.
echo Gotowe. Konfiguracja: %ProgramData%\NetVarRepeater\config.txt
echo Ikona w zasobniku uruchomi sie przy nastepnym logowaniu (lub uruchom NetVarRepeaterTray.exe teraz).
echo Jesli usluga nie startuje: Podglad zdarzen / services.msc.
pause
