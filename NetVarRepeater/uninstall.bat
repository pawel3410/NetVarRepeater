@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
    echo Uruchom uninstall.bat jako Administrator.
    pause
    exit /b 1
)

taskkill /f /im NetVarRepeaterTray.exe >nul 2>&1
sc.exe stop NetVarRepeater
timeout /t 2 /nobreak >nul
sc.exe delete NetVarRepeater

reg.exe delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v NetVarRepeaterTray /f >nul 2>&1

echo.
echo Usluga i autostart usuniete. Konfiguracja pozostala w %ProgramData%\NetVarRepeater
pause
