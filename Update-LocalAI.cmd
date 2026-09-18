@echo off
setlocal
cd /d "%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Update-LocalAI.ps1" %*
set ERR=%ERRORLEVEL%

if not "%ERR%"=="0" (
    echo.
    echo LocalAI update FAILED with exit code %ERR%.
    pause
    exit /b %ERR%
)

echo.
echo LocalAI update finished successfully.
pause
exit /b 0
