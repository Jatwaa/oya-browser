@echo off
setlocal
cd /d "%~dp0"
echo =================================================================
echo Launching Oya Browser Distribution Generator...
echo =================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0generate_distrib.ps1" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo Distribution build failed with error code %ERRORLEVEL%.
    pause
    exit /b %ERRORLEVEL%
)
endlocal
