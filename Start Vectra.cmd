@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -File "%~dp0scripts\start.ps1" -Background
if errorlevel 1 (
    echo.
    echo Vectra could not start. The error is above; server logs are in logs.
    pause
    exit /b 1
)
start "" "http://127.0.0.1:8000/app"
