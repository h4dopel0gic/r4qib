@echo off
title R4qib Server — The Watcher
color 0B

echo.
echo  ================================================
echo   R4qib — Autonomous Smart Contract Investigation
echo   The Watcher is initialising...
echo  ================================================
echo.

cd /d "%~dp0"

:: Check Node.js is available
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Node.js not found. Please install Node.js first.
    echo  https://nodejs.org
    pause
    exit /b 1
)

:: Check ws package is installed
if not exist node_modules\ws (
    echo  [INFO] Installing dependencies...
    npm install ws
    echo.
)

echo  [OK] Starting R4qib server on ws://localhost:3001
echo  [OK] Open assets\r4qib-dashboard.html in your browser
echo  [OK] Press Ctrl+C to stop the server
echo.
echo  ================================================
echo.

node core/r4qib-server.js

echo.
echo  [INFO] Server stopped.
pause
