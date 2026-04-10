@echo off
title Voting System C Backend Setup
color 0A
echo.
echo  ============================================
echo   Online Voting System - C Backend
echo   Developed by: Anas Farooq
echo   BS Computer Science - Ziauddin University
echo  ============================================
echo.

:: Kill any running instance first so we can overwrite the exe
echo [*] Stopping any running server instance...
taskkill /F /IM server.exe >nul 2>&1
timeout /t 1 /nobreak >nul

:: Check for GCC
where gcc >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [!] GCC not found in PATH.
    echo     Please install MinGW-w64 and add it to your system PATH.
    echo     Download from: https://www.mingw-w64.org/
    echo.
    pause
    exit /b 1
)

echo [*] GCC found. Compiling backend...
echo.

gcc -std=c99 -O2 ^
    -o server.exe ^
    c_src/server.c ^
    c_src/api_handlers.c ^
    c_src/db_wrapper.c ^
    c_src/session.c ^
    c_src/sha256.c ^
    c_src/sqlite3.c ^
    c_src/mongoose.c ^
    -lws2_32 ^
    -Wno-unused-result ^
    -Wno-unused-function ^
    -Wno-unused-but-set-variable ^
    2>compile_errors.txt

if %errorlevel% neq 0 (
    echo [!] Compilation FAILED. See compile_errors.txt for details.
    echo.
    type compile_errors.txt
    echo.
    pause
    exit /b 1
)

del compile_errors.txt >nul 2>&1
echo [*] Compilation successful!
echo.
echo  ============================================
echo   Starting Voting System...
echo.
echo   URL:      http://127.0.0.1:5000
echo   Admin:    admin@votingsystem.com
echo   Password: Admin@123
echo.
echo   Press Ctrl+C to stop the server
echo  ============================================
echo.

server.exe

pause
