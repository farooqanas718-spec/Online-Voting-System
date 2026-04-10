@echo off
title Update Admin Account
color 0E
echo.
echo  ============================================
echo   Update Admin Account
echo  ============================================
echo.

if not exist server.exe (
    echo [!] server.exe not found. Run install_and_run.bat first.
    pause
    exit /b 1
)

set /p CNIC="Enter Admin CNIC (13 digits, no dashes): "
set /p EMAIL="Enter Admin Email: "
set /p PASS="Enter Admin Password (min 8 chars): "

echo.
echo [*] Updating admin account...
server.exe --cmd update-admin %CNIC% %EMAIL% %PASS%
echo.
echo [*] Done. Login with: %EMAIL%
echo.
pause
