@echo off
title Reset Database
color 0C
echo.
echo  ============================================
echo   Reset Entire Database
echo  ============================================
echo.
echo  WARNING: This will DELETE everything including the admin account!
echo.
set /p CONFIRM="Type RESET to confirm complete database wipe: "
if "%CONFIRM%"=="RESET" (
    server.exe --cmd reset-db
    echo [*] Database reset. Run install_and_run.bat to recreate admin.
) else (
    echo [*] Cancelled.
)
echo.
pause
