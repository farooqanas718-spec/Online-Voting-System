@echo off
title Clear Elections
color 0C
echo.
echo  ============================================
echo   Clear All Elections
echo  ============================================
echo.
set /p CONFIRM="This will DELETE all elections, votes, applications and candidates. Type YES to confirm: "
if /i "%CONFIRM%"=="YES" (
    server.exe --cmd clear-elections
    echo [*] All elections cleared.
) else (
    echo [*] Cancelled.
)
echo.
pause
