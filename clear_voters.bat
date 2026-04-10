@echo off
title Clear Voters
color 0C
echo.
echo  ============================================
echo   Clear All Voters
echo  ============================================
echo.
set /p CONFIRM="This will DELETE all voters, votes, applications and candidates. Type YES to confirm: "
if /i "%CONFIRM%"=="YES" (
    server.exe --cmd clear-voters
    echo [*] All voters cleared.
) else (
    echo [*] Cancelled.
)
echo.
pause
