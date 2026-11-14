@echo off
chcp 65001 >nul
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
call "%BAT_DIR%\run_security_system.bat" %*
exit /b %ERRORLEVEL%
