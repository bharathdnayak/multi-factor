@echo off
chcp 65001 >nul
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
call "%PROJECT_DIR%\bat\run_viva_demo.bat" %*
