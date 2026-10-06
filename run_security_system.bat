@echo off
chcp 65001 >nul
setlocal
title Multi-Factor Behavioral Drift Security System

echo =====================================================================
echo     STARTING MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY       
echo =====================================================================
echo.

:: 1. Compute absolute project root directory safely
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"
echo [INFO] Project directory: "%PROJECT_DIR%"

:: 2. Find Python executable
set "PYTHON_EXE="
if exist "%PROJECT_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
    echo [INFO] Using virtual environment: venv
)
if not defined PYTHON_EXE if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
    echo [INFO] Using virtual environment: .venv
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where py 2^>nul') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not found in PATH or in a virtual environment!
    echo Please install Python and ensure it is added to your PATH.
    pause
    exit /b 1
)

echo [INFO] Using Python: "%PYTHON_EXE%"
echo.

:: 3. Launch Unified Process Supervisor
echo [INFO] Spawning Unified Security Supervisor and System Tray Icon...
"%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" %*

echo.
echo =====================================================================
echo       SECURITY SUPERVISOR SHUTDOWN COMPLETE                         
echo =====================================================================
echo.
pause
