@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Multi-Factor Behavioral Drift Security System

echo =====================================================================
echo     STARTING MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY       
echo =====================================================================
echo.

:: 1. Compute absolute project root directory (parent of bat folder)
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
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
    if "%NO_PAUSE%"=="" if "%~1" neq "--no-pause" pause
    exit /b 1
)

echo [INFO] Using Python: "%PYTHON_EXE%"
echo.

:: Parse arguments to isolate --no-pause and pass other parameters to Python
set "PY_ARGS="
set "NO_PAUSE_FLAG="
if "%NO_PAUSE%"=="1" set "NO_PAUSE_FLAG=1"

:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="--no-pause" (
    set "NO_PAUSE_FLAG=1"
) else (
    set PY_ARGS=!PY_ARGS! "%~1"
)
shift
goto parse_args
:end_parse

:: 3. Launch Unified Process Supervisor
echo [INFO] Spawning Unified Security Supervisor and System Tray Icon...
"%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" %PY_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

echo.
echo =====================================================================
echo       SECURITY SUPERVISOR SHUTDOWN COMPLETE                         
echo =====================================================================
echo.
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%
