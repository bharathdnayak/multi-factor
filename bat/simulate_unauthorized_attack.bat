@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Unauthorized Intrusion Attack Simulator - Behavioral Drift

echo =====================================================================
echo      UNAUTHORIZED INTRUSION ATTACK AND LOCKOUT SIMULATOR            
echo      Multi-Factor Behavioral Drift Continuous Security               
echo =====================================================================
echo.
echo [PURPOSE]
echo - Injects unauthorized imposter telemetry windows into the system.
echo - Tests acute anomaly spikes, rapid behavioral drift detection,
echo   silent webcam snapshot capture, OTP dispatch, and the Deception Lockout.
echo.

:: 1. Compute absolute project root directory (parent of bat folder)
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
cd /d "%PROJECT_DIR%"

:: 2. Find Python executable
set "PYTHON_EXE="
if exist "%PROJECT_DIR%\venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where py 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not found in PATH or in a virtual environment!
    echo Please ensure Python is installed and added to PATH.
    if "%NO_PAUSE%"=="" if "%~1" neq "--no-pause" pause
    exit /b 1
)

echo [INFO] Project Directory : "%PROJECT_DIR%"
echo [INFO] Python Executable : "%PYTHON_EXE%"
echo [INFO] Attack Script     : "%PROJECT_DIR%\scripts\simulate_unauthorized_attack.py"
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

:: 3. Run attack simulator with forwarded parameters
"%PYTHON_EXE%" "%PROJECT_DIR%\scripts\simulate_unauthorized_attack.py" %PY_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% equ 0 (
    echo =====================================================================
    echo       UNAUTHORIZED ATTACK SIMULATION COMPLETED!                      
    echo =====================================================================
    echo Check data\forensics\ for newly captured intruder photos and reports.
) else (
    echo [ERROR] Attack simulation finished with exit code %EXIT_CODE%.
)
echo.
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%
