@echo off
chcp 65001 >nul
setlocal
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
    pause
    exit /b 1
)

echo [INFO] Project Directory : "%PROJECT_DIR%"
echo [INFO] Python Executable : "%PYTHON_EXE%"
echo [INFO] Attack Script     : "%PROJECT_DIR%\scripts\simulate_unauthorized_attack.py"
echo.

:: 3. Run attack simulator with any passed parameters
"%PYTHON_EXE%" "%PROJECT_DIR%\scripts\simulate_unauthorized_attack.py" %*

echo.
echo =====================================================================
echo       UNAUTHORIZED ATTACK SIMULATION COMPLETED!                      
echo =====================================================================
echo Check data\forensics\ for newly captured intruder photos and reports.
echo.
pause
