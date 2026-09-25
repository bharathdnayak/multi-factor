@echo off
setlocal
title Unauthorized Intrusion Attack Simulator

echo =============================================================
echo      UNAUTHORIZED INTRUSION ATTACK & LOCKOUT SIMULATOR       
echo =============================================================
echo.
echo [INFO] Injects unauthorized imposter telemetry windows into the
echo        Quad-Factor Continuous Authentication security engine.
echo [INFO] Triggers acute anomaly spike, webcam capture, OTP dispatch,
echo        and the PyQt6 verification lock screen.
echo.

set "PROJECT_DIR=%~dp0.."
pushd "%PROJECT_DIR%"

:: Find Python executable
set "PYTHON_EXE="
if exist "venv\Scripts\python.exe" set "PYTHON_EXE=%CD%\venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=%CD%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE (
    echo [ERROR] Python not found in path or virtual environment!
    pause
    popd
    exit /b 1
)

"%PYTHON_EXE%" "%CD%\scripts\simulate_unauthorized_attack.py" %*

popd
pause
