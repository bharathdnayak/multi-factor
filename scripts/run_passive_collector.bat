@echo off
setlocal
title Passive Behavioral Data Collector

echo =============================================================
echo        PASSIVE BACKGROUND BEHAVIORAL DATA COLLECTOR         
echo =============================================================
echo.
echo [INFO] This script runs silently in the background.
echo [INFO] It captures your natural typing rhythm and cognitive pauses
echo        across LeetCode, VS Code, browsers, and terminal apps.
echo [INFO] ZERO lag, ZERO window focus stealing, ZERO interruption.
echo.

set "PROJECT_DIR=%~dp0.."
pushd "%PROJECT_DIR%"

:: Find Python
set "PYTHON_EXE="
if exist "venv\Scripts\python.exe" set "PYTHON_EXE=%CD%\venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=%CD%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE (
    echo [ERROR] Python not found!
    pause
    popd
    exit /b 1
)

echo [INFO] Using Python: "%PYTHON_EXE%"
echo [INFO] Starting Silent Telemetry Collector...
echo [INFO] You can minimize this window and continue your normal work!
echo [INFO] Press Ctrl+C in this window anytime to stop collecting.
echo.

"%PYTHON_EXE%" "%CD%\telemetry\agent.py" --silent

popd
pause
