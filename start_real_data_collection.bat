@echo off
chcp 65001 >nul
setlocal
title Continuous Behavioral Data Collector - Multi-Application

echo =====================================================================
echo       REAL BEHAVIORAL DATA COLLECTOR (MULTI-APPLICATION)
echo =====================================================================
echo.
echo  [ACTIVE MONITORING]
echo  - Tracks Google Chrome, Microsoft Edge, Brave, Firefox, Opera
echo  - Tracks VS Code, Terminals, Office Docs, Coding & Problem Solving
echo  - Automatically classifies tabs: LeetCode, YouTube, Docs, Chat, IDE
echo  - Captures: Thinking pauses, typing bursts, syntax symbols, scrolls
echo.
echo  [NO INTERRUPTION]
echo  - Zero input lag, zero focus stealing, zero screen popups.
echo  - MINIMIZE this window and carry on with your normal daily work!
echo  - To stop collecting, simply press Ctrl+C or close this window.
echo =====================================================================
echo.

:: 1. Compute project root directory
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"

:: 2. Locate Python executable
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
    echo [ERROR] Python was not found in PATH or in a venv!
    echo Please ensure Python is installed and added to PATH.
    pause
    exit /b 1
)

echo [INFO] Using Python: "%PYTHON_EXE%"
echo [INFO] Data Storage: "%PROJECT_DIR%\data\sessions"
echo [INFO] Starting Live Telemetry and Micro-Session Profiling...
echo.

"%PYTHON_EXE%" "%PROJECT_DIR%\telemetry\agent.py" --friendly

echo.
echo [INFO] Collector stopped. All micro-sessions have been safely saved.
pause
