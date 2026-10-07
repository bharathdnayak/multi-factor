@echo off
chcp 65001 >nul
setlocal
title Live Viva Demonstration Runner - Major Project 30

echo =====================================================================
echo       LIVE VIVA DEMONSTRATION RUNNER - MAJOR PROJECT TEAM 30         
echo   Multi-Factor Behavioral Drift Continuous Authentication and Deception
echo         Department of Information Science and Engineering, NMAMIT      
echo =====================================================================
echo.
echo [PURPOSE]
echo - Coordinates an end-to-end 5-stage demonstration for project viva,
echo   guide reviews, and academic evaluations.
echo - Stage 1: Legitimate user baseline operations (Continuous Quad-Factor)
echo - Stage 2: Physical walk-away and imposter takeover (BLE and ADWIN drift)
echo - Stage 3: Behavioral drift threshold crossed and autonomous defense
echo - Stage 4: Attacker diverted into sandboxed Deception Honeypot
echo - Stage 5: Legitimate user recovery and automated AI Forensic PDF report
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
echo [INFO] Viva Script       : "%PROJECT_DIR%\demo_viva_runner.py"
echo.

:: 3. Run interactive viva demo runner with any passed parameters
"%PYTHON_EXE%" "%PROJECT_DIR%\demo_viva_runner.py" %*

echo.
echo =====================================================================
echo       VIVA DEMONSTRATION EXECUTION SESSION CONCLUDED                 
echo =====================================================================
echo Check data\forensics\ for newly compiled Forensic PDF reports and photos.
echo.
pause
