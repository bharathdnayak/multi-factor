@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Behavioral Drift Security - Pre-Flight Diagnostic Doctor

echo =====================================================================
echo    MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY - SYSTEM DOCTOR 
echo         Pre-Flight Environment, Hardware and Sensor Diagnostics      
echo       Department of Information Science and Engineering, NMAMIT     
echo =====================================================================
echo.

:: 1. Compute absolute project root directory (parent of bat folder)
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
cd /d "%PROJECT_DIR%"

:: Parse --no-pause cleanly alongside NO_PAUSE=1
set "NO_PAUSE_FLAG="
if "%NO_PAUSE%"=="1" set "NO_PAUSE_FLAG=1"
set "PY_ARGS="
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

:: 2. Locate Python executable (prefer .venv first, then venv, then PATH)
set "PYTHON_EXE="
if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "%PROJECT_DIR%\venv\Scripts\python.exe" set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where py 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE (
    echo [FAIL] Python was not found in PATH or in a virtual environment!
    echo Please ensure Python 3.10+ is installed and run setup.bat.
    if not defined NO_PAUSE_FLAG pause
    exit /b 1
)

echo [INFO] Project Directory : "%PROJECT_DIR%"
echo [INFO] Python Executable : "%PYTHON_EXE%"
echo.

:: 3. Run Pre-Flight Diagnostics
"%PYTHON_EXE%" "%PROJECT_DIR%\scripts\check_prerequisites.py" %PY_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% equ 0 (
    echo [DOCTOR VERDICT] ALL CHECKS PASSED: System is operational.
) else (
    echo [DOCTOR VERDICT] ONE OR MORE CHECKS RETURNED WARNINGS OR FAILURES.
)
echo.
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%
