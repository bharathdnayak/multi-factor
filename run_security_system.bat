@echo off
setlocal EnableDelayedExpansion
title Multi-Factor Behavioral Drift Security System

echo =============================================================
echo     STARTING MULTI-FACTOR BEHAVIORAL DRIFT SECURITY SYSTEM    
echo =============================================================
echo.

:: 1. Compute absolute project root directory and strip trailing backslash safely
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"

:: Always switch current working directory to project root
cd /d "%PROJECT_DIR%"
echo [INFO] Project directory: "%PROJECT_DIR%"

:: 2. Find Python executable
set "PYTHON_EXE="

:: Check virtual environment in project directory
if exist "%PROJECT_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
    echo [INFO] Using virtual environment (venv)
) else if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
    echo [INFO] Using virtual environment (.venv)
) else (
    where python >nul 2>nul
    if !errorlevel! equ 0 (
        for /f "delims=" %%i in ('where python') do (
            if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
        )
    )
    if not defined PYTHON_EXE (
        where py >nul 2>nul
        if !errorlevel! equ 0 set "PYTHON_EXE=py"
    )
)

if not defined PYTHON_EXE (
    echo [ERROR] Python was not found in PATH or in a venv!
    echo Please install Python and ensure it is added to your PATH.
    pause
    exit /b 1
)

echo [INFO] Using Python: "!PYTHON_EXE!"
echo.

:: 3. Launch Telemetry Agent in a separate Command Prompt window
echo [INFO] Launching Background Telemetry Hook Agent...
start "Behavioral Telemetry Agent" /d "%PROJECT_DIR%" cmd /k "cd /d "%PROJECT_DIR%" && "!PYTHON_EXE!" telemetry\agent.py"

:: Wait 2 seconds for log initialization
ping 127.0.0.1 -n 3 >nul

:: 4. Launch Threat Evaluator Daemon in a separate Command Prompt window
echo [INFO] Launching Threat Evaluation Daemon...
start "Threat Evaluator Daemon" /d "%PROJECT_DIR%" cmd /k "cd /d "%PROJECT_DIR%" && "!PYTHON_EXE!" security\drift_detector.py"

echo.
echo =============================================================
echo      CORE COMPONENTS SUCCESSFULLY LAUNCHED IN SEPARATE CMDs   
echo =============================================================
echo 1. Telemetry Agent: Hooking keys, mouse, and process context.
echo 2. Threat Evaluator: Live-scoring and checking for drift.
echo.
echo Keep both windows open for continuous monitoring.
echo To stop the system, close the opened command windows.
echo.
pause
