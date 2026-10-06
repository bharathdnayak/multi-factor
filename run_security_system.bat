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

:: 3. Launch Telemetry Hook Agent in a separate Command Prompt window
echo [INFO] Launching Background Telemetry Hook Agent...
start "Behavioral Telemetry Agent" /d "%PROJECT_DIR%" cmd /k ^""%PYTHON_EXE%" "%PROJECT_DIR%\telemetry\agent.py"^"

:: Wait 2 seconds for agent initialization
ping 127.0.0.1 -n 3 >nul

:: 4. Launch Threat Evaluator Daemon in a separate Command Prompt window
echo [INFO] Launching Continuous Threat Evaluation Daemon...
start "Threat Evaluator Daemon" /d "%PROJECT_DIR%" cmd /k ^""%PYTHON_EXE%" "%PROJECT_DIR%\security\drift_detector.py"^"

:: Wait 2 seconds for evaluator initialization
ping 127.0.0.1 -n 3 >nul

:: 5. Launch Real-Time Cyber-Ops Web Dashboard Server
echo [INFO] Launching Cyber-Ops Defense Web Console (FastAPI on Port 8000)...
start "Cyber-Ops Web Dashboard" /d "%PROJECT_DIR%" cmd /k ^""%PYTHON_EXE%" -m uvicorn dashboard.app:app --host 127.0.0.1 --port 8000^"

:: Wait 2 seconds for ASGI server binding, then launch browser
ping 127.0.0.1 -n 3 >nul
start http://localhost:8000

echo.
echo =====================================================================
echo       ALL 3 CONTINUOUS SECURITY WORKERS SUCCESSFULLY LAUNCHED!       
echo =====================================================================
echo 1. Telemetry Agent      : Hooking keystrokes, mouse, and process context.
echo 2. Threat Evaluator     : Multi-scale ML evaluation and ADWIN drift monitor.
echo 3. Cyber Dashboard      : Real-time telemetry streaming at http://localhost:8000
echo.
echo Keep the worker windows open for continuous background monitoring.
echo To stop the system, simply close the respective command prompt windows.
echo =====================================================================
echo.
pause
