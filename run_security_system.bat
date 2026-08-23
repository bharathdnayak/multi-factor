@echo off
title Multi-Factor Behavioral Drift Security System
echo =============================================================
echo     STARTING MULTI-FACTOR BEHAVIORAL DRIFT SECURITY SYSTEM    
echo =============================================================
echo.

:: Check if Python virtual environment exists and activate it
if exist venv\Scripts\activate.bat (
    echo [INFO] Activating virtual environment (venv)...
    call venv\Scripts\activate.bat
) else if exist .venv\Scripts\activate.bat (
    echo [INFO] Activating virtual environment (.venv)...
    call .venv\Scripts\activate.bat
)

:: 1. Launch the Telemetry hook agent in a separate command window
echo [INFO] Launching Background Telemetry Hook Agent...
start "Behavioral Telemetry Agent" cmd /k "python telemetry/agent.py"

:: Wait 2 seconds for log initialization
timeout /t 2 /nobreak >nul

:: 2. Launch the Threat Evaluator Daemon in a separate command window
echo [INFO] Launching Threat Evaluation Daemon...
start "Threat Evaluator Daemon" cmd /k "python security/drift_detector.py"

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
