@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Behavioral Drift Security - Master VIVA_START Launcher

echo =====================================================================
echo      BEHAVIORAL DRIFT SECURITY - MASTER VIVA LAUNCHER (VIVA_START)
echo   Multi-Factor Continuous Auth, Deception Honeypot and AI Forensics
echo         Department of Information Science and Engineering, NMAMIT
echo =====================================================================
echo.

:: 1. Resolve absolute project root safely (supports paths with spaces)
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"
echo [INFO] Project Directory : "%PROJECT_DIR%"

:: 2. Parse master CLI flags first (before Python lookup so --no-pause works even if Python is missing)
set "NO_PAUSE_FLAG="
if "%NO_PAUSE%"=="1" set "NO_PAUSE_FLAG=1"
set "SKIP_DOCTOR=0"
set "STATUS_ONLY=0"
set "SUPERVISOR_ONLY=0"
set "DEMO_ONLY=0"
set "HAS_AUTO_STOP=0"
set "TARGET_PORT=8000"
set "PY_SUPERVISOR_ARGS="
set "PY_DEMO_ARGS="

:parse_args
if "%~1"=="" goto end_parse
if /i "%~1"=="--no-pause" (
    set "NO_PAUSE_FLAG=1"
) else if /i "%~1"=="--skip-doctor" (
    set "SKIP_DOCTOR=1"
) else if /i "%~1"=="--status" (
    set "STATUS_ONLY=1"
) else if /i "%~1"=="--supervisor-only" (
    set "SUPERVISOR_ONLY=1"
) else if /i "%~1"=="--demo-only" (
    set "DEMO_ONLY=1"
) else if /i "%~1"=="--port" (
    if not "%~2"=="" (
        set "TARGET_PORT=%~2"
        shift
    )
) else if /i "%~1"=="--auto-stop" (
    set "HAS_AUTO_STOP=1"
    if not "%~2"=="" (
        set PY_SUPERVISOR_ARGS=!PY_SUPERVISOR_ARGS! --auto-stop "%~2"
        shift
    )
) else if /i "%~1"=="--no-browser" (
    set PY_SUPERVISOR_ARGS=!PY_SUPERVISOR_ARGS! --no-browser
) else if /i "%~1"=="--no-tray" (
    set PY_SUPERVISOR_ARGS=!PY_SUPERVISOR_ARGS! --no-tray
) else if /i "%~1"=="--stage" (
    set PY_DEMO_ARGS=!PY_DEMO_ARGS! --stage
    if not "%~2"=="" (
        set PY_DEMO_ARGS=!PY_DEMO_ARGS! "%~2"
        shift
    )
) else (
    set PY_DEMO_ARGS=!PY_DEMO_ARGS! "%~1"
)
shift
goto parse_args
:end_parse

:: 3. Locate Python executable (prefer .venv, then venv, then system PATH)
set "PYTHON_EXE="
if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
    echo [INFO] Virtual Env       : .venv
)
if not defined PYTHON_EXE if exist "%PROJECT_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
    echo [INFO] Virtual Env       : venv
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)
if not defined PYTHON_EXE (
    for /f "delims=" %%i in ('where py 2^>nul') do if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
)

if not defined PYTHON_EXE (
    echo [ERROR] Python executable not found in .venv, venv, or system PATH!
    echo         Please run setup.bat first to initialize the environment.
    if not defined NO_PAUSE_FLAG pause
    exit /b 1
)
echo [INFO] Python Executable : "%PYTHON_EXE%"
echo.

:: 4. Status Check Fast Path
if "%STATUS_ONLY%"=="1" goto run_status_check
if "%SKIP_DOCTOR%"=="0" goto run_doctor_check
goto after_doctor

:run_status_check
"%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" --status --port %TARGET_PORT%
set "EXIT_CODE=%ERRORLEVEL%"
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%

:run_doctor_check
echo [STEP 1/3] Running Pre-Flight System Diagnostics...
"%PYTHON_EXE%" "%PROJECT_DIR%\scripts\check_prerequisites.py"
set "DOCTOR_EXIT=%ERRORLEVEL%"
if %DOCTOR_EXIT% neq 0 (
    echo.
    echo [ERROR] Pre-flight check detected critical missing prerequisites.
    echo         Resolve the FAIL items above or re-run with --skip-doctor if intentional.
    if not defined NO_PAUSE_FLAG pause
    exit /b %DOCTOR_EXIT%
)
echo.

:after_doctor
if "%DEMO_ONLY%"=="1" goto run_demo_only
if "%SUPERVISOR_ONLY%"=="1" goto run_supervisor_inline
if "%HAS_AUTO_STOP%"=="1" goto run_supervisor_inline
goto run_coordinated_viva

:run_demo_only
echo [STEP 2/3] Launching 5-Stage Live Viva Runner ^(Demo-Only Mode^)...
"%PYTHON_EXE%" "%PROJECT_DIR%\demo_viva_runner.py" %PY_DEMO_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%

:run_supervisor_inline
echo [STEP 2/3] Starting Unified Security Supervisor ^(Port %TARGET_PORT%^)...
"%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" --port %TARGET_PORT% %PY_SUPERVISOR_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo [INFO] Security Supervisor exited with code %EXIT_CODE%.
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%

:run_coordinated_viva
echo [STEP 2/3] Coordinating Supervisor Terminal ^& Web SOC ^(Port %TARGET_PORT%^)...
"%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" --status --port %TARGET_PORT% >nul 2>&1
if errorlevel 1 (
    echo [INFO] Launching dedicated Unified Process Supervisor terminal window...
    start "Behavioral Drift Supervisor (Port %TARGET_PORT%)" /D "%PROJECT_DIR%" "%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" --port %TARGET_PORT% %PY_SUPERVISOR_ARGS%

    echo [INFO] Waiting for Web SOC Console readiness at http://127.0.0.1:%TARGET_PORT%/api/status ...
    "%PYTHON_EXE%" "%PROJECT_DIR%\run_system.py" --port %TARGET_PORT% --wait-ready 20
    if errorlevel 1 (
        echo [WARNING] Web SOC took longer than expected to respond; check the Supervisor window and data\logs\.
    ) else (
        echo [OK] Web SOC Console and background security daemons are ONLINE.
    )
) else (
    echo [OK] Supervisor / Web SOC already ONLINE on port %TARGET_PORT% ^(duplicate launch prevented^).
)

echo.
echo [STEP 3/3] Starting 5-Stage Interactive Viva Demonstration Runner...
echo.
"%PYTHON_EXE%" "%PROJECT_DIR%\demo_viva_runner.py" %PY_DEMO_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

echo.
echo =====================================================================
echo   VIVA SESSION COMPLETE ^(Exit Code: %EXIT_CODE%^)
echo   - Web SOC Console remains active at http://localhost:%TARGET_PORT% ^(if started above^).
echo   - Right-click the Green Shield tray icon or close Supervisor window to stop services.
echo =====================================================================
if not defined NO_PAUSE_FLAG pause
exit /b %EXIT_CODE%
