@echo off
chcp 65001 >nul
setlocal
title Multi-Factor Behavioral Drift Security - Environment Setup

echo =====================================================================
echo    MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY - SETUP        
echo         Automated Portable Environment Installer and Verifier       
echo       Department of Information Science and Engineering, NMAMIT     
echo =====================================================================
echo.

:: 1. Compute absolute project root directory
set "PROJECT_DIR=%~dp0"
if "%PROJECT_DIR:~-1%"=="\" set "PROJECT_DIR=%PROJECT_DIR:~0,-1%"
cd /d "%PROJECT_DIR%"

echo [STEP 1/6] Validating Project Root Directory...
echo [INFO] Project Directory: "%PROJECT_DIR%"
echo.

:: 2. Find System Python
echo [STEP 2/6] Detecting Python Installation...
set "SYSTEM_PYTHON="
for %%P in (python py) do (
    if not defined SYSTEM_PYTHON (
        for /f "delims=" %%i in ('where %%P 2^>nul') do (
            if not defined SYSTEM_PYTHON set "SYSTEM_PYTHON=%%i"
        )
    )
)

if not defined SYSTEM_PYTHON (
    echo [ERROR] Python was not found in PATH!
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    if "%~1" neq "--no-pause" pause
    exit /b 1
)

echo [OK] Detected System Python: "%SYSTEM_PYTHON%"
"%SYSTEM_PYTHON%" --version
echo.

:: 3. Setup Virtual Environment (.venv)
echo [STEP 3/6] Configuring Virtual Environment...
set "VENV_DIR=%PROJECT_DIR%\.venv"
if exist "%PROJECT_DIR%\venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\venv\Scripts\python.exe"
    echo [INFO] Found existing virtual environment at 'venv'.
) else if exist "%PROJECT_DIR%\.venv\Scripts\python.exe" (
    set "PYTHON_EXE=%PROJECT_DIR%\.venv\Scripts\python.exe"
    echo [INFO] Found existing virtual environment at '.venv'.
) else (
    echo [INFO] Creating new isolated virtual environment at '.venv'...
    "%SYSTEM_PYTHON%" -m venv "%VENV_DIR%"
    if errorlevel 1 (
        echo [WARNING] Failed to create virtual environment. Falling back to system Python.
        set "PYTHON_EXE=%SYSTEM_PYTHON%"
    ) else (
        set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"
        echo [OK] Virtual environment created successfully!
    )
)
echo [OK] Active Python Executable: "%PYTHON_EXE%"
echo.

:: 4. Install Dependencies
echo [STEP 4/6] Installing and Validating Dependencies from requirements.txt...
echo [INFO] Upgrading pip...
"%PYTHON_EXE%" -m pip install --upgrade pip --quiet

echo [INFO] Installing required packages (PyQt6, Torch, OpenCV, FastAPI, etc.)...
"%PYTHON_EXE%" -m pip install -r "%PROJECT_DIR%\requirements.txt"
if errorlevel 1 (
    echo.
    echo [ERROR] Failed to install one or more dependencies from requirements.txt!
    echo Please inspect the error messages above.
    if "%~1" neq "--no-pause" pause
    exit /b 1
)
echo [OK] All dependencies successfully installed and verified!
echo.

:: 5. Initialize Runtime Directories and Configuration
echo [STEP 5/6] Initializing Directory Structures and Safe Configurations...
for %%D in (
    "data\sessions"
    "data\raw"
    "data\forensics"
    "data\sandbox"
    "data\logs"
    "data\harvested"
    "data\benchmarks"
    "models"
) do (
    if not exist "%PROJECT_DIR%\%%~D" (
        mkdir "%PROJECT_DIR%\%%~D" 2>nul
        echo [CREATED] Directory: "%%~D"
    )
)

:: Copy safe configuration templates if user config does not already exist (never overwrite!)
if not exist "%PROJECT_DIR%\security\config.json" (
    if exist "%PROJECT_DIR%\security\config.json.example" (
        copy "%PROJECT_DIR%\security\config.json.example" "%PROJECT_DIR%\security\config.json" >nul
        echo [CREATED] security\config.json (generated from template)
    )
) else (
    echo [PRESERVED] security\config.json (existing local configuration kept intact)
)

if not exist "%PROJECT_DIR%\.env" (
    if exist "%PROJECT_DIR%\.env.example" (
        copy "%PROJECT_DIR%\.env.example" "%PROJECT_DIR%\.env" >nul
        echo [CREATED] .env (generated from template)
    )
) else (
    echo [PRESERVED] .env (existing local environment configuration kept intact)
)
echo.

:: 6. Validate Machine Learning Models
echo [STEP 6/6] Verifying Machine Learning Models and Sequence Detector...
"%PYTHON_EXE%" "%PROJECT_DIR%\tests\verify_models.py"
if errorlevel 1 (
    echo.
    echo [WARNING] Model verification check failed or models require initial training.
    echo [INFO] Automatically retraining models on baseline dataset...
    "%PYTHON_EXE%" "%PROJECT_DIR%\ml_engine\train.py" --simulate
    "%PYTHON_EXE%" "%PROJECT_DIR%\tests\verify_models.py"
)

echo.
echo =====================================================================
echo        SETUP AND ENVIRONMENT VERIFICATION COMPLETED SUCCESSFULLY!    
echo =====================================================================
echo.
echo [QUICK LAUNCH COMMANDS]
echo.
echo  1. Start Complete Security Daemon (Dashboard + Supervisor + Tray):
echo     - Double-click 'start_system.bat' or 'bat\run_security_system.bat'
echo     - Opens Web Console at http://localhost:8000
echo.
echo  2. Run Live Viva Defense Demonstration:
echo     - Double-click 'run_viva_demo.bat' or 'bat\run_viva_demo.bat'
echo.
echo  3. Simulate Unauthorized Intrusion Breach:
echo     - Double-click 'bat\simulate_unauthorized_attack.bat'
echo.
echo  4. Run Full Component Test Suite:
echo     - Run: "%PYTHON_EXE%" scripts\verify_all_components.py
echo =====================================================================
echo.
if "%~1" neq "--no-pause" pause
