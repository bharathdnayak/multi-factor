@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Retrain Multi-Factor Behavioral Models

echo =============================================================
echo      RETRAIN MULTI-FACTOR BEHAVIORAL SECURITY MODELS         
echo =============================================================
echo.
echo [INFO] Training models on your latest collected telemetry:
echo        1. Biometric Dynamics (One-Class SVM)
echo        2. System Context Dynamics (Isolation Forest)
echo        3. Deep Keystroke Sequence Biometrics (Deep SVDD 1D-CNN)
echo        4. Behavioral AI Controller Baselines
echo.

:: 1. Compute absolute project root directory (parent of bat folder)
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
cd /d "%PROJECT_DIR%"

:: 2. Locate Python
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
    echo [ERROR] Python not found!
    if "%NO_PAUSE%"=="" if "%~1" neq "--no-pause" pause
    exit /b 1
)

echo [INFO] Project Directory : "%PROJECT_DIR%"
echo [INFO] Using Python      : "%PYTHON_EXE%"
echo.

:: Parse arguments to isolate --no-pause and pass other parameters to Python
set "PY_ARGS="
set "NO_PAUSE_FLAG="
if "%NO_PAUSE%"=="1" set "NO_PAUSE_FLAG=1"

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

"%PYTHON_EXE%" "%PROJECT_DIR%\ml_engine\train.py" %PY_ARGS%
set "TRAIN_EXIT=%ERRORLEVEL%"
if %TRAIN_EXIT% neq 0 (
    echo.
    echo [ERROR] Model training failed with exit code %TRAIN_EXIT%.
    if not defined NO_PAUSE_FLAG pause
    exit /b %TRAIN_EXIT%
)

echo.
echo [INFO] Running Model Verification...
echo.
"%PYTHON_EXE%" "%PROJECT_DIR%\tests\verify_models.py"
set "VERIFY_EXIT=%ERRORLEVEL%"
if %VERIFY_EXIT% neq 0 (
    echo.
    echo [ERROR] Model verification failed with exit code %VERIFY_EXIT%.
    if not defined NO_PAUSE_FLAG pause
    exit /b %VERIFY_EXIT%
)

echo.
echo =============================================================
echo      MODEL TRAINING AND VERIFICATION SUCCESSFULLY COMPLETED! 
echo =============================================================
if not defined NO_PAUSE_FLAG pause
exit /b 0
