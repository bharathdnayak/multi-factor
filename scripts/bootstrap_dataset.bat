@echo off
setlocal
title Bootstrap Genuine Dataset

echo =============================================================
echo      BOOTSTRAP GENUINE MULTI-APPLICATION BEHAVIORAL DATASET   
echo =============================================================
echo.
echo [INFO] Generates 1,200+ realistic micro-sessions across LeetCode,
echo        VS Code, Terminal, AI Chat, and Technical Reading.
echo [INFO] Builds baseline envelopes in data/sessions/app_baselines.json
echo        and retrains the core ML classifiers immediately.
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

"%PYTHON_EXE%" "%CD%\ml_engine\data_generator.py" --bootstrap --sessions 1200

echo.
echo [SUCCESS] Baseline data generated and models trained!
popd
pause
