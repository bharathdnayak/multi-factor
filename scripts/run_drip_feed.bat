@echo off
setlocal
title Background Continuous Drip Data Generator

echo =============================================================
echo     CONTINUOUS BACKGROUND GENUINE DATA DRIP GENERATOR       
echo =============================================================
echo.
echo [INFO] Emits genuine micro-sessions every 15 seconds in software.
echo [INFO] Zero hardware input, zero mouse jumps, zero interference.
echo [INFO] Feeds the AI Controller and baseline envelopes continuously.
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

"%PYTHON_EXE%" "%CD%\ml_engine\data_generator.py" --drip --interval 15

popd
pause
