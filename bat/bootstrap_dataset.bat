@echo off
chcp 65001 >nul
setlocal
title Bootstrap Genuine Multi-Application Behavioral Dataset

echo =============================================================
echo      BOOTSTRAP GENUINE MULTI-APPLICATION BEHAVIORAL DATASET   
echo =============================================================
echo.
echo [INFO] Generates 1,200+ realistic micro-sessions across LeetCode,
echo        VS Code, Terminal, AI Chat, and Technical Reading.
echo [INFO] Builds baseline envelopes in data/sessions/app_baselines.json
echo        and retrains the core ML classifiers immediately.
echo.

:: 1. Compute absolute project root directory (parent of bat folder)
set "BAT_DIR=%~dp0"
if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
cd /d "%PROJECT_DIR%"

:: 2. Find Python
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
    pause
    exit /b 1
)

echo [INFO] Project Directory : "%PROJECT_DIR%"
echo [INFO] Using Python      : "%PYTHON_EXE%"
echo.
"%PYTHON_EXE%" "%PROJECT_DIR%\ml_engine\data_generator.py" --bootstrap --sessions 1200 %*

echo.
echo [SUCCESS] Baseline data generated and models trained!
pause
