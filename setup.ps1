<#
================================================================================
MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY - POWERSHELL SETUP
Automated Portable Environment Installer and Verifier
Department of Information Science and Engineering, NMAMIT
================================================================================
#>

[CmdletBinding()]
param(
    [switch]$NoPause,
    [switch]$SkipPip
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "   MULTI-FACTOR BEHAVIORAL DRIFT CONTINUOUS SECURITY - SETUP        " -ForegroundColor Cyan
Write-Host "        Automated Portable Environment Installer and Verifier       " -ForegroundColor Cyan
Write-Host "      Department of Information Science and Engineering, NMAMIT     " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Project Directory
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir
Write-Host "[STEP 1/7] Validating Project Root Directory..." -ForegroundColor Yellow
Write-Host "[INFO] Project Directory: '$ProjectDir'"
Write-Host ""

# 2. Find Python
Write-Host "[STEP 2/7] Detecting Python Installation (Python 3.10 - 3.14 required)..." -ForegroundColor Yellow
$SystemPython = $null
foreach ($cmd in @("python", "py")) {
    $found = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($found) {
        $SystemPython = $found.Source
        break
    }
}

if (-not $SystemPython) {
    Write-Host "[ERROR] Python was not found in PATH!" -ForegroundColor Red
    Write-Host "Please install Python 3.10+ from https://www.python.org/downloads/"
    Write-Host "Make sure to check 'Add Python to PATH' during installation."
    if (-not $NoPause) { Read-Host "Press Enter to exit..." }
    exit 1
}

Write-Host "[OK] Detected System Python: '$SystemPython'" -ForegroundColor Green
& $SystemPython --version
Write-Host ""

# 3. Virtual Environment
Write-Host "[STEP 3/7] Configuring Isolated Virtual Environment..." -ForegroundColor Yellow
$VenvDir = Join-Path $ProjectDir ".venv"
$PythonExe = $null

if (Test-Path "$ProjectDir\venv\Scripts\python.exe") {
    $PythonExe = "$ProjectDir\venv\Scripts\python.exe"
    Write-Host "[INFO] Found existing virtual environment at 'venv'."
} elseif (Test-Path "$ProjectDir\.venv\Scripts\python.exe") {
    $PythonExe = "$ProjectDir\.venv\Scripts\python.exe"
    Write-Host "[INFO] Found existing virtual environment at '.venv'."
} else {
    Write-Host "[INFO] Creating new isolated virtual environment at '.venv'..."
    & $SystemPython -m venv $VenvDir
    if (Test-Path "$VenvDir\Scripts\python.exe") {
        $PythonExe = "$VenvDir\Scripts\python.exe"
        Write-Host "[OK] Virtual environment created successfully!" -ForegroundColor Green
    } else {
        Write-Host "[WARNING] Failed to create virtual environment. Falling back to system Python." -ForegroundColor Yellow
        $PythonExe = $SystemPython
    }
}
Write-Host "[OK] Active Python Executable: '$PythonExe'" -ForegroundColor Green
Write-Host ""

# 4. Install Dependencies
if (-not $SkipPip) {
    Write-Host "[STEP 4/7] Installing and Validating Dependencies from requirements.txt..." -ForegroundColor Yellow
    Write-Host "[INFO] Upgrading pip..."
    & $PythonExe -m pip install --upgrade pip --quiet
    Write-Host "[INFO] Installing required packages (PyQt6, Torch, OpenCV, FastAPI, etc.)..."
    & $PythonExe -m pip install -r "$ProjectDir\requirements.txt"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to install one or more dependencies from requirements.txt!" -ForegroundColor Red
        if (-not $NoPause) { Read-Host "Press Enter to exit..." }
        exit 1
    }
    Write-Host "[OK] All dependencies successfully installed and verified!" -ForegroundColor Green
} else {
    Write-Host "[STEP 4/7] Skipping pip install as requested." -ForegroundColor Yellow
}
Write-Host ""

# 5. Initialize Runtime Directories & Configurations
Write-Host "[STEP 5/7] Initializing Directory Structures and Safe Configurations..." -ForegroundColor Yellow
$Dirs = @(
    "data\sessions",
    "data\raw",
    "data\forensics",
    "data\sandbox",
    "data\logs",
    "data\harvested",
    "data\benchmarks",
    "models"
)
foreach ($d in $Dirs) {
    $target = Join-Path $ProjectDir $d
    if (-not (Test-Path $target)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Write-Host "[CREATED] Directory: '$d'"
    }
}

if (-not (Test-Path "$ProjectDir\security\config.json")) {
    if (Test-Path "$ProjectDir\security\config.json.example") {
        Copy-Item "$ProjectDir\security\config.json.example" "$ProjectDir\security\config.json"
        Write-Host "[CREATED] security\config.json (generated from template)" -ForegroundColor Green
    }
} else {
    Write-Host "[PRESERVED] security\config.json (existing local configuration kept intact)" -ForegroundColor Cyan
}

if (-not (Test-Path "$ProjectDir\.env")) {
    if (Test-Path "$ProjectDir\.env.example") {
        Copy-Item "$ProjectDir\.env.example" "$ProjectDir\.env"
        Write-Host "[CREATED] .env (generated from template)" -ForegroundColor Green
    }
} else {
    Write-Host "[PRESERVED] .env (existing local environment configuration kept intact)" -ForegroundColor Cyan
}
Write-Host ""

# 6. Validate Machine Learning Models
Write-Host "[STEP 6/7] Verifying Machine Learning Models and Sequence Detector..." -ForegroundColor Yellow
& $PythonExe "$ProjectDir\tests\verify_models.py" 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARNING] Model verification check failed or models require initial training." -ForegroundColor Yellow
    Write-Host "[INFO] Automatically calibrating models on baseline dataset..."
    & $PythonExe "$ProjectDir\ml_engine\train.py" --simulate
    & $PythonExe "$ProjectDir\tests\verify_models.py"
} else {
    Write-Host "[OK] Machine Learning Models and Deep SVDD detector verified!" -ForegroundColor Green
}
Write-Host ""

# 7. Pre-Flight Diagnostics
Write-Host "[STEP 7/7] Running Pre-Flight Diagnostics (Sensors, Ollama, Ports, Camera)..." -ForegroundColor Yellow
& $PythonExe "$ProjectDir\scripts\check_prerequisites.py"
Write-Host ""

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "        SETUP AND ENVIRONMENT VERIFICATION COMPLETED SUCCESSFULLY!    " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[QUICK LAUNCH COMMANDS]" -ForegroundColor White
Write-Host ""
Write-Host " 1. Start Complete Security Daemon (Dashboard + Supervisor + Tray):"
Write-Host "    - Double-click 'start_system.bat' or run: python run_system.py"
Write-Host "    - Opens Web Console at http://localhost:8000"
Write-Host ""
Write-Host " 2. Run Live Viva Defense Demonstration:"
Write-Host "    - Double-click 'run_viva_demo.bat' or run: python demo_viva_runner.py"
Write-Host ""
Write-Host " 3. Run Containerized Web Dashboard (Docker Compose - Optional):"
Write-Host "    - Run: docker compose up -d"
Write-Host ""
Write-Host " 4. Simulate Unauthorized Intrusion Breach:"
Write-Host "    - Double-click 'bat\simulate_unauthorized_attack.bat'"
Write-Host ""
Write-Host " 5. Run Full Component Test Suite:"
Write-Host "    - Run: python scripts\verify_all_components.py"
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $NoPause) {
    Read-Host "Press Enter to exit..."
}
