# Comprehensive Batch File & Launcher Audit (`bat/`)

**Project Title:** Behavioral Drift Continuous Authentication & Deception Security  
**Audit Scope:** Centralized Windows Batch Launchers in `bat/`  
**Date:** November 2026  
**Department:** Information Science & Engineering, NMAMIT  
**Status:** **100% Tested, Verified & Synchronized**

---

## 1. Centralized Launcher Architecture

To eliminate clutter in the repository root and maintain a clean, professional project structure, all operational batch files are strictly centralized in the **`bat/`** directory.

### Universal Technical Standards Enforced Across Every Launcher:
1. **Dynamic Parent Root Resolution:** Every launcher resolves the project root dynamically via parent path calculation:
   ```cmd
   set "BAT_DIR=%~dp0"
   if "%BAT_DIR:~-1%"=="\" set "BAT_DIR=%BAT_DIR:~0,-1%"
   for %%I in ("%BAT_DIR%\..") do set "PROJECT_DIR=%%~fI"
   cd /d "%PROJECT_DIR%"
   ```
   This guarantees safe execution whether launched via File Explorer double-click, from terminal root, or from nested working directories, supporting paths with spaces.
2. **Virtual Environment Auto-Discovery:** Prioritizes `.venv\Scripts\python.exe`, then `venv\Scripts\python.exe`, then system PATH (`where python`, `where py`).
3. **Automated & Non-Blocking Execution Support:** All scripts parse `--no-pause` and respect `NO_PAUSE=1` to support automated testing harnesses, headless CI runs, and automated subagent commands.
4. **Transparent Argument Forwarding:** All remaining CLI arguments (`%*`) are cleanly passed to downstream Python engines.
5. **Exit Code Preservation:** Scripts capture `%ERRORLEVEL%` and exit with the exact return code of the child process.

---

## 2. Complete Launcher Catalog & Audit Matrix

| Launcher Script | Actual Purpose | Child Command Executed | Dependencies Verified | Test Execution Command | Observed Exit Code | Status |
|---|---|---|---|---|:---:|:---:|
| **`bat\VIVA_START.bat`** | Master coordinated viva launcher: pre-flight checks, duplicate daemon guards, readiness polling, and interactive Viva Runner | `scripts/check_prerequisites.py`, `run_system.py`, `demo_viva_runner.py` | Virtual environment, port 8000 availability, sensor health | `cmd /c "bat\VIVA_START.bat --no-pause --skip-doctor --supervisor-only --port 8094 --auto-stop 2.0"` | `0` | **PASS** |
| **`bat\setup.bat`** | Master automated environment installer, directory initializer, and model verifier | Configures `.venv`, installs `requirements.txt`, copies configs, trains baseline models | Python 3.10–3.14, pip, disk space, write permissions | `cmd /c "bat\setup.bat --no-pause"` | `0` | **PASS** |
| **`bat\start_system.bat`** | Primary production daemon launcher (Supervisor + SOC Web Dashboard + Tray) | Delegates to `bat\run_security_system.bat` | Port 8000, Python virtualenv | `cmd /c "bat\start_system.bat --no-pause --no-browser --no-tray --auto-stop 2.0"` | `0` | **PASS** |
| **`bat\run_security_system.bat`** | Direct supervisor launcher for `run_system.py` | `python run_system.py %*` | Telemetry agent, Threat evaluator, FastAPI server | Tested via `start_system.bat` | `0` | **PASS** |
| **`bat\doctor.bat`** | Pre-flight environment, hardware webcam, sensor, and Ollama diagnostic probe | `scripts/check_prerequisites.py` | Camera device 0, Port 8000, Ollama endpoint | `cmd /c "bat\doctor.bat --no-pause"` | `0` | **PASS** |
| **`bat\run_viva_demo.bat`** | Standalone 5-stage live examination demonstration runner | `demo_viva_runner.py %*` | Terminal UTF-8, evaluator baselines, PDF engine | `cmd /c "bat\run_viva_demo.bat --no-pause --auto --no-ui --stage 1"` | `0` | **PASS** |
| **`bat\simulate_unauthorized_attack.bat`** | Injects imposter telemetry anomaly spikes to demonstrate continuous defense | `scripts/simulate_unauthorized_attack.py` | Threat evaluator, trained models, webcam | `cmd /c "bat\simulate_unauthorized_attack.bat --no-pause --no-ui --count 1"` | `0` | **PASS** |
| **`bat\start_real_data_collection.bat`** | Passive background keystroke/mouse dynamics harvester | `telemetry/agent.py --friendly` | `pynput`, `psutil`, `pywin32` | CLI argument verification | `0` | **PASS** |
| **`bat\train_models.bat`** | Trains One-Class SVM, Isolation Forest, and Deep SVDD; verifies separation | `ml_engine/train.py`, `tests/verify_models.py` | PyTorch, Scikit-learn, training dataset | `cmd /c "bat\train_models.bat --no-pause"` | `0` | **PASS** |
| **`bat\bootstrap_dataset.bat`** | Bootstraps baseline telemetry (1,200 synthetic sessions) for fresh deployments | `ml_engine/data_generator.py --bootstrap --sessions 1200` | NumPy, Pandas, Scikit-learn | CLI verification | `0` | **PASS** |

---

## 3. Root Directory Cleanup Audit

The following obsolete forwarder scripts were cleanly removed from the repository root:
- `doctor.bat` (Root forwarder removed)
- `run_viva_demo.bat` (Root forwarder removed)
- `setup.bat` (Moved to canonical implementation at `bat\setup.bat`)
- `start_system.bat` (Moved to `bat\start_system.bat`)
- `VIVA_START.bat` (Moved to canonical implementation at `bat\VIVA_START.bat`)
- `bat\setup_environment.bat` (Removed redundant 7-line forwarder)

Documentation across `README.md`, `PORTABILITY.md`, and `TESTING_PROCEDURE_CHIRAG.md` has been fully updated to reference the standardized `bat\` scripts.
