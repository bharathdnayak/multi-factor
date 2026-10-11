# Portable Deployment & Friend's Laptop Setup Guide

**Project:** Behavioral Drift — Continuous Authentication & Honeypot Forensics  
**Department:** Information Science & Engineering, NMAMIT  
**Target Platform:** Windows 10 / Windows 11 (64-bit)  
**Supported Python Versions:** Python 3.10 – 3.14 (64-bit)

---

## 1. System Requirements & Prerequisites

Before starting, ensure the target Windows laptop has the following installed:

1. **Python 3.10 to 3.14 (64-bit)**
   - Download from: [https://www.python.org/downloads/](https://www.python.org/downloads/)
   - ⚠️ **CRITICAL:** Check the box **"Add python.exe to PATH"** during installation.
2. **Git for Windows**
   - Download from: [https://git-scm.com/download/win](https://git-scm.com/download/win)
3. *(Optional)* **Ollama Local AI Runner** (Only needed if local LLM intent enrichment is desired; the system runs 100% fine without it via deterministic rules).
   - Download from: [https://ollama.com/download](https://ollama.com/download)

---

## 2. Quick-Start: Automated 1-Click Setup

The repository includes automated setup scripts that configure the isolated virtual environment, install all dependencies, verify machine learning checkpoints, and validate runtime directories.

### Option A: Using Windows Command Prompt / Double-Click (Recommended)

1. Open **Command Prompt** (`cmd.exe`) and clone the repository:
   ```cmd
   git clone https://github.com/bharathdnayak/multi-factor.git
   cd multi-factor
   ```
2. Run the automated setup launcher:
   ```cmd
   setup.bat
   ```
   *(Or simply double-click `setup.bat` in File Explorer).*

### Option B: Using Windows PowerShell

1. Open **PowerShell** and clone the repository:
   ```powershell
   git clone https://github.com/bharathdnayak/multi-factor.git
   cd multi-factor
   ```
2. Allow local script execution for this process (if restricted) and run:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\setup.ps1
   ```

---

## 3. Manual Step-by-Step Installation

If you prefer to configure the environment manually without batch scripts:

### Step 1: Create and Activate Virtual Environment
**PowerShell:**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(If PowerShell blocks script activation, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

**Command Prompt (CMD):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 2: Install Required Dependencies
```cmd
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Initialize Safe Local Configuration
Copy the safe configuration templates:
**CMD:**
```cmd
copy .env.example .env
copy security\config.json.example security\config.json
```
**PowerShell:**
```powershell
Copy-Item .env.example .env
Copy-Item security\config.json.example security\config.json
```

### Step 4: Validate Machine Learning Models
```cmd
python tests\verify_models.py
```
*Expected Output: `ALL VERIFICATIONS (SVM, Isolation Forest, and PyTorch 1D-CNN) PASSED SUCCESSFULLY!`*

### Step 5: Run the Portability Validator
```cmd
python scripts\validate_portability.py
```
*Expected Output: `[RESULT] PASSED -- All components verified and fully portable.`*

---

## 4. Offline AI Integration (Ollama + Qwen) — Optional

The honeypot forensic engine incorporates cognitive adversary profiling.

> [!IMPORTANT]
> **Git cloning does NOT download multi-gigabyte AI model weights.**  
> If you wish to use the offline LLM narrative features, you must pull the model once onto your laptop.

### Setting Up Ollama (One-Time Setup):
1. Install Ollama from [https://ollama.com](https://ollama.com).
2. Start the Ollama application or run `ollama serve`.
3. In a terminal, pull the recommended lightweight model:
   ```cmd
   ollama pull qwen2.5:3b
   ```
   *(Or pull `ollama pull qwen3.5:4b` if your laptop has $\ge 16\text{ GB}$ RAM).*
4. Verify the model is installed locally:
   ```cmd
   ollama list
   ```

### What happens if Ollama is NOT installed?
The entire application, including honeypot trapping, telemetry logging, risk scoring, and 12-section PDF report generation, **operates normally with zero errors**. The AI analyzer automatically falls back to the deterministic forensic rule engine.

---

## 5. Hardware Sensors & Workstation Evidence

- **Webcam / Optical Presence Sensor:**
  - The breach handler attempts to capture workstation presence via the laptop's default camera (`index 0`).
  - If no physical webcam is connected, or if privacy mode is enabled, the system logs `[OPTICAL CAPTURE IDLE / PRIVACY MODE ENABLED]` and proceeds safely without crashing.
- **Biometric Input Hooks (Keystroke & Mouse):**
  - Requires standard user privileges on Windows (no Administrator prompt required).
  - Listens to global hardware hooks using `pynput` while the session is active.

---

## 6. How to Run the Application

### 1. Launch the Complete Security Daemon & Dashboard
```cmd
start_system.bat
```
*(Or run `bat\run_security_system.bat`)*
- Spawns the continuous biometric collector, evaluation engine, and system tray monitor.
- Launches the Cyber-Ops Web Dashboard at: [http://localhost:8000](http://localhost:8000).

### 2. Run the Academic Viva Defense Demonstration
```cmd
run_viva_demo.bat
```
*(Or run `bat\run_viva_demo.bat`)*
- Executes a guided, step-by-step evaluation demonstration:
  1. Baseline owner biometric interaction.
  2. Acute hostile anomaly injection.
  3. Continuous authentication breach detection ($Risk \ge 0.55$).
  4. Transparent diversion into the stateful Windows 11 Honeypot Desktop.
  5. Decoy application probing (File Explorer, PowerShell, Chrome).
  6. Multi-Factor OTP security challenge.
  7. Digital forensics export & PDF compilation.

### 3. Generate a Fresh Forensic PDF Report
```cmd
python dashboard\pdf_generator.py
```
- Compiles a complete 12-section publication-ready PDF report from current session telemetry in `data\forensics\`.
- Displays the digital FIPS 180-4 SHA-256 seal.

---

## 7. Running Verification & Test Suites

You can independently verify that your laptop's environment is 100% operational:

| Verification Target | Command | Expected Output |
| :--- | :--- | :--- |
| **Portability Pre-Flight** | `python scripts\validate_portability.py` | `37 PASSED \| 0 WARNINGS \| 0 FAILED` |
| **Clean-Clone Simulation** | `python scripts\test_clean_checkout_simulation.py` | `CLEAN-CHECKOUT PORTABILITY TEST COMPLETED 100% SUCCESSFULLY!` |
| **Forensic PDF Engine** | `python -m unittest tests\test_forensic_report_engine.py` | `Ran 8 tests ... OK` |
| **Full Regression Suite** | `python -m unittest discover tests -v` | `Ran 95 tests ... OK` |

---

## 8. Common Issues and Solutions

### Issue 1: PowerShell Script Execution Error
*Error:* `File .\setup.ps1 cannot be loaded because running scripts is disabled on this system.`  
*Fix:* Run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in your PowerShell window, then re-run `.\setup.ps1`.

### Issue 2: Port 8000 Already in Use
*Error:* `[ERROR] Port 8000 is occupied by another process.`  
*Fix:* Open `.env` and change `PORT=8000` to `PORT=8080` or `PORT=8500`.

### Issue 3: Recovery Code Rejected
*Notice:* Trivial passwords like `admin`, `123456`, or `password` are intentionally blocked by the anti-bypass security policy.  
*Fix:* Use the cryptographic 6-digit session OTP generated during breach, or configure a non-trivial key in `.env` (`MASTER_BYPASS_PASSWORD=YourSecureKey2026!`).

---

## 9. Teammate Hand-Off Checklist

When a teammate tests this project on their physical laptop:

- [ ] Clone repository from GitHub (`git clone https://github.com/bharathdnayak/multi-factor.git`).
- [ ] Run `setup.bat` (or `setup.ps1`) to initialize dependencies and directories.
- [ ] Run `python scripts\validate_portability.py` and confirm all checks pass.
- [ ] Run `run_viva_demo.bat` to verify the honeypot desktop and continuous authentication flow.
- [ ] Inspect the generated PDF report in `data\forensics\` to verify formatting, 12 sections, and unbroken SHA-256 digests.
