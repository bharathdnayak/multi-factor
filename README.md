# Multi-Factor Behavioral Drift Continuous Security

> Continuous authentication system combining keystroke dynamics, mouse kinematics, intra-app cognitive context, environmental BLE smartphone proximity, ADWIN online concept drift detection, 3-tier dynamic risk orchestration, and active sandboxed deception honeypots.

---

## ⚡ Portable Quick Start (For New / Cloned Laptops)

This repository is completely self-contained. When cloned onto a new laptop, you can set up and run the entire system with zero machine-specific dependencies:

### 1. Prerequisites
- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14 ([Download Python](https://www.python.org/downloads/))  
  *(Ensure **"Add Python to PATH"** is checked during installation)*
- **Hardware:** Built-in laptop webcam or external USB webcam; keyboard & mouse.

### 2. First-Time Setup (Automated)
After cloning the repository, simply run the setup script:

```cmd
git clone https://github.com/bharathdnayak/multi-factor.git
cd multi-factor
setup.bat
```
*(Or double-click [`setup.bat`](setup.bat) in File Explorer)*

**What `setup.bat` does automatically:**
1. Validates the Python installation and environment.
2. Creates an isolated virtual environment (`.venv`) if one does not already exist.
3. Installs all required packages from [`requirements.txt`](requirements.txt).
4. Creates necessary runtime folders (`data/forensics`, `data/sandbox`, `data/logs`, etc.) without deleting existing data.
5. Instantiates safe local configuration files from templates (`security/config.json.example` -> `security/config.json`) without overwriting existing settings.
6. Verifies ML models and Deep SVDD keystroke sequence networks via [`tests/verify_models.py`](tests/verify_models.py).

---

## 🚀 Daily Execution Launchers

Once setup is complete, use any of the launchers below:

| Launcher | Purpose | Web Interface |
| :--- | :--- | :--- |
| **[`start_system.bat`](start_system.bat)**<br>*(or [`bat/run_security_system.bat`](bat/run_security_system.bat))* | **Production Continuous Security Daemon:** Spawns Unified Process Supervisor, background telemetry hooks, threat evaluator, system tray icon, and Cyber-Ops dashboard. | [`http://localhost:8000`](http://localhost:8000) |
| **[`run_viva_demo.bat`](run_viva_demo.bat)**<br>*(or [`bat/run_viva_demo.bat`](bat/run_viva_demo.bat))* | **5-Stage Live Viva Defense Runner:** Complete presentation demonstration showcasing baseline auth, walk-away drift, autonomous lock, honeypot diversion, and executive AI forensic PDF generation. | Terminal + System Viewers |
| **[`bat/simulate_unauthorized_attack.bat`](bat/simulate_unauthorized_attack.bat)** | **Unauthorized Imposter Attack Simulator:** Injects acute imposter typing anomalies, triggers webcam snapshot, OTP dispatch, and screen lockdown. | Terminal + Forensic Viewer |
| **[`bat/start_real_data_collection.bat`](bat/start_real_data_collection.bat)** | **Passive Multi-App Telemetry Harvester:** Runs silently in the background capturing genuine daily typing and mouse interactions without workflow lag. | Background Hook |
| **[`bat/train_models.bat`](bat/train_models.bat)** | **Train & Verify Security Models:** Retrains Deep SVDD 1D-CNN, OC-SVM, Isolation Forest, and AI Controller baselines. | Terminal |
| **[`bat/bootstrap_dataset.bat`](bat/bootstrap_dataset.bat)** | **Bootstrap Baseline Telemetry:** Generates 1,200 baseline micro-sessions across cognitive task modes. | Terminal |

---

## 🔒 Configuration & Secrets

All machine-specific settings and credentials use safe templates:

- **Security & OTP Configuration:**  
  Copy [`security/config.json.example`](security/config.json.example) to `security/config.json` (done automatically during `setup.bat`).  
  - `master_bypass_password`: Default is `"admin"` (used for emergency owner unlock in the lock screen and honeypot recovery hotkey: `Ctrl + Alt + Shift + U`).
  - `email`: Optional SMTP settings for OTP email dispatch.
  - `twilio`: Optional Twilio API settings for SMS dispatch.
- **Environment Settings (Optional):**  
  Copy [`.env.example`](.env.example) to `.env` to configure custom ports, host bindings, or webcam device indexes (`WEBCAM_DEVICE_INDEX=0` or `1`).

> [!NOTE]  
> `security/config.json`, `.env`, and temporary one-time PINs (`models/.active_otp`) are strictly excluded in `.gitignore` to prevent committing secrets.

---

## 📸 Camera & Forensic PDF Generation

The system captures physical intruder evidence and generates cryptographic forensic incident reports:

1. **Intruder Photo Capture:**  
   When threat risk crosses the elevated anomaly threshold, [`security/webcam.py`](security/webcam.py) triggers a silent snapshot via OpenCV.
   - Automatically probes primary device index `0`, with fallback to device `1` if index 0 is busy.
   - Applies Haar Cascade face detection to draw forensic bounding boxes.
   - Saves sealed frames to `data/forensics/intruder_<timestamp>.jpg`.

2. **Executive AI Forensic PDF Report:**  
   [`dashboard/pdf_generator.py`](dashboard/pdf_generator.py) autonomously compiles multi-page publication-ready PDFs:
   - Embedded intruder webcam photo evidence.
   - Chronological incident audit trail and honeypot command log.
   - AI-powered adversary intent prediction (offline Ollama LLM with heuristic rule fallback).
   - MITRE ATT&CK tactic kill-chain mapping.
   - Digital evidence SHA-256 chain of custody hashes.
   - Saved to `data/forensics/Forensic_Report_<timestamp>.pdf`.

---

## 🧪 Verification & Diagnostics

Verify system integrity at any time with the built-in diagnostic test suites:

```cmd
# 1. Verify ML Models (OC-SVM, Isolation Forest, Deep SVDD 1D-CNN)
python tests/verify_models.py

# 2. Verify All 14 Subsystems End-to-End
python scripts/verify_all_components.py

# 3. Run Full Automated Unit Test Discovery Suite (70 tests)
python -m unittest discover -s tests
```

---

## 🐳 Docker Container Support (Optional)

For containerized hosting of the Cyber-Ops Web Dashboard and REST APIs:

```bash
docker compose up --build
```
The web dashboard will be accessible at `http://localhost:8000`.

> [!TIP]  
> Because continuous keyboard/mouse hooks (`pynput`), physical webcam DirectShow capture, and PyQt6 honeypot desktop overlays interact directly with native Windows OS APIs, the full security daemon must run natively on Windows via `setup.bat` and `start_system.bat`.

---

## 📂 Project Architecture

```text
Behavioral-Drift-Security/
│
├── telemetry/             # Member 1: Continuous OS & Environmental Sensing
│   ├── agent.py           # Background hook capturing keystroke timing & cursor kinematics
│   ├── environmental_sensor.py  # BLE smartphone proximity path-loss & network monitor
│   └── evaluator.py       # Quad-factor continuous biometric threat evaluation daemon
│
├── ml_engine/             # Member 2: Feature Extraction & Deep Learning Models
│   ├── models.py          # One-Class SVM & Isolation Forest classifiers
│   ├── sequence_model.py  # Deep SVDD 1D-CNN temporal keystroke sequence neural net
│   ├── controller.py      # Intra-app cognitive baseline envelopes & task classifiers
│   ├── train.py           # Multi-model training and drift adaptation pipeline
│   └── data_generator.py  # Micro-session generator and intrusion simulator
│
├── security/              # Member 3: Concept Drift, Lockout & Dynamic Orchestration
│   ├── drift_detector.py  # Online Hoeffding-bound ADWIN multivariate concept drift
│   ├── risk_orchestrator.py # 3-Tier dynamic threat escalation (Nominal / Toast / Honeypot)
│   ├── lock_handler.py    # PyQt6 screen lock overlay with PIN/master bypass
│   ├── webcam.py          # Silent DirectShow webcam capture & Haar face detector
│   └── otp_service.py     # Multi-channel MFA OTP dispatcher (Email / Twilio / Local)
│
├── deception/             # Member 4: Sandboxed Honeypot Deception Layer
│   ├── honey_desktop.py   # Full-screen PyQt6 Windows 11 deception desktop overlay
│   ├── decoy_chrome.py    # Decoy browser with fake banking, AWS honey-tokens & recon traps
│   ├── forensic_tracker.py# Session recorder, file containment & SHA-256 evidence sealing
│   └── ai_intent_analyzer.py # Offline LLM / Ollama DFIR adversary intent classifier
│
├── dashboard/             # Cyber-Ops Web Dashboard & Reporting
│   ├── app.py             # FastAPI WebSocket & REST cyber defense server
│   ├── forensic_dashboard.py # Forensic incident playback console
│   ├── pdf_generator.py   # Publication-ready DFIR incident report PDF compiler
│   ├── static/            # CSS, JavaScript charts, and UI assets
│   └── templates/         # Cyber-ops responsive HTML dashboard
│
├── bat/                   # Execution Batch Launchers
│   ├── setup_environment.bat
│   ├── run_security_system.bat
│   ├── run_viva_demo.bat
│   ├── simulate_unauthorized_attack.bat
│   ├── start_real_data_collection.bat
│   ├── train_models.bat
│   └── bootstrap_dataset.bat
│
├── data/                  # Data Stores, Models & Evidence
│   ├── raw/               # Baseline keystroke and mouse kinematics CSVs
│   ├── sessions/          # Application baseline envelopes & profiles
│   ├── benchmarks/        # Academic CMU benchmark summaries and plots
│   ├── forensics/         # Intruder photos and generated PDF incident reports
│   └── sandbox/           # Quarantined attacker payloads and file modifications
│
├── models/                # Deep SVDD neural network weights & embedding metadata
├── scripts/               # Academic benchmarking, thesis generation & verification tools
├── docs/                  # Project thesis chapters, slides, and architectural diagrams
├── requirements.txt       # Unified Python dependency manifest
├── setup.bat              # One-click portable environment setup script
├── start_system.bat       # Production security supervisor launcher
└── README.md              # Project documentation (this file)
```
