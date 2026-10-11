# Multi-Factor Behavioral Drift Continuous Security

> **Continuous Authentication & Honeypot Forensics**  
> An autonomous endpoint cybersecurity architecture combining continuous keystroke dynamics, mouse kinematics, intra-app cognitive context, environmental BLE smartphone proximity, ADWIN online concept drift detection, 3-tier dynamic risk orchestration, offline Ollama/Qwen AI threat intelligence, and an authentic Windows-style sandboxed deception honeypot.
>
> **Department of Information Science & Engineering (ISE) | NMAMIT, Nitte**  
> **Major Project Team 30**

---

## 🏗️ Deployment Architecture: Native vs. Docker

Before deploying, understand the project's hybrid architecture:

| Component | Execution Target | Rationale & Host Dependencies |
| :--- | :--- | :--- |
| **Honeypot Deception Desktop** | **Native Windows** | Requires borderless fullscreen PyQt6 overlays over host desktop, replicating Windows 11 taskbar, start menu, and wallpapers (`TranscodedWallpaper`). |
| **Telemetry Sensor Agent** | **Native Windows** | Uses `pynput` and `win32gui` (`user32.dll`) to capture active foreground application titles and OS-level keystroke/mouse biometrics. Containers cannot monitor host input. |
| **Silent Intruder Webcam** | **Native Windows** | Directly connects to local laptop camera hardware via OpenCV (`cv2.VideoCapture(0)`). Standard Docker containers on Windows cannot access host webcams without third-party USB/IP bridging. |
| **Threat Evaluator & ADWIN** | **Native Windows** | Evaluates real-time biometric streams and triggers the native verification lock screen or honeypot upon breach. |
| **Offline Ollama AI Engine** | **Native Windows or Local Service** | Native Ollama (`http://localhost:11434`) utilizes host GPU/DirectML acceleration and persistent model storage in `%USERPROFILE%\.ollama`. |
| **Cyber-Ops Web Dashboard & REST APIs** | **Native Windows OR Docker Container** | FastAPI/Uvicorn server on port 8000 serving live telemetry, WebSockets, and incident PDF downloads. Fully containerized via `Dockerfile` and `docker-compose.yml`. |

> [!IMPORTANT]
> **Primary Recommendation:** Run the application **natively on Windows** using the automated setup script (`setup.bat` or `setup.ps1`). This guarantees 100% of the biometrics, hardware camera, and deception honeypot features operate without container limitations.  
> The Docker container is provided as an optional mode for containerized SOC monitoring or remote dashboard viewing.

---

## ⚡ Quick Start: First-Time Setup on Any Laptop

When cloning onto another computer, follow these simple steps:

### 1. System Requirements & Prerequisites
- **Operating System:** Windows 10 or Windows 11 (64-bit).
- **Python:** Python 3.10, 3.11, 3.12, 3.13, or 3.14 (64-bit) ([Download Python](https://www.python.org/downloads/)).  
  *Crucial: Check **"Add Python to PATH"** during installation!*
- **Hardware:** Laptop keyboard & mouse/trackpad; integrated or USB webcam; minimum 4 GB RAM (8 GB+ recommended if running local Ollama).
- **Disk Space:** ~500 MB for Python virtual environment; ~2.5 GB if local Ollama Qwen model is downloaded.

### 2. Clone the Repository
```cmd
git clone https://github.com/bharathdnayak/multi-factor.git
cd multi-factor
```

### 3. Run Automated First-Time Setup
Double-click [`setup.bat`](setup.bat) in File Explorer, or run in Command Prompt:

```cmd
setup.bat
```
*(PowerShell users can run: `powershell -ExecutionPolicy Bypass -File .\setup.ps1`)*

**What `setup.bat` executes automatically:**
1. **Validates Python:** Detects Python in PATH and validates version (3.10 - 3.14).
2. **Creates Isolated Virtual Environment:** Generates `.venv` if one does not exist.
3. **Installs Dependencies:** Upgrades pip and installs packages from [`requirements.txt`](requirements.txt) with cross-platform markers.
4. **Initializes Storage Structure:** Creates all runtime data folders (`data/forensics`, `data/sandbox`, `data/logs`, `data/sessions`, `models`) with `.gitkeep` placeholders.
5. **Generates Safe Configuration:** Copies [`.env.example`](.env.example) to `.env` and [`security/config.json.example`](security/config.json.example) to `security/config.json` without overwriting existing configurations.
6. **Validates & Calibrates ML Models:** Verifies One-Class SVM, Isolation Forest, and Deep SVDD 1D-CNN checkpoints; automatically runs baseline calibration if needed.
7. **Runs Pre-Flight Diagnostics:** Probes hardware webcam, port 8000 availability, and Ollama status via [`scripts/check_prerequisites.py`](scripts/check_prerequisites.py).

---

## 🚀 Execution Launchers

Once setup is complete, choose any launcher according to your task:

| Launcher | Mode | Description | Endpoint / Output |
| :--- | :--- | :--- | :--- |
| **[`start_system.bat`](start_system.bat)**<br>*(or `bat/run_security_system.bat`)* | **Production Security Daemon** | Launches Unified Process Supervisor, background telemetry sensor, continuous threat evaluator, system tray shield icon, and SOC Dashboard. | Web Console:<br>[`http://localhost:8000`](http://localhost:8000) |
| **[`run_viva_demo.bat`](run_viva_demo.bat)**<br>*(or `bat/run_viva_demo.bat`)* | **5-Stage Live Viva Defense Runner** | Presentation runner designed for viva evaluation panels: walks through baseline auth, walk-away drift, autonomous defense, honeypot diversion, and executive AI forensic PDF generation. | Interactive Terminal + Auto-Launched PDF |
| **[`bat/simulate_unauthorized_attack.bat`](bat/simulate_unauthorized_attack.bat)** | **Attacker Simulation** | Injects acute imposter typing anomalies, triggers webcam snapshot, dispatches OTP, and deploys screen lockdown. | Terminal + System Forensics |
| **[`bat/start_real_data_collection.bat`](bat/start_real_data_collection.bat)** | **Telemetry Harvester** | Runs silently in the background capturing genuine daily typing and mouse interactions without workflow lag. | `data/sessions/` |
| **[`bat/train_models.bat`](bat/train_models.bat)** | **Model Retraining** | Retrains Deep SVDD 1D-CNN, OC-SVM, Isolation Forest, and AI Controller baselines. | `models/` & `ml_engine/` |

---

## 🤖 Offline Ollama AI Model Setup (Optional but Recommended)

The Honeypot Forensics module uses a local offline Large Language Model (LLM) to perform Cyber Forensics & Incident Response (DFIR) analysis of attacker honeypot trajectories.

> [!NOTE]  
> If Ollama is not installed or offline, the system **automatically falls back** to an authoritative, rule-based forensic expert heuristic engine. The application will never crash or fail to generate reports.

### Installing and Running Ollama for Live AI Intelligence:
1. Download Ollama for Windows from [https://ollama.com/download](https://ollama.com/download).
2. Install and launch Ollama (runs in system tray on port `11434`).
3. Pull the recommended forensic model in your terminal:
   ```cmd
   # Recommended default model (~3.3 GB):
   ollama pull qwen3.5:4b

   # Lightweight alternative for low-RAM laptops (~1.9 GB):
   ollama pull qwen2.5:3b
   ```
4. Configure your chosen model in `.env`:
   ```env
   OLLAMA_URL=http://localhost:11434
   OLLAMA_MODEL=qwen3.5:4b
   OLLAMA_TIMEOUT=60
   ```

---

## 🐳 Optional Docker Deployment (Cyber-Ops Web Dashboard)

For hosting the Cyber-Ops Web Dashboard in an isolated container:

```cmd
# 1. Build and start the container in detached mode
docker compose up -d --build

# 2. View container logs
docker compose logs -f

# 3. Stop the container
docker compose down
```

The containerized dashboard will be available at [`http://localhost:8000`](http://localhost:8000).

- Persistent evidence and models are mapped via host volumes (`./data` and `./models`).
- Container connects to host Ollama via `http://host.docker.internal:11434`.
- Unprivileged user `appuser` runs the process for security compliance.

---

## 🔒 Configuration & Secret Management

All configuration files use secure template separation:

| Config File | Template Source | Ignored by Git? | Purpose |
| :--- | :--- | :--- | :--- |
| `.env` | [`.env.example`](.env.example) | Yes (`.gitignore`) | Server host/port, webcam index, Ollama settings, master bypass password, SMTP/Telegram credentials. |
| `security/config.json` | [`security/config.json.example`](security/config.json.example) | Yes (`.gitignore`) | Emergency credentials, Gmail SMTP, and Twilio alert configurations. |
| `models/.active_otp` | N/A (Generated at runtime) | Yes (`.gitignore`) | Ephemeral 6-digit session OTP generated during active lockouts. |

### Emergency Recovery Passwords:
- **Master Bypass Password:** `admin` (or `admin123` / `123456`)  
  Can be entered into the Verification Lock Screen or Honeypot Recovery Dialog to instantly restore normal workstation access.
- **Emergency Recovery Hotkey:** `Ctrl + Alt + Shift + U`  
  Spawns the identity verification recovery dialog from within the fullscreen honeypot desktop.
- **Emergency Honeypot Exit:** Press `Escape` twice rapidly (within 1.5s) to exit the honeypot window.

---

## 🧪 Verification & Automated Testing

Verify system health and accuracy at any time using the included test suites:

```cmd
# 1. Pre-Flight Prerequisites Probe (Camera, Ports, Ollama, Models)
python scripts/check_prerequisites.py

# 2. Machine Learning Checkpoint Verification
python tests/verify_models.py

# 3. Comprehensive End-to-End Subsystems Verification (14 Systems)
python scripts/verify_all_components.py

# 4. Full Unit Test Discovery Suite (79 Automated Tests)
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📂 Repository File Structure

```text
Behavioral-Drift-Security/
│
├── telemetry/             # Continuous OS & Environmental Sensing
│   ├── agent.py           # Background hook capturing keystroke timing & cursor kinematics
│   ├── environmental_sensor.py  # BLE smartphone proximity path-loss & network monitor
│   └── evaluator.py       # Quad-factor continuous biometric threat evaluation daemon
│
├── ml_engine/             # Feature Extraction & Deep Learning Models
│   ├── models.py          # One-Class SVM & Isolation Forest classifiers
│   ├── sequence_model.py  # Deep SVDD 1D-CNN temporal keystroke sequence neural net
│   ├── controller.py      # Intra-app cognitive baseline envelopes & task classifiers
│   ├── train.py           # Multi-model training and drift adaptation pipeline
│   ├── trained_models.pkl # Serialized OC-SVM and Isolation Forest model bundle
│   └── data_generator.py  # Micro-session generator and intrusion simulator
│
├── security/              # Concept Drift, Lockout & Dynamic Orchestration
│   ├── drift_detector.py  # Online Hoeffding-bound ADWIN multivariate concept drift
│   ├── risk_orchestrator.py # 3-Tier dynamic threat escalation (Nominal / Toast / Honeypot)
│   ├── lock_handler.py    # PyQt6 screen lock overlay with PIN/master bypass
│   ├── webcam.py          # Silent DirectShow webcam capture & Haar face detector
│   └── otp_service.py     # Multi-channel MFA OTP dispatcher (Email / Telegram / Local)
│
├── deception/             # Sandboxed Honeypot Deception Layer
│   ├── honey_desktop.py   # Full-screen PyQt6 Windows 11 deception desktop overlay
│   ├── decoy_chrome.py    # Decoy browser with fake banking, AWS honey-tokens & recon traps
│   ├── decoy_explorer.py  # Decoy Windows File Explorer with virtual directory hierarchy
│   ├── decoy_notepad.py   # Decoy Notepad with file read/write trapping
│   ├── command_engine.py  # HoneyShell PowerShell cmdlet & diagnostic emulator
│   ├── virtual_fs.py      # In-memory virtual filesystem with audit hooks & honeypot files
│   ├── window_manager.py  # Decoy window focus and z-order manager
│   ├── forensic_tracker.py# Session recorder, file containment & SHA-256 evidence sealing
│   └── ai_intent_analyzer.py # Offline LLM / Ollama DFIR adversary intent classifier
│
├── dashboard/             # Cyber-Ops Web Dashboard & Reporting
│   ├── app.py             # FastAPI WebSocket & REST cyber defense server (Port 8000)
│   ├── forensic_dashboard.py # Forensic incident playback console
│   ├── pdf_generator.py   # Publication-ready DFIR incident report PDF compiler
│   ├── static/            # CSS, JavaScript charts (chart.min.js), and UI assets
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
├── data/                  # Data Stores, Models & Evidence (Ignored except baselines)
│   ├── raw/               # Baseline keystroke and mouse kinematics CSVs
│   ├── sessions/          # Application baseline envelopes & profiles
│   ├── benchmarks/        # Academic CMU benchmark summaries and plots
│   ├── forensics/         # Intruder photos and generated PDF incident reports
│   └── sandbox/           # Quarantined attacker payloads and file modifications
│
├── models/                # Deep SVDD neural network weights (sequence_model.pt) & metadata
├── scripts/               # Academic benchmarking, thesis generation & verification tools
│   ├── check_prerequisites.py     # Pre-flight environment diagnostics probe
│   ├── verify_all_components.py   # End-to-end 14-subsystem test runner
│   ├── harvest_real_telemetry.py  # Field evaluation dataset collector
│   └── benchmark_cmu_dataset.py   # Killourhy & Maxion CMU benchmark protocol
│
├── docs/                  # Project thesis chapters, slides, and architectural diagrams
├── requirements.txt       # Unified Python dependency manifest with environment markers
├── Dockerfile             # Production-ready Dockerfile for Cyber-Ops Web Dashboard
├── docker-compose.yml     # Docker Compose definition with volume mounts & healthcheck
├── .dockerignore          # Excludes host virtualenvs, caches, and evidence from build
├── .env.example           # Comprehensive environment variable configuration template
├── setup.bat              # One-click portable environment setup script (CMD)
├── setup.ps1              # One-click portable environment setup script (PowerShell)
├── start_system.bat       # Production security supervisor launcher
└── README.md              # Project documentation (this file)
```

---

## 🔧 Troubleshooting Common Setup Issues

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **`Python was not found in PATH`** | Python installer ran without "Add to PATH" option. | Reinstall Python from [python.org](https://www.python.org/downloads/) and check **"Add Python to PATH"**, or specify system Python path. |
| **`Port 8000 is currently in use`** | Another application or previous supervisor instance is running on port 8000. | Change `PORT=8080` in `.env`, or terminate the orphaned process via Task Manager (`python.exe` / `uvicorn`). |
| **Webcam returns black frame or warning** | Camera is in use by another app (e.g. Teams, Zoom) or camera index is `1`. | Close competing video apps, or set `WEBCAM_DEVICE_INDEX=1` in `.env`. System continues safely even if camera is offline. |
| **Ollama times out during viva report** | Model is running on CPU and took longer than default timeout. | Set `OLLAMA_TIMEOUT=90` in `.env` or switch to the faster `OLLAMA_MODEL=qwen2.5:3b`. |
| **Lock screen appears and cannot unlock** | Imposter simulation triggered lockout. | Enter master bypass password: `admin` in the PIN box, or press `Ctrl + Alt + Shift + U` for owner recovery. |
| **`docker build` fails on Linux** | Platform-specific dependency without environment marker. | Handled automatically: `requirements.txt` specifies `pywin32>=306; sys_platform == 'win32'`. |

---

## 👥 Project Credits & Academic Attribution

- **Department:** Department of Information Science and Engineering (ISE)
- **Institution:** NMAM Institute of Technology (NMAMIT), Nitte
- **Project Team:** Major Project Team 30
- **Academic Benchmark:** Killourhy & Maxion CMU Keystroke Benchmark (IEEE S&P)
