# Standardized Batch Execution Launchers (`bat/`)

This directory contains all verified, production-ready Windows batch scripts for the **Multi-Factor Behavioral Drift Continuous Security** system. All scripts automatically resolve the project root (`..`), detect the active Python virtual environment (`.venv` or `venv`), and support standard execution flags including `--no-pause` and `NO_PAUSE=1`.

---

## Complete Launcher Catalog

| Script | Purpose | Command Line Usage |
| :--- | :--- | :--- |
| **`VIVA_START.bat`** | **Master Coordinated Viva Defense Launcher**<br>The primary one-click entry point for academic examination. Performs pre-flight doctor checks, guards against duplicate daemons, spawns the Unified Supervisor and Web SOC (`http://localhost:8000`) with automatic readiness polling, and runs the interactive 5-stage Viva Runner. | `bat\VIVA_START.bat`<br>`bat\VIVA_START.bat --skip-doctor`<br>`bat\VIVA_START.bat --demo-only` |
| **`setup.bat`** | **One-Click Environment Setup & Dependency Installer**<br>Validates Python 3.10–3.14, configures isolated `.venv`, installs requirements, initializes runtime directories (`data/`, `models/`), safely generates configuration templates, trains baseline models if needed, and runs pre-flight diagnostics. | `bat\setup.bat`<br>`bat\setup.bat --no-pause` |
| **`start_system.bat`** | **Unified System Daemon & SOC Launcher**<br>Convenience alias that starts the full security daemon: low-level OS telemetry hooks, threat evaluator, system tray icon, and live cyber-ops web dashboard on `http://localhost:8000`. | `bat\start_system.bat`<br>`bat\start_system.bat --port 8000` |
| **`run_security_system.bat`** | **Core Security Supervisor Launcher**<br>Direct launcher for `run_system.py`, spawning the security supervisor with configurable arguments (`--port`, `--no-tray`, `--no-browser`). | `bat\run_security_system.bat` |
| **`doctor.bat`** | **Pre-Flight Environment & Diagnostic Doctor**<br>Audits hardware sensors (webcam, mouse, keyboard), network ports (8000), local Ollama LLM service, and Python dependency integrity before launching demonstrations. | `bat\doctor.bat`<br>`bat\doctor.bat --no-pause` |
| **`run_viva_demo.bat`** | **Standalone 5-Stage Live Viva Runner**<br>Runs the 5-stage interactive demonstration console without launching a new supervisor instance (connects to an already running supervisor). | `bat\run_viva_demo.bat` |
| **`simulate_unauthorized_attack.bat`** | **Unauthorized Imposter Intrusion Simulator**<br>Simulates high-velocity behavioral drift anomalies to trigger immediate biometric deviation, webcam snapshot capture, lockdown toast, and honeypot diversion. | `bat\simulate_unauthorized_attack.bat` |
| **`start_real_data_collection.bat`** | **Multi-Application Passive Data Harvester**<br>Runs passive telemetry capture across applications (browsers, IDEs, office suites) to gather baseline keystroke dynamics and mouse kinematics. | `bat\start_real_data_collection.bat` |
| **`train_models.bat`** | **Train & Calibrate Machine Learning Baselines**<br>Extracts behavioral features from telemetry sessions, trains Deep SVDD, Isolation Forest, and One-Class SVM models, and validates checkpoint serialization. | `bat\train_models.bat` |
| **`bootstrap_dataset.bat`** | **Bootstrap Baseline Telemetry**<br>Generates synthetic micro-sessions across varied cognitive task modes and trains initial models (ideal for clean deployments on new presentation machines). | `bat\bootstrap_dataset.bat` |

---

## Standard CLI Options

Every launcher script in this directory respects the following options:

- `--no-pause`: Skips terminal pause on exit (ideal for automated headless scripts and test harnesses).
- `NO_PAUSE=1`: Environment variable alternative to `--no-pause`.
- Custom arguments passed to launchers are transparently forwarded to the underlying Python CLI scripts.
