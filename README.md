# Multi-Factor Behavioral Drift Security

Continuous authentication system combining keystroke dynamics, mouse kinematics, intra-app cognitive context, environmental BLE smartphone proximity, ADWIN online concept drift detection, 3-tier dynamic risk orchestration, and active sandboxed deception honeypots.

## Quick Start & Execution Launchers (`bat/`)

All execution batch scripts are organized inside the [`bat/`](bat/) directory:

| Launcher | Purpose |
| :--- | :--- |
| [`bat/run_viva_demo.bat`](bat/run_viva_demo.bat) | **Live Viva Demonstration Runner:** 5-stage interactive demonstration for examiners and guides. |
| [`bat/run_security_system.bat`](bat/run_security_system.bat) | **Production Security Daemon:** Spawns supervisor, background hooks, threat daemon, tray icon, and web dashboard (`http://localhost:8000`). |
| [`bat/simulate_unauthorized_attack.bat`](bat/simulate_unauthorized_attack.bat) | **Attack Simulator:** Injects imposter telemetry, triggers lockdown, webcam capture, and honeypot diversion. |
| [`bat/start_real_data_collection.bat`](bat/start_real_data_collection.bat) | **Passive Harvester:** Collects real telemetry across daily applications. |
| [`bat/train_models.bat`](bat/train_models.bat) | **Train Models:** Retrains Deep SVDD, OC-SVM, Isolation Forest, and baselines. |
| [`bat/bootstrap_dataset.bat`](bat/bootstrap_dataset.bat) | **Bootstrap Data:** Generates 1,200 baseline micro-sessions on fresh machines. |

## Project Structure

This project is divided into four main modules corresponding to each team member's role:

```text
Behavioral-Drift-Security/
│
├── telemetry/             # Member 1: Telemetry Data Collection
│   ├── __init__.py
│   └── agent.py           # Background agent capturing mouse & keystroke events
│
├── ml_engine/             # Member 2: Feature Extraction & ML Models
│   ├── __init__.py
│   ├── models.py          # OC-SVM & Isolation Forest model definitions
│   └── train.py           # Model training and baseline establishment script
│
├── security/              # Member 3: Concept Drift & Lock Mechanism
│   ├── __init__.py
│   ├── drift_detector.py  # ADWIN/concept drift calculation & threshold logic
│   └── lock_handler.py    # Simulated lock screen & MFA triggers
│
├── dashboard/             # Member 4: Real-time Visualization & Server
│   ├── __init__.py
│   ├── app.py             # Flask/FastAPI backend websocket server
│   ├── static/            # Frontend assets (CSS, JS, Charts)
│   └── templates/         # HTML dashboards
│
├── requirements.txt       # Shared project dependencies
└── README.md              # Project overview (this file)
```
