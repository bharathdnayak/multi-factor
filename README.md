# Multi-Factor Behavioral Drift Security

Continuous authentication system utilizing keystroke dynamics, mouse trajectory dynamics, and context-based anomaly detection.

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
