# Standardized Batch Execution Launchers

This directory contains all verified, production-ready Windows batch scripts for the **Multi-Factor Behavioral Drift Continuous Security** system. All scripts automatically discover the Python virtual environment and set the working directory to the project root.

---

## Launcher Catalog

| Script | Purpose | Usage |
| :--- | :--- | :--- |
| **`setup_environment.bat`** | **One-Click Environment Setup & Dependency Installer**<br>Validates Python, configures virtual environment, installs manifests, initializes runtime folders/configs, and verifies models. | Double-click or run from terminal |
| **`run_viva_demo.bat`** | **Interactive 5-Stage Live Viva Defense Runner**<br>Guides examiners through baseline operations, physical walk-away takeover, Tier 2 step-up toast challenge, Tier 3 honeypot diversion, and offline AI forensic reporting. Includes speaking points. | Double-click or run from terminal |
| **`run_security_system.bat`** | **Production Continuous Security System**<br>Spawns the Unified Process Supervisor, low-level OS telemetry hooks, threat evaluator daemon, system tray icon, and live cyber-ops web dashboard on `http://localhost:8000`. | Double-click or run from terminal |
| **`simulate_unauthorized_attack.bat`** | **Unauthorized Imposter Intrusion Simulator**<br>Injects acute typing anomaly spikes to demonstrate immediate behavioral drift detection, webcam intruder snapshot, screen lockdown, and honeypot diversion. | Double-click or run from terminal |
| **`start_real_data_collection.bat`** | **Multi-Application Passive Data Harvester**<br>Captures real keystroke dynamics, mouse kinematics, and active application context across Chrome, VS Code, terminals, etc., with zero workflow disruption. | Double-click or run from terminal |
| **`train_models.bat`** | **Train & Verify Security Models**<br>Trains Deep SVDD 1D-CNN, One-Class SVM, Isolation Forest, and AI Controller baselines on latest collected sessions, then runs verification tests. | Double-click or run from terminal |
| **`bootstrap_dataset.bat`** | **Bootstrap Baseline Telemetry**<br>Generates 1,200+ micro-sessions across varied cognitive task modes and trains initial models (ideal for clean deployment on new machines). | Double-click or run from terminal |
