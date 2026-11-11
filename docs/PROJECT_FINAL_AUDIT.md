# Final Project-Wide Architectural Audit & Verification Report

**Project Title:** Multi-Factor Behavioral Drift Continuous Authentication, Deception Simulation, and Digital Forensics  
**Department:** Department of Information Science & Engineering (ISE)  
**Institution:** NMAM Institute of Technology (NMAMIT), Nitte  
**Team Identification:** Major Project Team 30  
**Audit Timestamp:** October 2026  
**Auditor:** Senior Software Architect, ML Engineer, Full-Stack Developer & DFIR Specialist  
**Verification Level:** Rigorous End-to-End Dynamic Execution (Zero-Assumption Protocol)  

---

## 1. Executive Summary & Verification Verdict

This audit report represents the definitive, presentation-ready architectural assessment of the **Behavioral Drift Security** project prior to academic defense and project evaluation.

The system is a zero-trust continuous authentication endpoint defense solution. It continuously captures low-level timing intervals from physical keystrokes (dwell/flight) and mouse dynamics (velocity, acceleration, jerk, curvature) along with active application execution context. These signals are continuously streamed into a quad-factor ensemble comprising a PyTorch Deep SVDD 1D-CNN temporal sequence model, a Biometric Dynamics One-Class SVM, a Context Dynamics Isolation Forest, and an AI Cognitive Controller. Upon detecting statistical behavioral drift or acute intruder spikes, the system dynamically orchestrates defense actions: dispatching multi-channel cryptographic two-factor alerts, capturing silent optical snapshots of the intruder, and seamlessly diverting adversarial actors into an isolated, realistic Windows 11 deception honeypot with pre-seeded decoy credentials.

### Overall Verification Verdict: **PASS — OPERATIONAL & VERIFIED**
- **Core Subsystems Verified:** Evaluated via [`scripts/verify_all_components.py`](../scripts/verify_all_components.py) and `unittest` suite.
- **5 Coordinated Interfaces Integrated:** All graphical dashboards (Web SOC, Desktop Forensics Workbench, Honeypot Desktop, Lock Screen, Toast Widget) connected and surfaced.
- **Launchers Audited:** Every root and `bat/` launcher (`VIVA_START.bat`, `start_system.bat`, `run_viva_demo.bat`, `doctor.bat`, `setup.bat`, `setup.ps1`, and `bat/*.bat`) verified.

---

## 2. Initial Repository State & State Protection Audit

1. **Existing Improvements Preserved:** Prior improvements in honeypot self-healing ([`deception/virtual_fs.py`](../deception/virtual_fs.py)), dynamic synthetic username resolution, sandbox containment, and report sanitization were audited, preserved, and regression-tested.
2. **Safe Persistent State Protection:** Persistent runtime state (`data/sandbox/virtual_fs_state.json`, `data/forensics/`, `models/`, `data/sessions/`) was preserved cleanly without test pollution via isolated temporary directories.
3. **Dependency Manifest Verification:** Confirmed dependencies declared in [`requirements.txt`](../requirements.txt) are installed cleanly in `.venv`.

---

## 3. Complete Component Inventory & Classification

Every module across the project has been dynamically executed, tested, and classified:

| Subsystem / Component | Path | Purpose | Execution Status | Evidence / Test Suite |
|---|---|---|:---:|---|
| **Process Supervisor** | [`run_system.py`](../run_system.py) | Master 3-worker process supervisor, lock guard & Windows notification tray manager | **PASS** | [`tests/test_system_supervisor.py`](../tests/test_system_supervisor.py) |
| **Telemetry & Context Agent** | [`telemetry/agent.py`](../telemetry/agent.py) | Worker 1 low-level `pynput` hooks, 22+ feature extraction, and JSONL output | **PASS** | [`tests/test_collector.py`](../tests/test_collector.py) |
| **Environmental Sensor** | [`telemetry/environmental_sensor.py`](../telemetry/environmental_sensor.py) | BLE proximity & Wi-Fi/VPN ambient context sensor | **PASS** | [`tests/test_bug_hunt_regressions.py`](../tests/test_bug_hunt_regressions.py) |
| **Threat Evaluator Daemon** | [`telemetry/evaluator.py`](../telemetry/evaluator.py) | Worker 2 continuous quad-factor model scoring, cross-process sync & breach trigger | **PASS** | [`tests/test_bug_hunt_regressions.py`](../tests/test_bug_hunt_regressions.py) |
| **Biometric ML Models** | [`ml_engine/models.py`](../ml_engine/models.py) | One-Class SVM (RBF) & Context Isolation Forest wrappers + mouse baseline | **PASS** | [`tests/verify_models.py`](../tests/verify_models.py) |
| **Deep Sequence Model** | [`ml_engine/sequence_model.py`](../ml_engine/sequence_model.py) | PyTorch Deep SVDD 1D-CNN temporal sequence biometric detector | **PASS** | [`tests/verify_models.py`](../tests/verify_models.py) |
| **Cognitive Controller** | [`ml_engine/controller.py`](../ml_engine/controller.py) | User workflow & application transition likelihood model | **PASS** | Evaluated in component verification |
| **Online Adaptation** | [`ml_engine/train.py`](../ml_engine/train.py) | Baseline model training and post-recovery adaptation retraining | **PASS** | Validated in training & adaptation tests |
| **ADWIN Drift Monitor** | [`security/drift_detector.py`](../security/drift_detector.py) | Formal online adaptive sliding window statistical concept drift detection | **PASS** | [`tests/test_adwin_drift.py`](../tests/test_adwin_drift.py) |
| **Risk Orchestrator** | [`security/risk_orchestrator.py`](../security/risk_orchestrator.py) | 3-tier threat state machine (Silent -> Step-Up -> Lockdown) | **PASS** | [`tests/test_risk_orchestration.py`](../tests/test_risk_orchestration.py) |
| **Verification Lock Screen** | [`security/lock_handler.py`](../security/lock_handler.py) | Fullscreen modal security lock screen with gated demo shortcut | **PASS** | [`tests/test_deception_layer.py`](../tests/test_deception_layer.py) |
| **Optical Webcam Capture** | [`security/webcam.py`](../security/webcam.py) | Silent Haar-cascade intruder facial capture with screen fallback | **PASS** | Saved `intruder_*.jpg` frame capture |
| **OTP Service** | [`security/otp_service.py`](../security/otp_service.py) | CSPRNG / RFC 6238 OTP generator & Telegram/SMTP dispatcher (redacted logs) | **PASS** | [`tests/test_otp_and_recovery.py`](../tests/test_otp_and_recovery.py) |
| **Honeypot Desktop** | [`deception/honey_desktop.py`](../deception/honey_desktop.py) | Fullscreen realistic Windows 11 deception desktop with authenticated unlock | **PASS** | [`tests/test_honeypot_realistic_desktop.py`](../tests/test_honeypot_realistic_desktop.py) |
| **Virtual File System** | [`deception/virtual_fs.py`](../deception/virtual_fs.py) | Resilient in-memory/JSON VFS sandbox with traversal containment | **PASS** | [`tests/test_virtual_environment.py`](../tests/test_virtual_environment.py) |
| **Decoy Applications** | [`deception/decoy_chrome.py`](../deception/decoy_chrome.py), [`deception/decoy_explorer.py`](../deception/decoy_explorer.py), [`deception/decoy_notepad.py`](../deception/decoy_notepad.py) | Decoy Chrome, Decoy Explorer, Decoy Notepad & virtual shell engine | **PASS** | [`tests/test_decoy_portals.py`](../tests/test_decoy_portals.py) |
| **Forensic Tracker** | [`deception/forensic_tracker.py`](../deception/forensic_tracker.py) | Central audit database recording chronological attacker actions & MITRE tags | **PASS** | [`tests/test_honeypot_forensics.py`](../tests/test_honeypot_forensics.py) |
| **AI Intent Analyzer** | [`deception/ai_intent_analyzer.py`](../deception/ai_intent_analyzer.py) | Local Ollama LLM + expert heuristic rule classifier | **PASS** | Classified adversary persona and MITRE tactics |
| **Cyber-Ops Web SOC** | [`dashboard/app.py`](../dashboard/app.py) | FastAPI Uvicorn server, WebSocket streaming, REST APIs & verified reset | **PASS** | [`tests/test_web_dashboard.py`](../tests/test_web_dashboard.py) |
| **Desktop Forensics App** | [`dashboard/forensic_dashboard.py`](../dashboard/forensic_dashboard.py) | Native PyQt6 Desktop Forensic Analyst Workbench | **PASS** | Connected to Tray & Web SOC launcher API |
| **DFIR PDF Compiler** | [`dashboard/pdf_generator.py`](../dashboard/pdf_generator.py) | Multi-page executive forensic `fpdf2` generator with SHA-256 seal | **PASS** | [`tests/test_forensic_report_engine.py`](../tests/test_forensic_report_engine.py) |
| **Viva Demo Runner** | [`demo_viva_runner.py`](../demo_viva_runner.py) | 5-stage interactive viva presentation runner with talking points | **PASS** | [`tests/test_demo_viva_runner.py`](../tests/test_demo_viva_runner.py) |
| **Pre-Flight Doctor** | [`scripts/check_prerequisites.py`](../scripts/check_prerequisites.py) | Diagnostic validator for OS, models, ports, camera, and disk space | **PASS** | Ran via `doctor.bat` |
| **Portability Suite** | [`scripts/validate_portability.py`](../scripts/validate_portability.py) | Cross-environment dependency, link, and directory auditor | **PASS** | Executed with zero FAIL results |

---

## 4. End-to-End Pipeline Verification Results

### Pipeline A: Startup & Process Supervision
- **Command:** `VIVA_START.bat --no-pause --skip-doctor --no-browser --no-tray --port 8094 --auto-stop 2.0` / `python run_system.py --no-browser --no-tray --auto-stop 2.0`
- **Result:** **PASS**. Worker 1 (`telemetry/agent.py`), Worker 2 (`telemetry/evaluator.py`), and Worker 3 (`uvicorn dashboard.app:app`) spawn cleanly with duplicate-lock/port guard and clean child tree shutdown.

### Pipeline B: Telemetry Collection & Feature Extraction
- **Result:** **PASS**. `pynput` hooks capture key press/release timing without logging raw plaintext keystrokes. Idle windows evaluate neutrally.

### Pipeline C: Machine Learning Inference
- **Result:** **PASS**. Verified in [`tests/verify_models.py`](../tests/verify_models.py). Deep SVDD 1D-CNN, Biometric OC-SVM, and Context Isolation Forest load cleanly and separate owner vs imposter windows.

### Pipeline D: Risk Evaluation & Concept Drift
- **Result:** **PASS**. Fused risk, Tier 2 step-up MFA, ADWIN concept drift monitoring, and Tier 3 acute lockdown operate across worker boundaries.

### Pipeline E: Authentication & Incident Response
- **Result:** **PASS**. Upon Tier 3 breach, a CSPRNG 6-digit session OTP is written to `models/.active_otp` with 300s TTL (never leaked in plaintext on `/api/status` or WS).

### Pipeline F: Honeypot Desktop & Sandbox
- **Result:** **PASS**. Failing 3 OTP attempts transitions to the fullscreen Windows 11 Honeypot Desktop. File operations, Chrome searches, and notepad modifications stay contained inside the sandbox.

### Pipeline G: Forensic Recording & AI Analysis
- **Result:** **PASS**. Trapped actions are recorded with session isolation in `ForensicTracker`. The AI Intent Analyzer maps observed evidence dynamically with deterministic heuristic fallback when Ollama is offline.

### Pipeline H: Digital Forensic Report Generation
- **Result:** **PASS**. [`dashboard/pdf_generator.py`](../dashboard/pdf_generator.py) synthesizes an executive multi-page PDF containing captured intruder photo, risk trajectory, MITRE ATT&CK mapping, and SHA-256 digital seal.

### Pipeline I: Dashboard & Backend Integration
- **Result:** **PASS**. Real-time WebSocket `/ws/telemetry` streams live events cleanly. Reset endpoints enforce OTP/Emergency Recovery Key authentication.

### Pipeline J: Demonstration Workflow
- **Result:** **PASS**. Validated end-to-end via [`demo_viva_runner.py`](../demo_viva_runner.py) and [`scripts/test_end_to_end_forensic_flow.py`](../scripts/test_end_to_end_forensic_flow.py).

---

## 5. Security & Privacy Audit Findings

1. **Keystroke Privacy:** Verified that raw typed text is never stored in log files or transmitted over APIs; only timing intervals (dwell/flight) and statistical moments are captured.
2. **Credential Blacklisting:** Verified that trivial passwords (`admin`, `123456`, `password`, `root`) are blacklisted in [`telemetry/evaluator.py`](../telemetry/evaluator.py).
3. **Sandbox Escape Prevention:** Verified that honeypot shell commands and virtual file operations remain strictly contained in the sandbox directory and virtual filesystem state.

---

## 6. Environmental Limitations & Graceful Fallbacks

- **Hardware Camera:** If a physical webcam is unavailable or locked by another application, `security/webcam.py` returns `None` cleanly while the deception/dashboard layers fall back to a desktop wallpaper snapshot (`desktop_snapshot.png`) for forensic synthesis.
- **Local LLM Daemon:** If Ollama (`localhost:11434`) is offline, the AI Intent Analyzer engages its rule-based expert heuristic engine, generating complete MITRE ATT&CK classifications without error.
- **Multi-Monitor Layouts:** The verification lock screen and honeypot maximize to the primary Windows display.
