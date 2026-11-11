# Component Integration Matrix & Repository Inventory

**Project Title:** Behavioral Drift Continuous Authentication & Deception Security  
**Audit Date:** October 2026  
**Auditor:** Senior Software Architect & Cybersecurity Specialist  
**Classification:** Major Project Technical Documentation  

---

## 1. Overview & Decision Taxonomy

This matrix provides an exhaustive, component-by-component technical inventory of the entire repository. Every module, daemon, script, user interface, and model artifact has been audited against the actual source code.

### Action Decision Taxonomy:
- **KEEP**: Component is fully implemented, verified, robust, and correctly placed in the architecture.
- **INTEGRATE**: Component was functional but previously disconnected, obscured, or unreachable from the normal user workflow. Integrated into the supervisor, tray menu, web dashboard, or API.
- **FIX**: Component contained a logic defect, state pollution issue, hardcoded assumption, or security flaw that has been rectified.
- **REFACTOR**: Component was modified for improved modularity, error resilience, or cross-platform safety without altering functionality.
- **RETIRE**: Component is obsolete, duplicated, or superseded (retained in archive or safe fallback if necessary).

---

## 2. Master Component Inventory & Integration Matrix

| Component Path | Core Class / Functions | Primary Purpose | Status | Callers & Entry Points | UI Exposure | Decision | Changes & Integration Notes |
|---|---|---|:---:|---|---|:---:|---|
| [run_system.py](../run_system.py) | `SystemSupervisor`, `WorkerProcess`, `create_shield_icon` | Primary one-click launcher and process supervisor for background workers | Verified | Application entry point (`python run_system.py`) & `VIVA_START.bat` | Windows System Tray (Green Shield) + Browser launcher | **INTEGRATE** | Expanded tray context menu, added supervisor lock/port duplicate prevention, and recursive child shutdown. |
| [telemetry/agent.py](../telemetry/agent.py) | `TelemetryAgent`, `MicroSessionTracker`, `main` | Worker 1 background daemon. Captures keyboard/mouse dynamics, extracts 22+ features (10s windows), writes to journal | Verified | Spawned as Worker 1 by `run_system.py` | Status visible in supervisor & Web Console | **KEEP** | Flushes structured telemetry rows to `telemetry_data.jsonl` every 10 seconds without plaintext keystroke storage. |
| [telemetry/environmental_sensor.py](../telemetry/environmental_sensor.py) | `EnvironmentalSensorMonitor` | Passive BLE proximity & Wi-Fi/VPN environmental context | Verified | Called by `telemetry/agent.py` | Status integrated in risk evaluation | **KEEP** | Cleaned trusted SSID defaults; evaluates network & proximity penalties safely. |
| [telemetry/evaluator.py](../telemetry/evaluator.py) | `ThreatEvaluator`, `start_daemon` | Worker 2 continuous authentication daemon. Multi-scale temporal pooling, stream tailing & breach detection | Verified | Spawned as Worker 2 by `run_system.py` | Spawns PyQt6 verification lock screen on breach | **FIX** | Blacklisted trivial bypasses; synchronized OTP/reset disk IPC; UTF-8 & rotation-safe log tailing. |
| [ml_engine/models.py](../ml_engine/models.py) | `BehavioralModels` | Dual ML inference wrapper: Biometric OC-SVM (RBF) & Context Isolation Forest + mouse baseline | Verified | Imported by `ThreatEvaluator` | Risk gauge visualization on Web & Desktop | **KEEP** | Serialized in `ml_engine/trained_models.pkl`. Per-user mouse median/MAD baselines + robust fallbacks. |
| [ml_engine/sequence_model.py](../ml_engine/sequence_model.py) | `DeepSVDDDetector`, `KeystrokeSequenceCNN` | 1D-CNN PyTorch neural network for raw sequential keystroke embedding verification | Verified | Imported by `ThreatEvaluator` | "Neural Keystroke Signature" card on Web SOC | **KEEP** | Weight 0.35 in fused risk calculation. Model checkpoint verified in `models/sequence_model.pt`. |
| [ml_engine/controller.py](../ml_engine/controller.py) | `BehavioralAIController` | Cognitive context classifier predicting active application transition likelihoods | Verified | Imported by `ThreatEvaluator` | Active Process & Window Title cards on Web SOC | **KEEP** | Tracks user application habits and flags unauthorized administrative reconnaissance tools. |
| [ml_engine/train.py](../ml_engine/train.py) | `train_models`, `adapt_to_verified_drift` | Training pipeline for OC-SVM, Isolation Forest, and online incremental adaptation | Verified | Called during initial setup and after legitimate OTP recovery | None (Backend ML Pipeline) | **KEEP** | Performs legitimate adaptation retraining when owner recovers with valid OTP. |
| [security/drift_detector.py](../security/drift_detector.py) | `MultivariateDriftMonitor` | Formal online ADWIN concept drift monitor tracking multi-feature variance bounds | Verified | Integrated into `ThreatEvaluator` | Drift status badge on Web SOC | **KEEP** | Distinguishes gradual typing fatigue from sudden adversary takeover. |
| [security/risk_orchestrator.py](../security/risk_orchestrator.py) | `DynamicRiskOrchestrator`, `StepUpToastWidget` | 3-tier threat escalation state machine (Tier 1 Silent, Tier 2 Step-Up MFA, Tier 3 Lockdown) | Verified | Integrated into `ThreatEvaluator` | Non-blocking desktop toast widget for Tier 2 challenges | **KEEP** | Gracefully handles step-up MFA failures before escalating to full lockout. |
| [security/lock_handler.py](../security/lock_handler.py) | `VerificationLockScreen`, `launch_verification_lock` | Fullscreen modal security lock screen intercepting keyboard and mouse inputs | Verified | Launched by `evaluator.py` upon Tier 3 breach | Fullscreen Desktop Lock Screen | **FIX** | Removed misleading `(or Master Bypass: admin)` label; gated demo bypass button behind `ALLOW_DEMO_ESCAPE=1`. |
| [security/webcam.py](../security/webcam.py) | `capture_intruder` | Silent intruder facial capture using OpenCV Haar Cascades | Verified | Triggered upon Tier 3 breach escalation | Intruder photo card on Web SOC & Desktop Forensics | **KEEP** | Returns `None` gracefully when camera hardware is unavailable or in headless mode (dashboard/honeypot fall back to desktop snapshot). |
| [security/otp_service.py](../security/otp_service.py) | `generate_otp`, `dispatch_otp` | CSPRNG / RFC 6238 session OTP generator and multi-channel dispatcher (Telegram / Email) | Verified | Triggered upon breach escalation | Dispatches alerts with token redaction in logs | **FIX** | Redacted Telegram tokens in logs and masked console OTP codes. |
| [deception/honey_desktop.py](../deception/honey_desktop.py) | `HoneypotDesktop` | Realistic Windows 11 deception desktop with Taskbar, Start Menu, and decoy apps | Verified | Triggered on 3 failed lock screen OTPs or manual simulation | Fullscreen Windows 11 Desktop GUI | **INTEGRATE** | Connected to Windows System Tray and Web Dashboard launcher button (`POST /api/system/launch_honeypot_gui`). |
| [deception/virtual_fs.py](../deception/virtual_fs.py) | `VirtualFileSystem` | Isolated in-memory/JSON filesystem sandbox trapping attacker file mutations | Verified | Core dependency of `honey_desktop.py` and decoy apps | Decoy Windows Explorer interface | **FIX** | Fixed destructive state wipe on re-seeding; enforced path containment (`safe_sandbox_path`). |
| [deception/decoy_chrome.py](../deception/decoy_chrome.py), [decoy_explorer.py](../deception/decoy_explorer.py), [decoy_notepad.py](../deception/decoy_notepad.py) | `DecoyChrome`, `DecoyExplorer`, `DecoyNotepad`, `VirtualCommandEngine` | Realistic decoy desktop applications trapping credentials, searches, shell commands, and file edits | Verified | Launched inside `HoneypotDesktop` | Windows inside Honeypot Desktop | **KEEP** | Pre-seeded with corporate banking, AWS root keys, and GitHub decoys; contained to sandbox. |
| [deception/forensic_tracker.py](../deception/forensic_tracker.py) | `ForensicTracker`, `get_tracker` | Persistent SQLite/JSONL audit database recording chronological attacker actions & MITRE tags | Verified | Central audit sink for all deception components | Timeline feeds on Web SOC & Desktop Workbench | **KEEP** | Session-isolated forensic chain-of-custody across restarts. |
| [deception/ai_intent_analyzer.py](../deception/ai_intent_analyzer.py) | `IntruderIntentAnalyzer` | Offline AI threat intelligence engine using local Ollama (Qwen/Llama) + heuristic fallback | Verified | Called by Web SOC, Forensic Dashboard, and PDF generator | AI Intel card on Web SOC & Desktop Workbench | **KEEP** | Maps intruder commands, file views, and searches to discrete MITRE ATT&CK tactics. |
| [dashboard/app.py](../dashboard/app.py) | `app`, FastAPI server endpoints | Cyber-Ops Web SOC server (port 8000), real-time WebSockets, REST APIs, and GUI launchers | Verified | Spawned as Worker 3 by `run_system.py` | Browser UI at `http://localhost:8000` | **INTEGRATE** | Enforced verified OTP/recovery reset, removed plaintext OTP API/WS leaks, honest `IDLE`/`LIVE`/`STALE`/`SIMULATED` states. |
| [dashboard/forensic_dashboard.py](../dashboard/forensic_dashboard.py) | `ForensicDashboard` | Native PyQt6 Forensic Analyst Workbench displaying webcam photos, AI persona, and timeline | Verified | Standalone script or Tray / Web SOC launcher | Native PyQt6 Desktop Window | **INTEGRATE** | Exposed directly in System Tray context menu and Web Dashboard launcher button. |
| [dashboard/pdf_generator.py](../dashboard/pdf_generator.py) | `ForensicReportGenerator` | Multi-page executive digital forensic PDF compiler with `fpdf2` and SHA-256 seal | Verified | Triggered via Web SOC button or viva demonstration script | Generates downloadable PDF reports | **KEEP** | Verified multi-page output with embedded webcam photo, charts, and cryptographic digest. |
| [dashboard/templates/index.html](../dashboard/templates/index.html) | HTML5 / Jinja2 Template | Responsive cybersecurity SOC interface with KPIs, dual charts, and verified reset modal | Verified | Rendered by `dashboard/app.py` | Main Web Dashboard layout | **INTEGRATE** | Added desktop launcher buttons and `#resetAuthModal` OTP/Recovery Key verification. |
| [dashboard/static/js/dashboard.js](../dashboard/static/js/dashboard.js) | JavaScript Client | Real-time WebSocket consumer, dual Chart.js animator, and REST API dispatcher | Verified | Loaded by `index.html` | Client-side reactive rendering | **INTEGRATE** | Added DOM-safe logging, honest telemetry state badges, and launcher functions. |
| [demo_viva_runner.py](../demo_viva_runner.py) | `VivaDemoRunner` | 5-stage interactive viva presentation runner with verbal talking points for examiners | Verified | `VIVA_START.bat`, `run_viva_demo.bat`, or System Tray launcher | ANSI Colored Windows Terminal | **INTEGRATE** | Added one-click launch from `VIVA_START.bat` and Windows System Tray menu. |
| [scripts/demonstrate_realistic_honeypot.py](../scripts/demonstrate_realistic_honeypot.py) | Honeypot Walkthrough | 10-stage automated walkthrough of the honeypot deception and digital forensics layer | Verified | CLI command | Console test log | **KEEP** | 10/10 stages validated in automated suite. |
| [scripts/test_end_to_end_forensic_flow.py](../scripts/test_end_to_end_forensic_flow.py) | E2E Integration Suite | 7-stage end-to-end integration test validating baseline -> breach -> deception -> PDF report | Verified | CLI command | Console test log | **KEEP** | End-to-end pipeline validated. |
| [scripts/validate_portability.py](../scripts/validate_portability.py) | Portability Validator | Cross-platform directory, syntax, and dependency checker | Verified | CLI command | Console audit report | **KEEP** | Zero critical failures across portability checks. |

---

## 3. Directory & Artifact Structure

```
Behavioral-Drift-Security/
├── run_system.py                   # Master process supervisor & Windows system tray
├── demo_viva_runner.py             # 5-stage interactive viva demonstration runner
├── telemetry_data.jsonl            # Live IPC event journal between Sensor, Evaluator, and Web
├── data/
│   ├── forensics/                  # Captured webcam photos, forensic JSON, and signed PDFs
│   ├── sandbox/                    # Virtual File System state and trapped breadcrumbs
│   ├── logs/                       # Supervisor redirected stdout/stderr worker logs
│   ├── raw/                        # Baseline keystroke and mouse datasets
│   └── reference/                  # CMU / user benchmark biometrics
├── ml_engine/
│   ├── models.py                   # OC-SVM & Isolation Forest estimators
│   ├── sequence_model.py           # PyTorch Deep SVDD 1D-CNN architecture
│   ├── controller.py               # Cognitive application transition controller
│   ├── train.py                    # Model training and online drift adaptation
│   └── trained_models.pkl          # Serialized production ML checkpoint
├── models/
│   ├── sequence_model.pt           # Deep SVDD trained neural network weights
│   └── .active_otp                 # Ephemeral active session OTP record
├── security/
│   ├── lock_handler.py             # PyQt6 fullscreen verification lock screen
│   ├── risk_orchestrator.py        # 3-tier threat state machine & step-up toast
│   ├── drift_detector.py           # ADWIN multivariate concept drift monitor
│   ├── webcam.py                   # Silent OpenCV intruder facial capture
│   └── otp_service.py              # CSPRNG OTP generator & multi-channel dispatcher
├── deception/
│   ├── honey_desktop.py            # Isolated Windows 11 sandboxed deception desktop
│   ├── virtual_fs.py               # In-memory/JSON Virtual File System sandbox
│   ├── decoy_chrome.py         # Decoy Chrome browser portal
│   ├── decoy_explorer.py       # Decoy Windows Explorer window
│   ├── decoy_notepad.py        # Decoy Notepad editor window
│   ├── command_engine.py       # Sandboxed virtual PowerShell/cmd engine
│   ├── forensic_tracker.py     # Chronological forensic event database
│   └── ai_intent_analyzer.py   # Ollama LLM + heuristic threat intelligence
├── dashboard/
│   ├── app.py                  # FastAPI Web SOC server & REST/WebSocket APIs
│   ├── forensic_dashboard.py   # PyQt6 Desktop Forensic Analyst Workbench
│   ├── pdf_generator.py        # Multi-page fpdf2 PDF compiler with SHA-256 seal
│   ├── templates/index.html    # Responsive Cyber-Ops SOC web interface
│   └── static/                 # CSS, JS, and offline Chart.js visualizers
├── tests/                      # 14+ automated unit and regression test suites
├── scripts/                    # Benchmarking, diagnostic, and demo utilities
└── docs/                       # Architectural reports, matrices, and runbooks
```
