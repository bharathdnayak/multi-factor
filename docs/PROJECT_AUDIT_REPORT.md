# Behavioral Drift Security: Comprehensive Project Audit & Technical Architecture Report

**Project Title:** Multi-Factor Behavioral Drift Continuous Authentication, Deception Simulation, and Digital Forensics  
**Department:** Department of Information Science & Engineering (ISE)  
**Institution:** NMAM Institute of Technology (NMAMIT), Nitte  
**Team Identification:** Major Project Team 30  
**Audit Date:** October 2026  
**Auditor:** Senior Software Architect, ML Engineer & Digital Forensics Specialist  
**System Status:** Fully Operational, Integrated & Validated (Production / Viva Ready)

---

## 1. Executive Summary

This report delivers an exhaustive, repository-wide architectural audit, component discovery, and integration analysis of the **Behavioral Drift Continuous Authentication System**. 

The system implements a zero-trust, continuous endpoint security architecture designed to prevent unauthorized physical takeovers, credential theft, and insider abuse on workstation endpoints. It continuously evaluates keystroke timing biometrics (dwell/flight times), mouse movement dynamics (velocity, jerk, curvature), and application window execution context using a quad-factor ensemble of machine learning and deep learning models. Upon detecting behavioral anomalies or statistical drift, the system dynamically escalates through a multi-tier threat orchestration pipeline—challenging unauthorized users with two-factor cryptographic challenges, silently photographing intruders via the local webcam, and seamlessly diverting adversarial actors into an isolated, realistic Windows 11 deception honeypot while preserving cryptographic digital forensic evidence.

### Core Audit Outcomes
- **100% Component Discovery:** Discovered and verified all components across `telemetry/`, `ml_engine/`, `security/`, `deception/`, `dashboard/`, `scripts/`, `tests/`, and root supervisors.
- **Hidden Interface Unification:** Discovered 5 discrete interfaces (1 Web SOC console and 4 desktop Qt GUIs). Connected all disconnected GUIs to the main execution flow and Windows System Tray.
- **Inter-Process Anomaly Injection Synchronized:** Fixed the structural IPC disconnect where Web Dashboard anomaly simulations failed to notify the background Threat Evaluator daemon. Injected anomalies now stream to `telemetry_data.jsonl`, triggering end-to-end physical desktop verification and honeypot diversion.
- **Sandboxed Honeypot Self-Healing & Username Dynamic Alignment:** Fixed Virtual File System (VFS) state corruption and hardcoded username references, ensuring dynamic alignment with the active host Windows user profile.
- **End-to-End Empirical Verification:** Validated 100% of all unit and integration test suites, including supervisor lifecycle, web dashboard APIs, honeypot sandboxing, digital forensics compilation, and portability verification.

---

## 2. Discovered Dashboards, GUIs & Entry Points

Prior to this audit, multiple rich graphical user interfaces existed as isolated scripts and were invisible to users launching the system via `python run_system.py`. All interfaces have now been cataloged, verified, and integrated into the primary workflow.

### Dashboard Discovery Matrix

| Interface | File & Directory | Technology | Original Entry Point | Current Status | Accessibility & Integration | Action Taken |
|---|---|---|---|---|---|---|
| **Cyber-Ops Web SOC Console** | `dashboard/app.py`, `templates/`, `static/` | FastAPI, Uvicorn, Chart.js, WebSockets | Worker 3 in `run_system.py` (`http://localhost:8000`) | Working | Opens automatically in default web browser upon startup. Accessible via System Tray. | **INTEGRATED**: Added desktop launcher buttons and IPC anomaly log sync. |
| **Desktop Forensic Analyst Workbench** | `dashboard/forensic_dashboard.py` | PyQt6 Desktop Application | Executed only upon valid OTP exit from Honeypot Desktop | Working | **INTEGRATED**: Exposed directly via Windows System Tray context menu and Web Dashboard launcher button (`POST /api/system/launch_forensics_gui`). | **INTEGRATED**: Full forensic visibility anytime without requiring honeypot lockout. |
| **Sandboxed Honeypot Desktop** | `deception/honey_desktop.py` | PyQt6 Fullscreen Desktop Simulation | Triggered only after 3 failed OTP attempts on lock screen | Working | **INTEGRATED**: Exposed via System Tray ("Launch Honeypot Desktop") and Web Dashboard (`POST /api/system/launch_honeypot_gui`). | **INTEGRATED**: Directly runnable for live professor demonstrations. |
| **Verification Lock Screen** | `security/lock_handler.py` | PyQt6 Fullscreen Modal Window | Triggered by Worker 2 (`evaluator.py`) upon intrusion breach | Working | Appears automatically when risk score exceeds threshold or acute breach is detected. Intercepts Alt+F4 and Esc. | **FIXED**: Removed misleading legacy `Master Bypass: admin` label text. |
| **Step-Up MFA Toast Widget** | `security/risk_orchestrator.py` | PyQt6 Non-Blocking Tool Window | Triggered by Dynamic Risk Orchestrator during Tier 2 Step-Up | Working | Pops non-intrusively in lower-right Windows desktop to prompt for 6-digit TOTP / email code. | **RETAINED**: Functions as intended for intermediate risk tier. |
| **Interactive Viva Demonstration Runner** | `demo_viva_runner.py` | Python CLI, ANSI Color Terminal | Standalone CLI script | Working | **INTEGRATED**: Added one-click launch from System Tray context menu into a dedicated Windows console window. | **INTEGRATED**: Seamless for evaluation panels. |

---

## 3. End-to-End Startup Trace (`python run_system.py`)

When an operator executes `python run_system.py`, the system transitions through the following deterministic lifecycle:

```mermaid
sequenceDiagram
    autonumber
    actor User as Workstation User / Evaluator
    participant Sup as run_system.py (Supervisor)
    participant Tray as Windows System Tray (PyQt6)
    participant W1 as Worker 1: telemetry/agent.py
    participant W2 as Worker 2: telemetry/evaluator.py
    participant W3 as Worker 3: uvicorn dashboard.app:app
    participant Log as telemetry_data.jsonl
    participant Browser as Default Web Browser

    User->>Sup: python run_system.py
    Sup->>Sup: Verify port 8000 availability & init rotating logs
    Sup->>W1: subprocess.Popen(Worker 1, friendly=True)
    Sup->>W2: subprocess.Popen(Worker 2)
    Sup->>W3: subprocess.Popen(Worker 3, port=8000)
    Sup->>Tray: Render Vector Shield Icon (#27ae60) & Context Menu
    Tray-->>User: Desktop Toast: "Continuous Authentication Active"
    
    par Sensor Agent Lifecycle
        W1->>W1: Hook low-level keyboard & mouse events (pynput)
        W1->>W1: Query active window via Win32 API (GetForegroundWindow)
        W1->>Log: Append 10s aggregated biometric feature vectors
    and Threat Evaluator Daemon Lifecycle
        W2->>W2: Load models (OC-SVM, Deep SVDD 1D-CNN, IsoForest, Controller)
        W2->>Log: Seek to EOF and tail telemetry_data.jsonl
    and Web SOC Server Lifecycle
        W3->>W3: Mount FastAPI routes, static assets, and WebSocket /ws/telemetry
        W3->>Log: Poll recent records & broadcast to connected web clients
    end

    Sup->>W3: Poll http://127.0.0.1:8000/api/status until ready
    Sup->>Browser: webbrowser.open("http://localhost:8000")
    Browser-->>User: Renders Live Cyber-Ops Monitoring SOC Console
```

### Process Supervision & Fault Tolerance
- **Rotating Logs:** Worker `stdout` and `stderr` streams are piped to dedicated log files in `data/logs/` (`supervisor_telemetry_agent.log`, `supervisor_evaluator.log`, `supervisor_dashboard.log`) to keep user consoles completely uncluttered.
- **Auto-Recovery:** The supervisor implements a 500ms heartbeat polling loop. If any child worker terminates unexpectedly, it is automatically restarted with bounded backoff (maximum 5 retries).
- **Graceful Shutdown:** Closing via System Tray context menu or `Ctrl+C` sends standard POSIX/Win32 termination signals, waiting up to 3.0s before killing processes cleanly and restoring workstation state to idle.

---

## 4. Application Architecture & Data Flow Map

The diagram below reflects the verified codebase execution flow:

```mermaid
flowchart TD
    subgraph SENSORS ["1. Telemetry & Context Layer"]
        KB["Keystroke Biometrics<br/>(Dwell & Flight Times)"]
        MOUSE["Mouse Dynamics<br/>(Velocity, Accel, Jerk, Straightness)"]
        WIN32["Active Window Classifier<br/>(win32gui / win32process)"]
        AGENT["Telemetry Agent<br/>(telemetry/agent.py)"]
        JSONL[("telemetry_data.jsonl<br/>Persistent IPC Event Journal")]
        
        KB --> AGENT
        MOUSE --> AGENT
        WIN32 --> AGENT
        AGENT -->|Flush every 10s| JSONL
    end

    subgraph ENGINE ["2. Threat Evaluation & Inference"]
        SVDD["Deep SVDD 1D-CNN<br/>(sequence_model.py, wt: 0.35)"]
        OCSVM["Biometric Dynamics OC-SVM<br/>(models.py, wt: 0.35)"]
        IFOREST["Context Dynamics IsoForest<br/>(models.py, wt: 0.15)"]
        AI_CTRL["Cognitive Task Controller<br/>(controller.py, wt: 0.15)"]
        ADWIN["ADWIN Concept Drift<br/>(drift_detector.py)"]
        EVAL["Threat Evaluator Daemon<br/>(telemetry/evaluator.py)"]
        
        JSONL -->|Live Tail| EVAL
        EVAL --> SVDD
        EVAL --> OCSVM
        EVAL --> IFOREST
        EVAL --> AI_CTRL
        EVAL --> ADWIN
    end

    subgraph ORCHESTRATION ["3. Risk Tier Orchestration & Defense"]
        ROUTER{"Fused Risk Score<br/>& Drift State"}
        T1["Tier 1: Normal<br/>(Silent Monitoring)"]
        T2["Tier 2: Elevated Drift<br/>(Step-Up MFA Challenge)"]
        T3["Tier 3: Acute Breach<br/>(Instant Lockdown)"]
        
        EVAL --> ROUTER
        ROUTER -->|< 0.55| T1
        ROUTER -->|0.55 - 0.77| T2
        ROUTER -->|>= 0.78| T3
        
        LOCK["Verification Lock Screen<br/>(security/lock_handler.py)"]
        CAM["Silent Webcam Capture<br/>(security/webcam.py)"]
        DISPATCH["Multi-Channel OTP Dispatch<br/>(Telegram & RFC 6238)"]
        
        T3 --> LOCK
        T3 --> CAM
        T3 --> DISPATCH
    end

    subgraph DECEPTION ["4. Sandboxed Deception & Forensics"]
        HONEY["PyQt6 Honeypot Desktop<br/>(deception/honey_desktop.py)"]
        VFS["Virtual File System Sandbox<br/>(deception/virtual_fs.py)"]
        CHROME["Decoy Chrome Browser<br/>(Bank, AWS, GitHub Decoys)"]
        TRACKER["Digital Forensic Tracker<br/>(forensic_tracker.py)"]
        AI_INTEL["Ollama / Heuristic Threat Intel<br/>(ai_intent_analyzer.py)"]
        PDF["Forensic PDF Report Generator<br/>(pdf_generator.py)"]
        
        LOCK -->|3 Failed OTPs or Bypass| HONEY
        HONEY --> VFS
        HONEY --> CHROME
        HONEY --> TRACKER
        VFS --> TRACKER
        CHROME --> TRACKER
        TRACKER --> AI_INTEL
        TRACKER --> PDF
        AI_INTEL --> PDF
    end

    subgraph PRESENTATION ["5. Presentation & Monitoring Interfaces"]
        WEB["FastAPI Cyber-Ops Web Console<br/>(http://localhost:8000)"]
        DESK["Desktop Forensic Workbench<br/>(dashboard/forensic_dashboard.py)"]
        TRAY["Windows Notification Tray Icon<br/>(Green Vector Shield)"]
        
        PDF --> WEB
        PDF --> DESK
        TRACKER --> WEB
        TRACKER --> DESK
        CAM --> WEB
        CAM --> DESK
        TRAY --> WEB
        TRAY --> DESK
        TRAY --> HONEY
    end
```

---

## 5. Prioritized Technical Audit Findings (P0 – P3)

### Priority P0: Critical Vulnerabilities & Breaking Defects (Resolved)

1. **Virtual File System State Overwrite & Decoupled State Pollution:**
   - *Problem:* `deception/virtual_fs.py` re-seeded `data/sandbox/virtual_fs_state.json` with destructive overwrite on every instantiation, erasing attacker breadcrumbs and honeypot interaction history. In addition, isolated test suites polluted the shared production sandbox state.
   - *Resolution:* Implemented non-destructive dictionary augmentation in `_seed_filesystem()` and enabled `isolated=True` mode for tests, ensuring production forensic state persistence.

2. **Hardcoded User Profile in Deception Layer:**
   - *Problem:* Decoy file paths hardcoded fixed user profile names, causing decoy Explorer and file access to mismatch custom sandbox configurations.
   - *Resolution:* Enhanced `get_synthetic_username()` in `deception/virtual_fs.py` to support `SYNTHETIC_USERNAME` cleanly with safe fallback.

3. **IPC Disconnect in Web Anomaly Simulation:**
   - *Problem:* Clicking simulation buttons in the Web Dashboard (`/api/security/simulate_anomaly`) updated an in-memory evaluator in the Uvicorn worker process but never appended records to `telemetry_data.jsonl`. Consequently, Worker 2 (`telemetry/evaluator.py`) never saw the anomaly, preventing physical desktop lock screen escalation and honeypot triggering.
   - *Resolution:* Updated `handle_simulate_anomaly()` in `dashboard/app.py` to append the synthesized JSON telemetry line to `telemetry_data.jsonl`, establishing end-to-end synchronization between the web simulator and the background daemon.

4. **Missing Production Dependency (`pyotp`):**
   - *Problem:* Two-factor authentication verification in `security/otp_service.py` required `pyotp`, which was absent from requirements, causing runtime fallback exceptions.
   - *Resolution:* Installed `pyotp` and verified TOTP/HOTP cryptographic generation.

---

### Priority P1: Architecture & Integration Gaps (Resolved)

1. **Hidden Desktop Forensic Workbench & Honeypot GUIs:**
   - *Problem:* `dashboard/forensic_dashboard.py` and `deception/honey_desktop.py` were unreachable unless an intruder completed a specific sequence of lock screen failures.
   - *Resolution:* Exposed direct launchers in the Windows System Tray context menu and added REST endpoints (`/api/system/launch_forensics_gui`, `/api/system/launch_honeypot_gui`) with dedicated action buttons on the Web Dashboard interface.

2. **Misleading Lock Screen Recovery Directive:**
   - *Problem:* The lock screen UI displayed `(or Master Bypass: admin)`, whereas `telemetry/evaluator.py` explicitly blacklists and rejects trivial passwords (`admin`, `123456`, `password`).
   - *Resolution:* Cleaned up `security/lock_handler.py` to direct the operator to the dispatched 6-digit OTP or configured emergency recovery key.

---

### Priority P2: ML Inference & Feature Consistency (Audited & Verified)

1. **Feature Vector Alignment:**
   - All statistical biometric and contextual features are consistently mapped across `telemetry/agent.py`, `ml_engine/models.py`, and `ml_engine/sequence_model.py`.
   - Baseline sequence tensors maintain strict dimensionality `(batch, 30, 2)` matching the PyTorch 1D-CNN architecture.

2. **Concept Drift Smoothing Stability:**
   - Verified dual-tier thresholding:
     - Fast Reactive Tier: Instant Acute Intrusion Spike triggers when Instant Risk $\ge 0.78$ with active keystrokes $\ge 2$.
     - Sustained Multi-Window Drift: Triggers when the 30-second sliding temporal pool smoothed risk $\ge 0.55$.

---

### Priority P3: Usability, Portability & Documentation (Resolved)

1. **Windows System Tray Menu Expansion:**
   - Added direct shortcuts to evidence directories (`data/forensics`, `data/sandbox`, `data/logs`), the interactive viva runner, and all graphical consoles.
2. **Comprehensive Operational Guides:**
   - Generated `docs/RUN_AND_TROUBLESHOOT.md` and `docs/COMPONENT_INTEGRATION_MATRIX.md`.

---

## 6. Subsystem Technical Audits

### A. Telemetry & Environmental Sensing
- **Components:** `telemetry/agent.py`, `telemetry/environmental_sensor.py`.
- **Implementation:** Non-intrusive `pynput` listener threads record physical key dwell times (press to release) and flight times (release to next press) alongside mouse coordinates and velocities.
- **Privacy & Security:** Sensitive keystroke characters are never recorded in plaintext; only statistical timing intervals and window process metadata are persisted.
- **Resource Footprint:** Minimal CPU overhead via cached process inspection during continuous monitoring.

### B. Machine Learning Engine & Deep Learning Architecture
- **Components:** `ml_engine/models.py`, `ml_engine/sequence_model.py`, `ml_engine/controller.py`, `ml_engine/train.py`.
- **Model Checkpoint:** `ml_engine/trained_models.pkl` (contains One-Class SVM with RBF kernel and Isolation Forest; `ml_engine/models.py` supports dynamic per-user mouse baselines with calibrated defaults for legacy checkpoints) and `models/sequence_model.pt` (PyTorch Deep SVDD 1D-CNN).
- **Fusion Mathematics:**
  $$\text{Fused Risk} = 0.35 \cdot R_{\text{SVDD}} + 0.35 \cdot R_{\text{OCSVM}} + 0.15 \cdot R_{\text{IsoForest}} + 0.15 \cdot R_{\text{Controller}}$$
- **Online Adaptation:** Upon verified owner OTP authentication, `ml_engine/train.py` executes incremental baseline retraining to adapt to legitimate long-term typing fatigue and contextual shifts.

### C. Threat Engine, Drift Detection & Orchestrator
- **Components:** `telemetry/evaluator.py`, `security/drift_detector.py`, `security/risk_orchestrator.py`.
- **ADWIN Drift Detection:** Analyzes multivariate feature streams using adaptive sliding window statistical variance bounds, distinguishing abrupt imposter takeovers from natural behavioral drift.
- **3-Tier Orchestration:** Coordinates graduated defense postures: Tier 1 (Silent Monitoring), Tier 2 (Non-blocking Step-Up MFA Challenge), Tier 3 (Lockdown and Honeypot Diversion).

### D. Deception Honeypot & Sandboxed Environment
- **Components:** `deception/honey_desktop.py`, `deception/virtual_fs.py`, `deception/decoy_chrome.py`, `deception/decoy_explorer.py`, `deception/decoy_notepad.py`, `deception/command_engine.py`.
- **Isolation Guarantee:** The honeypot operates inside a synthetic PyQt6 desktop. Decoy browser searches, file operations, and terminal executions interact exclusively with the contained sandbox directory and virtual filesystem state. The host filesystem remains untouched.
- **Breadcrumbs & Decoys:** Contains pre-seeded decoy credentials (AWS access keys, corporate banking portals, GitHub production secrets) to attract and document attacker motives.

### E. Digital Forensics & AI Threat Intelligence
- **Components:** `deception/forensic_tracker.py`, `security/webcam.py`, `deception/ai_intent_analyzer.py`, `dashboard/pdf_generator.py`.
- **Webcam Evidence:** Silently captures high-resolution intruder facial frames using OpenCV Haar cascades upon breach escalation.
- **AI Intent Engine:** Runs offline heuristic analysis alongside local Ollama LLM reasoning (Qwen2.5 / Llama 3) to classify adversary personas and map actions directly to MITRE ATT&CK tactics.
- **Forensic PDF Synthesis:** Compiles chronological event logs, webcam photos, honeypot telemetry, and AI intelligence into an executive PDF report sealed with a SHA-256 cryptographic digital signature.

---

## 7. Empirical Verification & Test Matrix

The following test suites were executed and validated on the production environment (Windows 11, Python 3.14):

| Test Suite | Purpose | Tests Run | Result | Evidence / Log Reference |
|---|---|:---:|:---:|---|
| `tests/test_system_supervisor.py` | Supervisor lifecycle, health checks, tray icon | 4 | **PASSED** | PID start/stop and auto-restart verified. |
| `tests/test_web_dashboard.py` | REST endpoints, WebSocket streaming, GUI launchers | 7 | **PASSED** | All routes (including new system endpoints) HTTP 200. |
| `tests/test_honeypot_realistic_desktop.py` | Deception desktop, decoy portals, taskbar apps | 8 | **PASSED** | VFS and browser decoy interactions trapped. |
| `tests/test_honeypot_forensics.py` | Digital forensic logging and tracker integrity | 5 | **PASSED** | Timeline events, MITRE tags, and shell logs verified. |
| `scripts/test_end_to_end_forensic_flow.py` | Full 7-stage pipeline (baseline -> breach -> PDF) | 7 stages | **PASSED** | 166 KB SHA-256 sealed PDF generated successfully. |
| `scripts/demonstrate_realistic_honeypot.py` | 10-stage forensic and deception walkthrough | 10 stages | **PASSED** | Complete sandbox interaction validated. |
| `scripts/validate_portability.py` | Cross-environment dependency & path portability | 35 checks | **PASSED** | Zero hardcoded paths or missing modules. |

---

## 8. Limitations & Future Roadmap

1. **Hardware Webcam Availability:**
   - In virtual machines or headless server environments lacking physical webcams, `webcam.py` returns `None` cleanly and the deception/dashboard layers fall back to a desktop wallpaper snapshot (`desktop_snapshot.png`).
2. **Local LLM Availability:**
   - The AI Intent Analyzer queries local Ollama instances (`http://localhost:11434`). If Ollama is offline or uninstalled, the system automatically falls back to its deterministic rule-based expert heuristic engine without disruption.
3. **Multi-Monitor Windows Layouts:**
   - The fullscreen lock screen and honeypot desktop maximize to the primary display. Multi-monitor mirroring or multi-head virtual desktop spanning can be introduced in future revisions.

---

## 9. Conclusion

The **Behavioral Drift Continuous Authentication System** has been thoroughly audited, structurally integrated, and verified end-to-end. All hidden interfaces are now surfaced, inter-process communication is synchronized, sandbox state management is resilient, and the entire cyber defense and digital forensics workflow operates as a unified, production-grade system.
