# System Component Inventory

**Project:** Behavioral Drift — Continuous Authentication & Honeypot Forensics  
**Department:** Department of Information Science and Engineering, NMAMIT  
**Audit Date:** 2026-10-11  
**Role:** Senior Blue-Team / Defensive Security Engineer Inspection

---

## 1. Executive Summary

This inventory maps all operational subsystems, launchers, background workers, machine learning pipelines, deception mechanisms, and diagnostic entry points within the Behavioral Drift project. Every component is evaluated for purpose, dependencies, execution mechanism, input/output contracts, failure handling, and operational status.

---

## 2. Component Inventory Matrix

| ID | Component Name | Primary File | Invocation Launcher | Dependencies / Prerequisites | Process / Service Type | Security Role / Scope | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CMP-01** | **One-Click Supervisor** | `run_system.py` | `start_system.bat`, `bat/run_security_system.bat` | Python 3.10+, PyQt6, psutil, uvicorn | Foreground Supervisor + Windows Tray | Core service orchestrator, health monitor, process lifecycle | **OPERATIONAL** |
| **CMP-02** | **Telemetry Harvester** | `telemetry/agent.py` | `bat/start_real_data_collection.bat`, Supervised | pynput, psutil, pygetwindow | Background Worker / CLI | Least-privilege keystroke/mouse/context feature extraction | **OPERATIONAL** |
| **CMP-03** | **Threat Evaluator Daemon** | `telemetry/evaluator.py` | Supervised by `run_system.py`, CLI | `ml_engine/trained_models.pkl`, PyTorch SVDD | Background Daemon | Continuous multimodal fusion, ADWIN drift detection, alert trigger | **OPERATIONAL** |
| **CMP-04** | **Cyber-Ops SOC Web Console**| `dashboard/app.py` | Supervised by `run_system.py` (`uvicorn`) | FastAPI, uvicorn, websockets | HTTP / WebSocket Service (Port 8000) | SOC telemetry visualization, risk stream, manual step-up verification | **OPERATIONAL** |
| **CMP-05** | **ML Engine Trainer** | `ml_engine/train.py` | `bat/train_models.bat` | scikit-learn, joblib, PyTorch, telemetry sessions | Batch CLI Process | Fits OC-SVM, Isolation Forest, Deep SVDD 1D-CNN, builds app baselines | **OPERATIONAL** |
| **CMP-06** | **Dataset Bootstrapper** | `ml_engine/data_generator.py`| `bat/bootstrap_dataset.bat` | numpy, pandas | Batch CLI Process | Generates verified multi-application micro-session envelopes | **OPERATIONAL** |
| **CMP-07** | **Dynamic Risk Orchestrator**| `security/risk_orchestrator.py`| Embedded in `evaluator.py` & `app.py` | Python stdlib | In-process State Machine | 3-Tier policy gating (Nominal -> Step-Up MFA -> Full Lockdown) | **OPERATIONAL** |
| **CMP-08** | **Hardened OTP & Recovery** | `security/otp_service.py` | Embedded in `evaluator.py` & `lock_handler.py`| `models/.active_otp`, `security/config.json` | In-process Security Module | Constant-time HMAC verification, lockout brute-force defense | **OPERATIONAL** |
| **CMP-09** | **Verification Lockout UI** | `security/lock_handler.py` | Triggered by `evaluator.py` on breach | PyQt6, opencv-python (silent capture) | Full-screen GUI Lockout Overlay | Workstation containment, silent webcam photo, PIN challenge | **OPERATIONAL** |
| **CMP-10** | **Deception Honeypot Desktop**| `deception/honey_desktop.py`| Spawned on breach by lock handler | PyQt6, `deception/virtual_fs.py`, `command_engine.py`| Sandboxed Desktop GUI | High-interaction deception sandbox, honey-files, decoy command shell | **OPERATIONAL** |
| **CMP-11** | **Decoy Chrome Portal** | `deception/decoy_chrome.py` | Launched from Honey Desktop | PyQt6, QWebEngine / mock HTML | Sandboxed Browser GUI | Honey-tokens: NetBanking, AWS root keys, GitHub secrets traps | **OPERATIONAL** |
| **CMP-12** | **Virtual Filesystem Sandbox**| `deception/virtual_fs.py` | Embedded in Honey Desktop / HoneyShell | `data/sandbox/` storage | In-process Virtual VFS | Strict file isolation: prevents read/write to real host OS | **OPERATIONAL** |
| **CMP-13** | **Decoy Command Engine** | `deception/command_engine.py`| Embedded in `HoneyShell` | Python stdlib | In-process Command Parser | Simulates PowerShell/cmdlet recon; blocks arbitrary host execution | **OPERATIONAL** |
| **CMP-14** | **Forensic Audit Tracker** | `deception/forensic_tracker.py`| Singleton across deception layer | `data/forensics/honeypot_events.jsonl` | In-process Forensic Journal | Non-repudiation JSONL audit logging, hash seals, tamper detection | **OPERATIONAL** |
| **CMP-15** | **Offline AI Intent Engine** | `deception/ai_intent_analyzer.py`| Invoked by `pdf_generator.py` & Viva Runner | Ollama daemon (`http://localhost:11434`) | Local LLM Client + Rule Heuristics| Profiles attacker persona, intent, MITRE ATT&CK tactics (air-gapped) | **OPERATIONAL** |
| **CMP-16** | **Forensic Report Generator**| `dashboard/pdf_generator.py` | Invoked on recovery, Viva Runner, SOC | ReportLab, PIL, `data/forensics/` | Document Compiler | Generates cryptographically sealed multi-page incident PDF | **OPERATIONAL** |
| **CMP-17** | **Interactive Viva Runner** | `demo_viva_runner.py` | `run_viva_demo.bat`, `bat/run_viva_demo.bat` | All subsystems | Interactive 5-Stage Demo Runner | Complete academic/defense evaluation sequence with talking points | **OPERATIONAL** |
| **CMP-18** | **Intrusion Simulator** | `scripts/simulate_unauthorized_attack.py`| `bat/simulate_unauthorized_attack.bat` | `telemetry/evaluator.py` | Automated CLI Attack Injector | Injects fast/erratic biometric anomalies to trigger defense | **OPERATIONAL** |
| **CMP-19** | **Preflight Doctor / Checks** | `scripts/check_prerequisites.py`| `setup.bat`, `setup.ps1`, `doctor.bat` | Python stdlib, socket, shutil | Diagnostic Utility | 10 preflight checks: Python, dependencies, models, ports, camera | **OPERATIONAL** |
| **CMP-20** | **Full Verification Suite** | `scripts/verify_all_components.py`| Manual CLI / Test pipeline | PyQt6, unittest, PIL, torchvision | Diagnostic Test Runner | 14-point end-to-end component verification suite | **OPERATIONAL** |

---

## 3. Directory & Artifact Mapping

* **`bat/`**: Dedicated directory containing consolidated, path-safe Windows batch launchers.
* **`dashboard/`**: FastAPI web dashboard, templates, static web assets, and PDF forensic generator.
* **`data/`**: Runtime storage containing sessions, raw data, forensics, sandboxed VFS, and harvested datasets.
* **`deception/`**: Deception layer containing honey desktop, decoy browser, virtual filesystem, and AI intent analyzer.
* **`docs/`**: Architecture documentation, academic thesis chapters, and viva presentation slides.
* **`ml_engine/`**: Core machine learning models, sequence deep learning models, training scripts, and benchmarks.
* **`models/`**: Serialized PyTorch sequence models, metadata, and active OTP state files.
* **`reports/`**: Academic and independent verification audit reports.
* **`scripts/`**: Automation scripts, attack simulators, dataset harvesters, and diagnostic utilities.
* **`security/`**: Policy orchestration, concept drift monitoring, OTP service, webcam capture, and lock handler.
* **`telemetry/`**: Real-time agent harvesting, feature extraction, environmental sensors, and threat evaluator.
* **`tests/`**: Unit, integration, and regression test suites.
