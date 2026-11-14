# Final System Repair, Forensic Hardening & Verification Report

**Project Title:** Behavioral Drift Continuous Authentication, Honeypot Deception & Digital Forensics  
**Department:** Information Science & Engineering, NMAMIT  
**Date:** November 2026  
**Status:** **100% Repaired, Hardened, Tested & Verified**

---

## 1. Overview & Objective

This report documents the comprehensive technical investigation, structural repair, forensic hardening, and independent verification of the **Behavioral Drift Security** system.

Prior to this hardening phase, multiple critical integration issues affected system reliability:
1. Deletions and file modifications inside the simulated honeypot failed to appear in forensic reports.
2. Older incident records contaminated newer intrusion timelines when active telemetry was sparse.
3. Thread locks deadlocked under concurrent re-entrant operations.
4. Ollama LLM queries timed out or failed on non-standard model JSON responses without automated service startup.
5. Launching the honeypot desktop from the Web SOC trapped the operator without providing the active session OTP.
6. Batch launchers were split between root forwarders and nested scripts with inconsistent relative path handling.

All defect root causes were systematically identified and fixed at their architectural boundaries. Zero files were rebuilt from scratch; existing telemetry data, trained models, and historical baselines were strictly preserved.

---

## 2. Summary of Subsystem Repairs

### 2.1 Forensic Event Collection & VFS Instrumentation
- **Centralized Event Capture:** Instrumented `VirtualFileSystem` operation boundaries (`write_file`, `delete`, `restore_from_recycle_bin`, `empty_recycle_bin`, `copy`, `move`, `mkdir`) directly, rather than relying on disparate UI click handlers.
- **Pre-Deletion Evidence Preservation:** Captured original virtual path, filename, pre-deletion file size in bytes, and cryptographic SHA-256 digest before unlinking nodes from the in-memory tree.
- **Unified Textual Diffs:** Embedded `difflib.unified_diff` tracking for text file modifications under 64 KB, logging before/after hashes and exact line mutations.
- **Thread Safety Upgrade:** Upgraded `ForensicTracker._write_lock` from a standard non-reentrant mutex to `threading.RLock()`, eliminating thread deadlocks during nested session initialization.
- **Recycle Bin Lifecycle:** Emitted explicit `RESTORE_FILE` and `EMPTY_RECYCLE_BIN` telemetry events.

### 2.2 Strict Session Isolation & Evidence Archiving
- **Incident Identity Propagation:** Assigned globally unique `incident_id` and `session_id` identifiers at honeypot trigger time, propagating them across VFS, ForensicTracker, and PDF generator.
- **Session-Isolated Directory Layout:** Organized forensic storage into `data/forensics/sessions/session_<session_id>/` storing session-specific `events.jsonl` and `file_changes.jsonl`.
- **Zero Cross-Contamination:** Replaced legacy fallbacks in `get_timeline()` and `get_file_changes()` with strict session filtering. An incident with minimal telemetry never inherits historical records from prior intrusions.

### 2.3 Offline Ollama AI Reasoner & Heuristic Fallback
- **Automated Daemon Lifecycle:** Implemented `ensure_service_running()` to automatically detect local `ollama.exe` on Windows (`%LOCALAPPDATA%\Programs\Ollama\ollama.exe`), launch `ollama serve` in the background, and poll HTTP readiness.
- **Compact Model Optimization:** Configured fast lightweight offline models (`qwen2.5:1.5b`, `deepseek-r1:1.5b`) for low-latency CPU/GPU execution (2–6 seconds) on demonstration laptops.
- **Upgraded Timeout:** Expanded query timeout to 35 seconds (configurable via `OLLAMA_TIMEOUT`).
- **Multi-Stage JSON Parser:** Strips `<think>` tags, extracts markdown code fences, and repairs unescaped control characters.
- **Authoritative Deterministic Fallback:** If Ollama is offline or outputs non-compliant text, the deterministic rule engine produces full DFIR assessments with zero crashes.
- **Truthful Minimal-Session Reporting:** Sessions with 1 event report an inconclusive perimeter probe, eliminating false claims of credential harvesting or directory enumeration.

### 2.4 Web Dashboard Recovery & Anti-Trap Protection
- **Session OTP Generation:** `/api/system/launch_honeypot_gui` generates a cryptographic 6-digit session OTP, saves it to `models/.active_otp`, and returns it in the API response.
- **UI Launch Toast:** `dashboard/static/js/dashboard.js` presents the active Recovery OTP directly in the launch toast banner.
- **Non-Blocking Recovery:** Operators can restore the host desktop at any time using the 6-digit OTP, the configured `EMERGENCY_RECOVERY_KEY`, or `Ctrl + Alt + Shift + U` emergency bypass.

### 2.5 Publication-Grade PDF Generator Overhaul
- **Multi-Page Running Headers & Footers:** Configured running headers displaying Case Reference and Confidentiality marks, with dynamic page numbering.
- **Section 5: File & Directory Impact Analysis:**
  * Subsection 5.1: Forensically confirmed file deletions table (Path, Filename, Pre-Size, Pre-Deletion SHA-256 Digest, Source App, Recovery status).
  * Subsection 5.2: Unauthorized file modifications table with rendered monospaced unified diff blocks.
  * Subsection 5.3: Created and downloaded virtual artifacts table.
  * Subsection 5.4: Categorized behavioral observations linked to Event ID citations.
- **Section 7: Risk Assessment Reconciliation:** Reconciled why a host continuous biometric breach (Threshold $\ge 0.55$) diverts into the honeypot where post-diversion intruder activity is assessed on an independent threat floor (0.10 to 1.00).
- **Section 11: Cryptographic Integrity:** Computes point-in-time FIPS 180-4 SHA-256 digests of evidentiary artifacts on local disk.

### 2.6 Centralization of Batch Launchers
- All Windows batch scripts centralized into `bat/` (`bat\VIVA_START.bat`, `bat\setup.bat`, `bat\start_system.bat`, `bat\doctor.bat`, `bat\run_viva_demo.bat`, `bat\train_models.bat`, `bat\simulate_unauthorized_attack.bat`, `bat\start_real_data_collection.bat`, `bat\bootstrap_dataset.bat`).
- Standardized parent directory resolution (`for %%I in ("%~dp0..") do set "PROJECT_DIR=%%~fI"`).
- Removed root forwarders (`doctor.bat`, `run_viva_demo.bat`, `setup.bat`, `start_system.bat`, `VIVA_START.bat`, `bat\setup_environment.bat`).
- Published complete catalog documentation in `bat\README.md` and updated all project documentation.

---

## 3. Verification & Test Results

The entire project test suite was executed via unittest discovery:
```cmd
python -m unittest discover -s tests -p "test_*.py"
```

### Overall Outcome:
- **Total Tests Discovered & Executed:** 121
- **Passed:** 121
- **Failed:** 0
- **Errors:** 0
- **Execution Time:** 108.758s
- **Pass Rate:** **100.0%**

All subsystems—low-level telemetry hooks, Deep SVDD 1D-CNN sequence detection, ADWIN drift adaptation, threat orchestration, honeypot deception desktop, offline Ollama threat analysis, and publication-grade PDF generation—are fully operational and synchronized.
