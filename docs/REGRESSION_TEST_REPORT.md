# Regression Test Verification Report

**Project:** Behavioral Drift Security  
**Execution Environment:** Windows 11 (`win32`), Python `3.14.3` (`.venv\Scripts\python.exe`)  
**Verification Date:** 2026-11-11

---

## 1. Automated Unit & Integration Test Discovery

Executed after all production and test edits cleanly without any skipped or relaxed assertions:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

- **Result:** `Ran 110 tests in 74.281s — OK` (**110 Passed, 0 Failed, 0 Skipped**)
- **Covered Modules (`22` test modules):**
  - `test_adwin_drift.py` (5 tests): ADWIN stationary stability, gradual drift, abrupt shift, multivariate monitor, evaluator integration.
  - `test_bug_hunt_regressions.py` (12 new regression tests):
    - `test_01_sandbox_path_helpers_and_traversal_blocking` (host read/write traversal containment in `command_engine`, `decoy_chrome`, `decoy_notepad`, `virtual_fs`)
    - `test_02_honeypot_exit_requires_authentication_by_default` (`emergency_exit` & Double-Escape blocked without auth unless `ALLOW_DEMO_ESCAPE=1`)
    - `test_03_dashboard_reset_auth_no_otp_leak_and_ai_intel` (HTTP 403 on `'admin'`/empty reset, no plaintext `active_otp` leak, real `ai_analysis` output, HTTP 200 on valid OTP)
    - `test_04_telemetry_streamer_truncation_and_partial_line_safety` (incomplete JSONL buffering & equal-length file rewrite detection)
    - `test_05_dynamic_mouse_baseline_save_load_and_legacy_fallback` (custom mouse median/MAD fit/persistence/scoring)
    - `test_06_cross_process_sync_and_tier2_step_up_wiring` (Tier 2 OTP `is_breach=False` isolation, peer breach sync, cross-process `.session_reset` propagation)
    - `test_07_forensic_tracker_isolation_and_explorer_permanent_delete` (no `"$$$$$5"`, session archive isolation, Recycle Bin permanent delete VFS persistence)
    - `test_08_lock_screen_gates_bypass_and_recovery_alias_consistency` (`ALLOW_DEMO_ESCAPE=1` gating on `VerificationLockScreen.bypass_btn` and `MASTER_BYPASS_PASSWORD` recovery consistency)
    - `test_09_evaluator_stream_rotation_and_utf8_safety` (`_read_next_line_from_stream` UTF-8, partial line, and file rotation recovery)
    - `test_10_supervisor_duplicate_prevention_and_occupied_port_abort` (port collision abort + supervisor lock contention without spawning duplicate workers)
    - `test_11_uvicorn_real_websocket_delivery` (live Uvicorn RFC 6455 `/ws/telemetry` handshake and live JSONL broadcast)
    - `test_12_security_hardening_real_breach_otp_and_expired_recovery` (empty env var precedence, expired OTP + emergency recovery key, trivial blacklist rate limiting, simulation redaction under real breach)
  - `test_cmu_benchmark.py`: Killourhy & Maxion 51-subject protocol tests.
  - `test_collector.py` (1 isolated test): Privacy-safe dwell/flight/velocity window flushing & plaintext key exclusion.
  - `test_deception_layer.py`, `test_decoy_portals.py`, `test_demo_viva_runner.py`, `test_environmental_sensors.py`, `test_forensic_report_engine.py`, `test_honey_network_recon.py`, `test_honeypot_forensics.py`, `test_honeypot_realistic_desktop.py`, `test_live_pipeline_dynamics.py`, `test_member3_pipeline.py`, `test_micro_sessions.py`, `test_otp_and_recovery.py`, `test_real_telemetry_harvester.py`, `test_risk_orchestration.py` (incl. `TestClient` Tier REST routes), `test_system_supervisor.py`, `test_thesis_and_presentation.py`, `test_virtual_environment.py`, `test_web_dashboard.py` (`TestClient` HTTP + WebSocket `/ws/telemetry` + 403/200 reset auth checks).

---

## 2. Standalone Verification Scripts

Executed post-edit and observed exiting with code `0`:

| Command | Scope | Observed Outcome |
| :--- | :--- | :--- |
| `.\.venv\Scripts\python.exe tests\verify_models.py` | OC-SVM, Isolation Forest, Deep SVDD 1D-CNN separation | **PASSED** (`Owner Biometric Risk: 0.0016`, `Imposter: 1.0000`; `Owner Context Risk: 0.0744`, `Imposter: 0.8502`; `Deep SVDD Owner: 0.0960`, `Imposter: 1.0000`) |
| `.\.venv\Scripts\python.exe tests\test_model_packaging_and_rollback.py` | Checkpoints, metadata v2.0.0, legacy rollback parity | **PASSED** (`Legacy Risk: 0.3698`, `Dynamic Risk: 0.3582`) |
| `.\.venv\Scripts\python.exe tests\test_live_pipeline_dynamics.py` | Modality weighting, idle neutrality, walk-away penalty, hostility trigger | **PASSED** (Code 0 across all live dynamic checks) |
| `.\.venv\Scripts\python.exe scripts\validate_portability.py` | Environment, dependencies, storage permissions, models, PDF engine, sensors | **PASSED WITH WARNINGS** (`35 PASSED \| 1 WARNINGS \| 0 FAILED` — Ollama offline expected warning) |
| `.\.venv\Scripts\python.exe scripts\check_prerequisites.py` | Python version, disk, dirs, models, camera, port 8000 | **SUCCESS** (`157.6 GB free`, `Webcam active (Device 0)`, `Port 8000 AVAILABLE`, Ollama offline warning) |

---

## 3. Persistent State Integrity Verification

Verified via SHA-256 hash comparison against the pre-audit Phase 1 backup (`backup_state`):
- `ml_engine/trained_models.pkl` — **Unchanged (`untouched=True`)**
- `telemetry_data.jsonl` — **Unchanged (`untouched=True`)**
- `data/sessions/app_baselines.json` — **Unchanged (`untouched=True`)**
- `data/forensics/session_actions.jsonl` — **Unchanged (`untouched=True`)**
- `data/sandbox/virtual_fs_state.json` — **Unchanged (`untouched=True`)**
- Ephemeral lock/IPC tokens (`models/.active_otp`, `models/.session_reset`) — **Cleanly removed after tests**
