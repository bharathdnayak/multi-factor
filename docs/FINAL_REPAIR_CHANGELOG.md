# Final Repair Changelog

**Date:** 2026-11-11  
**Audit Scope:** Full-stack security hardening, live telemetry fidelity, ML baseline calibration, cross-process synchronization, sandbox containment, and automated test isolation.

---

## Security & Sandbox Hardening

- **`deception/virtual_fs.py`**:
  - Added `safe_sandbox_path()` and `resolve_contained_sandbox_path()` enforcing strict `os.path.realpath` containment inside `sandbox_dir` for all quarantined writes and sandbox fallback reads.
  - Added `VirtualFileSystem.permanently_delete_from_recycle_bin()` with `_notify_change()` persistence.
  - Added `use_temp_state()` / `restore_state_file()` helpers for isolated unit testing.
- **`deception/command_engine.py`**:
  - Enforced `resolve_contained_sandbox_path()` in `_cmd_type()` and `safe_sandbox_path()` in `_handle_redirection()` and `_cmd_curl()` to block host traversal (`../`, `C:\...`).
  - Replaced hardcoded `"Dell"` accounts in `_cmd_net()` with `get_synthetic_username()`.
- **`deception/decoy_chrome.py`**:
  - Enforced `safe_sandbox_path()` for intercepted browser downloads in `navigate_to_real_web()`.
  - Added optional `sandbox_dir` parameter to `DecoyChrome.__init__()`.
- **`deception/decoy_notepad.py`**:
  - Enforced `safe_sandbox_path()` for sandbox write replication in `on_content_changed()`.
  - Replaced hardcoded `"Dell"` default paths in `prompt_save_as()` and `prompt_open_file()` with `get_synthetic_username()`.
- **`deception/honey_desktop.py`, `security/lock_handler.py`, `dashboard/forensic_dashboard.py`**:
  - Removed unauthenticated `emergency_exit()` and Double-Escape bypasses by default; gated dev shortcut behind explicit `ALLOW_DEMO_ESCAPE=1`.
  - Wired `HoneypotVerificationDialog` to reuse parent `evaluator`, require valid 6-digit OTP or configured `EMERGENCY_RECOVERY_KEY`, and pass `quit_app_on_close` to `ForensicDashboard` so closing recovery UI restores `app.setQuitOnLastWindowClosed(True)` and exits Qt event loops cleanly.
  - Replaced hardcoded `"Dell"` UI labels with `get_synthetic_username()`.
- **`security/risk_orchestrator.py` & `docker-compose.yml`**:
  - Removed trivial `"admin"` placeholder from `StepUpToastWidget` and removed default `:-admin` password fallback from `docker-compose.yml`.
- **`security/otp_service.py`**:
  - Added `_redact_telegram_token()` so HTTP/connection exceptions never print raw Telegram bot tokens; masked console OTP outputs.
- **`.gitignore` & `.dockerignore`**:
  - Excluded ephemeral `models/.session_reset` IPC signal alongside `models/.active_otp`.

---

## Dashboard, Telemetry & ML Calibration

- **`dashboard/app.py`, `dashboard/templates/index.html`, `dashboard/static/js/dashboard.js`**:
  - Fixed `handle_security_reset()` and WebSocket `"reset"` handler to strictly enforce `evaluator.verify_otp_and_reset()` (returning HTTP `403` and WebSocket `RESET_DENIED` on failure) instead of resetting state unconditionally.
  - Removed default `"admin"` bypass values from `ResetSecurityRequest`, `StepUpVerifyRequest`, and frontend `triggerReset()`; implemented `#resetAuthModal` in UI.
  - Removed plaintext `active_otp` exposure from `GET /api/status` and WebSocket frames (`otp_issued` flag used instead; explicit `simulated_otp` retained solely on simulation POST response).
  - Removed fake `time.time() % N` metric oscillations; introduced honest `data_state` (`IDLE`, `LIVE`, `STALE`, `SIMULATED`), real `svdd_confidence`, heartbeat vs chart-append distinction (`append_chart`), EOF-safe tailing with `_last_file_head` rewrite detection, cached async `IntruderIntentAnalyzer` summary on `GET /api/forensics/latest`, and XSS-safe `textContent` incident log rendering.
- **`ml_engine/models.py` & `telemetry/evaluator.py`**:
  - Learned and serialized per-user robust mouse median/MAD baselines inside `BehavioralModels.train()`/`save()`/`load()` with calibrated legacy fallback defaults.
  - Stored `last_svdd_conf` and `last_policy_action`; acted on `TIER_2_MEDIUM` challenges (issuing non-breach step-up OTP) and Tier 3 failure exhaustion escalation.
  - Implemented `models/.session_reset` and `is_breach`-aware `.active_otp` cross-process state sync in `ThreatEvaluator.sync_cross_process_state()` and `start_daemon()`.
- **`telemetry/agent.py` & `telemetry/environmental_sensor.py`**:
  - Cached `psutil.Process` handles (priming CPU deltas so active process CPU is not permanently `0.0`); added `self._data_lock` and stale held-key (>10s) pruning.
  - Propagated custom `sessions_dir` paths from `MicroSessionTracker` to its internal `BehavioralAIController`.
  - Removed stray `"$$$$$5"` SSID from `EnvironmentalSensorMonitor.DEFAULT_TRUSTED_SSIDS`.

---

## Forensics, Documentation & Test Isolation

- **`deception/forensic_tracker.py` & `deception/decoy_explorer.py`**:
  - Eliminated silent 1800s archived session spillover in `get_timeline()` unless `include_recent_archive=True` is explicitly set; added UUID uniqueness suffix to `session_id`.
  - Updated `DecoyExplorer.permanently_delete_node()` to persist VFS state, removed Python 3.10-incompatible f-string backslashes, and added Qt thread check in `on_vfs_changed()`.
- **Documentation & Hygiene**:
  - Updated `README.md`, `TESTING_PROCEDURE_CHIRAG.md`, `docs/FINAL_VIVA_PRESENTATION_SLIDES.md`, and `scripts/generate_slide_deck_assets.py` to remove obsolete `'admin'`/`Bypass Prompt`/`Escape twice` guidance.
  - Updated `scripts/test_clean_checkout_simulation.py` to use `get_synthetic_username()`.
  - Removed accidental untracked stub `1.java` and empty baseline test PDFs.
- **Test Suite Hardening (`tests/`)**:
  - Rewrote `tests/test_collector.py` into an isolated `unittest.TestCase`.
  - Isolated temporary storage/state paths and mocked retraining/alert side effects across `test_deception_layer.py`, `test_decoy_portals.py`, `test_demo_viva_runner.py`, `test_forensic_report_engine.py`, `test_honey_network_recon.py`, `test_honeypot_forensics.py`, `test_honeypot_realistic_desktop.py`, `test_member3_pipeline.py`, `test_otp_and_recovery.py`, `test_virtual_environment.py`, and `test_web_dashboard.py`.
  - Added `tests/test_bug_hunt_regressions.py` with 7 targeted regression tests covering P0/P1/P2 fixes.
