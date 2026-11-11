# Remaining Issues, Environmental Constraints & Known Operational Notes

**Date:** 2026-11-11  
**Project:** Behavioral Drift Security

---

## 1. Environment & Service Dependencies (Non-Defect)

1. **Local Ollama LLM Daemon Offline in Test Environment**
   - `scripts/validate_portability.py` and `scripts/check_prerequisites.py` emit `[WARN] Ollama daemon not running / not reachable at http://localhost:11434`.
   - Impact: Offline DFIR AI threat intelligence falls back automatically to the deterministic rule-based heuristic analyzer (`IntruderIntentAnalyzer._heuristic_expert_analysis`), which succeeded cleanly in tests. Live LLM narrative inference still requires installing Ollama and pulling a configured model (e.g. `qwen3.5:4b` or `qwen2.5:3b`).
2. **External Alert Delivery & Network Restrictions**
   - During sandboxed runs without network access (`test_03` / earlier unmocked runs), Telegram Bot API calls failed cleanly without crashing (`dispatch_otp` falls back to writing `models/.active_otp` with masked stdout notice). Unsandboxed runs verified live Telegram dispatch works when `.env` / `security/config.json` tokens are present; SMTP dispatch skipped safely when credentials remain placeholders.

---

## 2. Features Intentionally Isolated or Requiring Interactive Desktop Verification

1. **Full Interactive Multi-Process Desktop Flow (`run_system.py` + `PyQt6` System Tray & Fullscreen Lock)**
   - Individual PyQt6 widgets (`VerificationLockScreen`, `HoneypotDesktop`, `HoneypotVerificationDialog`, `ForensicDashboard`, `StepUpToastWidget`), supervisor subprocess launch/teardown (`test_system_supervisor.py`), and cross-process IPC signals (`test_06_cross_process_sync_and_tier2_step_up_wiring`) are covered by automated tests.
   - However, an end-to-end live interactive GUI session spanning OS `pynput` key/mouse capture -> fullscreen `showFullScreen()` lock overlay -> 3x wrong OTP -> fullscreen Honeypot -> `Ctrl+Alt+Shift+U` -> `ForensicDashboard` Close & Resume was not executed interactively in this automated session and should be sanity-checked on the host desktop prior to presentation.
2. **Development-Only Demo Shortcuts (`ALLOW_DEMO_ESCAPE=1`)**
   - Unauthenticated `Double-Escape` and `Emergency Exit` bypasses inside `HoneypotDesktop` as well as the one-click `Simulate Intruder Bypass` button on `VerificationLockScreen` are intentionally disabled by default (`ALLOW_DEMO_ESCAPE` unset). Presenters wishing to use quick escape/skip controls during UI rehearsal must launch explicitly with `ALLOW_DEMO_ESCAPE=1` in an isolated terminal.
3. **Standalone Script Execution Note (`tests/test_live_pipeline_dynamics.py`)**
   - Running `tests/test_live_pipeline_dynamics.py` directly outside `unittest` (`__main__`) triggers a real `ThreatEvaluator.evaluate_row()` host breach test (capturing a camera frame if webcam is attached and writing `models/.active_otp`), whereas running via `unittest` uses isolated test suites. Keep its standalone `capture_intruder` unmocked or pass mocks if running offline demonstrations is preferred.

---

## 3. Upstream Library Deprecation Warnings & Minor Notes

1. **`starlette.testclient` / `httpx` Warning**
   - Importing `fastapi.testclient.TestClient` under the installed package versions logs `StarletteDeprecationWarning: Using 'httpx' with 'starlette.testclient' is deprecated; install 'httpx2' instead`. Deferred dependency upgrade to avoid violating package freeze policy.
2. **`clean_checkout_simulation.py` Git Clone Target**
   - `scripts/test_clean_checkout_simulation.py` clones `git HEAD`, so verify/stage all modified files into Git before running clean-checkout simulations on another machine.
3. **`matplotlib` Font Cache Directory in Locked Sandboxes**
   - Under read-only `%USERPROFILE%\.matplotlib`, `matplotlib` emits a harmless warning and uses a temp cache directory unless `MPLCONFIGDIR` is set.
