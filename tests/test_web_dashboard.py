import os
import sys
import unittest
import json
import tempfile
from unittest.mock import patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

os.environ["DISABLE_SIM_TELEMETRY_WRITE"] = "1"

from fastapi.testclient import TestClient
import dashboard.app as dash_app
from dashboard.app import app


class TestWebDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="web_dash_test_")
        dash_app.tracker.use_temp_storage(cls.tmp_dir.name)
        cls._orig_pdf_dir = dash_app.report_generator.output_dir
        cls._orig_tel_file = dash_app.streamer.telemetry_file
        dash_app.report_generator.output_dir = os.path.join(cls.tmp_dir.name, "forensics")
        dash_app.streamer.telemetry_file = os.path.join(cls.tmp_dir.name, "telemetry.jsonl")
        os.makedirs(dash_app.report_generator.output_dir, exist_ok=True)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        dash_app.report_generator.output_dir = cls._orig_pdf_dir
        dash_app.streamer.telemetry_file = cls._orig_tel_file
        dash_app.tracker.restore_storage()
        for fname in (".active_otp", ".session_reset"):
            p = os.path.join(PROJECT_ROOT, "models", fname)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        cls.tmp_dir.cleanup()

    def test_01_root_page(self):
        """Tests that the main dashboard UI renders HTTP 200 with HTML content."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("BEHAVIORAL DRIFT SOC", response.text)
        self.assertIn("Continuous Desktop Security", response.text)
        self.assertIn("riskTrajectoryChart", response.text)

    def test_02_static_assets(self):
        """Tests that all static CSS, JS, and offline Chart.js assets are served."""
        css_res = self.client.get("/static/css/dashboard.css")
        self.assertEqual(css_res.status_code, 200)
        self.assertIn("--neon-cyan", css_res.text)

        js_res = self.client.get("/static/js/dashboard.js")
        self.assertEqual(js_res.status_code, 200)
        self.assertIn("connectWebSocket", js_res.text)

        chart_res = self.client.get("/static/js/chart.min.js")
        self.assertEqual(chart_res.status_code, 200)
        self.assertGreater(len(chart_res.content), 50000)

        svg_res = self.client.get("/static/img/webcam_placeholder.svg")
        self.assertEqual(svg_res.status_code, 200)

    def test_03_status_and_telemetry_api(self):
        """Tests system health and rolling telemetry REST endpoints."""
        status_res = self.client.get("/api/status")
        self.assertEqual(status_res.status_code, 200)
        status_data = status_res.json()
        self.assertEqual(status_data["status"], "ONLINE")
        self.assertTrue(status_data["evaluator_models_loaded"])
        self.assertNotIn("active_otp", status_data)
        self.assertIn("otp_issued", status_data)
        self.assertIn("data_state", status_data)
        self.assertIn("uptime_seconds", status_data)

        recent_res = self.client.get("/api/telemetry/recent?limit=30")
        self.assertEqual(recent_res.status_code, 200)
        recent_data = recent_res.json()
        self.assertIn("history", recent_data)
        self.assertIn("current", recent_data)

    def test_04_forensics_endpoints(self):
        """Tests forensics metadata inquiry and PDF generation/download."""
        forensics_res = self.client.get("/api/forensics/latest")
        self.assertEqual(forensics_res.status_code, 200)
        fdata = forensics_res.json()
        self.assertIn("has_forensics", fdata)
        self.assertIn("stats", fdata)
        self.assertIn("ai_analysis", fdata)
        self.assertIn("attacker_persona", fdata["ai_analysis"])

        # PDF download or fallback generation
        pdf_res = self.client.get("/api/forensics/download_pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers.get("content-type"), "application/pdf")
        self.assertGreater(len(pdf_res.content), 1000)

    def test_05_simulation_and_reset(self):
        """Tests viva anomaly injection, strict OTP auth enforcement on reset, and valid OTP acceptance."""
        with patch("telemetry.evaluator.dispatch_otp", return_value=True), \
             patch("telemetry.evaluator.capture_intruder", return_value=None):
            # 1. Simulate anomaly
            sim_res = self.client.post(
                "/api/security/simulate_anomaly",
                json={"anomaly_type": "acute_spike", "severity": 0.88}
            )
            self.assertEqual(sim_res.status_code, 200)
            sim_data = sim_res.json()
            self.assertEqual(sim_data["status"], "success")
            self.assertTrue(sim_data["is_breached"])
            self.assertTrue(sim_data["is_simulated"])
            self.assertGreaterEqual(sim_data["instant_risk"], 0.78)
            valid_otp = sim_data.get("simulated_otp")
            self.assertTrue(valid_otp and len(str(valid_otp)) == 6)

            # 2. Verify trivial/unauthenticated reset ('admin') is strictly DENIED (HTTP 403)
            denied_res = self.client.post(
                "/api/security/reset",
                json={"bypass_key": "admin"}
            )
            self.assertEqual(denied_res.status_code, 403)
            denied_data = denied_res.json()
            self.assertEqual(denied_data["status"], "denied")
            self.assertTrue(denied_data["is_breached"])

            # 3. Verify valid 6-digit session OTP resets lockdown cleanly
            with patch("ml_engine.train.adapt_to_verified_drift"), \
                 patch.object(dash_app.evaluator.controller, "learn_from_session"):
                reset_res = self.client.post(
                    "/api/security/reset",
                    json={"bypass_key": valid_otp}
                )
            self.assertEqual(reset_res.status_code, 200)
            reset_data = reset_res.json()
            self.assertEqual(reset_data["status"], "success")
            self.assertFalse(reset_data["is_breached"])

    def test_06_websocket_stream(self):
        """Tests real-time bi-directional telemetry streaming over WebSocket."""
        with self.client.websocket_connect("/ws/telemetry") as ws:
            # 1. Receive initial snapshot
            init_msg = ws.receive_json()
            self.assertEqual(init_msg["type"], "INITIAL_SNAPSHOT")
            self.assertIn("data", init_msg)
            self.assertIn("instant_risk", init_msg["data"])

            # 2. Ping-pong round-trip
            ws.send_json({"command": "ping"})
            pong_msg = ws.receive_json()
            self.assertEqual(pong_msg["type"], "PONG")

    def test_07_desktop_system_endpoints(self):
        """Tests system GUI launch and explorer directory endpoints."""
        from unittest.mock import patch

        # Test folder open with valid and invalid options
        with patch("os.startfile", return_value=None):
            res_valid = self.client.post("/api/system/open_folder?folder=logs")
            self.assertEqual(res_valid.status_code, 200)
            self.assertEqual(res_valid.json()["status"], "success")

            res_invalid = self.client.post("/api/system/open_folder?folder=nonexistent_xyz")
            self.assertEqual(res_invalid.status_code, 400)

        # Test GUI launchers
        with patch("subprocess.Popen", return_value=None) as mock_popen:
            res_forensics = self.client.post("/api/system/launch_forensics_gui")
            self.assertEqual(res_forensics.status_code, 200)
            self.assertEqual(res_forensics.json()["status"], "success")
            self.assertTrue(mock_popen.called)

        with patch("subprocess.Popen", return_value=None) as mock_popen:
            res_honeypot = self.client.post("/api/system/launch_honeypot_gui")
            self.assertEqual(res_honeypot.status_code, 200)
            self.assertEqual(res_honeypot.json()["status"], "success")
            self.assertTrue(mock_popen.called)


if __name__ == "__main__":
    unittest.main()
