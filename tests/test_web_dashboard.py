import os
import sys
import unittest
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from fastapi.testclient import TestClient
from dashboard.app import app


class TestWebDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

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

        # PDF download or fallback generation
        pdf_res = self.client.get("/api/forensics/download_pdf")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers.get("content-type"), "application/pdf")
        self.assertGreater(len(pdf_res.content), 1000)

    def test_05_simulation_and_reset(self):
        """Tests viva demonstration anomaly injection and emergency reset."""
        # 1. Simulate anomaly
        sim_res = self.client.post(
            "/api/security/simulate_anomaly",
            json={"anomaly_type": "acute_spike", "severity": 0.88}
        )
        self.assertEqual(sim_res.status_code, 200)
        sim_data = sim_res.json()
        self.assertEqual(sim_data["status"], "success")
        self.assertTrue(sim_data["is_breached"])
        self.assertGreaterEqual(sim_data["instant_risk"], 0.78)

        # 2. Reset system
        reset_res = self.client.post(
            "/api/security/reset",
            json={"bypass_key": "admin"}
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


if __name__ == "__main__":
    unittest.main()
