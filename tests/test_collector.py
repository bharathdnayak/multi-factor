import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.agent import TelemetryAgent, AppBehaviorProfiler, MicroSessionTracker


class TestTelemetryCollector(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="collector_test_")
        self.output_log = os.path.join(self.tmp_dir.name, "telemetry_test.jsonl")

        self.agent = TelemetryAgent(
            output_file=self.output_log,
            window_size_seconds=1,
            silent=True,
            friendly=False,
        )
        # Redirect nested trackers/profilers completely into isolated temp dir
        self.agent.profiler = AppBehaviorProfiler(
            profiles_path=os.path.join(self.tmp_dir.name, "app_profiles.json")
        )
        self.agent.session_tracker = MicroSessionTracker(
            sessions_dir=os.path.join(self.tmp_dir.name, "sessions")
        )

    def tearDown(self):
        self.agent.running = False
        self.tmp_dir.cleanup()

    def test_01_privacy_safe_feature_aggregation(self):
        """Verifies telemetry windows record statistical features without plaintext keystrokes."""
        self.agent.running = True
        import threading

        self.agent.aggregation_thread = threading.Thread(
            target=self.agent._aggregate_and_output,
            daemon=True,
        )
        self.agent.aggregation_thread.start()

        # Simulate realistic typing burst and mouse stroke directly into agent callbacks
        sample_keys = [SimpleNamespace(char=c, name=None) for c in "security"]
        for k in sample_keys:
            self.agent.on_press(k)
            time.sleep(0.03)
            self.agent.on_release(k)
            time.sleep(0.02)

        for step in range(8):
            self.agent.on_move(100 + step * 25, 200 + step * 10)
            time.sleep(0.02)

        # Wait until at least one non-empty telemetry window flushes (up to 3.0s)
        deadline = time.time() + 3.0
        records = []
        while time.time() < deadline:
            if os.path.exists(self.output_log):
                with open(self.output_log, "r", encoding="utf-8") as f:
                    records = [json.loads(ln.strip()) for ln in f if ln.strip()]
                if any(r.get("keystroke_count", 0) > 0 for r in records):
                    break
            time.sleep(0.15)

        self.agent.running = False
        self.agent.aggregation_thread.join(timeout=2.5)

        self.assertTrue(os.path.exists(self.output_log), "Isolated telemetry JSONL must be created")
        self.assertGreaterEqual(len(records), 1)
        active_records = [r for r in records if r.get("keystroke_count", 0) > 0]
        self.assertGreaterEqual(len(active_records), 1, f"Expected active telemetry record, got: {records}")
        record = active_records[0]
        for req_key in ["dwell_mean", "flight_mean", "mouse_velocity_mean", "active_app", "cpu_usage", "ram_usage_mb"]:
            self.assertIn(req_key, record)
        self.assertEqual(record["keystroke_count"], 8)
        self.assertGreater(record["dwell_mean"], 0.0)
        # Ensure plaintext keystroke text is NEVER persisted
        raw_text = json.dumps(record)
        self.assertNotIn("security", raw_text)


if __name__ == "__main__":
    unittest.main()
