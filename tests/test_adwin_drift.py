import os
import sys
import unittest
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.drift_detector import ADWINDriftDetector, MultivariateDriftMonitor
from telemetry.evaluator import ThreatEvaluator


class TestADWINConceptDrift(unittest.TestCase):
    def setUp(self):
        # Seed for reproducible statistical test runs
        np.random.seed(42)

    def test_01_adwin_stationary_no_false_alarm(self):
        """
        Tests that an authentic stationary behavioral stream (stable typing rhythm)
        produces zero false alarms, allowing the ADWIN window to grow normally.
        """
        print("\n--- Testing ADWIN Stationary Behavioral Stability ---")
        detector = ADWINDriftDetector(delta=0.05, min_subwindow=4, name="Dwell Time")

        false_alarms = 0
        for _ in range(60):
            # Authentic user baseline: mean=0.10s, std=0.015s
            val = float(np.random.normal(0.10, 0.015))
            drift, dtype, _ = detector.add_element(val)
            if drift:
                false_alarms += 1

        self.assertEqual(false_alarms, 0, f"Expected 0 false alarms on stationary stream, got {false_alarms}")
        self.assertEqual(detector.window_size, 60)
        self.assertAlmostEqual(detector.mean, 0.10, delta=0.02)
        print(f"[OK] Stationary stream: 60/60 samples verified. False alarms: 0 | Mean: {detector.mean:.4f}")

    def test_02_adwin_gradual_drift_adaptation(self):
        """
        Tests that gradual behavioral shift (user fatigue, typing pace slowing down)
        is correctly flagged as GRADUAL drift, triggering model adaptation rather than lockout.
        """
        print("\n--- Testing ADWIN Gradual Behavioral Drift Adaptation ---")
        detector = ADWINDriftDetector(delta=0.05, min_subwindow=4, name="Keystroke Latency")

        # 1. Authentic baseline
        for _ in range(40):
            detector.add_element(float(np.random.normal(0.10, 0.015)))

        # 2. Gradual fatigue drift over 50 steps (0.10s -> 0.28s)
        gradual_detected = False
        detected_event = None

        for i in range(50):
            fatigue_val = 0.10 + (0.18 * (i / 50.0)) + float(np.random.normal(0, 0.015))
            drift, dtype, event = detector.add_element(fatigue_val)
            if drift:
                gradual_detected = True
                detected_event = event
                self.assertEqual(dtype, "GRADUAL")
                break

        self.assertTrue(gradual_detected, "ADWIN failed to detect gradual behavioral drift.")
        self.assertIsNotNone(detected_event)
        self.assertLess(detected_event["new_mean"], 0.60)
        print(f"[OK] Gradual drift detected: Type={detected_event['drift_type']} | Old Mean={detected_event['old_mean']:.4f} -> New Mean={detected_event['new_mean']:.4f}")

    def test_03_adwin_abrupt_intrusion_shift(self):
        """
        Tests that acute imposter mismatch (sudden high dwell or severe threat score)
        triggers an immediate ABRUPT drift alert under the Hoeffding bound.
        """
        print("\n--- Testing ADWIN Abrupt Intruder Distribution Shift ---")
        detector = ADWINDriftDetector(delta=0.05, min_subwindow=4, name="Threat Risk")

        # 1. Normal baseline
        for _ in range(30):
            detector.add_element(float(np.random.normal(0.08, 0.02)))

        # 2. Acute intruder injection (jump to 0.88)
        abrupt_detected = False
        abrupt_event = None

        for step in range(10):
            imposter_val = float(np.random.normal(0.88, 0.02))
            drift, dtype, event = detector.add_element(imposter_val)
            if drift:
                abrupt_detected = True
                abrupt_event = event
                self.assertEqual(dtype, "ABRUPT")
                break

        self.assertTrue(abrupt_detected, "ADWIN failed to detect abrupt intruder distribution shift.")
        self.assertIsNotNone(abrupt_event)
        self.assertGreaterEqual(abrupt_event["new_mean"], 0.45)
        self.assertGreaterEqual(abrupt_event["diff"], 0.30)
        print(f"[OK] Abrupt intruder shift detected at step {step + 1}: Type={abrupt_event['drift_type']} | New Mean={abrupt_event['new_mean']:.4f}")

    def test_04_multivariate_drift_monitor(self):
        """
        Tests parallel multi-channel drift monitoring across risk, dwell, flight, and mouse velocity.
        """
        print("\n--- Testing MultivariateDriftMonitor Multi-Channel Orchestration ---")
        monitor = MultivariateDriftMonitor(delta=0.05)

        normal_row = {
            "dwell_mean": 0.095,
            "flight_mean": 0.115,
            "mouse_velocity_mean": 380.0,
            "keystroke_count": 30
        }

        # Feed normal stationary stream
        for _ in range(25):
            verdict = monitor.process_telemetry_row(normal_row, risk_score=0.08)
            self.assertEqual(verdict["recommended_action"], "MONITOR")

        # Feed anomalous row with acute drift
        anomalous_row = {
            "dwell_mean": 0.35,
            "flight_mean": 0.65,
            "mouse_velocity_mean": 1800.0,
            "keystroke_count": 10
        }

        # Multi-window abrupt shift
        for _ in range(8):
            verdict = monitor.process_telemetry_row(anomalous_row, risk_score=0.92)

        summary = monitor.get_summary()
        self.assertIn("channels", summary)
        self.assertIn("risk_score", summary["channels"])
        self.assertGreater(summary["total_evaluations"], 25)
        print(f"[OK] Multivariate monitor evaluated {summary['total_evaluations']} cycles across {len(summary['channels'])} channels.")

    def test_05_adwin_evaluator_integration(self):
        """
        Tests that ThreatEvaluator integrates ADWIN seamlessly without breaking any ML scoring.
        """
        print("\n--- Testing ThreatEvaluator ADWIN Integration ---")
        evaluator = ThreatEvaluator()
        self.assertIsNotNone(evaluator.drift_monitor)

        row = {
            "dwell_mean": 0.09,
            "flight_mean": 0.11,
            "mouse_velocity_mean": 250.0,
            "keystroke_count": 25,
            "cpu_usage": 10.0,
            "ram_usage_mb": 200.0,
            "active_app": "Code.exe",
            "active_window": "Workspace"
        }

        fused_risk, smoothed_risk, triggered = evaluator.evaluate_row(row)
        self.assertFalse(triggered)
        self.assertLess(fused_risk, 0.40)
        print(f"[OK] ThreatEvaluator scored row: Fused Risk={fused_risk:.4f} | Smoothed={smoothed_risk:.4f} | Triggered={triggered}")


if __name__ == "__main__":
    unittest.main()
