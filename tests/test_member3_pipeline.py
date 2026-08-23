import os
import sys
import unittest
import json
import shutil

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from security.drift_detector import ThreatEvaluator

class TestSecurityPipeline(unittest.TestCase):
    def setUp(self):
        # Initialize the evaluator with low alert threshold for testing
        self.evaluator = ThreatEvaluator(threshold=0.60)
        self.forensics_dir = os.path.join(project_dir, "data", "test_forensics")
        os.makedirs(self.forensics_dir, exist_ok=True)
        
    def tearDown(self):
        # Clear mock directories
        if os.path.exists(self.forensics_dir):
            shutil.rmtree(self.forensics_dir)
            
    def test_end_to_end_scoring_fusion(self):
        print("\n--- Running End-to-End Security Scoring Fusion Test ---")
        
        # 1. Simulate Normal Behavior (should NOT trigger breach)
        normal_row = {
            "dwell_mean": 0.09,
            "dwell_std": 0.015,
            "flight_mean": 0.12,
            "flight_std": 0.02,
            "mouse_velocity_mean": 250.0,
            "mouse_acceleration_mean": 12.0,
            "mouse_jerk_mean": 1.1,
            "mouse_straightness_mean": 0.92,
            "hour_of_day": 14,
            "cpu_usage": 2.5,
            "ram_usage_mb": 150.0,
            "active_app": "code.exe"
        }
        
        print("Feeding 3 normal telemetry records...")
        for i in range(3):
            f_risk, s_risk, triggered = self.evaluator.evaluate_row(normal_row)
            print(f"   [Normal {i+1}] Fused Risk: {f_risk:.4f} | Smoothed Risk: {s_risk:.4f} | Triggered: {triggered}")
            self.assertFalse(triggered)
            self.assertFalse(self.evaluator.is_breached)

        # 2. Simulate Imposter / High Anomaly Behavior (should trigger breach after sliding window)
        imposter_row = {
            "dwell_mean": 0.28,
            "dwell_std": 0.05,
            "flight_mean": 0.38,
            "flight_std": 0.07,
            "mouse_velocity_mean": 800.0,
            "mouse_acceleration_mean": 60.0,
            "mouse_jerk_mean": 10.5,
            "mouse_straightness_mean": 0.50,
            "hour_of_day": 23,
            "cpu_usage": 70.0,
            "ram_usage_mb": 600.0,
            "active_app": "cmd.exe"
        }
        
        print("\nFeeding 3 anomalous telemetry records...")
        triggered_at_least_once = False
        
        for i in range(3):
            f_risk, s_risk, triggered = self.evaluator.evaluate_row(imposter_row)
            print(f"   [Imposter {i+1}] Fused Risk: {f_risk:.4f} | Smoothed Risk: {s_risk:.4f} | Triggered: {triggered}")
            if triggered:
                triggered_at_least_once = True
                
        self.assertTrue(triggered_at_least_once)
        self.assertTrue(self.evaluator.is_breached)
        self.assertIsNotNone(self.evaluator.active_otp)
        print(f"[OK] System breached state set. Generated OTP: {self.evaluator.active_otp}")
        
        # 3. Test OTP Verification and Restoring State
        print("\nVerifying correct OTP...")
        correct_otp = self.evaluator.active_otp
        verification_ok = self.evaluator.verify_otp_and_reset(correct_otp)
        
        self.assertTrue(verification_ok)
        self.assertFalse(self.evaluator.is_breached)
        self.assertIsNone(self.evaluator.active_otp)
        print("[OK] Session successfully restored, and breach lock cleared.")

if __name__ == "__main__":
    unittest.main()
