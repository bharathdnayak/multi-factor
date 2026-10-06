import os
import sys
import unittest
import time

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from demo_viva_runner import VivaDemoRunner


class TestVivaDemoRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["HEADLESS_TEST"] = "1"
        cls.runner = VivaDemoRunner(interactive=False, auto=True, delay=0.1, show_ui=False)

    def test_01_runner_initialization(self):
        """Verifies that VivaDemoRunner initializes all core security and ML engines."""
        self.assertIsNotNone(self.runner.evaluator)
        self.assertIsNotNone(self.runner.tracker)
        self.assertIsNotNone(self.runner.ai_analyzer)
        self.assertIsNotNone(self.runner.pdf_generator)
        self.assertFalse(self.runner.interactive)
        self.assertTrue(self.runner.auto)

    def test_02_stage_1_baseline_operations(self):
        """Verifies Stage 1 evaluates authentic user telemetry within Tier 1 nominal risk (< 0.40)."""
        res = self.runner.run_stage_1()
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("tier"), "TIER_1_LOW")
        self.assertLess(res.get("avg_risk"), 0.40)
        self.assertGreaterEqual(res.get("samples_evaluated"), 3)

    def test_03_stage_2_physical_walkaway_and_drift(self):
        """Verifies Stage 2 registers environmental penalty and flags Tier 2 elevated risk (0.40 - 0.75)."""
        res = self.runner.run_stage_2()
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("tier"), "TIER_2_MEDIUM")
        self.assertGreaterEqual(res.get("elevated_risk"), 0.40)
        self.assertLessEqual(res.get("elevated_risk"), 0.75)

    def test_04_stage_3_acute_lockdown_and_otp(self):
        """Verifies Stage 3 triggers acute lockdown (> 0.78), generates 6-digit OTP, and records evidence."""
        res = self.runner.run_stage_3()
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("tier"), "TIER_3_HIGH")
        self.assertGreaterEqual(res.get("risk"), 0.78)
        self.assertIsNotNone(res.get("otp"))
        self.assertEqual(len(str(res.get("otp"))), 6)

    def test_05_stage_4_honeypot_deception_traps(self):
        """Verifies Stage 4 traps honey-token credentials, network recon, and C2 download in sandbox."""
        res = self.runner.run_stage_4()
        self.assertTrue(res.get("success"))
        self.assertGreaterEqual(res.get("events_captured"), 5)
        # Verify quarantined binary exists in data/sandbox
        sandbox_binary = os.path.join(PROJECT_ROOT, "data", "sandbox", "malicious_c2_dropper.exe")
        self.assertTrue(os.path.exists(sandbox_binary))

    def test_06_stage_5_recovery_and_pdf_generation(self):
        """Verifies Stage 5 verifies identity, performs AI threat classification, and produces valid PDF."""
        res = self.runner.run_stage_5(open_report=False, generate_pdf=True)
        self.assertTrue(res.get("success"))
        self.assertTrue(res.get("verified"))
        self.assertIsNotNone(res.get("persona"))
        self.assertIsNotNone(res.get("threat_level"))
        self.assertIsNotNone(res.get("pdf_path"))

        pdf_path = res.get("pdf_path")
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 5000)

    def test_07_selective_stage_execution(self):
        """Verifies master workflow handles selective stage execution cleanly."""
        success = self.runner.run_all(single_stage=1)
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
