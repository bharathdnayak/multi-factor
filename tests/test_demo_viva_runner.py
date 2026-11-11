import os
import sys
import tempfile
import unittest
import time
from unittest.mock import patch

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from demo_viva_runner import VivaDemoRunner
from deception.virtual_fs import get_vfs


class TestVivaDemoRunner(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["HEADLESS_TEST"] = "1"
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="viva_demo_test_")
        cls.runner = VivaDemoRunner(interactive=False, auto=True, delay=0.1, show_ui=False)
        cls.runner.tracker.use_temp_storage(cls.tmp_dir.name)
        cls.runner.sandbox_dir = os.path.join(cls.tmp_dir.name, "sandbox")
        cls.runner.pdf_generator.output_dir = os.path.join(cls.tmp_dir.name, "forensics")
        os.makedirs(cls.runner.sandbox_dir, exist_ok=True)
        os.makedirs(cls.runner.pdf_generator.output_dir, exist_ok=True)
        cls.vfs = get_vfs()
        cls.vfs.use_temp_state(os.path.join(cls.tmp_dir.name, "vfs_state.json"))

    @classmethod
    def tearDownClass(cls):
        cls.vfs.restore_state_file()
        cls.runner.tracker.restore_storage()
        for fname in (".active_otp", ".session_reset"):
            p = os.path.join(PROJECT_ROOT, "models", fname)
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        cls.tmp_dir.cleanup()

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
        with patch("telemetry.evaluator.dispatch_otp", return_value=True), \
             patch("telemetry.evaluator.capture_intruder", return_value=None):
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
        # Verify quarantined binary exists in isolated sandbox
        sandbox_binary = os.path.join(self.runner.sandbox_dir, "malicious_c2_dropper.exe")
        self.assertTrue(os.path.exists(sandbox_binary))

    def test_06_stage_5_recovery_and_pdf_generation(self):
        """Verifies Stage 5 verifies identity, performs AI threat classification, and produces valid PDF."""
        with patch("ml_engine.train.adapt_to_verified_drift"), \
             patch.object(self.runner.evaluator.controller, "learn_from_session"):
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
