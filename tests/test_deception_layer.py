import sys
import os
import unittest

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from PyQt6.QtWidgets import QApplication

class TestDeceptionUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a single QApplication instance for all UI unit tests
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)
            
    def test_lock_screen_initialization(self):
        print("\n--- Testing PyQt6 Lock Screen Initialization ---")
        from security.drift_detector import ThreatEvaluator
        from security.lock_handler import VerificationLockScreen
        
        evaluator = ThreatEvaluator()
        evaluator.is_breached = True
        evaluator.active_otp = "999999"
        
        # Instantiate window without calling showFullScreen to test compilation
        lock_screen = VerificationLockScreen(evaluator)
        self.assertGreaterEqual(lock_screen.otp_input.maxLength(), 6)
        self.assertEqual(lock_screen.failed_attempts, 0)
        
        # Verify master bypass password support
        self.assertTrue(evaluator.verify_otp_and_reset("admin"))
        
        # Reset and verify active session OTP
        evaluator.is_breached = True
        evaluator.active_otp = "999999"
        evaluator._save_active_otp("999999")
        self.assertTrue(evaluator.verify_otp_and_reset("999999"))
        print("[OK] VerificationLockScreen widget and bypass logic verified successfully.")

    def test_honey_desktop_initialization(self):
        print("\n--- Testing PyQt6 Honey Desktop & Terminal Initialization ---")
        from deception.honey_desktop import HoneypotDesktop
        
        desktop = HoneypotDesktop()
        self.assertIsNotNone(desktop.terminal)
        self.assertTrue(os.path.exists(desktop.sandbox_dir))
        print("[OK] HoneypotDesktop widget initialized successfully.")

    def test_forensic_dashboard_initialization(self):
        print("\n--- Testing PyQt6 Forensic Recovery Dashboard Initialization ---")
        from dashboard.forensic_dashboard import ForensicDashboard
        
        dash = ForensicDashboard()
        self.assertIsNotNone(dash.image_display)
        self.assertIsNotNone(dash.log_console)
        self.assertIsNotNone(dash.sandbox_list)
        print("[OK] ForensicDashboard widget initialized successfully.")

if __name__ == "__main__":
    unittest.main()
