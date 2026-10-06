import sys
import os
import unittest
import json
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

from deception.forensic_tracker import ForensicTracker, get_tracker
from deception.ai_intent_analyzer import IntruderIntentAnalyzer
from dashboard.pdf_generator import ForensicReportGenerator


class TestHoneypotForensicsPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Create a single QApplication for PyQt widgets if needed
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.tracker = get_tracker()
        self.tracker.reset_session()

    def test_01_forensic_tracker_recording(self):
        print("\n--- Testing ForensicTracker Recording Engine ---")
        # 1. Record folder navigation
        self.tracker.record_folder_navigation(
            folder_path="C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security",
            source_path="C:\\Users\\Dell\\Desktop\\clg"
        )
        
        # 2. Record file access
        self.tracker.record_file_access("passwords.txt", action="OPEN")
        
        # 3. Record browser search in Decoy Chrome
        self.tracker.record_browser_search("how to extract passwords from windows vault")
        
        # 4. Record shell command
        self.tracker.record_shell_command("whoami /all", "C:\\Windows\\system32")
        self.tracker.record_shell_command("ipconfig /all", "C:\\Windows\\system32")
        
        # 5. Record diverted sandbox write
        self.tracker.record_sandbox_write("malicious_dropper.bat", 256)
        
        timeline = self.tracker.get_timeline()
        stats = self.tracker.get_summary_stats()
        
        self.assertGreaterEqual(len(timeline), 5)
        self.assertIn("passwords.txt", stats["files_accessed"])
        self.assertIn("whoami /all", stats["commands_executed"])
        self.assertIn("malicious_dropper.bat", stats["sandbox_interceptions"])
        self.assertGreaterEqual(stats["suspicious_events_count"], 1)
        print(f"[OK] ForensicTracker captured {len(timeline)} events. Stats: {stats['suspicious_events_count']} suspicious flags.")

    def test_02_decoy_chrome_and_explorer(self):
        print("\n--- Testing DecoyChrome & DecoyExplorer Widgets ---")
        from deception.decoy_chrome import DecoyChrome
        from deception.honey_desktop import DecoyExplorer
        
        # Test DecoyChrome
        chrome = DecoyChrome()
        self.assertIsNotNone(chrome.omnibox)
        chrome.google_search_input.setText("internal database login")
        chrome.execute_google_search()
        
        # Check that search was logged
        timeline = self.tracker.get_timeline()
        searches = [e["target"] for e in timeline if e["action_type"] == "BROWSER_SEARCH"]
        self.assertIn("internal database login", searches)
        print("[OK] DecoyChrome executed and recorded search query.")
        
        # Test DecoyExplorer
        sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
        log_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
        explorer = DecoyExplorer(sandbox_dir, log_dir)
        
        # Navigate to a subfolder
        explorer.on_folder_clicked("Behavioral-Drift-Security")
        self.assertIn("Behavioral-Drift-Security", explorer.current_path)
        
        # Check folder navigation logged
        timeline = self.tracker.get_timeline()
        navs = [e["target"] for e in timeline if e["action_type"] == "FOLDER_NAVIGATED"]
        self.assertTrue(any("Behavioral-Drift-Security" in n for n in navs))
        print("[OK] DecoyExplorer navigated directory tree and recorded event.")

    def test_03_ai_intent_analyzer(self):
        print("\n--- Testing Offline AI Intruder Intent Analyzer ---")
        analyzer = IntruderIntentAnalyzer()
        
        # Seed realistic intruder audit trail
        self.tracker.record_folder_navigation("C:\\Users\\Dell\\Desktop\\Personal_Vault")
        self.tracker.record_file_access("master_passwords_vault.txt", action="OPEN")
        self.tracker.record_browser_search("corporate bank transfer login")
        self.tracker.record_shell_command("echo exploit_code > payload.exe", "C:\\Windows\\system32")
        self.tracker.record_sandbox_write("payload.exe", 512)
        
        timeline = self.tracker.get_timeline()
        stats = self.tracker.get_summary_stats()
        
        report = analyzer.analyze_session(timeline, stats)
        
        self.assertIsNotNone(report)
        self.assertIn("attacker_persona", report)
        self.assertIn("primary_intent", report)
        self.assertIn(report.get("threat_level"), ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertGreaterEqual(len(report.get("mitre_tactics", [])), 1)
        self.assertGreaterEqual(len(report.get("recommendations", [])), 1)
        
        print(f"[OK] AI Threat Engine evaluated intruder: Persona: '{report.get('attacker_persona')}' | Threat: {report.get('threat_level')}")
        print(f"[OK] Primary Intent: {report.get('primary_intent')}")

    def test_04_pdf_report_generation(self):
        print("\n--- Testing Forensic PDF Report Generator ---")
        gen = ForensicReportGenerator()
        pdf_path = gen.generate_report()
        
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 5000) # Must be a substantial PDF file
        
        # Validate PDF header bytes
        with open(pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")
            
        print(f"[OK] Generated valid Forensic PDF Report ({os.path.getsize(pdf_path):,} bytes) at '{pdf_path}'")


if __name__ == "__main__":
    unittest.main()
