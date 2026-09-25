import os
import sys
import json
import time
import shutil
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.controller import classify_activity_context, BehavioralAIController
from telemetry.agent import MicroSessionTracker

class TestMicroSessionSystem(unittest.TestCase):
    def setUp(self):
        self.test_sessions_dir = os.path.join(PROJECT_ROOT, "data", "test_sessions_temp")
        os.makedirs(self.test_sessions_dir, exist_ok=True)
        self.tracker = MicroSessionTracker(sessions_dir=self.test_sessions_dir)
        self.controller = BehavioralAIController(
            baselines_path=os.path.join(self.test_sessions_dir, "test_baselines.json"),
            history_path=os.path.join(self.test_sessions_dir, "test_history.jsonl"),
            active_session_path=os.path.join(self.test_sessions_dir, "test_active.json")
        )

    def tearDown(self):
        if os.path.exists(self.test_sessions_dir):
            shutil.rmtree(self.test_sessions_dir)

    def test_context_classification(self):
        # 1. LeetCode / Coding Problem Solving
        ctx1 = classify_activity_context("chrome.exe", "Two Sum - LeetCode - Google Chrome")
        self.assertEqual(ctx1, "coding_problem_solving")
        
        ctx2 = classify_activity_context("brave.exe", "3Sum - HackerRank Online Judge")
        self.assertEqual(ctx2, "coding_problem_solving")

        # 2. IDE Development
        ctx3 = classify_activity_context("code.exe", "agent.py - Behavioral-Drift-Security - Visual Studio Code")
        self.assertEqual(ctx3, "ide_development")

        # 3. AI Chat & Prompting
        ctx4 = classify_activity_context("chrome.exe", "ChatGPT - OpenAI")
        self.assertEqual(ctx4, "ai_chat_prompting")

        # 4. Technical Reading
        ctx5 = classify_activity_context("msedge.exe", "python dict popitem - Stack Overflow")
        self.assertEqual(ctx5, "technical_reading")

        # 5. Terminal
        ctx6 = classify_activity_context("powershell.exe", "Administrator: Windows PowerShell")
        self.assertEqual(ctx6, "terminal_command_line")

    def test_tracker_burst_and_pause_recording(self):
        # Initialize context for Chrome LeetCode
        self.tracker.heartbeat("chrome.exe", "Two Sum - LeetCode - Google Chrome")
        self.assertEqual(self.tracker.current_context, "coding_problem_solving")

        # Simulate typing a code snippet: for (int i = 0; i < n; i++) {
        # First burst
        for ch in "for (int i = 0; i < n; i++)":
            is_symbol = ch in "{}[];:=+-*/<>!~^%&|()?'\"`\\@#$"
            self.tracker.record_key_press(ch, is_backspace=False, is_symbol=is_symbol)
            self.tracker.record_key_release(dwell=0.09, flight=0.14)
            time.sleep(0.005)

        # Simulate thinking pause: wait 1.6s
        # (simulate time jump to avoid actual wall-clock sleeping)
        self.tracker.last_event_time -= 2.0  # simulate 2s thinking pause
        
        # Second burst: { count += 1; }
        for ch in "{ count += 1; }":
            is_symbol = ch in "{}[];:=+-*/<>!~^%&|()?'\"`\\@#$"
            self.tracker.record_key_press(ch, is_backspace=False, is_symbol=is_symbol)
            self.tracker.record_key_release(dwell=0.088, flight=0.15)
            time.sleep(0.005)

        # Backspace correction
        self.tracker.record_key_press(None, is_backspace=True, is_symbol=False)
        self.tracker.record_key_release(dwell=0.09, flight=0.12)

        # Finalize
        self.tracker._finalize_and_save_session()

        # Check session history log
        history_file = os.path.join(self.test_sessions_dir, "session_history.jsonl")
        self.assertTrue(os.path.exists(history_file))
        
        with open(history_file, "r") as f:
            lines = [json.loads(line) for line in f]
            
        self.assertEqual(len(lines), 1)
        session = lines[0]
        self.assertEqual(session["app_name"], "chrome.exe")
        self.assertEqual(session["context_mode"], "coding_problem_solving")
        self.assertGreaterEqual(session["thinking_pause_count"], 1)
        self.assertGreater(session["code_symbol_count"], 5)
        self.assertGreater(session["code_symbol_ratio"], 0.15)
        self.assertEqual(session["backspace_count"], 1)

    def test_controller_anomaly_evaluation(self):
        # 1. Evaluate normal genuine LeetCode session (expected low anomaly score)
        genuine_session = {
            "app_name": "chrome.exe",
            "window_title": "Two Sum - LeetCode - Google Chrome",
            "context_mode": "coding_problem_solving",
            "keystrokes": 120,
            "avg_thinking_pause_sec": 5.4,
            "thinking_pause_ratio": 0.38,
            "avg_burst_length": 21.0,
            "code_symbol_ratio": 0.22,
            "backspace_ratio": 0.09,
            "dwell_mean": 0.092,
            "flight_mean": 0.160
        }
        score, details = self.controller.evaluate_micro_session(genuine_session)
        print(f"\n[TEST] Genuine LeetCode session anomaly score: {score:.4f} (distance: {details['composite_distance']})")
        self.assertLess(score, 0.40)

        # 2. Evaluate imposter on LeetCode:
        # Imposter does not think (pause=0.2s), types prose without symbols (ratio=0.01),
        # abnormal key timings (dwell=0.29s, flight=0.45s)
        imposter_session = {
            "app_name": "chrome.exe",
            "window_title": "Two Sum - LeetCode - Google Chrome",
            "context_mode": "coding_problem_solving",
            "keystrokes": 120,
            "avg_thinking_pause_sec": 0.3,
            "thinking_pause_ratio": 0.02,
            "avg_burst_length": 95.0,
            "code_symbol_ratio": 0.01,
            "backspace_ratio": 0.01,
            "dwell_mean": 0.290,
            "flight_mean": 0.450
        }
        imposter_score, imp_details = self.controller.evaluate_micro_session(imposter_session)
        print(f"[TEST] Imposter LeetCode session anomaly score: {imposter_score:.4f} (distance: {imp_details['composite_distance']})")
        self.assertGreater(imposter_score, 0.70)
        self.assertGreater(len(imp_details["reasons"]), 0)

        # 3. Test baseline learning
        self.controller.learn_from_session(genuine_session, verified=True)
        baseline = self.controller.get_baseline("chrome.exe", "coding_problem_solving")
        self.assertGreaterEqual(baseline["sample_count"], 1)

if __name__ == "__main__":
    unittest.main()
