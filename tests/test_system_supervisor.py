import os
import sys
import time
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from run_system import (
    SystemSupervisor,
    create_shield_icon,
    run_supervisor,
    PYQT_AVAILABLE
)


class TestSystemSupervisor(unittest.TestCase):
    def setUp(self):
        self.supervisor = SystemSupervisor(port=8099, enable_browser=False, enable_tray=False)

    def tearDown(self):
        if self.supervisor and self.supervisor.running:
            self.supervisor.stop_all_workers()

    def test_01_supervisor_initialization(self):
        print("\n--- Testing Supervisor Initialization & Worker Registry ---")
        self.assertIn("telemetry_agent", self.supervisor.workers)
        self.assertIn("threat_evaluator", self.supervisor.workers)
        self.assertIn("web_dashboard", self.supervisor.workers)
        self.assertEqual(self.supervisor.port, 8099)
        self.assertFalse(self.supervisor.running)
        print("[OK] Supervisor initialized with 3 registered security workers.")

    def test_02_shield_icon_generation(self):
        print("\n--- Testing Vector Shield Tray Icon Generation ---")
        if PYQT_AVAILABLE:
            icon = create_shield_icon("#27ae60")
            self.assertIsNotNone(icon)
            print("[OK] Vector security shield icon rendered cleanly via QPainter.")
        else:
            print("[SKIP] PyQt6 not available in headless test.")

    def test_03_lifecycle_start_and_stop(self):
        print("\n--- Testing Worker Lifecycle (Start -> Health Check -> Stop) ---")
        self.supervisor.start_all_workers()
        self.assertTrue(self.supervisor.running)
        time.sleep(1.5)

        # Check workers alive
        for name, worker in self.supervisor.workers.items():
            self.assertTrue(worker.is_alive(), f"Worker {name} should be alive")
            self.assertIsNotNone(worker.pid())
            print(f"   [Worker Alive] {worker.name:<28} (PID {worker.pid()})")

        # Get status summary
        status = self.supervisor.get_status_summary()
        self.assertTrue(status["supervisor_running"])
        self.assertEqual(status["port"], 8099)
        self.assertIn("telemetry_agent", status["workers"])

        # Stop workers
        self.supervisor.stop_all_workers()
        self.assertFalse(self.supervisor.running)
        time.sleep(0.5)

        for name, worker in self.supervisor.workers.items():
            self.assertFalse(worker.is_alive(), f"Worker {name} should be stopped")

        print("[OK] Full lifecycle verified: all 3 workers started and terminated cleanly.")

    def test_04_auto_stop_mode(self):
        print("\n--- Testing Auto-Stop Mode (Non-blocking Supervisor Execution) ---")
        t0 = time.time()
        sup = run_supervisor(port=8098, enable_browser=False, enable_tray=False, auto_stop_sec=2.0)
        elapsed = time.time() - t0
        self.assertTrue(1.5 <= elapsed <= 4.0)
        self.assertFalse(sup.running)
        print(f"[OK] Auto-stop completed after {elapsed:.2f}s with all workers terminated.")


if __name__ == "__main__":
    unittest.main()
