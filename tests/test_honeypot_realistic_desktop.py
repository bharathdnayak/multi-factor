import os
import sys
import unittest
import json
import time
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

from deception.virtual_fs import get_vfs, PathUtils, VirtualFileSystem
from deception.command_engine import VirtualCommandEngine
from deception.forensic_tracker import get_tracker
from deception.honey_desktop import HoneypotDesktop, DecoySettings, Windows11StartMenu
from deception.decoy_explorer import DecoyExplorer
from deception.decoy_notepad import DecoyNotepad
from deception.decoy_chrome import DecoyChrome
from deception.ai_intent_analyzer import IntruderIntentAnalyzer, extract_behavioral_indicators


class TestHoneypotRealisticDesktop(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.vfs = get_vfs()
        self.tracker = get_tracker()
        self.tracker.reset_session()
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "test_realistic_sandbox")
        self.log_dir = os.path.join(PROJECT_ROOT, "data", "test_realistic_forensics")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.sandbox_dir):
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
        if os.path.exists(self.log_dir):
            shutil.rmtree(self.log_dir, ignore_errors=True)

    def test_01_vfs_persistence_and_extended_user_profile(self):
        print("\n--- Testing VFS Extended Profile & JSON Serialization Persistence ---")
        # 1. Extended user profile paths
        expected_dirs = [
            "C:\\Users\\Public\\Desktop",
            "C:\\Users\\Dell\\Documents",
            "C:\\Users\\Dell\\Downloads",
            "C:\\Users\\Dell\\Pictures",
            "C:\\Users\\Dell\\AppData",
            "C:\\$Recycle.Bin"
        ]
        for d in expected_dirs:
            self.assertTrue(self.vfs.exists(d), f"Missing expected standard directory: {d}")

        # 2. Add custom test file to VFS
        test_file = "C:\\Users\\Dell\\Documents\\Persisted_Report_2026.txt"
        self.vfs.create_file(test_file, content="CONFIDENTIAL TEST DATA", overwrite=True)
        self.assertTrue(self.vfs.exists(test_file))

        # 3. Save state
        test_state_file = os.path.join(self.sandbox_dir, "test_vfs_state.json")
        saved = self.vfs.save_state(test_state_file)
        self.assertTrue(saved)
        self.assertTrue(os.path.exists(test_state_file))
        self.assertGreater(os.path.getsize(test_state_file), 1000)

        # 4. Create new isolated VirtualFileSystem and load state
        fresh_vfs = VirtualFileSystem(seed_standard_dirs=False)
        self.assertFalse(fresh_vfs.exists(test_file))

        loaded = fresh_vfs.load_state(test_state_file)
        self.assertTrue(loaded)
        self.assertTrue(fresh_vfs.exists(test_file))
        self.assertEqual(fresh_vfs.read_file(test_file), "CONFIDENTIAL TEST DATA")
        self.assertTrue(fresh_vfs.exists("C:\\$Recycle.Bin"))
        print("[OK] VFS extended user profile and JSON persistence load/save verified.")

    def test_02_decoy_settings_tabs_and_state(self):
        print("\n--- Testing DecoySettings App Tabs, Spec Cards, and Telemetry ---")
        settings = DecoySettings()

        # Initial state should be System
        self.assertEqual(settings.active_tab, "System")

        # Test tab navigation
        settings.navigate_tab("Display")
        self.assertEqual(settings.active_tab, "Display")
        self.assertEqual(settings.stack.currentIndex(), 1)

        settings.navigate_tab("Personalization")
        self.assertEqual(settings.active_tab, "Personalization")
        self.assertEqual(settings.stack.currentIndex(), 2)

        settings.navigate_tab("Privacy")
        self.assertEqual(settings.active_tab, "Privacy")
        self.assertEqual(settings.stack.currentIndex(), 3)

        # Check telemetry events
        timeline = self.tracker.get_timeline()
        settings_events = [e for e in timeline if e.get("action_type") == "SETTINGS_ACCESSED"]
        self.assertGreaterEqual(len(settings_events), 3)
        print(f"[OK] DecoySettings tab switching and telemetry verified ({len(settings_events)} events logged).")

    def test_03_desktop_wallpaper_theming_and_events(self):
        print("\n--- Testing Desktop Wallpaper Theming & PERSONALIZATION_CHANGED Events ---")
        desktop = HoneypotDesktop()

        themes = ["Bloom", "Light", "Sunrise", "Dark"]
        for t in themes:
            desktop.set_wallpaper_theme(t)
            self.assertEqual(desktop.current_theme, t)
            self.assertIsNotNone(desktop.screenshot)
            self.assertFalse(desktop.screenshot.isNull())

        timeline = self.tracker.get_timeline()
        theme_events = [e for e in timeline if e.get("action_type") == "PERSONALIZATION_CHANGED"]
        self.assertGreaterEqual(len(theme_events), 4)
        targets = [e.get("target") for e in theme_events]
        for t in themes:
            self.assertIn(t, targets)
        print(f"[OK] Wallpaper dynamic theming and {len(theme_events)} PERSONALIZATION_CHANGED events verified.")

    def test_04_start_menu_interactive_search(self):
        print("\n--- Testing Start Menu Interactive Search & Launch Routing ---")
        desktop = HoneypotDesktop()
        start_menu = desktop.start_menu

        # 1. Search for application
        start_menu.on_search_changed("powershell")
        self.assertTrue(start_menu.grid_widget.isHidden())
        self.assertFalse(start_menu.results_scroll.isHidden())
        self.assertIn("Best match", start_menu.hdr.text())

        # 2. Search for virtual file
        start_menu.on_search_changed("passwords")
        self.assertIn("Best match", start_menu.hdr.text())

        # 3. Clear search returns to pinned grid
        start_menu.on_search_changed("")
        self.assertFalse(start_menu.grid_widget.isHidden())
        self.assertTrue(start_menu.results_scroll.isHidden())
        self.assertEqual(start_menu.hdr.text(), "Pinned")
        print("[OK] Windows11StartMenu search filtering and pinned mode toggle verified.")

    def test_05_decoy_chrome_download_synchronization(self):
        print("\n--- Testing Decoy Chrome Downloads Synchronization to VFS ---")
        chrome = DecoyChrome()
        downloads_dir = "C:\\Users\\Dell\\Downloads"

        # Simulate clicking download link in Decoy Chrome
        test_download_name = "test_financial_exfil.csv"
        chrome.on_drive_file_clicked(test_download_name)

        expected_vfs_path = f"{downloads_dir}\\{test_download_name}"
        self.assertTrue(self.vfs.exists(expected_vfs_path))
        content = self.vfs.read_file(expected_vfs_path)
        self.assertIn("Decoy Payload Data", content)

        timeline = self.tracker.get_timeline()
        dl_events = [e for e in timeline if e.get("action_type") == "BROWSER_DOWNLOAD_COMPLETED"]
        self.assertGreaterEqual(len(dl_events), 1)
        self.assertIn(test_download_name, dl_events[-1].get("target"))
        print(f"[OK] Decoy Chrome download sync to '{expected_vfs_path}' verified.")

    def test_06_recycle_bin_lifecycle_and_ui(self):
        print("\n--- Testing Recycle Bin Deletion, Listing, Restoration, and Purge ---")
        explorer = DecoyExplorer(self.sandbox_dir, self.log_dir)

        # 1. Create file and delete to recycle bin
        target_path = "C:\\Users\\Dell\\Desktop\\disposable_plan.txt"
        self.vfs.create_file(target_path, content="TOP SECRET PLAN", overwrite=True)
        self.assertTrue(self.vfs.exists(target_path))

        self.vfs.delete(target_path, to_recycle_bin=True)
        self.assertFalse(self.vfs.exists(target_path))

        # 2. Check recycle bin items
        rb_items = self.vfs.get_recycle_bin_items()
        self.assertGreaterEqual(len(rb_items), 1)
        rb_orig_paths = [e.original_path for e in rb_items]
        self.assertIn(target_path, rb_orig_paths)

        # 3. Navigate Explorer to Recycle Bin
        explorer.navigate_to("C:\\$Recycle.Bin")
        self.assertEqual(explorer.current_path, "C:\\$Recycle.Bin")

        # 4. Restore file
        restored = self.vfs.restore_from_recycle_bin(target_path)
        self.assertIsNotNone(restored)
        self.assertTrue(self.vfs.exists(target_path))
        self.assertEqual(self.vfs.read_file(target_path), "TOP SECRET PLAN")

        # 5. Re-delete and empty recycle bin
        self.vfs.delete(target_path, to_recycle_bin=True)
        self.assertGreaterEqual(len(self.vfs.get_recycle_bin_items()), 1)

        explorer.empty_recycle_bin()
        self.assertEqual(len(self.vfs.get_recycle_bin_items()), 0)

        timeline = self.tracker.get_timeline()
        empty_events = [e for e in timeline if e.get("action_type") in ["EMPTY_RECYCLE_BIN", "FILE_EMPTY_RECYCLE_BIN"]]
        self.assertGreaterEqual(len(empty_events), 1)
        print("[OK] Recycle Bin deletion, listing, restoration, and emptying verified.")

    def test_07_virtual_powershell_extended_cmdlets(self):
        print("\n--- Testing Virtual Command Engine Cmdlets (tree, Get-Date, Get-Service) ---")
        engine = VirtualCommandEngine(self.sandbox_dir, self.log_dir)

        # 1. tree
        out_tree, _ = engine.execute("tree C:\\Users\\Dell\\Desktop")
        self.assertIn("Folder PATH listing", out_tree)
        self.assertIn("+---", out_tree)

        # 2. Get-Date
        out_date, _ = engine.execute("Get-Date")
        self.assertIn(time.strftime("%Y"), out_date)

        # 3. Get-Service
        out_svc, _ = engine.execute("Get-Service")
        self.assertIn("WinDefend", out_svc)
        self.assertIn("Running", out_svc)

        # 4. Alias gl for Get-Location
        out_gl, _ = engine.execute("gl")
        self.assertIn("Path", out_gl)
        print("[OK] PowerShell tree, Get-Date, Get-Service, and gl verified.")

    def test_08_explainable_behavioral_indicators(self):
        print("\n--- Testing Explainable Behavioral Indicators Derivation ---")
        # Synthesize realistic timeline
        mock_timeline = [
            {"event_id": "EVT-0001", "elapsed_seconds": 1.2, "application": "FILE_EXPLORER", "action": "FOLDER_NAVIGATED", "target": "C:\\Users\\Dell\\Documents", "result": "SUCCESS"},
            {"event_id": "EVT-0002", "elapsed_seconds": 2.1, "application": "FILE_EXPLORER", "action": "FOLDER_NAVIGATED", "target": "C:\\Users\\Dell\\Desktop\\clg", "result": "SUCCESS"},
            {"event_id": "EVT-0003", "elapsed_seconds": 3.0, "application": "POWERSHELL", "action": "SHELL_COMMAND", "target": "whoami", "result": "SUCCESS"},
            {"event_id": "EVT-0004", "elapsed_seconds": 4.5, "application": "POWERSHELL", "action": "SHELL_COMMAND", "target": "ipconfig /all", "result": "SUCCESS"},
            {"event_id": "EVT-0005", "elapsed_seconds": 8.0, "application": "NOTEPAD", "action": "FILE_VIEW", "target": "passwords.txt", "result": "SUCCESS"},
            {"event_id": "EVT-0006", "elapsed_seconds": 15.0, "application": "CHROME", "action": "BROWSER_DOWNLOAD_COMPLETED", "target": "financial_records.csv", "result": "SUCCESS"},
            {"event_id": "EVT-0007", "elapsed_seconds": 16.5, "application": "FILE_EXPLORER", "action": "PATH_ACCESS_FAILED", "target": "C:\\Admin\\Secrets", "result": "FAILURE"}
        ]

        indicators = extract_behavioral_indicators(mock_timeline)

        self.assertIn("distinct_applications", indicators)
        self.assertIn("virtual_directories_visited", indicators)
        self.assertIn("sensitive_files_targeted", indicators)
        self.assertIn("file_operations_summary", indicators)
        self.assertIn("rapid_navigation_bursts", indicators)
        self.assertIn("recon_to_exfil_latency", indicators)
        self.assertIn("behavioral_indicator_score", indicators)

        # Check citations
        apps = {a["application"]: a["event_ids"] for a in indicators["distinct_applications"]}
        self.assertIn("POWERSHELL", apps)
        self.assertIn("EVT-0003", apps["POWERSHELL"])

        # Check recon-to-exfil latency
        latency_info = indicators["recon_to_exfil_latency"]
        self.assertIsNotNone(latency_info["latency_seconds"])
        self.assertEqual(latency_info["initial_recon_event_id"], "EVT-0003")
        self.assertEqual(latency_info["first_sensitive_event_id"], "EVT-0005")
        self.assertAlmostEqual(latency_info["latency_seconds"], 5.0, delta=0.5)

        # Check rapid navigation bursts
        bursts = indicators["rapid_navigation_bursts"]
        self.assertGreaterEqual(len(bursts), 1)

        print("[OK] Explainable behavioral indicators verified with event_id citations.")


if __name__ == "__main__":
    unittest.main()
