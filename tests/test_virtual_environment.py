import sys
import os
import unittest
import json
import time
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication

from deception.virtual_fs import get_vfs, PathUtils, VirtualFileSystem, VirtualClipboard
from deception.window_manager import get_window_manager, DecoyWindowManager
from deception.command_engine import VirtualCommandEngine
from deception.decoy_notepad import DecoyNotepad
from deception.decoy_explorer import DecoyExplorer
from deception.decoy_chrome import DecoyChrome
from deception.honey_desktop import HoneyShell, HoneypotDesktop
from deception.forensic_tracker import get_tracker


class TestVirtualWindowsEnvironment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.vfs = get_vfs()
        self.tracker = get_tracker()
        self.tracker.reset_session()
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "test_sandbox_env")
        self.log_dir = os.path.join(PROJECT_ROOT, "data", "test_forensics_env")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

    def tearDown(self):
        if os.path.exists(self.sandbox_dir):
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
        if os.path.exists(self.log_dir):
            shutil.rmtree(self.log_dir, ignore_errors=True)

    def test_01_path_normalization_and_case_insensitivity(self):
        print("\n--- Testing Windows Path Normalization & Case-Insensitive Lookup ---")
        p1 = PathUtils.normalize("c:/users/dell/desktop/../documents/projects")
        self.assertEqual(p1, "C:\\Users\\Dell\\Documents\\projects")

        p2 = PathUtils.normalize("C:\\Windows\\System32\\..\\System32\\drivers")
        self.assertEqual(p2, "C:\\Windows\\System32\\drivers")

        # Case-insensitive equality
        self.assertTrue(PathUtils.path_equal("C:\\Users\\Dell\\Desktop", "c:\\users\\dell\\desktop"))
        self.assertTrue(PathUtils.path_equal("C:/windows/system32", "C:\\WINDOWS\\SYSTEM32"))

        # Parent-child splitting and descendant check
        parent, name = PathUtils.split_path("C:\\Users\\Dell\\Desktop\\clg")
        self.assertEqual(parent, "C:\\Users\\Dell\\Desktop")
        self.assertEqual(name, "clg")

        self.assertTrue(PathUtils.is_descendant("C:\\Users\\Dell", "C:\\Users\\Dell\\Desktop\\clg"))
        self.assertFalse(PathUtils.is_descendant("C:\\Users\\Dell\\Desktop", "C:\\Windows"))

        # Case-insensitive node lookup in VFS
        node = self.vfs.get_node("c:\\users\\dell\\desktop\\clg\\behavioral-drift-security\\passwords.txt")
        self.assertIsNotNone(node)
        self.assertEqual(node.name, "passwords.txt")
        self.assertFalse(node.is_dir)
        print("[OK] Path normalization, resolution, and case-insensitive lookup verified.")

    def test_02_vfs_file_and_directory_lifecycle(self):
        print("\n--- Testing Virtual Filesystem CRUD & Lifecycle ---")
        test_dir = "C:\\Users\\Dell\\Desktop\\UnitTest_Sandbox"
        test_file = f"{test_dir}\\secret_plan.txt"

        # 1. Create directory
        d = self.vfs.mkdir(test_dir)
        self.assertTrue(self.vfs.exists(test_dir))
        self.assertTrue(self.vfs.is_dir(test_dir))

        # 2. Create and read file
        f = self.vfs.create_file(test_file, content="CONFIDENTIAL OPERATION 2026")
        self.assertTrue(self.vfs.exists(test_file))
        self.assertEqual(self.vfs.read_file(test_file), "CONFIDENTIAL OPERATION 2026")

        # 3. Append content
        self.vfs.write_file(test_file, "\nPHASE 2 DEPLOYED", append=True)
        self.assertIn("PHASE 2 DEPLOYED", self.vfs.read_file(test_file))

        # 4. Rename
        renamed_file = self.vfs.rename(test_file, "final_plan.txt")
        self.assertEqual(renamed_file.name, "final_plan.txt")
        self.assertFalse(self.vfs.exists(test_file))
        self.assertTrue(self.vfs.exists(f"{test_dir}\\final_plan.txt"))

        # 5. Copy
        copied_file = self.vfs.copy(f"{test_dir}\\final_plan.txt", "C:\\Users\\Dell\\Documents")
        self.assertTrue(self.vfs.exists("C:\\Users\\Dell\\Documents\\final_plan.txt"))

        # 6. Delete to Recycle Bin
        self.vfs.delete(f"{test_dir}\\final_plan.txt", to_recycle_bin=True)
        self.assertFalse(self.vfs.exists(f"{test_dir}\\final_plan.txt"))

        # 7. Restore from Recycle Bin
        rb_items = self.vfs.get_recycle_bin_items()
        self.assertGreaterEqual(len(rb_items), 1)
        restored = self.vfs.restore_from_recycle_bin("final_plan.txt")
        self.assertIsNotNone(restored)
        self.assertTrue(self.vfs.exists(f"{test_dir}\\final_plan.txt"))

        # Cleanup
        self.vfs.delete(test_dir, to_recycle_bin=False)
        self.vfs.delete("C:\\Users\\Dell\\Documents\\final_plan.txt", to_recycle_bin=False)
        print("[OK] VFS Directory, File, Rename, Copy, Recycle Bin, and Restoration verified.")

    def test_03_vfs_search_and_clipboard(self):
        print("\n--- Testing VFS Search & Virtual Clipboard ---")
        # Search
        passwords = self.vfs.search("password", root_path="C:\\Users\\Dell")
        self.assertGreaterEqual(len(passwords), 1)
        self.assertTrue(any("passwords.txt" in p.name for p in passwords))

        # Virtual Clipboard
        clip = self.vfs.clipboard
        clip.copy(["C:\\Users\\Dell\\Desktop\\root_credentials.txt"])
        self.assertTrue(clip.has_items())
        mode, items = clip.get_items()
        self.assertEqual(mode, "copy")
        self.assertEqual(len(items), 1)

        clip.clear()
        self.assertFalse(clip.has_items())
        print("[OK] VFS Search and Virtual Clipboard verified.")

    def test_04_cross_application_synchronization(self):
        print("\n--- Testing Synchronization Between PowerShell, Explorer, and Notepad ---")
        shell = HoneyShell(self.sandbox_dir, self.log_dir)
        explorer = DecoyExplorer(self.sandbox_dir, self.log_dir)
        notepad = DecoyNotepad(self.sandbox_dir, self.log_dir)

        # Step 1: Create a file in PowerShell using redirection
        shell.input_field.setText("cd C:\\Users\\Dell\\Desktop")
        shell.process_command()

        shell.input_field.setText("echo sync_secret_key=98765 > sync_test.txt")
        shell.process_command()

        # Step 2: Verify File Explorer immediately sees it
        explorer.navigate_to("C:\\Users\\Dell\\Desktop")
        desktop_items = self.vfs.list_dir("C:\\Users\\Dell\\Desktop")
        self.assertTrue(any(item.name == "sync_test.txt" for item in desktop_items))

        # Step 3: Open and edit file in DecoyNotepad
        sync_file_path = "C:\\Users\\Dell\\Desktop\\sync_test.txt"
        notepad.open_virtual_file(sync_file_path)
        self.assertEqual(notepad.editor.toPlainText().strip(), "sync_secret_key=98765")

        # Step 4: Modify and save in Notepad
        notepad.editor.setPlainText("sync_secret_key=MODIFIED_IN_NOTEPAD")
        save_ok = notepad.save_file()
        self.assertTrue(save_ok)

        # Step 5: Read back in PowerShell terminal via 'type'
        shell.input_field.setText("type sync_test.txt")
        shell.process_command()
        self.assertIn("sync_secret_key=MODIFIED_IN_NOTEPAD", shell.console.toPlainText())

        # Cleanup
        self.vfs.delete(sync_file_path, to_recycle_bin=False)
        print("[OK] Complete cross-application stateful synchronization verified!")

    def test_05_powershell_virtual_command_engine(self):
        print("\n--- Testing PowerShell Virtual Command Engine Cmdlets ---")
        engine = VirtualCommandEngine(self.sandbox_dir, self.log_dir)

        # pwd
        res, _ = engine.execute("pwd")
        self.assertIn("C:\\Windows\\system32", res)

        # cd & dir
        res, _ = engine.execute("cd C:\\Users\\Dell\\Desktop\\clg")
        self.assertEqual(engine.current_dir, "C:\\Users\\Dell\\Desktop\\clg")

        res, _ = engine.execute("dir")
        self.assertIn("Behavioral-Drift-Security", res)

        # mkdir & New-Item
        res, _ = engine.execute("mkdir TempFolder")
        self.assertTrue(self.vfs.exists("C:\\Users\\Dell\\Desktop\\clg\\TempFolder"))

        res, _ = engine.execute("New-Item -ItemType File -Name script.ps1")
        self.assertTrue(self.vfs.exists("C:\\Users\\Dell\\Desktop\\clg\\script.ps1"))

        # system diagnostics (whoami, hostname, ipconfig)
        res, _ = engine.execute("whoami")
        self.assertIn("administrator", res)

        res, _ = engine.execute("hostname")
        self.assertIn("DESKTOP-SEC-WIN11", res)

        res, _ = engine.execute("ipconfig")
        self.assertIn("192.168.1.142", res)

        # Invalid command error
        res, _ = engine.execute("invalid_hack_tool --exploit")
        self.assertIn("is not recognized as the name of a cmdlet", res)

        # Cleanup
        self.vfs.delete("C:\\Users\\Dell\\Desktop\\clg\\TempFolder", to_recycle_bin=False)
        self.vfs.delete("C:\\Users\\Dell\\Desktop\\clg\\script.ps1", to_recycle_bin=False)
        print("[OK] Virtual Command Engine cmdlets, diagnostics, and errors verified.")

    def test_06_window_manager_and_taskbar(self):
        print("\n--- Testing Decoy Window Manager & Focus Management ---")
        wm = get_window_manager()
        notepad = DecoyNotepad(self.sandbox_dir, self.log_dir)
        explorer = DecoyExplorer(self.sandbox_dir, self.log_dir)

        wm.register_window("test_notepad", notepad, "Notepad", "📝")
        wm.register_window("test_explorer", explorer, "Explorer", "📁")

        wm.bring_to_front("test_notepad")
        self.assertEqual(wm.active_app_id, "test_notepad")
        self.assertTrue(wm.is_open("test_notepad"))

        wm.minimize("test_notepad")
        self.assertTrue(wm.is_minimized("test_notepad"))

        wm.bring_to_front("test_explorer")
        self.assertEqual(wm.active_app_id, "test_explorer")

        wm.unregister_window("test_notepad")
        wm.unregister_window("test_explorer")
        print("[OK] Decoy Window Manager registration, focus, and state tracking verified.")

    def test_07_decoy_chrome_real_internet_and_isolation(self):
        print("\n--- Testing Decoy Chrome Real Internet Configuration & Download Protection ---")
        chrome = DecoyChrome()

        # By default, real internet access must be disabled
        self.assertFalse(chrome.internet_enabled, "Real internet browsing must be disabled by default!")
        self.assertIn("Isolated Mode", chrome.internet_badge.text())

        # Test simulated honeypot routing (always routes locally)
        chrome.omnibox.setText("https://bank.corp.internal/login")
        chrome.on_omnibox_enter()
        self.assertEqual(chrome.pages_stack.currentIndex(), 5)

        # Enable isolated internet mode for testing
        chrome.internet_enabled = True
        chrome.toggle_internet_mode() # Toggles back to False
        self.assertFalse(chrome.internet_enabled)
        chrome.toggle_internet_mode() # Toggles to True
        self.assertTrue(chrome.internet_enabled)

        # Test download interception & sandbox quarantine
        c2_payload_url = "http://194.26.29.112/suspicious_backdoor.exe"
        chrome.omnibox.setText(c2_payload_url)
        chrome.on_omnibox_enter()

        # Verify payload quarantined to sandbox
        quarantined_file = os.path.join(chrome.sandbox_dir, "suspicious_backdoor.exe")
        self.assertTrue(os.path.exists(quarantined_file), "Malicious executable must be quarantined in sandbox!")
        with open(quarantined_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("[QUARANTINED BY HONEYPOT DECEPTION BROWSER]", content)

        # Verify ForensicTracker captured download
        timeline = self.tracker.get_timeline()
        c2_events = [e for e in timeline if e["action_type"] == "C2_PAYLOAD_INTERCEPTED"]
        self.assertGreaterEqual(len(c2_events), 1)

        # Restore default state
        chrome.internet_enabled = False
        if os.path.exists(quarantined_file):
            os.remove(quarantined_file)
        print("[OK] Decoy Chrome isolated browsing and download quarantine verified.")

    def test_08_host_isolation_guarantee(self):
        print("\n--- Testing Host Filesystem Isolation Guarantee ---")
        # Ensure modifying virtual paths does NOT write to actual host paths
        vfs_path = "C:\\Windows\\System32\\test_virtual_driver.sys"
        self.vfs.create_file(vfs_path, content="FAKE_DRIVER_CODE")
        self.assertTrue(self.vfs.exists(vfs_path))

        # Real host check: must NOT exist on real machine!
        real_host_path = r"C:\Windows\System32\test_virtual_driver.sys"
        self.assertFalse(
            os.path.exists(real_host_path),
            f"SECURITY VIOLATION: Honeypot file must never be written to host {real_host_path}!"
        )

        self.vfs.delete(vfs_path, to_recycle_bin=False)
        print("[OK] Host filesystem isolation confirmed: zero modification to real host OS.")


if __name__ == "__main__":
    unittest.main()
