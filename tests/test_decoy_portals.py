import sys
import os
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from PyQt6.QtWidgets import QApplication
from deception.forensic_tracker import get_tracker
from deception.decoy_chrome import DecoyChrome


class TestDecoyWebPortals(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)

    def setUp(self):
        self.tracker = get_tracker()
        self.tracker.reset_session()
        self.chrome = DecoyChrome()

    def test_01_corporate_netbanking_portal_trap(self):
        print("\n--- Testing Decoy Corporate NetBanking Credential Trap ---")
        # Navigate to banking
        self.chrome.navigate_to_banking()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 5)
        self.assertEqual(self.chrome.omnibox.text(), "https://bank.corp.internal/login")
        self.assertEqual(self.chrome.tab_title.text(), "Corporate NetBanking")

        # Fill credentials into trap form
        self.chrome.bank_user_input.setText("CHIEF_FINANCIAL_OFFICER")
        self.chrome.bank_pass_input.setText("SuperSecretP@ssw0rd2026!")
        self.chrome.bank_token_input.setText("891024")
        self.chrome.on_bank_login_submitted()

        # Verify trap logged to ForensicTracker
        timeline = self.tracker.get_timeline()
        trap_events = [e for e in timeline if e["action_type"] == "CREDENTIAL_TRAP_TRIGGERED"]
        self.assertGreaterEqual(len(trap_events), 1)
        trap = trap_events[-1]
        self.assertIn("Corporate NetBanking", trap["target"])
        self.assertIn("CHIEF_FINANCIAL_OFFICER", trap["target"])
        self.assertEqual(trap["details"]["captured_username"], "CHIEF_FINANCIAL_OFFICER")
        self.assertEqual(trap["details"]["password_length"], 24)
        self.assertIn("891***", trap["details"]["notes"])
        print("[OK] Corporate NetBanking credential trap successfully captured and logged.")

    def test_02_aws_management_console_honey_tokens(self):
        print("\n--- Testing Decoy AWS Management Console Honey-Tokens ---")
        # Navigate to AWS
        self.chrome.navigate_to_aws()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 6)
        self.assertEqual(self.chrome.omnibox.text(), "https://aws.amazon.com/console/signin")

        # Test extracting root honey-token keys
        self.chrome.on_aws_keys_extracted()
        
        # Test enumerating S3 bucket
        self.chrome.on_s3_bucket_clicked("corp-finance-q3-payroll-backups")

        timeline = self.tracker.get_timeline()
        key_exfil = [e for e in timeline if "AWS_HONEY_TOKEN" in e["target"]]
        self.assertGreaterEqual(len(key_exfil), 1)
        self.assertEqual(key_exfil[0]["action_type"], "FILE_CREDENTIAL_EXFILTRATION_ATTEMPT")

        s3_access = [e for e in timeline if "corp-finance-q3-payroll-backups" in e["target"]]
        self.assertGreaterEqual(len(s3_access), 1)
        self.assertEqual(s3_access[0]["action_type"], "FILE_S3_BUCKET_ENUMERATE")
        print("[OK] AWS Root honey-tokens and S3 bucket enumeration successfully trapped.")

    def test_03_github_enterprise_secrets_repo(self):
        print("\n--- Testing Decoy GitHub Enterprise Secrets Repository ---")
        # Navigate to GitHub
        self.chrome.navigate_to_github()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 7)
        self.assertEqual(self.chrome.omnibox.text(), "https://github.corp.internal")

        # Switch repo
        self.chrome.on_repo_clicked("payment-gateway-service")
        self.assertIn("payment-gateway-service", self.chrome.gh_repo_header.text())

        # Extract env secrets
        self.chrome.on_github_secrets_extracted()

        timeline = self.tracker.get_timeline()
        gh_exfil = [e for e in timeline if "prod-infrastructure-secrets/.env.production" in e["target"]]
        self.assertGreaterEqual(len(gh_exfil), 1)
        self.assertEqual(gh_exfil[0]["action_type"], "FILE_SECRETS_EXFILTRATION_ATTEMPT")
        print("[OK] GitHub Enterprise repository inspection and secrets exfiltration successfully trapped.")

    def test_04_omnibox_dynamic_routing(self):
        print("\n--- Testing Decoy Chrome Omnibox Dynamic Routing ---")
        # Test routing to bank
        self.chrome.omnibox.setText("https://internal.bank.net/transfer")
        self.chrome.on_omnibox_enter()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 5)

        # Test routing to aws
        self.chrome.omnibox.setText("aws.amazon.com")
        self.chrome.on_omnibox_enter()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 6)

        # Test routing to github
        self.chrome.omnibox.setText("https://github.internal")
        self.chrome.on_omnibox_enter()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 7)

        # Test routing to search
        self.chrome.omnibox.setText("https://www.google.com")
        self.chrome.on_omnibox_enter()
        self.assertEqual(self.chrome.pages_stack.currentIndex(), 0)
        print("[OK] Omnibox dynamically routed all simulated intruder navigation requests.")


if __name__ == "__main__":
    unittest.main()
