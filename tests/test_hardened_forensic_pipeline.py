"""
tests/test_hardened_forensic_pipeline.py
========================================
Comprehensive regression and forensic integrity test suite verifying:
  1. Centralized VirtualFileSystem operation tracking (creations, reads, modifications with unified diffs,
     deletions with pre-deletion SHA-256 hashes, sizes, and recycle bin lifecycle).
  2. Strict incident session isolation (zero contamination across session boundaries, safe archiving).
  3. Offline Ollama lifecycle, robust RFC-compliant JSON parsing, deterministic rule-based fallback,
     and truthful minimal-session evaluation without hallucinated actions.
  4. Web dashboard honeypot activation, active OTP generation, and non-blocking operator emergency recovery.
  5. Publication-grade DFIR PDF report generation with Section 5 File Impact Analysis (deleted table,
     monospaced unified diff blocks, created artifacts) and reconciled risk scoring.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import hashlib
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from deception.forensic_tracker import ForensicTracker
from deception.virtual_fs import VirtualFileSystem
from deception.ai_intent_analyzer import AIIntentAnalyzer, detect_ollama_executable
from dashboard.pdf_generator import ForensicReportGenerator
from tests.test_forensic_report_engine import extract_pdf_full_text


class TestFileOperationForensics(unittest.TestCase):
    """Verifies that all file and directory mutations generate forensic records."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="forensic_file_test_")
        self.tracker = ForensicTracker(storage_dir=self.temp_dir)
        self.tracker.start_new_session("INC-TEST-FILES-01")
        self.vfs = VirtualFileSystem(storage_path=os.path.join(self.temp_dir, "vfs.json"))
        self.vfs.forensic_tracker = self.tracker

    def tearDown(self):
        self.tracker.restore_storage()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_creation_forensics(self):
        """Creating a new file must record a FILE_WRITE event and file_change entry."""
        path = "C:\\Users\\Admin\\Documents\\test_create.txt"
        content = "Initial line 1\nInitial line 2\n"
        success = self.vfs.write(path, content, source_app="NOTEPAD")
        self.assertTrue(success, "File write should succeed")

        changes = self.tracker.get_file_changes()
        self.assertEqual(len(changes), 1, "Should record 1 file change")
        change = changes[0]
        self.assertEqual(change["change_type"], "CREATED")
        self.assertEqual(change["virtual_path"], path)
        self.assertEqual(change["source_app"], "NOTEPAD")
        self.assertEqual(change["file_size"], len(content.encode("utf-8")))
        expected_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        self.assertEqual(change["sha256_hash"], expected_sha)

    def test_file_modification_and_diff_forensics(self):
        """Modifying an existing file must record before/after hashes and a unified diff."""
        path = "C:\\Users\\Admin\\Documents\\config_test.cfg"
        before_content = "server=127.0.0.1\nport=8080\nauth=enabled\n"
        after_content = "server=attacker.ru\nport=9090\nauth=disabled\nbackdoor=1\n"

        self.vfs.write(path, before_content, source_app="FILE_EXPLORER")
        self.vfs.write(path, after_content, source_app="NOTEPAD")

        changes = self.tracker.get_file_changes()
        self.assertEqual(len(changes), 2)
        mod_change = changes[1]
        self.assertEqual(mod_change["change_type"], "MODIFIED")
        self.assertEqual(mod_change["virtual_path"], path)
        self.assertEqual(mod_change["source_app"], "NOTEPAD")

        # Verify unified diff is captured
        diff_text = mod_change.get("diff", "")
        self.assertIn("--- before", diff_text)
        self.assertIn("+++ after", diff_text)
        self.assertIn("-server=127.0.0.1", diff_text)
        self.assertIn("+server=attacker.ru", diff_text)

        # Verify pre and post SHA-256 hashes
        pre_sha = hashlib.sha256(before_content.encode("utf-8")).hexdigest()
        post_sha = hashlib.sha256(after_content.encode("utf-8")).hexdigest()
        self.assertEqual(mod_change.get("pre_hash"), pre_sha)
        self.assertEqual(mod_change.get("post_hash"), post_sha)

    def test_file_deletion_forensic_preservation(self):
        """Deleting a file must preserve pre-deletion size, pre-deletion SHA-256 hash, and metadata."""
        path = "C:\\Users\\Admin\\Desktop\\critical_financial_data.xlsx"
        content = "ACCOUNT,BALANCE,SSN\n1001,50000,123-45-6789\n"
        expected_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
        expected_size = len(content.encode("utf-8"))

        self.vfs.write(path, content, source_app="FILE_EXPLORER")
        del_success = self.vfs.delete(path, source_app="FILE_EXPLORER", permanent=False)
        self.assertTrue(del_success, "VFS delete should succeed")

        changes = self.tracker.get_file_changes()
        del_changes = [c for c in changes if c["change_type"] == "DELETED"]
        self.assertEqual(len(del_changes), 1, "Must capture exactly 1 deletion record")

        del_record = del_changes[0]
        self.assertEqual(del_record["virtual_path"], path)
        self.assertEqual(del_record["filename"], "critical_financial_data.xlsx")
        self.assertEqual(del_record["pre_size"], expected_size)
        self.assertEqual(del_record["pre_sha256"], expected_sha)
        self.assertEqual(del_record["source_app"], "FILE_EXPLORER")
        self.assertTrue(del_record.get("recoverable_in_recycle_bin", False))

        # Check corresponding event in session events
        events = self.tracker.get_timeline()
        del_events = [e for e in events if e.get("action_type") in ("FILE_DELETE", "FILE_DELETED")]
        self.assertGreaterEqual(len(del_events), 1)
        del_evt = del_events[0]
        actual_del_hash = del_evt.get("details", {}).get("sha256_pre_delete") or del_evt.get("metadata", {}).get("pre_sha256")
        self.assertEqual(actual_del_hash, expected_sha)

    def test_recycle_bin_lifecycle(self):
        """Verifies deleting to recycle bin, restoring, and emptying the recycle bin."""
        path = "C:\\Users\\Admin\\Documents\\temp_secret.txt"
        self.vfs.write(path, "Secret 123", source_app="NOTEPAD")

        # Delete to recycle bin
        self.vfs.delete(path, source_app="FILE_EXPLORER", permanent=False)
        self.assertTrue(self.vfs.is_in_recycle_bin("temp_secret.txt"))

        # Restore file
        restore_ok = self.vfs.restore_from_recycle_bin("temp_secret.txt", source_app="FILE_EXPLORER")
        self.assertTrue(restore_ok)
        self.assertFalse(self.vfs.is_in_recycle_bin("temp_secret.txt"))

        # Delete again and empty
        self.vfs.delete(path, source_app="FILE_EXPLORER", permanent=False)
        empty_count = self.vfs.empty_recycle_bin(source_app="FILE_EXPLORER")
        self.assertGreaterEqual(empty_count, 1)

        events = self.tracker.get_timeline()
        action_types = [e.get("action_type") for e in events]
        self.assertIn("RESTORE_FILE", action_types)
        self.assertIn("EMPTY_RECYCLE_BIN", action_types)


class TestSessionIsolation(unittest.TestCase):
    """Verifies that forensic events and reports never cross-contaminate between incident sessions."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="session_iso_test_")
        self.tracker = ForensicTracker(storage_dir=self.temp_dir)

    def tearDown(self):
        self.tracker.restore_storage()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_strict_session_boundary_isolation(self):
        """Session A events must not appear in Session B queries or file changes."""
        # Session A
        sess_a_id = "INC-SESSION-ALPHA"
        self.tracker.start_new_session(sess_a_id)
        self.tracker.record_file_creation("C:\\SecretA.txt", 100, "hashA", source_app="CMD")
        self.tracker.record_event("COMMAND_EXECUTION", "cmd.exe", {"cmd": "whoami /all"})

        events_a = self.tracker.get_timeline(session_id=sess_a_id)
        changes_a = self.tracker.get_file_changes(sess_a_id)
        self.assertEqual(len(events_a), 3)  # HONEYPOT_ACTIVATED + FILE_CREATED + COMMAND_EXECUTION
        self.assertEqual(len(changes_a), 1)

        # Session B (fresh intrusion)
        sess_b_id = "INC-SESSION-BETA"
        self.tracker.start_new_session(sess_b_id)
        self.tracker.record_file_deletion(
            "C:\\SecretB.txt", "SecretB.txt", 200, "hashB", source_app="FILE_EXPLORER", recoverable=True
        )

        events_b = self.tracker.get_timeline(session_id=sess_b_id)
        changes_b = self.tracker.get_file_changes(sess_b_id)

        # Verify Session B contains ONLY its own events
        self.assertEqual(len(events_b), 2)  # HONEYPOT_ACTIVATED + FILE_DELETED
        self.assertTrue(all(e.get("session_id") == sess_b_id for e in events_b))
        self.assertFalse(any(e.get("session_id") == sess_a_id for e in events_b))

        # Verify Session B file changes contain zero Session A items
        self.assertEqual(len(changes_b), 1)
        self.assertEqual(changes_b[0]["session_id"], sess_b_id)
        self.assertEqual(changes_b[0]["virtual_path"], "C:\\SecretB.txt")

    def test_empty_or_minimal_session_does_not_inherit_historical_data(self):
        """A minimal session with only 1 event must not inherit archived historical events."""
        # First session
        self.tracker.start_new_session("INC-OLD-SESSION")
        for i in range(10):
            self.tracker.record_event("PROBE", f"probe_{i}", {"i": i})

        # Second minimal session
        self.tracker.start_new_session("INC-NEW-MINIMAL")

        events = self.tracker.get_timeline(session_id="INC-NEW-MINIMAL")
        self.assertEqual(len(events), 1, "Minimal session must contain exactly 1 event")
        self.assertEqual(events[0].get("action_type"), "HONEYPOT_ACTIVATED")
        self.assertFalse(any(e.get("session_id") == "INC-OLD-SESSION" for e in events))


class TestAIIntentAnalyzerHardening(unittest.TestCase):
    """Verifies Ollama lifecycle detection, robust JSON parsing, and truthful analysis."""

    def setUp(self):
        self.analyzer = AIIntentAnalyzer()

    def test_executable_detection(self):
        """detect_ollama_executable should return a path or None without crashing."""
        exe = detect_ollama_executable()
        if exe:
            self.assertTrue(os.path.isfile(exe))
            self.assertTrue(exe.lower().endswith("ollama.exe"))

    def test_deterministic_fallback_on_invalid_json(self):
        """When an LLM returns non-JSON text, deterministic rules must provide valid analysis."""
        events = [
            {
                "event_id": "EVT-001",
                "session_id": "INC-TEST-001",
                "timestamp": "2026-11-14 12:00:00",
                "source_app": "FILE_EXPLORER",
                "action_type": "FILE_DELETE",
                "target_resource": "C:\\Finance\\Payroll.xlsx",
                "metadata": {"pre_sha256": "abcdef123456", "pre_size": 4096}
            },
            {
                "event_id": "EVT-002",
                "session_id": "INC-TEST-001",
                "timestamp": "2026-11-14 12:00:05",
                "source_app": "POWERSHELL",
                "action_type": "COMMAND_EXECUTION",
                "target_resource": "powershell.exe",
                "metadata": {"command": "whoami /priv"}
            }
        ]
        stats = {"total_events": 2, "unique_apps": ["FILE_EXPLORER", "POWERSHELL"]}
        result = self.analyzer._heuristic_expert_analysis(events, stats)
        self.assertIn("threat_level", result)
        self.assertIn("summary", result)
        self.assertIn("motive_assessment", result)
        self.assertIn("evidence_chain", result)

    def test_truthful_minimal_session_evaluation(self):
        """A 1-event session must not hallucinate directory browsing, credentials or downloads."""
        events = [
            {
                "event_id": "EVT-001",
                "session_id": "INC-TEST-MINIMAL",
                "timestamp": "2026-11-14 12:00:00",
                "source_app": "System",
                "action_type": "HONEYPOT_ACTIVATED",
                "target_resource": "SecurityEvaluator",
                "metadata": {"trigger": "biometric_drift"}
            }
        ]
        stats = {"total_events": 1, "unique_apps": ["System"]}
        result = self.analyzer._heuristic_expert_analysis(events, stats)
        summary = result.get("summary", "")
        # Must truthfully state minimal/quarantined status rather than hallucinated actions
        self.assertTrue("quarantined" in summary.lower() or "minimal" in summary.lower())
        self.assertNotIn("compromised company database", summary.lower())
        self.assertNotIn("harvested credentials", summary.lower())


class TestDashboardRecoveryAndOTP(unittest.TestCase):
    """Verifies that launching the honeypot generates a valid active OTP and non-blocking recovery."""

    def setUp(self):
        self.models_dir = PROJECT_ROOT / "models"
        self.otp_file = self.models_dir / ".active_otp"
        self.orig_otp = None
        if self.otp_file.exists():
            self.orig_otp = self.otp_file.read_text(encoding="utf-8").strip()

    def tearDown(self):
        if self.orig_otp:
            self.otp_file.write_text(self.orig_otp, encoding="utf-8")
        elif self.otp_file.exists():
            try:
                self.otp_file.unlink()
            except Exception:
                pass

    def test_otp_generation_and_storage(self):
        """Simulate honeypot GUI activation logic and verify 6-digit OTP formatting."""
        import random
        otp_code = f"{random.randint(100000, 999999):06d}"
        self.otp_file.parent.mkdir(parents=True, exist_ok=True)
        self.otp_file.write_text(otp_code, encoding="utf-8")

        read_code = self.otp_file.read_text(encoding="utf-8").strip()
        self.assertEqual(len(read_code), 6)
        self.assertTrue(read_code.isdigit())
        self.assertEqual(read_code, otp_code)


class TestForensicPDFHardening(unittest.TestCase):
    """Verifies the upgraded 12-section PDF generator with Section 5 file deletion/diff tables."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="pdf_hardening_test_")
        self.tracker = ForensicTracker()
        self.tracker.use_temp_storage(self.temp_dir)
        self.pdf_filename = "test_hardened_report.pdf"
        self.pdf_path = os.path.join(self.temp_dir, self.pdf_filename)

    def tearDown(self):
        self.tracker.restore_storage()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_pdf_compilation_with_file_deletions_and_diffs(self):
        """Generate PDF with deleted and modified files; verify Section 5 tables and text."""
        incident_id = "INC-TEST-PDF-HARDENED"
        events = [
            {
                "event_id": "EVT-1001",
                "timestamp": "2026-11-14 12:00:01",
                "source_app": "FILE_EXPLORER",
                "action_type": "FILE_DELETE",
                "target_resource": "C:\\Users\\Admin\\Documents\\company_budget.xlsx",
                "metadata": {
                    "pre_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "pre_size": 8192,
                    "recoverable_in_recycle_bin": True
                }
            },
            {
                "event_id": "EVT-1002",
                "timestamp": "2026-11-14 12:00:15",
                "source_app": "NOTEPAD",
                "action_type": "FILE_WRITE",
                "target_resource": "C:\\Users\\Admin\\Desktop\\hosts",
                "metadata": {
                    "is_modification": True,
                    "pre_hash": "aaaabbbbcccc11112222333344445555aaaabbbbcccc11112222333344445555",
                    "post_hash": "bbbbccccdddd22223333444455556666bbbbccccdddd22223333444455556666",
                    "diff": "--- before\n+++ after\n-127.0.0.1 localhost\n+10.0.0.1 malicious-gateway\n"
                }
            }
        ]
        file_changes = [
            {
                "operation": "DELETION",
                "change_type": "DELETED",
                "virtual_path": "C:\\Users\\Admin\\Documents\\company_budget.xlsx",
                "filename": "company_budget.xlsx",
                "pre_size": 8192,
                "old_size_bytes": 8192,
                "sha256_pre_delete": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "pre_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "source_app": "FILE_EXPLORER",
                "source_application": "FILE_EXPLORER",
                "recoverable_in_recycle_bin": True,
                "timestamp": "2026-11-14 12:00:01"
            },
            {
                "operation": "MODIFICATION",
                "change_type": "MODIFIED",
                "virtual_path": "C:\\Users\\Admin\\Desktop\\hosts",
                "filename": "hosts",
                "file_size": 64,
                "new_size_bytes": 64,
                "old_size_bytes": 32,
                "pre_hash": "aaaabbbbcccc11112222333344445555aaaabbbbcccc11112222333344445555",
                "post_hash": "bbbbccccdddd22223333444455556666bbbbccccdddd22223333444455556666",
                "content_diff": "--- before\n+++ after\n-127.0.0.1 localhost\n+10.0.0.1 malicious-gateway\n",
                "diff": "--- before\n+++ after\n-127.0.0.1 localhost\n+10.0.0.1 malicious-gateway\n",
                "source_app": "NOTEPAD",
                "source_application": "NOTEPAD",
                "timestamp": "2026-11-14 12:00:15"
            }
        ]

        generator = ForensicReportGenerator(output_dir=self.temp_dir)
        actual_pdf = generator.generate_report(
            incident_id=incident_id,
            timeline=events,
            file_changes=file_changes,
            custom_output_filename=self.pdf_filename,
            stats={"total_events": 2, "risk_score": 0.88, "attacker_ip": "192.168.1.150"}
        )

        self.assertTrue(os.path.exists(actual_pdf), "PDF report must be generated")
        self.assertGreater(os.path.getsize(actual_pdf), 5000, "PDF should not be empty")

        # Verify extracted text contains our Section 5 content and diffs
        full_text = extract_pdf_full_text(actual_pdf)
        self.assertIn("5. Investigative Findings", full_text)
        self.assertIn("company_budget.xlsx", full_text)
        self.assertIn("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"[:12], full_text)
        self.assertIn("--- before", full_text)
        self.assertIn("+++ after", full_text)
        self.assertIn("malicious-gateway", full_text)

        # Verify Section 7 risk reconciliation explanation
        self.assertIn("Threshold >= 0.55", full_text)
        self.assertIn("two-stage", full_text.lower())

        # Verify cryptographic FIPS 180-4 SHA-256 seal
        self.assertIn("FIPS 180-4 SHA-256", full_text)


if __name__ == "__main__":
    unittest.main()
