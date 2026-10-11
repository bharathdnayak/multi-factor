"""
Test Suite: Forensic Report Engine Verification
Validates the publication-grade multi-page forensic triage report generation:
1. 12-Section Architecture & Heading Presence
2. Event Count Reconciliation & Data Grounding
3. FIPS 180-4 SHA-256 Hex Digest Integrity (Unbroken 64-char verification)
4. Dynamic Multi-Page Pagination on Variable Telemetry Volumes
5. Sensitive Information Redaction (OTPs, AWS keys, Passwords)
6. Offline Graceful Fallback Mode
7. Unaltered OTP & Recovery Subsystem Verification
"""

import os
import sys
import time
import hashlib
import unittest
from typing import List, Dict, Any

# Ensure project root is in python path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.pdf_generator import (
    ForensicReportGenerator,
    redact_sensitive_presentation,
    sanitize_pdf_text,
    clean_markdown,
    MITRE_TECHNIQUE_METADATA
)
from PyQt6.QtPdf import QPdfDocument


def extract_pdf_full_text(pdf_path: str) -> str:
    """Extracts all text across all pages using PyQt6 QPdfDocument."""
    doc = QPdfDocument(None)
    doc.load(pdf_path)
    pages_text = []
    for p in range(doc.pageCount()):
        sel = doc.getAllText(p)
        pages_text.append(sel.text())
    return "\n--- PAGE BREAK ---\n".join(pages_text)


def get_pdf_page_count(pdf_path: str) -> int:
    """Returns the total number of pages in the PDF document."""
    doc = QPdfDocument(None)
    doc.load(pdf_path)
    return doc.pageCount()


class TestForensicReportEngine(unittest.TestCase):
    """Rigorous unit and integration test suite for ForensicReportGenerator."""

    @classmethod
    def setUpClass(cls):
        cls.test_out_dir = os.path.join(PROJECT_ROOT, "data", "test_report_artifacts")
        os.makedirs(cls.test_out_dir, exist_ok=True)
        cls.generator = ForensicReportGenerator(output_dir=cls.test_out_dir)

    def test_01_all_12_sections_present_in_generated_report(self):
        """Verifies that all 12 DFIR sections exist in the compiled PDF report."""
        timeline = [
            {
                "event_id": "EVT-0001",
                "timestamp": "2026-10-11 12:00:00",
                "elapsed_seconds": 0.0,
                "application": "explorer.exe",
                "action_type": "FOLDER_NAVIGATED",
                "target": "C:\\Decoy\\Confidential",
                "severity": "SUSPICIOUS"
            },
            {
                "event_id": "EVT-0002",
                "timestamp": "2026-10-11 12:00:05",
                "elapsed_seconds": 5.0,
                "application": "powershell.exe",
                "action_type": "SHELL_COMMAND",
                "target": "whoami /all",
                "severity": "ALERT"
            }
        ]
        stats = {
            "total_events": len(timeline),
            "session_duration_seconds": 15.0,
            "session_id": "SESS_TEST_12_SECTIONS"
        }
        ai_report = {
            "threat_level": "HIGH",
            "threat_score": 0.85,
            "attacker_persona": "Internal Discovery Auditor",
            "primary_intent": "Enumerate local system accounts and directory structures.",
            "behavioral_trajectory": "Adversary navigated to confidential directory then ran shell commands.",
            "alternative_explanations": ["Authorized admin running troubleshooting diagnostics."],
            "model_name": "Offline Local Reasoner",
            "confidence": 0.88
        }

        pdf_path = self.generator.generate_report(
            ai_report=ai_report,
            timeline=timeline,
            stats=stats,
            incident_id="INC-TEST-12SECT",
            save_filename="test_12_sections.pdf"
        )
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 5000)

        full_text = extract_pdf_full_text(pdf_path)

        expected_sections = [
            "1. Incident Identification & Case Metadata",
            "2. Executive Summary",
            "3. Incident Overview & System Context",
            "4. Chronological Incident Timeline",
            "5. Investigative Findings",
            "6. AI-Assisted Behavioral Reconstruction",
            "7. Deterministic Risk & Severity Assessment",
            "8. Containment & Host-Protection Status",
            "9. MITRE ATT&CK Framework Mapping",
            "10. Recommended Remediation & Verification Actions",
            "11. Evidence Inventory & Cryptographic Integrity",
            "12. Methodology, Limitations, and Glossary"
        ]

        for sec in expected_sections:
            self.assertIn(
                sec, full_text,
                f"Missing required forensic section header: '{sec}'"
            )

    def test_02_event_count_reconciliation(self):
        """Verifies that the report metadata accurately reconciles the total recorded events."""
        event_count = 5
        timeline = [
            {
                "event_id": f"EVT-{i:04d}",
                "timestamp": f"2026-10-11 12:00:{i:02d}",
                "elapsed_seconds": float(i),
                "application": "notepad.exe",
                "action_type": "FILE_OPEN",
                "target": f"file_{i}.txt",
                "severity": "INFO"
            }
            for i in range(1, event_count + 1)
        ]
        stats = {
            "total_events": event_count,
            "session_duration_seconds": 12.0,
            "session_id": "SESS_TEST_RECONCILE"
        }

        ai_report = {
            "threat_level": "LOW",
            "threat_score": 0.20,
            "attacker_persona": "Benign Operator",
            "primary_intent": "Routine file operations",
            "behavioral_trajectory": "Benign operations performed.",
            "alternative_explanations": [],
            "model_name": "Test Mock Engine",
            "confidence": 0.90
        }

        pdf_path = self.generator.generate_report(
            ai_report=ai_report,
            timeline=timeline,
            stats=stats,
            incident_id="INC-RECONCILE-001",
            save_filename="test_reconciliation.pdf"
        )
        full_text = extract_pdf_full_text(pdf_path)

        self.assertIn("5 Discrete Events Captured", full_text)
        self.assertIn("5 Events", full_text)
        self.assertIn("EVT-0001", full_text)
        self.assertIn("EVT-0005", full_text)

    def test_03_evidence_inventory_sha256_unbroken_hashes(self):
        """Verifies that Evidence Inventory generates valid 64-char unbroken SHA-256 digests."""
        timeline = [{"event_id": "EVT-0001", "timestamp": "2026-10-11 12:00:00", "application": "test", "action_type": "TEST", "target": "test", "severity": "INFO"}]
        stats = {"total_events": 1, "session_id": "SESS_INTEGRITY"}
        ai_report = {
            "threat_level": "MEDIUM",
            "threat_score": 0.40,
            "attacker_persona": "Integrity Verifier",
            "primary_intent": "Validate cryptographic digests",
            "behavioral_trajectory": "Verification activity.",
            "alternative_explanations": [],
            "model_name": "Test Mock Engine",
            "confidence": 0.85
        }

        pdf_path = self.generator.generate_report(
            ai_report=ai_report,
            timeline=timeline,
            stats=stats,
            incident_id="INC-INTEGRITY-001",
            save_filename="test_integrity.pdf"
        )
        full_text = extract_pdf_full_text(pdf_path)

        # Check for presence of verified on-disk files
        self.assertIn("Forensic Event Journal", full_text)
        self.assertIn("VFS Serialized State", full_text)
        self.assertIn("SHA-256:", full_text)

        # Check session_actions.jsonl real digest
        journal_path = os.path.join(PROJECT_ROOT, "data", "forensics", "session_actions.jsonl")
        if os.path.exists(journal_path):
            with open(journal_path, "rb") as f:
                real_journal_hash = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(len(real_journal_hash), 64)
            self.assertIn(real_journal_hash, full_text, "Full 64-char SHA-256 digest of journal missing or fragmented in PDF!")

    def test_04_dynamic_multi_page_pagination(self):
        """Verifies that the generator dynamically expands pages based on event volume without crashing."""
        ai_report = {
            "threat_level": "HIGH",
            "threat_score": 0.80,
            "attacker_persona": "Paging Auditor",
            "primary_intent": "Test dynamic pagination",
            "behavioral_trajectory": "Multiple events executed.",
            "alternative_explanations": [],
            "model_name": "Test Mock Engine",
            "confidence": 0.85
        }

        # 1. Short session -> 3 pages
        short_timeline = [{"event_id": "EVT-0001", "timestamp": "2026-10-11 12:00:00", "application": "app", "action_type": "ACT", "target": "tgt", "severity": "INFO"}]
        pdf_short = self.generator.generate_report(
            ai_report=ai_report,
            timeline=short_timeline,
            stats={"total_events": 1, "session_id": "SESS_SHORT"},
            save_filename="test_page_short.pdf"
        )
        short_pages = get_pdf_page_count(pdf_short)
        self.assertEqual(short_pages, 3, f"Expected 3 pages for short session, got {short_pages}")

        # 2. Long session (40 events) -> dynamically expands to 4+ pages
        long_timeline = [
            {
                "event_id": f"EVT-{i:04d}",
                "timestamp": f"2026-10-11 12:00:{i%60:02d}",
                "elapsed_seconds": float(i * 1.5),
                "application": "powershell.exe" if i % 2 == 0 else "explorer.exe",
                "action_type": "COMMAND" if i % 2 == 0 else "NAVIGATE",
                "target": f"C:\\Simulated\\Path_{i}\\target_asset_{i}.txt",
                "severity": "ALERT" if i % 5 == 0 else "INFO"
            }
            for i in range(1, 41)
        ]
        pdf_long = self.generator.generate_report(
            ai_report=ai_report,
            timeline=long_timeline,
            stats={"total_events": 40, "session_id": "SESS_LONG"},
            save_filename="test_page_long.pdf"
        )
        long_pages = get_pdf_page_count(pdf_long)
        self.assertGreater(long_pages, short_pages, f"Long session ({long_pages} pages) should have more pages than short session ({short_pages} pages)")
        self.assertGreaterEqual(long_pages, 4, f"Expected at least 4 pages for 40 events, got {long_pages}")

    def test_05_offline_heuristic_fallback(self):
        """Verifies that report generation succeeds smoothly when AI models are unavailable."""
        timeline = [{"event_id": "EVT-0001", "timestamp": "2026-10-11 12:00:00", "application": "powershell.exe", "action_type": "SHELL_COMMAND", "target": "whoami", "severity": "ALERT"}]
        stats = {"total_events": 1, "session_id": "SESS_OFFLINE"}

        # Passing ai_report=None invokes IntruderIntentAnalyzer offline fallback
        pdf_path = self.generator.generate_report(
            ai_report=None,
            timeline=timeline,
            stats=stats,
            save_filename="test_offline_fallback.pdf"
        )
        self.assertTrue(os.path.exists(pdf_path))
        self.assertGreater(os.path.getsize(pdf_path), 5000)

        full_text = extract_pdf_full_text(pdf_path)
        self.assertIn("6. AI-Assisted Behavioral Reconstruction", full_text)
        self.assertIn("Investigative Aid Notice", full_text)

    def test_06_sensitive_presentation_redaction(self):
        """Verifies that secrets (OTPs, AWS keys, passwords, bearer tokens) are safely masked in report output."""
        sample_secret_text = "aws_key=AKIA1234567890ABCDEF bearer=Bearer secret_token_xyz_12345678 otp=654321 pass=SuperSecretPassword123"
        redacted = redact_sensitive_presentation(sample_secret_text)

        self.assertNotIn("AKIA1234567890ABCDEF", redacted)
        self.assertIn("[REDACTED_AWS_KEY]", redacted)

        self.assertNotIn("secret_token_xyz_12345678", redacted)
        self.assertIn("[REDACTED_TOKEN]", redacted)

        self.assertNotIn("654321", redacted)
        self.assertIn("654***", redacted)

        self.assertNotIn("SuperSecretPassword123", redacted)
        self.assertIn("***REDACTED***", redacted)

    def test_07_mitre_catalog_integrity(self):
        """Verifies that MITRE ATT&CK techniques in the report adhere strictly to Matrix v15 definitions."""
        self.assertIn("T1082", MITRE_TECHNIQUE_METADATA)
        self.assertIn("T1087.001", MITRE_TECHNIQUE_METADATA)
        self.assertIn("T1552.001", MITRE_TECHNIQUE_METADATA)
        self.assertIn("T1059.001", MITRE_TECHNIQUE_METADATA)

        for tid, data in MITRE_TECHNIQUE_METADATA.items():
            self.assertIn("name", data)
            self.assertIn("tactic", data)
            self.assertIn("evidence", data)
            self.assertIn("confidence", data)
            self.assertIn("caveat", data)
            self.assertIn(data["confidence"], ("Supported", "Candidate Mapping"))

    def test_08_otp_and_recovery_remains_untouched(self):
        """Ensures that the teammate's OTP service and recovery implementations remain intact."""
        from security.otp_service import generate_otp, dispatch_otp, get_alert_config
        otp = generate_otp()
        self.assertTrue(isinstance(otp, str))
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

        cfg = get_alert_config()
        self.assertIn("email", cfg)
        self.assertIn("security", cfg)

        from telemetry.evaluator import ThreatEvaluator
        evaluator = ThreatEvaluator()
        self.assertTrue(hasattr(evaluator, "verify_recovery_code"))
        # Verify strict non-trivial rejection
        self.assertFalse(evaluator.verify_recovery_code("123456"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
