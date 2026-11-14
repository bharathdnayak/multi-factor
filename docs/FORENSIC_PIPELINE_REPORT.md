# Forensic Event Collection & DFIR Pipeline Hardening Report

**Project Title:** Behavioral Drift Continuous Authentication, Honeypot Deception & Digital Forensics  
**Subsystem:** Digital Forensics and Incident Response (DFIR) Event-Collection & Reporting Engine  
**Date:** November 2026  
**Department:** Information Science & Engineering, NMAMIT  
**Status:** **100% Repaired, Hardened, Instrumented & Verified**

---

## 1. Executive Summary

During forensic evaluation and viva defense simulations, several critical discrepancies were identified in the legacy honeypot event collection and reporting pipeline:
1. **Unrecorded File Operations:** Destructive file deletions performed inside the honeypot desktop did not appear in the generated forensic report, and file modification diffs were uncaptured.
2. **Session Cross-Contamination:** Historical telemetry from prior intrusion incidents contaminated subsequent incident reports whenever the active incident recorded few events.
3. **Threading Lock Deadlock:** Re-entrant calls in `ForensicTracker` under concurrent UI actions caused worker threads to freeze on non-reentrant mutexes.
4. **Attribution & Motive Deficiencies:** Downstream PDF reports lacked granular per-application attribution, adversarial motive deduction, and cryptographic file state proofs.

Through exhaustive source-level auditing and centralized instrumentation across `deception/forensic_tracker.py`, `deception/virtual_fs.py`, `deception/ai_intent_analyzer.py`, and `dashboard/pdf_generator.py`, the entire forensic event collection pipeline has been unified and hardened. All 121 automated test cases across the repository now pass with zero failures.

---

## 2. Root Cause Analysis

### 2.1 VirtualFileSystem Operation Boundaries Bypassing Tracker
* **Root Cause:** Deletion operations executed inside `VirtualFileSystem.delete()` removed nodes from the in-memory tree but relied on peripheral UI listeners to record forensic events. If a user deleted a file via honey command shell, script, or programmatic API, no forensic deletion record was created.
* **Fix:** Centralized tracking directly inside `VirtualFileSystem` methods (`write_file`, `delete`, `restore_from_recycle_bin`, `empty_recycle_bin`, `move`, `copy`, `mkdir`). Before modifying or unlinking any virtual node, the pre-operation state (size, type, SHA-256 digest, and textual content) is captured.

### 2.2 Threading Deadlock on Re-Entrant Lock Acquisition
* **Root Cause:** `ForensicTracker._write_lock` was instantiated as a standard, non-reentrant `threading.Lock()`. When high-level routines (`start_new_session` or `use_temp_storage`) acquired `_write_lock` and subsequently invoked `record_event()` on the same thread, the second acquisition blocked indefinitely.
* **Fix:** Upgraded `self._write_lock = threading.RLock()` to permit safe re-entrant lock acquisition across compound operations.

### 2.3 Historical Log Leakage and Session Contamination
* **Root Cause:** `get_timeline()` contained an unsafe heuristic that fell back to legacy `session_actions.jsonl` logs from previous intrusions if the active session recorded few events.
* **Fix:** Enforced strict session isolation. Every intrusion generates a globally unique `incident_id` and `session_id`. Logs and file changes are archived into isolated directories (`data/forensics/sessions/session_<session_id>/`). `get_timeline()` and `get_file_changes()` strictly filter queries by `session_id`, guaranteeing zero historical data leakage.

### 2.4 Attribute vs. Callable Type Deserialization Defect
* **Root Cause:** In `deception/virtual_fs.py`, deserialized virtual nodes stored `type_description` as a string attribute, while dynamically constructed nodes provided a method. Invoking `node.type_description()` threw an unhandled `TypeError: 'str' object is not callable`.
* **Fix:** Standardized node inspection to `node.type_description() if callable(getattr(node, "type_description", None)) else getattr(node, "type_description", "File")`.

---

## 3. Implemented Forensic Architecture & Schema

### 3.1 Standardized Forensic Event Schema
Every interaction within the honeypot environment produces an immutable JSON record containing:
- `event_id`: Unique sequential identifier (`EVT-0001`, `EVT-0002`, ...).
- `incident_id` & `session_id`: Strict cryptographic incident boundaries.
- `timestamp` & `timestamp_utc`: ISO 8601 string with timezone metadata.
- `source_application`: Canonical origin (`DESKTOP`, `FILE_EXPLORER`, `NOTEPAD`, `POWERSHELL`, `DECOY_CHROME`).
- `action_type`: Normalized event taxonomy (`FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `RESTORE_FILE`, `EMPTY_RECYCLE_BIN`, `COMMAND_EXECUTION`, `URL_VISITED`).
- `target_resource`: Normalized virtual path or target endpoint.
- `details`: Granular operation metadata including pre-deletion SHA-256, delta bytes, and recovery state.

### 3.2 Structured File Change Tracking (`file_changes.jsonl`)
In addition to the raw event journal, all file modifications and deletions emit structured change evidence:
```json
{
  "evidence_id": "EVT-CHG-0001",
  "event_id": "EVT-0004",
  "session_id": "SESS_20261114_120000_a1b2c3",
  "operation": "DELETION",
  "change_type": "DELETED",
  "virtual_path": "C:\\Users\\Admin\\Documents\\company_budget.xlsx",
  "filename": "company_budget.xlsx",
  "file_type": "Virtual Document",
  "old_size_bytes": 8192,
  "new_size_bytes": 0,
  "pre_size": 8192,
  "sha256_before": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "pre_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "sha256_after": "DELETED",
  "diff_summary": "File 'company_budget.xlsx' (8192 bytes) removed from virtual filesystem.",
  "content_diff": null,
  "source_app": "FILE_EXPLORER",
  "to_recycle_bin": true,
  "recoverable_in_recycle_bin": true,
  "result": "SUCCESS"
}
```

### 3.3 Textual Unified Diff Capture
For text files up to 64 KB, modifications capture unified diff blocks (`difflib.unified_diff`) showing exact lines added, removed, or altered:
```diff
--- before
+++ after
@@ -1,3 +1,4 @@
 server=127.0.0.1
-port=8080
+port=9090
 auth=disabled
+backdoor=1
```
For binary files or content exceeding safe diff sizes, cryptographic pre/post hashes and size deltas are recorded without memory bloating.

---

## 4. PDF Report Generator Overhaul (`dashboard/pdf_generator.py`)

The PDF generation engine has been upgraded to a publication-grade, 12-section DFIR document:
- **Repeated Headers & Footers:** Running headers display Incident Reference and Confidentiality markings across all pages; footers display page counts (`Page X of Y`).
- **Section 5: File & Directory Impact Analysis & Investigative Findings:**
  * **Subsection 5.1:** Forensically confirmed file deletions table displaying Target Virtual Path, Filename, Pre-Size, Pre-Deletion SHA-256 Digest (truncated cleanly with ellipsis to fit cell width), Source Application, and Recycle Bin Recovery status.
  * **Subsection 5.2:** Unauthorized file modifications displaying before/after size deltas and rendered monospaced unified diff blocks (`Courier`, 6.5pt, navy container).
  * **Subsection 5.3:** Newly created and downloaded artifacts table with post-write SHA-256 digests.
  * **Subsection 5.4:** Categorized behavioral observations linked to Event ID citations.
- **Section 7: Risk Assessment Reconciliation:** Explicitly documents the two-stage defense model, reconciling why a host continuous biometric breach (Threshold $\ge 0.55$) diverts into the honeypot where post-diversion intruder activity is assessed on an independent threat floor (0.10 to 1.00).
- **Section 11: Cryptographic Integrity:** Real-time point-in-time FIPS 180-4 SHA-256 digests computed over all evidentiary logs on disk.

---

## 5. Verification & Regression Testing

The pipeline was verified through the dedicated regression suite `tests/test_hardened_forensic_pipeline.py`:
- `test_file_creation_forensics`: Verified creation events, sizes, and SHA-256 digests.
- `test_file_modification_and_diff_forensics`: Verified pre/post hashes and unified diff rendering.
- `test_file_deletion_forensic_preservation`: Verified pre-deletion size, pre-deletion hash, and recycle bin recovery flag.
- `test_recycle_bin_lifecycle`: Verified delete, restore, and empty recycle bin lifecycle.
- `test_strict_session_boundary_isolation`: Verified zero event/file crossover across sessions.
- `test_empty_or_minimal_session_does_not_inherit_historical_data`: Verified minimal sessions contain only active events.
- `test_deterministic_fallback_on_invalid_json`: Verified graceful rule-based fallback without unhandled exceptions.
- `test_truthful_minimal_session_evaluation`: Verified minimal sessions do not hallucinate file or credential exfiltration.
- `test_otp_generation_and_storage`: Verified active 6-digit OTP formatting and storage in `models/.active_otp`.
- `test_pdf_compilation_with_file_deletions_and_diffs`: Verified PDF generation with complete Section 5 deletion and diff tables.

**Result:** `Ran 121 tests in 108.758s. OK (100% Pass Rate).`
