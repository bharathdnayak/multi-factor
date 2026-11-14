import os
import sys
import time
import json
import glob
import uuid
import hashlib
import threading
from collections import deque
from typing import Optional, List, Dict, Any, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Sensitive keyword patterns indicating high-threat reconnaissance or credential hunting
SENSITIVE_KEYWORDS = {
    "password", "passwords", "pwd", "credential", "creds", "secret", "token",
    "api_key", "private_key", "id_rsa", "database", "backup", "admin", "root",
    "shadow", "vault", "crypto", "wallet", "seed", "finance", "bank", "confidential",
    "mimikatz", "dump", "exfil", "malware", "payload", "exploit", "hack", "bypass"
}


class ForensicTracker:
    """
    Centralized Thread-Safe Forensic Event Recorder for the Honeypot Environment.
    Records every interaction made by the intruder after honeypot activation:
    - Application launches (Chrome, PowerShell, Explorer, Notepad)
    - Folder paths traversed & directory operations (mkdir, rename, move, delete)
    - Files opened, viewed, created, modified (with before/after diffs & hashes), deleted
    - Recycle Bin transitions (restore, permanent delete, empty)
    - Web searches and URLs typed inside Decoy Chrome
    - Shell commands and diverted sandbox file writes
    
    Persists structured events to:
      1. data/forensics/sessions/session_<id>/events.jsonl (Session-isolated journal)
      2. data/forensics/sessions/session_<id>/file_changes.jsonl (Session-isolated file change log)
      3. data/forensics/session_actions.jsonl (Active session JSON lines mirror)
      4. data/forensics/file_changes.jsonl (Active session file change mirror)
      5. data/forensics/honeypot_commands.log (Human-readable audit log)
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ForensicTracker, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, log_dir=None, storage_dir=None, **kwargs):
        effective_dir = log_dir or storage_dir
        if getattr(self, "_initialized", False):
            if effective_dir and effective_dir != self.log_dir:
                self.use_temp_storage(effective_dir)
            return
            
        self.log_dir = effective_dir or os.path.join(PROJECT_ROOT, "data", "forensics")
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.sessions_dir = os.path.join(self.log_dir, "sessions")
        os.makedirs(self.sessions_dir, exist_ok=True)
        
        self.jsonl_path = os.path.join(self.log_dir, "session_actions.jsonl")
        self.file_changes_path = os.path.join(self.log_dir, "file_changes.jsonl")
        self.text_log_path = os.path.join(self.log_dir, "honeypot_commands.log")
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        
        self.archive_dir = os.path.join(self.log_dir, "archive")
        os.makedirs(self.archive_dir, exist_ok=True)

        self._write_lock = threading.RLock()
        self._recent_signatures = deque(maxlen=30)
        self.events: List[Dict[str, Any]] = []
        self.file_changes: List[Dict[str, Any]] = []
        
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S")
        self.incident_id = f"INC-{timestamp_slug}"
        self.session_id = f"SESS_{timestamp_slug}_{uuid.uuid4().hex[:6]}"
        self.session_start = time.time()
        self._init_session_directory()

        # Check if an active session already exists on disk and is healthy
        has_active_session = False
        if os.path.exists(self.jsonl_path) and os.path.getsize(self.jsonl_path) > 0:
            try:
                disk_events = []
                with open(self.jsonl_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            disk_events.append(json.loads(line))
                if disk_events:
                    self.events = disk_events
                    last_event = disk_events[-1]
                    self.session_id = last_event.get("session_id", self.session_id)
                    self.incident_id = last_event.get("incident_id", self.incident_id)
                    self.session_start = disk_events[0].get("unix_time", self.session_start)
                    self._init_session_directory()
                    has_active_session = True
            except Exception:
                pass

        # Load any existing active file changes
        if os.path.exists(self.file_changes_path) and os.path.getsize(self.file_changes_path) > 0:
            try:
                with open(self.file_changes_path, "r", encoding="utf-8") as f:
                    self.file_changes = [json.loads(line) for line in f if line.strip()]
            except Exception:
                pass

        self._initialized = True

        if not has_active_session:
            # Log initial session activation
            self.record_event(
                action_type="HONEYPOT_ACTIVATED",
                target="Honeypot Deception Subsystem",
                details={
                    "status": "Intruder trapped in active deception sandbox",
                    "session_id": self.session_id,
                    "incident_id": self.incident_id
                },
                severity="ALERT",
                application="SYSTEM",
                outcome="SUCCESS"
            )

    def _init_session_directory(self):
        """Creates and resolves the isolated per-session evidence directory."""
        self.session_dir = os.path.join(self.sessions_dir, f"session_{self.session_id}")
        self.session_evidence_dir = os.path.join(self.session_dir, "evidence")
        os.makedirs(self.session_dir, exist_ok=True)
        os.makedirs(self.session_evidence_dir, exist_ok=True)
        self.session_jsonl_path = os.path.join(self.session_dir, "events.jsonl")
        self.session_file_changes_path = os.path.join(self.session_dir, "file_changes.jsonl")

    def record_event(
        self,
        action_type: str,
        target: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "INFO",
        application: str = "SYSTEM",
        outcome: str = "SUCCESS",
        actor: str = "unauthorized_operator"
    ) -> Dict[str, Any]:
        """
        Records a single forensic event with standardized schema, ISO timestamp,
        sequential event_id, outcome, UTC formatting, correlation_id, and immediate persistent flush.
        Strictly writes to both active session mirror and isolated session directory.
        """
        now = time.time()
        tz_name = time.tzname[0] if time.tzname else "UTC"
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        timestamp_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        elapsed_ms = int(round((now - self.session_start) * 1000))
        details = dict(details or {})
        
        # Redact sensitive credentials in parameters
        for sec_key in ["password", "pwd", "otp", "auth_token", "private_key", "secret_key"]:
            if sec_key in details and isinstance(details[sec_key], str) and len(details[sec_key]) > 0:
                details[f"{sec_key}_length"] = len(details[sec_key])
                details[sec_key] = "***REDACTED***"

        # Categorize event type
        atype_upper = str(action_type).upper()
        if any(atype_upper.startswith(prefix) for prefix in ["FILE_", "FOLDER_", "PATH_", "VFS_", "DIRECTORY_"]):
            event_type = "FILE_OPERATION"
        elif any(atype_upper.startswith(prefix) for prefix in ["SHELL_", "COMMAND_"]):
            event_type = "COMMAND_EXECUTION"
        elif any(atype_upper.startswith(prefix) for prefix in ["BROWSER_", "URL_", "SEARCH_", "C2_"]):
            event_type = "BROWSER_ACTIVITY"
        elif atype_upper.startswith("WINDOW_") or atype_upper.startswith("HOTKEY_"):
            event_type = "WINDOW_MANAGEMENT"
        elif atype_upper in ["HONEYPOT_ACTIVATED", "CREDENTIAL_TRAP_TRIGGERED", "SANDBOX_FILE_INTERCEPTED", "SESSION_RECOVERY"]:
            event_type = "HONEYPOT_SECURITY"
        elif atype_upper in ["PERSONALIZATION_CHANGED", "START_MENU_SEARCH", "SETTINGS_CHANGED"]:
            event_type = "SYSTEM_SETTING"
        else:
            event_type = atype_upper

        # Determine target type
        str_target = str(target)
        if str_target.startswith("http://") or str_target.startswith("https://"):
            target_type = "URL"
            target_virtual_path = str_target
        elif "\\" in str_target or "/" in str_target or str_target.startswith("C:"):
            target_type = "DIRECTORY" if any(k in atype_upper.lower() for k in ["dir", "folder"]) else "FILE"
            target_virtual_path = str_target
        elif "command" in atype_upper.lower() or "shell" in atype_upper.lower():
            target_type = "COMMAND"
            target_virtual_path = str_target
        elif "window" in atype_upper.lower() or "app" in atype_upper.lower():
            target_type = "WINDOW"
            target_virtual_path = str_target
        else:
            target_type = "SYSTEM"
            target_virtual_path = str(details.get("virtual_path", details.get("destination", str_target)))

        # Analyze target and details for sensitive indicators
        check_str = f"{target} {json.dumps(details)}".lower()
        flagged_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in check_str]
        if flagged_keywords and severity == "INFO":
            severity = "SUSPICIOUS"
            details["flagged_keywords"] = flagged_keywords

        with self._write_lock:
            # Deduplication: Check for identical event logged within 50ms (suppress duplicate Qt callbacks)
            nav_m = str(details.get("navigation_method", ""))
            src_f = str(details.get("source_folder", ""))
            sig = (action_type, str_target, application, outcome, nav_m, src_f)
            if hasattr(self, "_recent_signatures"):
                for prev_sig, prev_time in self._recent_signatures:
                    if prev_sig == sig and (now - prev_time) < 0.05:
                        return self.events[-1] if self.events else None
                self._recent_signatures.append((sig, now))

            evt_num = len(self.events) + 1
            event_id = f"EVT-{evt_num:04d}"
            corr_prefix = getattr(self, "session_id", "SESS")[-6:]
            correlation_id = details.get("correlation_id", f"CORR-{corr_prefix}-{evt_num:04d}")

            event = {
                # Standardized DFIR Schema Fields
                "event_id": event_id,
                "session_id": getattr(self, "session_id", "SESS_DEFAULT"),
                "incident_id": getattr(self, "incident_id", "INC_DEFAULT"),
                "timestamp": timestamp_str,
                "timestamp_utc": timestamp_utc,
                "timezone": tz_name,
                "elapsed_seconds": round(now - self.session_start, 2),
                "elapsed_ms": elapsed_ms,
                "actor": actor,
                "application": application or details.get("application", "SYSTEM"),
                "event_type": event_type,
                "action": action_type,
                "target_type": target_type,
                "target_virtual_path": target_virtual_path,
                "result": outcome,
                "severity": severity,
                "metadata": details,
                "correlation_id": correlation_id,

                # Legacy fields for complete backward compatibility
                "action_type": action_type,
                "target": str_target,
                "outcome": outcome,
                "details": details,
                "unix_time": now
            }

            self.events.append(event)
            
            # 1. Append to active session JSONL mirror
            self._safe_append_jsonl(self.jsonl_path, event)
            # 2. Append to session-isolated events.jsonl
            if hasattr(self, "session_jsonl_path"):
                self._safe_append_jsonl(self.session_jsonl_path, event)
                
            # 3. Append to human-readable audit log
            try:
                with open(self.text_log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{timestamp_str} {tz_name}] [{severity}] [{action_type}] [{application}] {target} ({outcome}) | {json.dumps(details)}\n")
                    f.flush()
            except Exception as e:
                print(f"[FORENSICS] Error writing to text log: {e}", file=sys.stderr)
                
        return event

    def _safe_append_jsonl(self, filepath: str, record: Dict[str, Any]):
        """Safely appends a JSON record with immediate disk flush and sync."""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception as e:
            print(f"[FORENSICS] Error appending to '{filepath}': {e}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Dedicated File Operations Forensic Instrumentation
    # -------------------------------------------------------------------------
    def record_file_deletion(
        self,
        virtual_path: str,
        filename: str,
        file_type: str = "File",
        file_size: int = 0,
        sha256_pre_delete: str = "",
        to_recycle_bin: bool = True,
        application: str = "VFS",
        success: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        source_app: Optional[str] = None,
        recoverable: Optional[bool] = None,
        pre_sha256: Optional[str] = None,
        pre_size: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Records a detailed forensic file deletion event, preserving pre-deletion state,
        hashes, sizes, recovery status, and application source.
        """
        if source_app:
            application = source_app
        if recoverable is not None:
            to_recycle_bin = recoverable
        if pre_sha256:
            sha256_pre_delete = pre_sha256
        if pre_size is not None:
            file_size = pre_size
        details = {
            "operation": "DELETE",
            "original_path": virtual_path,
            "filename": filename,
            "file_type": file_type,
            "file_size_bytes": file_size,
            "sha256_pre_delete": sha256_pre_delete or "N/A",
            "to_recycle_bin": to_recycle_bin,
            "recovery_status": "Recoverable in Virtual Recycle Bin" if to_recycle_bin else "Permanently Deleted",
            "source_application": application
        }
        if metadata:
            details.update(metadata)

        action_name = "FILE_DELETED" if success else "FILE_DELETE_FAILED"
        outcome = "SUCCESS" if success else "FAILURE"
        sev = "ALERT" if success else "SUSPICIOUS"

        event = self.record_event(
            action_type=action_name,
            target=virtual_path,
            details=details,
            severity=sev,
            application=application,
            outcome=outcome
        )

        # Record structured change evidence
        change_record = {
            "evidence_id": f"EVT-CHG-{len(self.file_changes)+1:04d}",
            "event_id": event.get("event_id"),
            "session_id": getattr(self, "session_id", "SESS_DEFAULT"),
            "operation": "DELETION",
            "change_type": "DELETED",
            "virtual_path": virtual_path,
            "filename": filename,
            "file_type": file_type,
            "old_size_bytes": file_size,
            "new_size_bytes": 0,
            "pre_size": file_size,
            "sha256_before": sha256_pre_delete or "N/A",
            "sha256_pre_delete": sha256_pre_delete or "N/A",
            "pre_sha256": sha256_pre_delete or "N/A",
            "sha256_after": "DELETED",
            "diff_summary": f"File '{filename}' ({file_size} bytes) removed from virtual filesystem.",
            "content_diff": None,
            "application": application,
            "source_app": application,
            "to_recycle_bin": to_recycle_bin,
            "recoverable_in_recycle_bin": to_recycle_bin,
            "timestamp": event.get("timestamp"),
            "timestamp_utc": event.get("timestamp_utc"),
            "result": outcome
        }
        self._record_file_change(change_record)
        return event

    def record_file_modification(
        self,
        virtual_path: str,
        old_size: int = 0,
        new_size: int = 0,
        sha256_before: str = "",
        sha256_after: str = "",
        diff: Optional[str] = None,
        application: str = "VFS",
        success: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Records a detailed forensic file modification event, capturing before-and-after
        metadata, SHA-256 digests, and textual diff.
        """
        if diff is None and "content_diff" in kwargs:
            diff = kwargs["content_diff"]
        filename = os.path.basename(virtual_path.replace("\\", "/"))
        details = {
            "operation": "MODIFY",
            "virtual_path": virtual_path,
            "filename": filename,
            "old_size_bytes": old_size,
            "new_size_bytes": new_size,
            "size_delta_bytes": new_size - old_size,
            "sha256_before": sha256_before or "N/A",
            "sha256_after": sha256_after or "N/A",
            "has_diff": bool(diff),
            "diff_snippet": diff[:1000] if diff else None,
            "source_application": application
        }

        sev = "ALERT" if any(kw in virtual_path.lower() for kw in SENSITIVE_KEYWORDS) else "SUSPICIOUS"
        event = self.record_event(
            action_type="FILE_MODIFIED",
            target=virtual_path,
            details=details,
            severity=sev,
            application=application,
            outcome="SUCCESS" if success else "FAILURE"
        )

        change_record = {
            "evidence_id": f"EVT-CHG-{len(self.file_changes)+1:04d}",
            "event_id": event.get("event_id"),
            "session_id": getattr(self, "session_id", "SESS_DEFAULT"),
            "operation": "MODIFICATION",
            "change_type": "MODIFIED",
            "virtual_path": virtual_path,
            "filename": filename,
            "file_type": "Virtual Document",
            "old_size_bytes": old_size,
            "new_size_bytes": new_size,
            "file_size": new_size,
            "sha256_before": sha256_before or "N/A",
            "pre_hash": sha256_before or "N/A",
            "sha256_after": sha256_after or "N/A",
            "post_hash": sha256_after or "N/A",
            "diff_summary": f"Content modified: {old_size}B -> {new_size}B (Delta: {new_size - old_size:+d}B)",
            "content_diff": diff,
            "diff": diff,
            "application": application,
            "source_app": application,
            "to_recycle_bin": False,
            "timestamp": event.get("timestamp"),
            "timestamp_utc": event.get("timestamp_utc"),
            "result": "SUCCESS" if success else "FAILURE"
        }
        self._record_file_change(change_record)
        return event

    def record_file_creation(
        self,
        virtual_path: str,
        file_size: int = 0,
        sha256_hash: str = "",
        is_overwrite: bool = False,
        application: str = "VFS",
        success: bool = True,
        source_app: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Records file creation or overwrite events."""
        application = source_app or application
        filename = os.path.basename(virtual_path.replace("\\", "/"))
        action_name = "FILE_OVERWRITTEN" if is_overwrite else "FILE_CREATED"
        details = {
            "operation": "CREATE" if not is_overwrite else "OVERWRITE",
            "virtual_path": virtual_path,
            "filename": filename,
            "file_size_bytes": file_size,
            "sha256": sha256_hash or "N/A",
            "is_overwrite": is_overwrite,
            "source_application": application
        }

        sev = "SUSPICIOUS" if any(kw in virtual_path.lower() for kw in SENSITIVE_KEYWORDS) else "INFO"
        event = self.record_event(
            action_type=action_name,
            target=virtual_path,
            details=details,
            severity=sev,
            application=application,
            outcome="SUCCESS" if success else "FAILURE"
        )

        change_record = {
            "evidence_id": f"EVT-CHG-{len(self.file_changes)+1:04d}",
            "event_id": event.get("event_id"),
            "session_id": getattr(self, "session_id", "SESS_DEFAULT"),
            "operation": "CREATION" if not is_overwrite else "OVERWRITE",
            "change_type": "CREATED" if not is_overwrite else "OVERWRITTEN",
            "virtual_path": virtual_path,
            "filename": filename,
            "file_type": "Virtual File",
            "old_size_bytes": 0,
            "new_size_bytes": file_size,
            "file_size": file_size,
            "sha256_before": "NONE",
            "sha256_after": sha256_hash or "N/A",
            "sha256_hash": sha256_hash or "N/A",
            "diff_summary": f"New virtual file created ({file_size} bytes).",
            "content_diff": None,
            "application": application,
            "source_app": application,
            "to_recycle_bin": False,
            "timestamp": event.get("timestamp"),
            "timestamp_utc": event.get("timestamp_utc"),
            "result": "SUCCESS" if success else "FAILURE"
        }
        self._record_file_change(change_record)
        return event

    def record_file_read(
        self,
        virtual_path: str,
        file_size: int = 0,
        sha256_hash: Optional[str] = None,
        application: str = "VFS"
    ) -> Dict[str, Any]:
        """Records file read / open / inspection operations."""
        filename = os.path.basename(virtual_path.replace("\\", "/"))
        is_sensitive = any(kw in virtual_path.lower() for kw in SENSITIVE_KEYWORDS)
        details = {
            "operation": "READ",
            "virtual_path": virtual_path,
            "filename": filename,
            "file_size_bytes": file_size,
            "sha256": sha256_hash or "N/A",
            "sensitive_flag": is_sensitive,
            "source_application": application
        }
        sev = "ALERT" if is_sensitive else "INFO"
        return self.record_event(
            action_type="FILE_READ",
            target=virtual_path,
            details=details,
            severity=sev,
            application=application,
            outcome="SUCCESS"
        )

    def record_directory_operation(
        self,
        action: str,
        target_path: str,
        application: str = "VFS",
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "SUCCESS"
    ) -> Dict[str, Any]:
        """Records directory operations (mkdir, rename, move, delete)."""
        d = dict(details or {})
        d.update({"source_application": application, "directory_path": target_path})
        atype = f"DIRECTORY_{action.upper()}"
        sev = "SUSPICIOUS" if "DELETE" in atype else "INFO"
        return self.record_event(
            action_type=atype,
            target=target_path,
            details=d,
            severity=sev,
            application=application,
            outcome=outcome
        )

    def record_recycle_bin_action(
        self,
        action: str,
        target: str,
        details: Optional[Dict[str, Any]] = None,
        application: str = "VFS"
    ) -> Dict[str, Any]:
        """Records virtual recycle bin actions: restore, permanent delete, empty."""
        d = dict(details or {})
        d["application"] = application
        act_clean = action.upper()
        if "EMPTY" in act_clean:
            action_type = "EMPTY_RECYCLE_BIN"
            sev = "ALERT"
        elif "RESTORE" in act_clean:
            action_type = "RESTORE_FILE"
            sev = "INFO"
        elif "PERMANENT" in act_clean:
            action_type = "PERMANENT_DELETE"
            sev = "ALERT"
        else:
            action_type = f"RECYCLE_BIN_{act_clean}"
            sev = "INFO"
        return self.record_event(
            action_type=action_type,
            target=target,
            details=d,
            severity=sev,
            application=application,
            outcome="SUCCESS"
        )

    def _record_file_change(self, change_record: Dict[str, Any]):
        """Persists a structured file change evidence record."""
        with self._write_lock:
            self.file_changes.append(change_record)
            self._safe_append_jsonl(self.file_changes_path, change_record)
            if hasattr(self, "session_file_changes_path"):
                self._safe_append_jsonl(self.session_file_changes_path, change_record)

    def get_file_changes(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Returns the structured file changes for the specified or current active session."""
        target_session = session_id or getattr(self, "session_id", None)
        with self._write_lock:
            if not target_session:
                return list(self.file_changes)
            return [fc for fc in self.file_changes if fc.get("session_id") == target_session or fc.get("incident_id") == target_session]

    # -------------------------------------------------------------------------
    # High-level Decoy Application Recorders
    # -------------------------------------------------------------------------
    def record_app_launch(self, app_name):
        return self.record_event(
            "APP_LAUNCH",
            app_name,
            {"application": app_name},
            severity="INFO",
            application="DESKTOP",
            outcome="SUCCESS"
        )

    def record_folder_navigation(self, folder_path, source_path=None, method="NAVIGATE", outcome="SUCCESS"):
        return self.record_event(
            "FOLDER_NAVIGATED",
            folder_path,
            {
                "source_folder": source_path,
                "destination_folder": folder_path,
                "navigation_method": method
            },
            severity="INFO",
            application="FILE_EXPLORER",
            outcome=outcome
        )

    def record_failed_access(self, path, reason="Path not found in virtual filesystem", application="FILE_EXPLORER"):
        return self.record_event(
            "PATH_ACCESS_FAILED",
            path,
            {"path": path, "reason": reason},
            severity="SUSPICIOUS",
            application=application,
            outcome="FAILURE"
        )

    def record_window_action(self, app_id, action="focused"):
        return self.record_event(
            f"WINDOW_{action.upper()}",
            app_id,
            {"window": app_id, "window_action": action},
            severity="INFO",
            application="WINDOW_MANAGER",
            outcome="SUCCESS"
        )

    def record_action(self, action_type, target="", details=None, severity="INFO", application=None, outcome="SUCCESS"):
        return self.record_event(
            action_type,
            target,
            details or {},
            severity=severity,
            application=application or "DESKTOP",
            outcome=outcome
        )

    def record_desktop_icon_click(self, icon_name):
        return self.record_event(
            "DESKTOP_ICON_CLICKED",
            icon_name,
            {"icon_name": icon_name},
            severity="INFO",
            application="DESKTOP",
            outcome="SUCCESS"
        )

    def record_properties_view(self, item_path, is_dir=False):
        return self.record_event(
            "PROPERTIES_VIEW",
            item_path,
            {"path": item_path, "is_directory": is_dir},
            severity="INFO",
            application="FILE_EXPLORER",
            outcome="SUCCESS"
        )

    def record_clipboard_action(self, action="COPY", paths=None, application="FILE_EXPLORER"):
        return self.record_event(
            f"CLIPBOARD_{action.upper()}",
            str(paths or []),
            {"action": action, "paths": paths or []},
            severity="INFO",
            application=application,
            outcome="SUCCESS"
        )

    def record_file_access(self, file_path, action="VIEW", application="FILE_EXPLORER", outcome="SUCCESS"):
        is_sensitive = any(kw in file_path.lower() for kw in SENSITIVE_KEYWORDS)
        sev = "SUSPICIOUS" if is_sensitive else "INFO"
        return self.record_event(
            f"FILE_{action.upper()}",
            file_path,
            {"file_path": file_path, "mode": action, "sensitive_flag": is_sensitive},
            severity=sev,
            application=application,
            outcome=outcome
        )

    def record_shell_command(self, command, current_dir):
        is_suspicious = any(kw in command.lower() for kw in SENSITIVE_KEYWORDS) or any(
            t in command.lower() for t in ["whoami", "ipconfig", "net user", "reg ", "echo ", ">", "curl", "powershell", "rm", "del"]
        )
        sev = "SUSPICIOUS" if is_suspicious else "INFO"
        return self.record_event(
            "SHELL_COMMAND",
            command,
            {"working_directory": current_dir, "command": command},
            severity=sev,
            application="POWERSHELL"
        )

    def record_browser_search(self, query):
        is_suspicious = any(kw in query.lower() for kw in SENSITIVE_KEYWORDS)
        return self.record_event(
            "BROWSER_SEARCH",
            query,
            {"search_query": query},
            severity="SUSPICIOUS" if is_suspicious else "INFO",
            application="CHROME"
        )

    def record_url_visit(self, url):
        return self.record_event(
            "URL_VISITED",
            url,
            {"destination_url": url},
            severity="INFO",
            application="CHROME"
        )

    def record_sandbox_write(self, filename, byte_size):
        return self.record_event(
            "SANDBOX_FILE_INTERCEPTED",
            filename,
            {"filename": filename, "bytes_written": byte_size, "sandbox_path": os.path.join(self.sandbox_dir, filename)},
            severity="ALERT",
            application="SANDBOX"
        )

    def record_credential_trap(self, service: str, username: str, password_length: int = 0, notes: str = ""):
        return self.record_event(
            "CREDENTIAL_TRAP_TRIGGERED",
            f"{service} ({username})",
            {
                "service": service,
                "captured_username": username,
                "password_length": password_length,
                "notes": notes
            },
            severity="ALERT",
            application="HONEYPOT_PORTAL"
        )

    def record_network_recon(self, command: str, target: str, recon_type: str = "NETWORK_DISCOVERY"):
        """Records network diagnostic and reconnaissance commands (ping, arp, route, ssh, etc.)."""
        return self.record_event(
            "NETWORK_RECONNAISSANCE",
            f"{recon_type}: {target}",
            {
                "command": command,
                "target": target,
                "recon_type": recon_type
            },
            severity="SUSPICIOUS",
            application="POWERSHELL"
        )

    def record_c2_download(self, url: str, c2_host: str, filename: str, file_size: int = 0):
        """Records intercepted C2 payload download attempts diverted to the sandbox."""
        return self.record_event(
            "C2_PAYLOAD_INTERCEPTED",
            f"{filename} from {c2_host}",
            {
                "source_url": url,
                "c2_server": c2_host,
                "diverted_filename": filename,
                "bytes_diverted": file_size,
                "sandbox_destination": os.path.join(self.sandbox_dir, filename)
            },
            severity="ALERT",
            application="CHROME"
        )

    # -------------------------------------------------------------------------
    # Session Management & Strict Isolation
    # -------------------------------------------------------------------------
    def start_new_session(self, incident_id: Optional[str] = None, session_id: Optional[str] = None, archive_previous: bool = True):
        """
        Begins a brand new, isolated forensic session.
        Archives previous session logs into both the archive directory and the dedicated
        historical session directory so only current active session data is in active logs.
        """
        with self._write_lock:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            old_session_id = getattr(self, "session_id", None)

            # Archive previous logs if they contain data
            if archive_previous and old_session_id:
                if os.path.exists(self.jsonl_path) and os.path.getsize(self.jsonl_path) > 0:
                    try:
                        archive_jsonl = os.path.join(self.archive_dir, f"session_actions_{timestamp}_{old_session_id}.jsonl")
                        with open(self.jsonl_path, "r", encoding="utf-8") as src, open(archive_jsonl, "w", encoding="utf-8") as dst:
                            dst.write(src.read())
                    except Exception as e:
                        print(f"[FORENSICS] Error archiving JSONL: {e}", file=sys.stderr)
                
                if os.path.exists(self.text_log_path) and os.path.getsize(self.text_log_path) > 0:
                    try:
                        archive_txt = os.path.join(self.archive_dir, f"honeypot_commands_{timestamp}_{old_session_id}.log")
                        with open(self.text_log_path, "r", encoding="utf-8") as src, open(archive_txt, "w", encoding="utf-8") as dst:
                            dst.write(src.read())
                    except Exception as e:
                        print(f"[FORENSICS] Error archiving text log: {e}", file=sys.stderr)

            # Reset active session files to be completely clean
            try:
                with open(self.jsonl_path, "w", encoding="utf-8") as f:
                    pass
                with open(self.file_changes_path, "w", encoding="utf-8") as f:
                    pass
                with open(self.text_log_path, "w", encoding="utf-8") as f:
                    pass
            except Exception as e:
                print(f"[FORENSICS] Error clearing active session logs: {e}", file=sys.stderr)

            self.incident_id = incident_id or session_id or f"INC-{timestamp}"
            self.session_id = session_id or incident_id or f"SESS_{timestamp}_{uuid.uuid4().hex[:6]}"
            self.session_start = time.time()
            self.events = []
            self.file_changes = []
            self._recent_signatures.clear()
            self._init_session_directory()

            # Record active session state file
            try:
                active_meta = {
                    "incident_id": self.incident_id,
                    "session_id": self.session_id,
                    "session_start": self.session_start,
                    "created_at": timestamp
                }
                meta_path = os.path.join(self.log_dir, "active_incident_session.json")
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(active_meta, f, indent=2)
            except Exception:
                pass

            # Log session initialization event
            init_event = self.record_event(
                action_type="HONEYPOT_ACTIVATED",
                target="Honeypot Deception Subsystem",
                details={
                    "status": "Intruder trapped in active deception sandbox",
                    "session_id": self.session_id,
                    "incident_id": self.incident_id
                },
                severity="ALERT",
                application="SYSTEM",
                outcome="SUCCESS"
            )
            
            return self.session_id

    def get_timeline(self, include_recent_archive: bool = False, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Returns the chronological list of recorded events for the CURRENT active session
        or the requested specific session_id.
        STRICT SESSION ISOLATION: Never inherits or mixes events from older/archived sessions.
        """
        target_session = session_id or getattr(self, "session_id", None)
        with self._write_lock:
            disk_events = []
            if os.path.exists(self.jsonl_path):
                try:
                    with open(self.jsonl_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.strip():
                                disk_events.append(json.loads(line))
                except Exception:
                    pass

            if disk_events and len(disk_events) >= len(self.events):
                self.events = disk_events

            if target_session and self.events:
                matched = [e for e in self.events if e.get("session_id") == target_session or e.get("incident_id") == target_session]
                if matched:
                    return list(matched)
                # If target is explicitly different, check the session archive directory
                sess_file = os.path.join(self.sessions_dir, f"session_{target_session}", "events.jsonl")
                if os.path.exists(sess_file):
                    try:
                        with open(sess_file, "r", encoding="utf-8") as f:
                            return [json.loads(l) for l in f if l.strip()]
                    except Exception:
                        pass

            # Return current events matching active session or all active events if single session
            if target_session:
                return [e for e in self.events if e.get("session_id") == target_session or e.get("incident_id") == target_session]
            return list(self.events)

    def get_summary_stats(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Computes statistical metrics strictly for the specified or current active session."""
        events = self.get_timeline(session_id=session_id)
        total = len(events)
        elapsed = round(time.time() - self.session_start, 2)
        target_session = session_id or getattr(self, "session_id", "SESS_ACTIVE")
        
        folders_visited = set()
        files_accessed = set()
        files_created = set()
        files_modified = set()
        files_deleted = set()
        commands_run = []
        searches_performed = []
        sandbox_files = []
        network_recon = []
        c2_downloads = []
        credential_traps = []
        sensitive_flags = []
        failed_operations = []
        apps_engaged = set()

        for e in events:
            atype = e.get("action_type", e.get("action", ""))
            target = e.get("target", "")
            app = e.get("application", "")
            result = e.get("result", e.get("outcome", "SUCCESS"))
            if app and app != "SYSTEM":
                apps_engaged.add(app)

            if result == "FAILURE" or "FAILED" in atype:
                failed_operations.append(f"{atype}: {target}")

            if "FOLDER" in atype or atype == "FOLDER_NAVIGATED" or "DIRECTORY" in atype:
                folders_visited.add(target)
            elif atype == "SANDBOX_FILE_INTERCEPTED":
                sandbox_files.append(target)
            elif atype == "C2_PAYLOAD_INTERCEPTED":
                c2_downloads.append(target)
            elif atype == "NETWORK_RECONNAISSANCE":
                network_recon.append(target)
            elif atype == "CREDENTIAL_TRAP_TRIGGERED":
                credential_traps.append(target)
            elif "DELETE" in atype:
                files_deleted.add(target)
            elif "MODIFY" in atype:
                files_modified.add(target)
            elif "CREATE" in atype or "OVERWRITTEN" in atype:
                files_created.add(target)
            elif "FILE_" in atype:
                files_accessed.add(target)
            elif atype == "SHELL_COMMAND":
                commands_run.append(target)
            elif atype == "BROWSER_SEARCH":
                searches_performed.append(target)

            if e.get("severity") in ("SUSPICIOUS", "ALERT", "CRITICAL"):
                sensitive_flags.append(f"{atype}: {target}")

        file_changes = self.get_file_changes(session_id=target_session)

        return {
            "incident_id": getattr(self, "incident_id", "INC_ACTIVE"),
            "session_id": target_session,
            "total_actions": total,
            "session_duration_seconds": elapsed,
            "folders_visited": list(folders_visited),
            "files_accessed": list(files_accessed),
            "files_created": list(files_created),
            "files_modified": list(files_modified),
            "files_deleted": list(files_deleted),
            "file_changes_count": len(file_changes),
            "file_changes": file_changes,
            "commands_executed": commands_run,
            "browser_searches": searches_performed,
            "sandbox_interceptions": sandbox_files,
            "network_recon_events": network_recon,
            "c2_payloads_intercepted": c2_downloads,
            "credential_traps": credential_traps,
            "suspicious_events_count": len(sensitive_flags),
            "suspicious_events": sensitive_flags,
            "failed_operations_count": len(failed_operations),
            "failed_operations": failed_operations,
            "applications_engaged": list(apps_engaged)
        }

    def reset_session(self):
        """Resets tracker for a new session and archives previous actions."""
        return self.start_new_session(archive_previous=True)

    def use_temp_storage(self, temp_dir: str):
        """Redirects tracker log/sandbox storage into `temp_dir` for isolated tests."""
        with self._write_lock:
            if not hasattr(self, "_orig_storage"):
                self._orig_storage = (
                    self.log_dir,
                    self.jsonl_path,
                    self.file_changes_path,
                    self.text_log_path,
                    self.sandbox_dir,
                    self.archive_dir,
                    self.sessions_dir
                )
            self.log_dir = os.path.join(temp_dir, "forensics")
            self.sandbox_dir = os.path.join(temp_dir, "sandbox")
            self.archive_dir = os.path.join(self.log_dir, "archive")
            self.sessions_dir = os.path.join(self.log_dir, "sessions")
            self.jsonl_path = os.path.join(self.log_dir, "session_actions.jsonl")
            self.file_changes_path = os.path.join(self.log_dir, "file_changes.jsonl")
            self.text_log_path = os.path.join(self.log_dir, "honeypot_commands.log")
            os.makedirs(self.log_dir, exist_ok=True)
            os.makedirs(self.sandbox_dir, exist_ok=True)
            os.makedirs(self.archive_dir, exist_ok=True)
            os.makedirs(self.sessions_dir, exist_ok=True)
        return self.start_new_session(archive_previous=False)

    def restore_storage(self):
        """Restores original ForensicTracker storage directories after isolated testing."""
        with self._write_lock:
            if hasattr(self, "_orig_storage"):
                (
                    self.log_dir,
                    self.jsonl_path,
                    self.file_changes_path,
                    self.text_log_path,
                    self.sandbox_dir,
                    self.archive_dir,
                    self.sessions_dir
                ) = self._orig_storage
                del self._orig_storage
            self.events = []
            self.file_changes = []


# Global helper instance
def get_tracker():
    return ForensicTracker()
