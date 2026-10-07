import os
import sys
import time
import json
import threading

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
    - Folder paths traversed
    - Files opened, previewed, or modified
    - Web searches and URLs typed inside Decoy Chrome
    - Shell commands and diverted sandbox file writes
    
    Persists structured events to:
      1. data/forensics/session_actions.jsonl (Machine-parseable JSON lines)
      2. data/forensics/honeypot_commands.log (Human-readable audit log)
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ForensicTracker, cls).__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, log_dir=None):
        if self._initialized:
            return
            
        self.log_dir = log_dir or os.path.join(PROJECT_ROOT, "data", "forensics")
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.jsonl_path = os.path.join(self.log_dir, "session_actions.jsonl")
        self.text_log_path = os.path.join(self.log_dir, "honeypot_commands.log")
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        
        self.archive_dir = os.path.join(self.log_dir, "archive")
        os.makedirs(self.archive_dir, exist_ok=True)
        self.session_id = f"SESS_{time.strftime('%Y%m%d_%H%M%S')}"
        self.session_start = time.time()
        self.events = []
        self._write_lock = threading.Lock()
        self._initialized = True
        
        # Log session initialization
        self.record_event(
            action_type="HONEYPOT_ACTIVATED",
            target="Honeypot Deception Subsystem",
            details={"status": "Intruder trapped in active deception sandbox", "session_id": self.session_id},
            severity="ALERT"
        )

    def record_event(self, action_type, target, details=None, severity="INFO"):
        """
        Records a single forensic event with ISO timestamp, classification, and severity.
        """
        now = time.time()
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        details = details or {}
        
        # Analyze target and details for sensitive indicators
        check_str = f"{target} {json.dumps(details)}".lower()
        flagged_keywords = [kw for kw in SENSITIVE_KEYWORDS if kw in check_str]
        if flagged_keywords and severity == "INFO":
            severity = "SUSPICIOUS"
            details["flagged_keywords"] = flagged_keywords

        event = {
            "timestamp": timestamp_str,
            "unix_time": now,
            "elapsed_seconds": round(now - self.session_start, 2),
            "session_id": getattr(self, "session_id", "SESS_DEFAULT"),
            "action_type": action_type,
            "target": str(target),
            "severity": severity,
            "details": details
        }
        
        with self._write_lock:
            self.events.append(event)
            
            # 1. Append to JSONL log
            try:
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                print(f"[FORENSICS] Error writing to JSONL: {e}", file=sys.stderr)
                
            # 2. Append to human-readable log
            try:
                with open(self.text_log_path, "a", encoding="utf-8") as f:
                    f.write(f"[{timestamp_str}] [{severity}] [{action_type}] {target} | {json.dumps(details)}\n")
            except Exception as e:
                print(f"[FORENSICS] Error writing to text log: {e}", file=sys.stderr)
                
        return event

    def record_app_launch(self, app_name):
        return self.record_event("APP_LAUNCH", app_name, {"application": app_name}, severity="INFO")

    def record_folder_navigation(self, folder_path, source_path=None):
        return self.record_event(
            "FOLDER_NAVIGATED",
            folder_path,
            {"source_folder": source_path, "destination_folder": folder_path},
            severity="INFO"
        )

    def record_file_access(self, file_path, action="VIEW"):
        is_sensitive = any(kw in file_path.lower() for kw in SENSITIVE_KEYWORDS)
        sev = "SUSPICIOUS" if is_sensitive else "INFO"
        return self.record_event(
            f"FILE_{action.upper()}",
            file_path,
            {"file_path": file_path, "mode": action, "sensitive_flag": is_sensitive},
            severity=sev
        )

    def record_shell_command(self, command, current_dir):
        is_suspicious = any(kw in command.lower() for kw in SENSITIVE_KEYWORDS) or any(
            t in command.lower() for t in ["whoami", "ipconfig", "net user", "reg ", "echo ", ">", "curl", "powershell"]
        )
        sev = "SUSPICIOUS" if is_suspicious else "INFO"
        return self.record_event(
            "SHELL_COMMAND",
            command,
            {"working_directory": current_dir, "command": command},
            severity=sev
        )

    def record_browser_search(self, query):
        is_suspicious = any(kw in query.lower() for kw in SENSITIVE_KEYWORDS)
        return self.record_event(
            "BROWSER_SEARCH",
            query,
            {"search_query": query},
            severity="SUSPICIOUS" if is_suspicious else "INFO"
        )

    def record_url_visit(self, url):
        return self.record_event(
            "URL_VISITED",
            url,
            {"destination_url": url},
            severity="INFO"
        )

    def record_sandbox_write(self, filename, byte_size):
        return self.record_event(
            "SANDBOX_FILE_INTERCEPTED",
            filename,
            {"filename": filename, "bytes_written": byte_size, "sandbox_path": os.path.join(self.sandbox_dir, filename)},
            severity="ALERT"
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
            severity="ALERT"
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
            severity="SUSPICIOUS"
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
            severity="ALERT"
        )

    def start_new_session(self, archive_previous=True):
        """
        Begins a brand new, isolated forensic session.
        Archives any previous session logs so only the current active session
        is recorded in session_actions.jsonl and presented in dashboards/reports.
        """
        with self._write_lock:
            # Archive previous logs if they contain data
            if archive_previous:
                timestamp = time.strftime("%Y%m%d_%H%M%S")
                if os.path.exists(self.jsonl_path) and os.path.getsize(self.jsonl_path) > 0:
                    try:
                        archive_jsonl = os.path.join(self.archive_dir, f"session_actions_{timestamp}.jsonl")
                        with open(self.jsonl_path, "r", encoding="utf-8") as src, open(archive_jsonl, "w", encoding="utf-8") as dst:
                            dst.write(src.read())
                    except Exception as e:
                        print(f"[FORENSICS] Error archiving JSONL: {e}", file=sys.stderr)
                
                if os.path.exists(self.text_log_path) and os.path.getsize(self.text_log_path) > 0:
                    try:
                        archive_txt = os.path.join(self.archive_dir, f"honeypot_commands_{timestamp}.log")
                        with open(self.text_log_path, "r", encoding="utf-8") as src, open(archive_txt, "w", encoding="utf-8") as dst:
                            dst.write(src.read())
                    except Exception as e:
                        print(f"[FORENSICS] Error archiving text log: {e}", file=sys.stderr)

            # Reset current files to be empty for this session
            try:
                with open(self.jsonl_path, "w", encoding="utf-8") as f:
                    pass
                with open(self.text_log_path, "w", encoding="utf-8") as f:
                    pass
            except Exception as e:
                print(f"[FORENSICS] Error clearing active session logs: {e}", file=sys.stderr)

            self.session_id = f"SESS_{time.strftime('%Y%m%d_%H%M%S')}"
            self.session_start = time.time()
            self.events = []

            # Log session initialization
            init_event = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.session_start)),
                "unix_time": self.session_start,
                "elapsed_seconds": 0.0,
                "session_id": self.session_id,
                "action_type": "HONEYPOT_ACTIVATED",
                "target": "Honeypot Deception Subsystem",
                "severity": "ALERT",
                "details": {"status": "Intruder trapped in active deception sandbox", "session_id": self.session_id}
            }
            self.events.append(init_event)
            try:
                with open(self.jsonl_path, "w", encoding="utf-8") as f:
                    f.write(json.dumps(init_event) + "\n")
                with open(self.text_log_path, "w", encoding="utf-8") as f:
                    f.write(f"[{init_event['timestamp']}] [ALERT] [HONEYPOT_ACTIVATED] Honeypot Deception Subsystem | {json.dumps(init_event['details'])}\n")
            except Exception:
                pass
            
            return self.session_id

    def get_timeline(self):
        """
        Returns the chronological list of recorded events for the CURRENT active session.
        Strictly isolates from any previous sessions.
        """
        with self._write_lock:
            if self.events:
                return list(self.events)

            if os.path.exists(self.jsonl_path):
                try:
                    all_events = []
                    with open(self.jsonl_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.strip():
                                all_events.append(json.loads(line))
                    
                    if not all_events:
                        return []

                    # Filter to return only the latest active session
                    latest_sess_id = getattr(self, "session_id", None)
                    if latest_sess_id is None:
                        latest_sess_id = all_events[-1].get("session_id")

                    if latest_sess_id:
                        session_events = [e for e in all_events if e.get("session_id") == latest_sess_id]
                        if session_events:
                            return session_events

                    # Fallback: find the last HONEYPOT_ACTIVATED index
                    last_idx = 0
                    for i, e in enumerate(all_events):
                        if e.get("action_type") == "HONEYPOT_ACTIVATED":
                            last_idx = i
                    return all_events[last_idx:]
                except Exception:
                    return []
            return []

    def get_summary_stats(self):
        """Computes statistical metrics for forensic reporting and AI intent analysis."""
        events = self.get_timeline()
        total = len(events)
        elapsed = round(time.time() - self.session_start, 2)
        
        folders_visited = set()
        files_accessed = set()
        commands_run = []
        searches_performed = []
        sandbox_files = []
        network_recon = []
        c2_downloads = []
        credential_traps = []
        sensitive_flags = []
        for e in events:
            atype = e.get("action_type", "")
            target = e.get("target", "")
            if atype == "FOLDER_NAVIGATED":
                folders_visited.add(target)
            elif atype == "SANDBOX_FILE_INTERCEPTED":
                sandbox_files.append(target)
            elif atype == "C2_PAYLOAD_INTERCEPTED":
                c2_downloads.append(target)
            elif atype == "NETWORK_RECONNAISSANCE":
                network_recon.append(target)
            elif atype == "CREDENTIAL_TRAP_TRIGGERED":
                credential_traps.append(target)
            elif "FILE_" in atype:
                files_accessed.add(target)
            elif atype == "SHELL_COMMAND":
                commands_run.append(target)
            elif atype == "BROWSER_SEARCH":
                searches_performed.append(target)
            if e.get("severity") in ("SUSPICIOUS", "ALERT", "CRITICAL"):
                sensitive_flags.append(f"{atype}: {target}")
                
        return {
            "session_id": getattr(self, "session_id", "SESS_ACTIVE"),
            "total_actions": total,
            "session_duration_seconds": elapsed,
            "folders_visited": list(folders_visited),
            "files_accessed": list(files_accessed),
            "commands_executed": commands_run,
            "browser_searches": searches_performed,
            "sandbox_interceptions": sandbox_files,
            "network_recon_events": network_recon,
            "c2_payloads_intercepted": c2_downloads,
            "credential_traps": credential_traps,
            "suspicious_events_count": len(sensitive_flags),
            "suspicious_events": sensitive_flags
        }

    def reset_session(self):
        """Resets tracker for a new session and archives previous actions."""
        return self.start_new_session(archive_previous=True)


# Global helper instance
def get_tracker():
    return ForensicTracker()

