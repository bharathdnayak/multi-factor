import os
import sys
import json
import time
import urllib.request
import urllib.error

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deception.forensic_tracker import get_tracker, SENSITIVE_KEYWORDS

# Prefer fast, accurate local models in order of priority
OLLAMA_PREFERRED_MODELS = ["qwen2.5:3b", "qwen2.5:1.5b", "deepseek-r1:1.5b", "qwen2.5-coder:1.5b"]


class IntruderIntentAnalyzer:
    """
    Offline AI / LLM Threat Intelligence Engine for Deception Environments.
    Analyzes the chronological trajectory of an intruder's interactions inside
    the Honeypot (opened folders, accessed files, web searches, typed shell commands)
    to predict:
      1. Attacker Typology & Persona (e.g. Opportunistic Snooper vs. Targeted Data Thief)
      2. Primary Objective & Strategic Intent
      3. Reconnaissance Vector & Exploited Targets
      4. Threat Severity Rating (LOW / MEDIUM / HIGH / CRITICAL)
      5. MITRE ATT&CK Tactic Mapping & Containment Recommendations
      
    Utilizes local, completely free offline Ollama API (http://localhost:11434)
    with seamless fallback to an expert cybersecurity rule-based heuristic engine
    if the local LLM server is temporarily unavailable.
    """
    def __init__(self, ollama_url="http://localhost:11434", model_name=None, timeout=30):
        self.ollama_url = ollama_url.rstrip("/")
        self.model_name = model_name
        self.timeout = timeout
        self.tracker = get_tracker()

    def check_ollama_available(self):
        """Checks if local Ollama daemon is reachable and lists installed models."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", headers={"User-Agent": "SecurityForensics/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", [])]
                return True, models
        except Exception:
            return False, []

    def select_best_model(self, available_models):
        """Selects the most suitable model from available Ollama models."""
        if self.model_name and self.model_name in available_models:
            return self.model_name
            
        for pref in OLLAMA_PREFERRED_MODELS:
            for avail in available_models:
                if avail == pref or avail.startswith(pref.split(":")[0]):
                    return avail
                    
        return available_models[0] if available_models else "qwen2.5:3b"

    def analyze_session(self, timeline=None, stats=None):
        """
        Main entry point: Generates comprehensive cybersecurity intent assessment.
        Returns a structured dictionary with both machine-readable keys and human-readable text.
        """
        if timeline is None:
            timeline = self.tracker.get_timeline()
        if stats is None:
            stats = self.tracker.get_summary_stats()

        # If no events occurred yet, return baseline benign state
        if not timeline or len(timeline) <= 1:
            return self._build_empty_session_report()

        # Attempt to run via local Ollama LLM
        is_ollama_up, installed_models = self.check_ollama_available()
        if is_ollama_up and installed_models:
            chosen_model = self.select_best_model(installed_models)
            try:
                print(f"[AI INTENT] Querying local offline Ollama model '{chosen_model}' for intruder behavioral analysis...", flush=True)
                llm_result = self._query_ollama(timeline, stats, chosen_model)
                if llm_result:
                    return self._parse_llm_response(llm_result, chosen_model, stats)
            except Exception as e:
                print(f"[AI INTENT] [WARNING] Ollama inference encountered issue: {e}. Falling back to expert heuristics.", file=sys.stderr, flush=True)

        # Fallback: Expert Rule-Based Cybersecurity Heuristic Engine
        print("[AI INTENT] Running offline expert heuristic intelligence engine...", flush=True)
        return self._heuristic_expert_analysis(timeline, stats)

    def _build_prompt(self, timeline, stats):
        """Formats the honeypot audit trail into a precise cybersecurity analyst prompt."""
        chronology_text = []
        for idx, event in enumerate(timeline):
            t = event.get("elapsed_seconds", 0)
            atype = event.get("action_type", "UNKNOWN")
            target = event.get("target", "")
            details = json.dumps(event.get("details", {}))
            chronology_text.append(f"{idx+1}. [T+{t}s] [{atype}] Target: {target} | Context: {details}")

        events_dump = "\n".join(chronology_text[:40]) # limit to first 40 events for token efficiency

        prompt = f"""You are a Lead Digital Forensics & Incident Response (DFIR) Specialist.
An unauthorized intruder hijacked a workstation terminal and was trapped inside our high-interaction Honeypot sandbox.

Review the chronological log of what the intruder opened, searched, and executed:

--- HONEYPOT INTRUDER AUDIT TRAIL ---
Total Actions: {stats.get('total_actions', 0)}
Session Duration: {stats.get('session_duration_seconds', 0)} seconds
Folders Navigated: {stats.get('folders_visited', [])}
Files Accessed/Previewed: {stats.get('files_accessed', [])}
Shell Commands Run: {stats.get('commands_executed', [])}
Browser Searches / Visited URLs: {stats.get('browser_searches', [])}
Sandbox Interceptions: {stats.get('sandbox_interceptions', [])}

--- DETAILED CHRONOLOGICAL ACTIONS ---
{events_dump}

--- REQUIRED FORENSIC ANALYSIS FORMAT ---
Provide a concise, professional cybersecurity incident analysis with these exact sections:

[ATTACKER PERSONA]: Classify the attacker (e.g. Opportunistic Snooper, Malicious Insider, Targeted Data Thief, Script Kiddie).
[ESTIMATED INTENT]: What was the intruder hunting for or attempting to achieve?
[BEHAVIORAL TRAJECTORY]: Analyze why they opened specific folders, ran specific commands, or searched for specific items.
[THREAT LEVEL]: State strictly one of: LOW, MEDIUM, HIGH, CRITICAL.
[TARGETED HIGH-VALUE ASSETS]: List any confidential data or sensitive system assets targeted.
[MITRE ATT&CK TACTICS]: List applicable MITRE tactics (e.g., T1082 System Information Discovery, T1552 Unsecured Credentials, T1071 C2).
[INCIDENT RESPONSE ACTIONS]: 2-3 immediate technical containment recommendations.
"""
        return prompt

    def _query_ollama(self, timeline, stats, model_name):
        """Dispatches prompt to local Ollama generate API."""
        prompt = self._build_prompt(timeline, stats)
        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_predict": 600
            }
        }
        
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SecurityForensics/1.0"}
        )
        
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "")

    def _parse_llm_response(self, raw_text, model_name, stats):
        """Extracts structured fields from the LLM textual response."""
        persona = "Targeted Intruder / Data Exfiltrator"
        intent = "Credential hunting and unauthorized sensitive data discovery"
        threat = "HIGH"
        trajectory = raw_text
        mitre = ["T1082 (System Discovery)", "T1552 (Credential Access)", "T1005 (Data from Local System)"]
        recommendations = [
            "Rotate all corporate passwords and SSH keys stored or accessed during the active session.",
            "Review firewall outbound egress logs for any staging endpoints.",
            "Revoke terminal session tokens and mandate hardware MFA."
        ]

        # Extract sections if markers exist
        lines = raw_text.splitlines()
        for line in lines:
            if "[ATTACKER PERSONA]" in line:
                persona = line.replace("[ATTACKER PERSONA]:", "").replace("[ATTACKER PERSONA]", "").strip()
            elif "[ESTIMATED INTENT]" in line:
                intent = line.replace("[ESTIMATED INTENT]:", "").replace("[ESTIMATED INTENT]", "").strip()
            elif "[THREAT LEVEL]" in line:
                t_str = line.replace("[THREAT LEVEL]:", "").replace("[THREAT LEVEL]", "").strip().upper()
                for valid in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                    if valid in t_str:
                        threat = valid
                        break

        return {
            "source": f"Ollama Local AI ({model_name})",
            "model": model_name,
            "status": "SUCCESS",
            "attacker_persona": persona,
            "primary_intent": intent,
            "threat_level": threat,
            "trajectory_analysis": raw_text,
            "mitre_tactics": mitre,
            "recommendations": recommendations,
            "stats_summary": stats
        }

    def _heuristic_expert_analysis(self, timeline, stats):
        """
        Expert Cybersecurity Rule-Based Heuristic Inference Engine.
        Deterministic MITRE ATT&CK-based profiling if Ollama server is offline.
        """
        commands = [c.lower() for c in stats.get("commands_executed", [])]
        searches = [s.lower() for s in stats.get("browser_searches", [])]
        files = [f.lower() for f in stats.get("files_accessed", [])]
        sandboxed = stats.get("sandbox_interceptions", [])
        
        has_cred_hunting = any(kw in " ".join(commands + searches + files) for kw in ["password", "token", "key", "cred", "vault", "seed", "login", "root", "hash"])
        has_network_recon = any(c in " ".join(commands) for c in ["ipconfig", "netstat", "ping", "arp", "route", "curl", "wget"])
        has_account_enum = any(c in " ".join(commands) for c in ["whoami", "net user", "net localgroup", "query user"])
        has_payload_creation = len(sandboxed) > 0 or any(">" in c or "echo" in c for c in commands)
        has_financial_target = any(kw in " ".join(searches + files) for kw in ["bank", "transfer", "finance", "crypto", "salary", "ssn", "ledger"])

        # Determine Persona & Intent
        if has_payload_creation and has_cred_hunting:
            persona = "Advanced Intruder / Staging Operator"
            intent = "Credential theft followed by active staging of malicious payloads in the filesystem."
            threat = "CRITICAL"
        elif has_cred_hunting and has_network_recon:
            persona = "Targeted Corporate Infiltrator"
            intent = "Harvesting administrator credentials, internal infrastructure secrets, and mapping internal subnets."
            threat = "HIGH"
        elif has_financial_target:
            persona = "Financial Data Exfiltrator / Extortionist"
            intent = "Locating financial ledgers, banking routing numbers, and sensitive employee compensation documents."
            threat = "HIGH"
        elif has_account_enum or len(commands) > 0:
            persona = "Reconnaissance Operator / Snooper"
            intent = "Profiling local user privileges, running system diagnostics, and inspecting directory hierarchy."
            threat = "MEDIUM"
        else:
            persona = "Opportunistic Physical Walk-Away Explorer"
            intent = "Browsing user folders, desktop files, and browser history without deep administrative probing."
            threat = "LOW"

        trajectory = (
            f"The intruder initiated interaction by accessing {len(stats.get('folders_visited', []))} directory nodes "
            f"and previewing {len(files)} files. "
        )
        if searches:
            trajectory += f"In Decoy Chrome, the user actively executed search queries: {', '.join(stats.get('browser_searches', []))}. "
        if commands:
            trajectory += f"Inside the Honey-Shell terminal, {len(commands)} commands were executed ({', '.join(stats.get('commands_executed', []))}). "
        if sandboxed:
            trajectory += f"CRITICAL: The honeypot successfully trapped and redirected file creation attempts ({', '.join(sandboxed)}) into the isolated sandbox without host damage."

        mitre = []
        if has_account_enum:
            mitre.append("T1087.001 - Local Account Discovery")
        if has_network_recon:
            mitre.append("T1016 - System Network Configuration Discovery")
        if has_cred_hunting:
            mitre.append("T1552.001 - Credentials in Files")
        if has_payload_creation:
            mitre.append("T1059.001 - Command and Scripting Interpreter")
        if not mitre:
            mitre.append("T1082 - System Information Discovery")

        recs = [
            "Mandate immediate password rotation for all accounts referenced in accessed documents.",
            "Inspect honeypot sandbox directory (data/sandbox/) to analyze trapped payloads.",
            "Verify terminal physical security and enforce passive biometric drift auto-lockdown."
        ]

        return {
            "source": "Offline Expert Cybersecurity Heuristics (MITRE ATT&CK Model)",
            "model": "Rule-Based Heuristic Threat Intelligence",
            "status": "SUCCESS",
            "attacker_persona": persona,
            "primary_intent": intent,
            "threat_level": threat,
            "trajectory_analysis": trajectory,
            "mitre_tactics": mitre,
            "recommendations": recs,
            "stats_summary": stats
        }

    def _build_empty_session_report(self):
        return {
            "source": "None",
            "model": "None",
            "status": "NO_ACTIVITY",
            "attacker_persona": "None (No significant intruder actions recorded)",
            "primary_intent": "Idle or immediate termination",
            "threat_level": "LOW",
            "trajectory_analysis": "Honeypot was activated but no interactions, folder navigations, or commands were recorded.",
            "mitre_tactics": ["T1082 - Discovery"],
            "recommendations": ["No active response required."],
            "stats_summary": {"total_actions": 0}
        }


if __name__ == "__main__":
    analyzer = IntruderIntentAnalyzer()
    print("Testing IntruderIntentAnalyzer...")
    available, models = analyzer.check_ollama_available()
    print(f"Ollama Available: {available} | Models: {models}")
    
    mock_stats = {
        "total_actions": 5,
        "session_duration_seconds": 45,
        "folders_visited": ["C:\\Users\\Dell\\Desktop\\clg", "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security"],
        "files_accessed": ["passwords.txt", "database_backup.sql"],
        "commands_executed": ["whoami", "ipconfig", "dir", "echo malware > test.exe"],
        "browser_searches": ["how to find passwords in windows", "company admin login"],
        "sandbox_interceptions": ["test.exe"]
    }
    mock_timeline = [
        {"elapsed_seconds": 5, "action_type": "FOLDER_NAVIGATED", "target": "clg", "details": {}},
        {"elapsed_seconds": 12, "action_type": "FILE_VIEWED", "target": "passwords.txt", "details": {}},
        {"elapsed_seconds": 22, "action_type": "SHELL_COMMAND", "target": "whoami", "details": {}},
        {"elapsed_seconds": 35, "action_type": "BROWSER_SEARCH", "target": "how to find passwords", "details": {}},
        {"elapsed_seconds": 44, "action_type": "SANDBOX_FILE_INTERCEPTED", "target": "test.exe", "details": {}}
    ]
    report = analyzer.analyze_session(mock_timeline, mock_stats)
    print("\n--- GENERATED REPORT ---")
    print(json.dumps(report, indent=2))
