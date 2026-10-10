import re
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

# Default target offline model from environment variable, defaulting to qwen3.5:4b
DEFAULT_OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3.5:4b")

# Preferred offline models in order of priority
OLLAMA_PREFERRED_MODELS = [
    DEFAULT_OLLAMA_MODEL,
    "qwen3.5:4b",
    "qwen2.5:3b",
    "qwen2.5:1.5b",
    "deepseek-r1:1.5b",
    "qwen2.5-coder:1.5b"
]

# Dedicated Cyber Forensics & Incident Response (DFIR) Unit System Prompt
DFIR_SYSTEM_PROMPT = """You are the Lead Digital Forensics & Incident Response (DFIR) Cyber Investigation Unit and Computer Crime Analysis Team.
You specialize in hostile adversary tradecraft profiling, deception counter-intelligence, post-breach filesystem and command trajectory reconstruction, and MITRE ATT&CK kill-chain mapping.
Conduct a rigorous, authoritative forensic post-incident examination of the unauthorized intruder captured inside our deception honeypot sandbox.
Behave strictly as an elite digital forensics laboratory: objective, technically precise, evidence-grounded, and authoritative.
Do NOT output conversational pleasantries, greetings, speculative filler, or emojis.
Output clean, standard ASCII cybersecurity analysis strictly conforming to the requested section headers."""


def sanitize_narrative(text) -> str:
    """
    Recursively converts raw text, dictionaries, and lists from LLM outputs into clean,
    grammatically fluid English text. Strips markdown fences, emojis, non-ASCII symbols,
    and raw Python stringified lists (e.g. "['chrome', 'explorer']").
    """
    if text is None:
        return ""
    if isinstance(text, (list, tuple)):
        items = [sanitize_narrative(x) for x in text if str(x).strip()]
        return ", ".join(items) if items else ""
    if isinstance(text, dict):
        parts = []
        for k, v in text.items():
            k_clean = str(k).replace("_", " ").strip().title()
            v_clean = sanitize_narrative(v)
            if v_clean:
                parts.append(f"{k_clean}: {v_clean}")
        return ". ".join(parts) + "."

    val = str(text)
    # Strip DeepSeek thinking tags (<think>...</think>)
    val = re.sub(r'<think>.*?</think>', '', val, flags=re.DOTALL)
    # Strip markdown code blocks
    val = re.sub(r'```(?:json)?\s*', '', val)
    val = re.sub(r'```', '', val)
    # Strip emojis and non-BMP symbols
    val = re.sub(r'[\U00010000-\U0010ffff]', '', val)
    val = re.sub(r'[\u2600-\u27bf\ufe00-\ufe0f\u2300-\u23ff]', '', val)
    # Strip inline markdown symbols
    val = re.sub(r'\*\*([^*]+)\*\*', r'\1', val)
    val = re.sub(r'__([^_]+)__', r'\1', val)
    val = re.sub(r'\*([^*]+)\*', r'\1', val)
    val = re.sub(r'_([^_]+)_', r'\1', val)
    val = re.sub(r'`([^`]+)`', r'\1', val)
    val = re.sub(r'^[#*\-:\s]+', '', val)
    val = val.replace("#", "")

    # Strip raw Python stringified lists: "['a', 'b']" -> "a, b"
    val = re.sub(r"\[(['\"])(.*?)\1\]", r"\2", val)
    val = val.replace("['", "").replace("']", "").replace("[\"", "").replace("\"]", "")
    val = re.sub(r',\s*,\s*', ', ', val)
    val = re.sub(r'\s+', ' ', val)
    return val.strip()


class IntruderIntentAnalyzer:
    """
    Offline AI / LLM Threat Intelligence Engine for Deception Environments.
    Analyzes the complete chronological trajectory of an intruder's interactions inside
    the Honeypot (opened folders, accessed files, web searches, typed shell commands,
    file modifications, deletions, and sandbox quarantine events) to predict:
      1. Attacker Typology & Persona (grounded in observed TTPs)
      2. Primary Objective & Strategic Intent
      3. Complete Behavioral Progression & Trajectory
      4. Grounded Supporting Evidence linking to exact Event IDs
      5. Authoritative Multi-Factor Threat Severity Rating (LOW / MEDIUM / HIGH / CRITICAL)
      6. Alternative Interpretations & Uncertainty Caveats
      7. MITRE ATT&CK Tactic Mapping & Prioritized Remediation Recommendations
      
    Utilizes local, completely offline Ollama API (http://localhost:11434)
    with seamless multi-model fallback and an authoritative rule-based forensic
    engine to guarantee zero downgrading of critical threat activities.
    """
    def __init__(self, ollama_url="http://localhost:11434", model_name=None, timeout=45):
        self.ollama_url = ollama_url.rstrip("/")
        self.model_name = model_name or os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)
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
            if pref in available_models:
                return pref

        for pref in OLLAMA_PREFERRED_MODELS:
            base = pref.split(":")[0]
            for avail in available_models:
                if avail.startswith(base):
                    return avail
                    
        return available_models[0] if available_models else "qwen2.5:3b"

    def evaluate_deterministic_threat(self, timeline, stats=None):
        """
        Authoritative Forensic Rule-Based Heuristic Evaluation.
        Extracts verified evidence from actual recorded events, computes multi-factor
        threat scores, establishes a deterministic minimum threat floor, and constructs
        grounded evidence rows with genuine Event IDs.
        """
        if stats is None:
            stats = self.tracker.get_summary_stats()

        cred_keywords = [
            "password", "root_credential", "backup_recovery_keys", "secret", "vault",
            "key", "seed", "token", "login", "auth", ".env", "aws", "ssh", "credential",
            "database_backup", "id_rsa", "keystore"
        ]
        fin_keywords = [
            "financial", "bank", "tax", "investment", "routing", "salary",
            "ledger", "portfolio", "deposit", "accounting", "wire"
        ]
        tamper_actions = ["FILE_MODIFY", "FILE_SAVE", "SANDBOX_FILE_INTERCEPTED"]
        delete_actions = ["FILE_DELETE"]

        cred_events = []
        fin_events = []
        tamper_events = []
        delete_events = []
        portal_events = []
        recon_events = []
        shell_events = []

        for ev in timeline:
            eid = ev.get("event_id")
            atype = str(ev.get("action_type", "")).upper()
            tgt = str(ev.get("target", ""))
            tgt_lower = tgt.lower()
            details_str = json.dumps(ev.get("details", {})).lower()
            content = f"{tgt_lower} {details_str} {atype.lower()}"

            if any(kw in content for kw in cred_keywords) or atype == "CREDENTIAL_TRAP":
                cred_events.append((eid, atype, tgt))
            if any(kw in content for kw in fin_keywords):
                fin_events.append((eid, atype, tgt))
            if atype in tamper_actions:
                tamper_events.append((eid, atype, tgt))
            if atype in delete_actions:
                delete_events.append((eid, atype, tgt))
            if atype == "URL_VISITED" or any(p in tgt_lower for p in ["aws.amazon.com", "mail.internal.corp", "bank", "portal", "login"]):
                portal_events.append((eid, atype, tgt))
            if any(cmd in content for cmd in ["whoami", "ipconfig", "netstat", "arp", "route", "ping", "net user", "nmap"]):
                recon_events.append((eid, atype, tgt))
            if atype in ["SHELL_COMMAND", "APP_LAUNCH"] and any(sh in content for sh in ["powershell", "cmd", "curl", "wget", "bash"]):
                shell_events.append((eid, atype, tgt))

        score = 0.10
        factors = []
        if cred_events:
            score += 0.35
            factors.append("Credential Asset Access")
        if fin_events:
            score += 0.25
            factors.append("Financial Records Targeted")
        if tamper_events:
            score += 0.25
            factors.append("File Modification / Tampering Intercepted")
        if delete_events:
            score += 0.25
            factors.append("Destructive File Deletion Observed")
        if portal_events:
            score += 0.15
            factors.append("External Cloud/Mail Portal Probing")
        if recon_events or shell_events:
            score += 0.15
            factors.append("Command-Line & Network Reconnaissance")
        if len(timeline) >= 15:
            score += 0.10
            factors.append("Extended Interaction Depth")

        score = min(1.0, round(score, 2))

        # Determine authoritative baseline threat level
        if score >= 0.70 or (cred_events and (tamper_events or delete_events)):
            level = "CRITICAL"
        elif score >= 0.45 or cred_events or fin_events or tamper_events or delete_events:
            level = "HIGH"
        elif score >= 0.25 or recon_events or portal_events:
            level = "MEDIUM"
        else:
            level = "LOW"

        # Determine authoritative grounded persona and objective
        if delete_events and (cred_events or fin_events):
            persona = "Targeted Corporate Infiltrator & Data Saboteur"
            objective = "Harvest administrative credentials, inspect sensitive corporate records, and execute destructive deletions to impede operations."
        elif fin_events and cred_events:
            persona = "Financial Cybercriminal & Credential Harvester"
            objective = "Target corporate banking, direct deposit routing, tax filings, and root credentials for financial extortion."
        elif cred_events and (tamper_events or shell_events):
            persona = "Privilege Escalation & Staging Operator"
            objective = "Extract system passwords, modify filesystem objects, and stage command-line tools."
        elif cred_events:
            persona = "Targeted Credential Harvester"
            objective = "Discover system secrets, SSH keys, and cloud credentials for unauthorized lateral access."
        elif fin_events:
            persona = "Financial Data Exfiltrator"
            objective = "Target confidential banking records, accounting ledgers, and investment portfolios."
        elif tamper_events:
            persona = "Unauthorized Staging Operator"
            objective = "Modify local filesystem contents and test persistence."
        elif recon_events or shell_events:
            persona = "Active Reconnaissance Operator"
            objective = "Enumerate local system accounts, network configuration, and directory hierarchy."
        else:
            persona = "Opportunistic Workstation Snooper"
            objective = "Casual or unauthorized exploration of local folders without targeted credential probing."

        # Construct balanced grounded evidence rows (max 6) across distinct categories
        evidence_rows = []
        seen_targets = set()
        categories = [
            ("Credential Discovery", cred_events, "Direct inspection of sensitive credential repository ({})"),
            ("File Tampering", tamper_events, "Unauthorized document modification trapped and isolated by sandbox ({})"),
            ("Destructive Deletion", delete_events, "Destructive file deletion targeting ({})"),
            ("Financial Intelligence", fin_events, "Accessed confidential corporate financial document ({})"),
            ("External Portal Probing", portal_events, "Navigated to authentication portal ({})"),
            ("Reconnaissance", recon_events, "Executed system/network reconnaissance command ({})"),
        ]

        # First pass: pick top event from each category for broad coverage
        for cat_name, cat_list, relevance_tmpl in categories:
            for eid, atype, tgt in cat_list:
                clean_tgt = os.path.basename(tgt) or tgt
                key = (atype, clean_tgt)
                if key not in seen_targets and len(evidence_rows) < 6:
                    seen_targets.add(key)
                    evidence_rows.append({
                        "event_id": eid or f"EVT-{len(evidence_rows)+1:04d}",
                        "action": atype,
                        "target": clean_tgt,
                        "relevance": relevance_tmpl.format(clean_tgt)
                    })
                    break

        # Second pass: fill remaining slots up to 6 if needed
        for cat_name, cat_list, relevance_tmpl in categories:
            for eid, atype, tgt in cat_list:
                clean_tgt = os.path.basename(tgt) or tgt
                key = (atype, clean_tgt)
                if key not in seen_targets and len(evidence_rows) < 6:
                    seen_targets.add(key)
                    evidence_rows.append({
                        "event_id": eid or f"EVT-{len(evidence_rows)+1:04d}",
                        "action": atype,
                        "target": clean_tgt,
                        "relevance": relevance_tmpl.format(clean_tgt)
                    })

        return {
            "threat_level": level,
            "threat_score": score,
            "persona": persona,
            "objective": objective,
            "factors": factors,
            "evidence_rows": evidence_rows,
            "cred_count": len(cred_events),
            "fin_count": len(fin_events),
            "tamper_count": len(tamper_events),
            "delete_count": len(delete_events)
        }

    def analyze_session(self, timeline=None, stats=None):
        """
        Main entry point: Generates comprehensive cybersecurity intent assessment.
        Fuses LLM cognitive reasoning with authoritative deterministic telemetry rules.
        """
        if timeline is None:
            timeline = self.tracker.get_timeline()
        if stats is None:
            stats = self.tracker.get_summary_stats()

        # If zero events occurred, return baseline benign state
        if not timeline or len(timeline) == 0:
            return self._build_empty_session_report()

        # Compute deterministic baseline analysis
        det_eval = self.evaluate_deterministic_threat(timeline, stats)

        # Attempt to run via local Ollama LLM
        is_ollama_up, installed_models = self.check_ollama_available()
        if is_ollama_up and installed_models:
            models_to_try = []
            if self.model_name and self.model_name in installed_models:
                models_to_try.append(self.model_name)

            for pref in OLLAMA_PREFERRED_MODELS:
                if pref in installed_models and pref not in models_to_try:
                    models_to_try.append(pref)

            for avail in installed_models:
                if avail not in models_to_try:
                    models_to_try.append(avail)

            for chosen_model in models_to_try:
                try:
                    print(f"[AI INTENT] Querying local offline Ollama model '{chosen_model}' (DFIR Cyber Investigation Team role)...", flush=True)
                    llm_result, raw_prompt = self._query_ollama(timeline, stats, chosen_model, det_eval)
                    if llm_result:
                        return self._parse_llm_response(llm_result, chosen_model, stats, raw_prompt, timeline, det_eval)
                except Exception as e:
                    print(f"[AI INTENT] [WARNING] Ollama model '{chosen_model}' issue: {e}. Trying next option...", file=sys.stderr, flush=True)

        # Fallback: Authoritative Expert Forensic Rule-Based Engine
        print("[AI INTENT] Running offline expert heuristic intelligence engine...", flush=True)
        return self._heuristic_expert_analysis(timeline, stats, det_eval)

    def _record_audit_log(self, entry):
        """Thread-safe persistent audit logging of AI prompt generation and response parsing."""
        try:
            audit_path = os.path.join(PROJECT_ROOT, "data", "forensics", "ai_threat_analysis_audit.jsonl")
            os.makedirs(os.path.dirname(audit_path), exist_ok=True)
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[AI INTENT] [WARNING] Failed to write AI audit log: {e}", file=sys.stderr)

    def _build_prompt(self, timeline, stats, det_eval):
        """Formats the honeypot audit trail into a precise cybersecurity analyst prompt requiring RFC 8259 JSON."""
        chronology_text = []
        for idx, event in enumerate(timeline):
            eid = event.get("event_id", f"EVT-{idx+1:04d}")
            t = event.get("elapsed_seconds", 0)
            atype = event.get("action_type", "UNKNOWN")
            app = event.get("application", "")
            target = event.get("target", "")
            outcome = event.get("outcome", "SUCCESS")
            sev = event.get("severity", "INFO")
            details = json.dumps(event.get("details", {}))
            app_str = f"[{app}] " if app else ""
            chronology_text.append(f"{idx+1}. [{eid}] [T+{t}s] [{sev}] [{atype}] {app_str}Target: {target} | Outcome: {outcome} | Context: {details}")

        # Intelligent lossless chronological batching up to 80 events
        if len(chronology_text) <= 80:
            events_dump = "\n".join(chronology_text)
        else:
            head = chronology_text[:35]
            tail = chronology_text[-30:]
            middle_suspicious = [
                f"{idx+1}. [{e.get('event_id', f'EVT-{idx+1:04d}')}] [T+{e.get('elapsed_seconds', 0)}s] [{e.get('severity', 'INFO')}] [{e.get('action_type', '')}] Target: {e.get('target', '')}"
                for idx, e in enumerate(timeline[35:-30])
                if e.get("severity") in ("SUSPICIOUS", "ALERT", "CRITICAL") or e.get("action_type") in ("FILE_DELETE", "FILE_MODIFY", "SANDBOX_FILE_INTERCEPTED")
            ][:25]
            omitted = len(timeline) - len(head) - len(tail) - len(middle_suspicious)
            events_dump = "\n".join(head) + f"\n... [{omitted} intermediate events summarized for token capacity] ...\n" + "\n".join(middle_suspicious) + "\n" + "\n".join(tail)

        factors_summary = ", ".join(det_eval.get("factors", [])) or "None identified"

        prompt = f"""[INCIDENT RESPONSE CASE REPORT: DFIR FORENSIC UNIT]
Operational Context: Workstation continuous biometric anomaly detectors flagged an unauthorized intruder and diverted them into our high-interaction sandboxed deception honeypot.
Review the forensic telemetry capturing the adversary's actions:

--- HONEYPOT FORENSIC AUDIT TRAIL ---
Case Session ID: {stats.get('session_id', 'ACTIVE')}
Total Recorded Actions: {stats.get('total_actions', len(timeline))}
Engagement Duration: {stats.get('session_duration_seconds', 0)}s
Detected Threat Factors: {factors_summary}
Authoritative Minimum Threat Floor: {det_eval.get('threat_level')}

--- CHRONOLOGICAL ACTION SEQUENCE ---
{events_dump}

--- THREAT EVALUATION GUIDELINES ---
- CRITICAL: Credential theft/harvesting, unauthorized modification/deletion of sensitive documents or financial records, payload staging, lateral movement attempts.
- HIGH: Direct access to credentials, financial documents, tax records, or network reconnaissance.
- MEDIUM: Probing system configurations, account enumeration (whoami), general file viewing without sensitive secrets.
- LOW: Benign workstation interactions with zero sensitive targets accessed.
CRITICAL CONSTRAINT: You must NEVER classify an intrusion that accessed credentials or deleted files as 'LOW'.

--- REQUIRED JSON OUTPUT FORMAT ---
You are an authoritative DFIR investigator. Output ONLY a valid JSON object strictly conforming to this schema:
{{
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "threat_score": 0.0 to 1.0,
  "attacker_persona": "<authoritative cybersecurity threat persona, e.g. 'Targeted Financial & Credential Exfiltrator'>",
  "primary_intent": "<comprehensive paragraph explaining the primary strategic objective>",
  "secondary_intents": ["<secondary objective 1>", "<secondary objective 2>"],
  "executive_assessment": "<high-level summary paragraph for executives and CISO>",
  "behavioral_trajectory": "<chronological reconstruction in clear narrative prose describing progression across reconnaissance, discovery, and tampering phases>",
  "supporting_evidence": [
    {{
      "event_id": "<real Event ID from chronology, e.g. EVT-0002>",
      "action": "<action type>",
      "target": "<target filename or resource>",
      "relevance": "<specific investigative significance>"
    }}
  ],
  "observed_facts": ["<observed telemetry fact 1>", "<observed telemetry fact 2>"],
  "inferences": ["<analytical deduction 1>", "<analytical deduction 2>"],
  "alternative_explanations": ["<alternative plausible hypothesis 1>", "<alternative plausible hypothesis 2>"],
  "confidence_level": "HIGH" | "MEDIUM" | "LOW",
  "confidence_score": 0.0 to 1.0,
  "confidence_justification": "<concise explanation of why this confidence level was assigned>",
  "limitations": "<analytical caveats and telemetry limits>",
  "recommended_actions": [
    {{
      "priority": 1,
      "action": "<containment or remediation action>",
      "timeframe": "<e.g. Immediate (Within 1 hour)>"
    }}
  ],
  "mitre_tactics": ["T1552.001 (Credentials in Files)", "T1082 (System Discovery)"]
}}
CRITICAL: Do NOT output conversational pleasantries, markdown code fences, or text outside the JSON object. Output valid JSON only."""
        return prompt

    def _query_ollama(self, timeline, stats, model_name, det_eval):
        """Dispatches prompt to local Ollama generate API with JSON formatting and DFIR system prompt."""
        prompt = self._build_prompt(timeline, stats, det_eval)
        payload = {
            "model": model_name,
            "system": DFIR_SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.15,
                "top_p": 0.9,
                "num_predict": 1200
            }
        }
        
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "SecurityForensics/1.0"}
        )
        
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", ""), prompt

    def _parse_llm_response(self, raw_text, model_name, stats, raw_prompt, timeline, det_eval):
        """Extracts structured fields from LLM response, applies multi-factor threat fusion, and normalizes output."""
        cleaned_text = re.sub(r'<think>.*?</think>', '', raw_text, flags=re.DOTALL).strip()
        cleaned_text = re.sub(r'^```(?:json)?\s*', '', cleaned_text)
        cleaned_text = re.sub(r'```\s*$', '', cleaned_text).strip()

        parsed_json = None
        try:
            parsed_json = json.loads(cleaned_text)
        except Exception:
            match = re.search(r'(\{.*\})', cleaned_text, flags=re.DOTALL)
            if match:
                try:
                    parsed_json = json.loads(match.group(1))
                except Exception:
                    pass

        if not isinstance(parsed_json, dict):
            # Fall back to deterministic analysis if model failed to return JSON
            print(f"[AI INTENT] [WARNING] Model '{model_name}' did not output valid JSON. Falling back to deterministic rules.", flush=True)
            return self._heuristic_expert_analysis(timeline, stats, det_eval)

        # 1. Multi-Factor Threat Level & Score Fusion
        level_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        raw_threat = str(parsed_json.get("threat_level", "HIGH")).upper()
        ai_level = "HIGH"
        for valid in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if valid in raw_threat:
                ai_level = valid
                break

        det_level = det_eval.get("threat_level", "HIGH")
        ai_rank = level_ranks.get(ai_level, 2)
        det_rank = level_ranks.get(det_level, 3)

        # Deterministic threat floor guardrail: Never downgrade below verified forensic facts
        if ai_rank >= det_rank:
            final_threat = ai_level
            threat_justification = f"Assessed at {final_threat} by AI intent analysis and confirmed by telemetry risk indicators ({', '.join(det_eval.get('factors', []))})."
        else:
            final_threat = det_level
            threat_justification = (
                f"Assessed at {final_threat} by authoritative forensic rules (elevated from model rating '{ai_level}' "
                f"due to verified activity: {', '.join(det_eval.get('factors', []))})."
            )

        try:
            ai_score = float(parsed_json.get("threat_score", det_eval.get("threat_score", 0.75)))
        except (ValueError, TypeError):
            ai_score = det_eval.get("threat_score", 0.75)
        final_score = max(ai_score, det_eval.get("threat_score", 0.50))
        final_score = min(1.0, max(0.1, round(final_score, 2)))

        # 2. Attacker Persona (Sanitize against generic placeholders)
        persona = sanitize_narrative(parsed_json.get("attacker_persona", ""))
        persona = re.sub(r'^(The attacker appears to be|Persona:)\s*', '', persona, flags=re.IGNORECASE).strip()
        invalid_personas = ["scriptkiddie", "script kiddie", "benign", "unknown", "none", "concise attacker typology"]
        if not persona or any(inv in persona.lower() for inv in invalid_personas):
            persona = det_eval.get("persona", "Targeted Corporate Infiltrator & Data Exfiltrator")

        # 3. Primary Intent & Objectives
        primary_intent = sanitize_narrative(parsed_json.get("primary_intent", ""))
        if not primary_intent or len(primary_intent) < 20:
            primary_intent = det_eval.get("objective", "Locate high-value administrative credentials, exfiltrate financial records, and probe internal systems.")

        raw_secondary = parsed_json.get("secondary_intents", [])
        secondary_intents = []
        if isinstance(raw_secondary, list):
            secondary_intents = [sanitize_narrative(s) for s in raw_secondary if sanitize_narrative(s)]
        elif isinstance(raw_secondary, str) and raw_secondary.strip():
            secondary_intents = [sanitize_narrative(raw_secondary)]
        if not secondary_intents:
            secondary_intents = [
                "Map local workstation filesystem and internal network architecture",
                "Stage local reconnaissance tools and test security perimeter responsiveness"
            ]

        # 4. Executive Assessment
        exec_summary = sanitize_narrative(parsed_json.get("executive_assessment", ""))
        if not exec_summary or len(exec_summary) < 20:
            exec_summary = (
                f"An unauthorized actor engaged the workstation environment, generating {len(timeline)} telemetry events. "
                f"The engagement was successfully contained inside the deceptive honeypot sandbox without host writes. "
                f"Forensic indicators show targeted interest in credentials and financial assets, warranting immediate credential rotation."
            )

        # 5. Behavioral Trajectory (Strictly fluid narrative prose without raw lists)
        raw_traj = parsed_json.get("behavioral_trajectory") or parsed_json.get("behavioral_analysis", "")
        clean_traj = sanitize_narrative(raw_traj)
        if not clean_traj or len(clean_traj) < 30:
            clean_traj = (
                f"The adversary initiated session activity by enumerating desktop directories and browsing local documents. "
                f"Subsequently, the actor targeted sensitive credential files (including passwords and recovery keys) "
                f"and navigated into confidential financial records. Destructive or modifying operations were safely trapped "
                f"within the deception sandbox."
            )

        # 6. Supporting Evidence (Validate real Event IDs from incident)
        timeline_event_ids = {e.get("event_id") for e in timeline if e.get("event_id")}
        raw_evidence = parsed_json.get("supporting_evidence", [])
        evidence_list = []

        if isinstance(raw_evidence, list):
            for item in raw_evidence:
                if isinstance(item, dict):
                    eid = sanitize_narrative(item.get("event_id", ""))
                    act = sanitize_narrative(item.get("action", ""))
                    tgt = sanitize_narrative(item.get("target", ""))
                    rel = sanitize_narrative(item.get("relevance", ""))
                    # Verify event_id is genuine
                    if eid in timeline_event_ids and act and tgt:
                        evidence_list.append({
                            "event_id": eid,
                            "action": act,
                            "target": os.path.basename(tgt) or tgt,
                            "relevance": rel or f"Telemetry observation of {act} against {tgt}"
                        })

        # Grounding guarantee: If model provided fewer than 3 valid items, merge with authoritative evidence rows
        if len(evidence_list) < 3:
            det_rows = det_eval.get("evidence_rows", [])
            seen_eids = {e["event_id"] for e in evidence_list}
            for dr in det_rows:
                if dr["event_id"] not in seen_eids and len(evidence_list) < 6:
                    evidence_list.append(dr)
                    seen_eids.add(dr["event_id"])

        # 7. Observed Facts vs. Inferences
        raw_facts = parsed_json.get("observed_facts", [])
        observed_facts = [sanitize_narrative(f) for f in raw_facts if sanitize_narrative(f)] if isinstance(raw_facts, list) else []
        if not observed_facts:
            observed_facts = [
                f"Recorded {len(timeline)} discrete honeypot interaction events across desktop, notepad, and browser.",
                f"Observed access to {det_eval.get('cred_count', 0)} credential-related resources and {det_eval.get('fin_count', 0)} financial records.",
                f"Trapped {det_eval.get('tamper_count', 0)} file write/modification events inside isolated sandbox.",
                f"Recorded {det_eval.get('delete_count', 0)} destructive file deletion events in honeypot folders."
            ]

        raw_inferences = parsed_json.get("inferences", [])
        inferences = [sanitize_narrative(i) for i in raw_inferences if sanitize_narrative(i)] if isinstance(raw_inferences, list) else []
        if not inferences:
            inferences = [
                "Targeting of root credentials and recovery keys indicates deliberate intent to achieve privilege escalation.",
                "Sequential opening and deletion of financial documents suggests deliberate sabotage or data exfiltration staging.",
                "Engagement with external sign-in portals indicates intent to harvest credentials for external cloud access."
            ]

        # 8. Alternative Explanations
        raw_alts = parsed_json.get("alternative_explanations", [])
        alternative_explanations = [sanitize_narrative(a) for a in raw_alts if sanitize_narrative(a)] if isinstance(raw_alts, list) else []
        if not alternative_explanations:
            alternative_explanations = [
                "Unauthorized internal employee or guest exploring workstation without malicious persistence intent.",
                "Automated discovery utility or script executing pre-configured search patterns without human supervision."
            ]

        # 9. Confidence Level & Score
        conf_level = str(parsed_json.get("confidence_level", "HIGH")).upper()
        if conf_level not in ["HIGH", "MEDIUM", "LOW"]:
            conf_level = "HIGH" if len(timeline) >= 20 else "MEDIUM"
        try:
            conf_score = float(parsed_json.get("confidence_score", 0.88 if conf_level == "HIGH" else 0.65))
        except (ValueError, TypeError):
            conf_score = 0.88 if conf_level == "HIGH" else 0.65
        conf_score = min(1.0, max(0.1, round(conf_score, 2)))

        conf_justification = sanitize_narrative(parsed_json.get("confidence_justification", ""))
        if not conf_justification:
            conf_justification = f"High confidence based on {len(timeline)} sequentially verified telemetry events, multiple corroborating credential traps, and sandbox quarantine intercepts."

        # 10. Limitations
        limitations = sanitize_narrative(parsed_json.get("limitations", ""))
        if not limitations:
            limitations = "Observed interactions represent verified honeypot telemetry; actor motivation, attribution, and external coordination remain probabilistic AI inferences."

        # 11. Recommendations
        raw_recs = parsed_json.get("recommended_actions") or parsed_json.get("recommendations", [])
        recommendations = []
        if isinstance(raw_recs, list):
            for idx, r in enumerate(raw_recs):
                if isinstance(r, dict):
                    recommendations.append({
                        "priority": r.get("priority", idx + 1),
                        "action": sanitize_narrative(r.get("action", "")),
                        "timeframe": sanitize_narrative(r.get("timeframe", "Immediate"))
                    })
                elif isinstance(r, str) and r.strip():
                    recommendations.append({
                        "priority": idx + 1,
                        "action": sanitize_narrative(r),
                        "timeframe": "Immediate" if idx == 0 else "Within 4 Hours"
                    })

        # Reconcile narrative text with authoritative threat level
        benign_markers = ["benign", "routine", "testing", "no evidence", "no indication", "without any indication", "no malicious", "no further action", "no action required"]
        if final_threat in ("HIGH", "CRITICAL"):
            if any(m in primary_intent.lower() for m in benign_markers):
                primary_intent = det_eval.get("objective", "Locate high-value administrative credentials, exfiltrate financial records, and probe internal systems.")
            if any(m in exec_summary.lower() for m in benign_markers):
                exec_summary = (
                    f"An unauthorized actor engaged the workstation environment, generating {len(timeline)} telemetry events. "
                    f"The engagement was successfully contained inside the deceptive honeypot sandbox without host writes. "
                    f"Forensic indicators show verified hostile targeting of credentials and sensitive records ({', '.join(det_eval.get('factors', []))}), "
                    f"warranting immediate credential rotation and forensic containment."
                )
            clean_recs = []
            for r in recommendations:
                act_str = r.get("action", "") if isinstance(r, dict) else str(r)
                if not any(m in act_str.lower() for m in benign_markers):
                    clean_recs.append(r)
            if not clean_recs:
                clean_recs = [
                    {"priority": 1, "action": "Immediately revoke and rotate all credentials, SSH keys, and passwords referenced during session.", "timeframe": "Immediate (Within 1 hour)"},
                    {"priority": 2, "action": "Verify isolation of honeypot sandbox directory (data/sandbox/) and inspect quarantined payloads.", "timeframe": "Within 2 hours"},
                    {"priority": 3, "action": "Enforce mandatory multi-factor authentication (MFA) step-up on the host workstation.", "timeframe": "Immediate"},
                    {"priority": 4, "action": "Review perimeter firewall egress logs for connection attempts to external reconnaissance targets.", "timeframe": "Within 4 hours"}
                ]
            recommendations = clean_recs

        # 12. MITRE Tactics
        raw_mitre = parsed_json.get("mitre_tactics", [])
        mitre_tactics = [sanitize_narrative(m) for m in raw_mitre if sanitize_narrative(m)] if isinstance(raw_mitre, list) else []
        if not mitre_tactics:
            mitre_tactics = [
                "T1552.001 - Credentials in Files",
                "T1082 - System Information Discovery",
                "T1059.001 - Command and Scripting Interpreter",
                "T1485 - Data Destruction"
            ]

        result = {
            "source": f"Ollama DFIR Forensic Unit ({model_name})",
            "model_name": model_name,
            "status": "SUCCESS_STRUCTURED",
            "threat_level": final_threat,
            "threat_score": final_score,
            "threat_justification": threat_justification,
            "attacker_persona": persona,
            "primary_intent": primary_intent,
            "secondary_intents": secondary_intents,
            "executive_assessment": exec_summary,
            "behavioral_trajectory": clean_traj,
            "trajectory_analysis": clean_traj,
            "supporting_evidence": evidence_list,
            "observed_facts": observed_facts,
            "inferences": inferences,
            "alternative_explanations": alternative_explanations,
            "confidence_level": conf_level,
            "confidence_score": conf_score,
            "confidence_justification": conf_justification,
            "limitations": limitations,
            "recommended_actions": recommendations,
            "recommendations": recommendations,
            "mitre_tactics": mitre_tactics,
            "stats_summary": stats
        }

        self._record_audit_log({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "session_id": stats.get("session_id", "ACTIVE"),
            "model": model_name,
            "raw_prompt_length": len(raw_prompt) if raw_prompt else 0,
            "raw_response": raw_text,
            "status": "SUCCESS_STRUCTURED",
            "threat_level": final_threat,
            "threat_score": final_score,
            "predicted_persona": persona,
            "primary_intent": primary_intent
        })
        return result

    def _heuristic_expert_analysis(self, timeline, stats, det_eval=None):
        """
        Expert Rule-Based Forensic Analysis Engine.
        Produces full structured assessment matching the exact AI schema
        guaranteeing seamless downstream PDF rendering even if Ollama daemon is offline.
        """
        if det_eval is None:
            det_eval = self.evaluate_deterministic_threat(timeline, stats)

        final_threat = det_eval.get("threat_level", "HIGH")
        final_score = det_eval.get("threat_score", 0.75)
        persona = det_eval.get("persona", "Targeted Corporate Infiltrator & Data Exfiltrator")
        objective = det_eval.get("objective", "Harvest administrative credentials and confidential financial records.")
        evidence_list = det_eval.get("evidence_rows", [])

        exec_summary = (
            f"An unauthorized actor engaged the workstation environment, generating {len(timeline)} telemetry events. "
            f"The engagement was successfully contained inside the deceptive honeypot sandbox with zero host modifications. "
            f"Forensic telemetry detected critical risk factors ({', '.join(det_eval.get('factors', []))}), "
            f"indicating high-intent targeting of credentials and financial records."
        )

        traj_parts = [
            f"The adversary initiated session activity by traversing desktop directories and inspecting user repositories."
        ]
        if det_eval.get("cred_count", 0) > 0:
            traj_parts.append(f"The intruder targeted sensitive credential repositories ({det_eval['cred_count']} access events observed).")
        if det_eval.get("fin_count", 0) > 0:
            traj_parts.append(f"Confidential corporate financial and banking records were opened ({det_eval['fin_count']} access events observed).")
        if det_eval.get("tamper_count", 0) > 0:
            traj_parts.append(f"File modification attempts were trapped and isolated by the deception sandbox.")
        if det_eval.get("delete_count", 0) > 0:
            traj_parts.append(f"Destructive file deletions were executed targeting financial files ({det_eval['delete_count']} deletion events).")
        trajectory = " ".join(traj_parts)

        observed_facts = [
            f"Recorded {len(timeline)} discrete honeypot interaction events across desktop, notepad, and browser.",
            f"Observed access to {det_eval.get('cred_count', 0)} credential-related resources and {det_eval.get('fin_count', 0)} financial records.",
            f"Trapped {det_eval.get('tamper_count', 0)} file write/modification events inside isolated sandbox.",
            f"Recorded {det_eval.get('delete_count', 0)} destructive file deletion events in honeypot folders."
        ]

        inferences = [
            "Targeting of root credentials and recovery keys indicates deliberate intent to achieve privilege escalation.",
            "Sequential opening and deletion of financial documents indicates deliberate sabotage or data exfiltration staging.",
            "Engagement with external sign-in portals indicates intent to harvest credentials for external cloud access."
        ]

        alternative_explanations = [
            "Unauthorized internal employee or guest exploring workstation without malicious persistence intent.",
            "Automated discovery utility or script executing pre-configured search patterns without human supervision."
        ]

        recommendations = [
            {"priority": 1, "action": "Immediately revoke and rotate all credentials, SSH keys, and passwords referenced during session.", "timeframe": "Immediate (Within 1 hour)"},
            {"priority": 2, "action": "Verify isolation of honeypot sandbox directory (data/sandbox/) and inspect quarantined payloads.", "timeframe": "Within 2 hours"},
            {"priority": 3, "action": "Enforce mandatory multi-factor authentication (MFA) step-up on the host workstation.", "timeframe": "Immediate"},
            {"priority": 4, "action": "Review perimeter firewall egress logs for connection attempts to external reconnaissance targets.", "timeframe": "Within 4 hours"}
        ]

        mitre_tactics = [
            "T1552.001 - Credentials in Files",
            "T1082 - System Information Discovery",
            "T1059.001 - Command and Scripting Interpreter",
            "T1485 - Data Destruction"
        ]

        return {
            "source": "Offline Expert Cybersecurity Heuristics (Rule-Based Engine)",
            "model_name": "Rule-Based Heuristic Threat Intelligence",
            "status": "SUCCESS_HEURISTIC",
            "threat_level": final_threat,
            "threat_score": final_score,
            "threat_justification": f"Assessed at {final_threat} by authoritative forensic rules based on verified activities: {', '.join(det_eval.get('factors', []))}.",
            "attacker_persona": persona,
            "primary_intent": objective,
            "secondary_intents": [
                "Map local workstation filesystem and internal network architecture",
                "Stage local reconnaissance tools and test security perimeter responsiveness"
            ],
            "executive_assessment": exec_summary,
            "behavioral_trajectory": trajectory,
            "trajectory_analysis": trajectory,
            "supporting_evidence": evidence_list,
            "observed_facts": observed_facts,
            "inferences": inferences,
            "alternative_explanations": alternative_explanations,
            "confidence_level": "HIGH" if len(timeline) >= 15 else "MEDIUM",
            "confidence_score": 0.85 if len(timeline) >= 15 else 0.65,
            "confidence_justification": f"High confidence established through deterministic evaluation of {len(timeline)} recorded honeypot events.",
            "limitations": "Deterministic heuristic evaluation provides objective factual telemetry mapping without probabilistic LLM semantic extrapolation.",
            "recommended_actions": recommendations,
            "recommendations": recommendations,
            "mitre_tactics": mitre_tactics,
            "stats_summary": stats
        }

    def _build_empty_session_report(self):
        """Builds benign baseline assessment for empty or inactive honeypot sessions."""
        return {
            "source": "None",
            "model_name": "None",
            "status": "NO_ACTIVITY",
            "threat_level": "LOW",
            "threat_score": 0.05,
            "threat_justification": "No interaction events recorded during honeypot activation window.",
            "attacker_persona": "None (No significant intruder actions recorded)",
            "primary_intent": "Session idle or immediate termination without interaction.",
            "secondary_intents": [],
            "executive_assessment": "The honeypot deception subsystem was activated, but zero subsequent interaction events were recorded. Workstation remains secure.",
            "behavioral_trajectory": "Honeypot was activated but no interactions, folder navigations, or commands were recorded.",
            "supporting_evidence": [],
            "observed_facts": ["Zero interactions recorded."],
            "inferences": ["Intruder aborted interaction immediately upon redirection."],
            "alternative_explanations": ["Accidental diversion or immediate departure."],
            "confidence_level": "HIGH",
            "confidence_score": 0.95,
            "confidence_justification": "Absence of telemetry confirms zero hostile actions taken.",
            "limitations": "None.",
            "recommended_actions": [
                {"priority": 1, "action": "No immediate containment required. Maintain continuous biometric monitoring.", "timeframe": "Ongoing"}
            ],
            "mitre_tactics": ["T1082 - System Information Discovery"],
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
        {"event_id": "EVT-0001", "elapsed_seconds": 5, "action_type": "FOLDER_NAVIGATED", "target": "clg", "details": {}, "severity": "INFO"},
        {"event_id": "EVT-0002", "elapsed_seconds": 12, "action_type": "FILE_VIEWED", "target": "passwords.txt", "details": {}, "severity": "SUSPICIOUS"},
        {"event_id": "EVT-0003", "elapsed_seconds": 22, "action_type": "SHELL_COMMAND", "target": "whoami", "details": {}, "severity": "INFO"},
        {"event_id": "EVT-0004", "elapsed_seconds": 35, "action_type": "BROWSER_SEARCH", "target": "how to find passwords", "details": {}, "severity": "SUSPICIOUS"},
        {"event_id": "EVT-0005", "elapsed_seconds": 44, "action_type": "SANDBOX_FILE_INTERCEPTED", "target": "test.exe", "details": {}, "severity": "ALERT"}
    ]
    report = analyzer.analyze_session(mock_timeline, mock_stats)
    print("\n--- GENERATED REPORT ---")
    print(json.dumps(report, indent=2))
