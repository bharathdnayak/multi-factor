import os
import sys
import json
import time
import math
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Common coding symbols frequently typed in programming environments
CODE_SYMBOLS = set("{}[];:=+-*/<>!~^%&|()?'\"`\\@#$")

def classify_activity_context(app_name, window_title):
    """
    Classifies the user's active window and application into a granular behavioral context.
    Recognizes all web browsers (Chrome, Edge, Brave, Firefox, Opera, Arc, Vivaldi) and categorizes
    their specific tab/site activities: coding platforms, AI prompting, messaging/social,
    online productivity/docs, technical reading, media streaming, and general web browsing.
    """
    app_lower = str(app_name or "").lower()
    title_lower = str(window_title or "").lower()
    
    # 1. Coding & Problem Solving Platforms (LeetCode, HackerRank, Codeforces, etc.)
    coding_platforms = [
        "leetcode", "hackerrank", "codeforces", "neetcode", "atcoder", 
        "codechef", "codewars", "interviewbit", "geeksforgeeks.org/problems",
        "kaggle.com/code", "replit", "codesandbox"
    ]
    if any(p in title_lower for p in coding_platforms):
        return "coding_problem_solving"
        
    # 2. AI Chat & Prompting (ChatGPT, Claude, Gemini, Antigravity, Perplexity)
    ai_platforms = [
        "chatgpt", "claude", "gemini", "perplexity", "copilot", 
        "antigravity", "chat.openai", "claude.ai", "mistral.ai",
        "huggingface", "poe.com", "character.ai"
    ]
    if any(p in title_lower or p in app_lower for p in ai_platforms):
        return "ai_chat_prompting"

    # 3. Online Productivity & Document Writing (Google Docs, Sheets, Slides, Notion, etc.)
    productivity_platforms = [
        "google docs", "google sheets", "google slides", "docs.google", "sheets.google",
        "notion", "trello", "jira", "asana", "confluence", "overleaf", "canva", "figma",
        "excalidraw", "miro.com", "airtable"
    ]
    if any(p in title_lower for p in productivity_platforms):
        return "online_productivity"

    # 4. Web Mail, Messaging & Social (Gmail, Outlook Web, WhatsApp, Discord, Slack, etc.)
    communication_platforms = [
        "gmail", "mail.google", "outlook", "whatsapp", "discord", "slack",
        "telegram", "teams.microsoft", "reddit", "twitter", "x.com",
        "linkedin", "instagram", "facebook"
    ]
    if any(p in title_lower for p in communication_platforms):
        return "communication_and_social"
        
    # 5. Technical Reading, Documentation & Research
    reading_keywords = [
        "stack overflow", "github.com", "gitlab", "documentation", 
        "docs.python", "mdn", "geeksforgeeks", "medium.com", 
        "arxiv", "w3schools", "devdocs", "api reference", "wikipedia.org",
        "dev.to", "tutorialspoint"
    ]
    if any(k in title_lower for k in reading_keywords):
        return "technical_reading"
        
    # 6. Media & Video Streaming
    media_keywords = [
        "youtube", "netflix", "spotify", "twitch", "prime video", 
        "hotstar", "disney+", "hulu", "soundcloud", "vlc.exe"
    ]
    if any(k in title_lower or k in app_lower for k in media_keywords):
        return "media_consumption"

    # 7. Code Development & IDEs (VS Code, Cursor, PyCharm, Sublime, etc.)
    code_extensions = [
        ".py", ".ts", ".js", ".cpp", ".c", ".h", ".java", ".go", 
        ".rs", ".html", ".css", ".json", ".sql", ".sh", ".bat", ".md"
    ]
    ide_apps = [
        "code.exe", "cursor.exe", "pycharm.exe", "idea64.exe", 
        "clion64.exe", "sublime_text.exe", "devenv.exe", "notepad++.exe"
    ]
    if any(app in app_lower for app in ide_apps) or any(ext in title_lower for ext in code_extensions):
        return "ide_development"
        
    # 8. Terminal & Command Line
    terminal_apps = [
        "cmd.exe", "powershell.exe", "windowsterminal.exe", 
        "bash.exe", "conhost.exe", "wsl.exe", "mintty.exe"
    ]
    if any(app in app_lower for app in terminal_apps):
        return "terminal_command_line"
        
    # 9. All Web Browsers (Chrome, Edge, Brave, Firefox, Opera, etc.)
    browser_apps = [
        "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", 
        "opera.exe", "opera_gx.exe", "vivaldi.exe", "arc.exe", 
        "waterfox.exe", "tor.exe", "chromium.exe"
    ]
    if any(app in app_lower for app in browser_apps):
        return "web_browsing"
        
    return "general_productivity"


class BehavioralAIController:
    """
    Central AI Controller that maintains task-relative behavioral envelopes per application.
    Continuously monitors user interaction dynamics (thinking pauses, burst typing, code symbols,
    backspace revisions, scroll cadence) and scores incoming micro-sessions and telemetry against
    the learned genuine baseline for the active application/task.
    """
    def __init__(self, baselines_path=None, history_path=None, active_session_path=None):
        data_dir = os.path.join(PROJECT_ROOT, "data", "sessions")
        os.makedirs(data_dir, exist_ok=True)
        
        self.baselines_path = baselines_path or os.path.join(data_dir, "app_baselines.json")
        self.history_path = history_path or os.path.join(data_dir, "session_history.jsonl")
        self.active_session_path = active_session_path or os.path.join(data_dir, "active_session.json")
        
        self.baselines = self.load_baselines()
        
    def load_baselines(self):
        """Loads learned behavioral profiles for each (app, context) pair."""
        if os.path.exists(self.baselines_path):
            try:
                with open(self.baselines_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[CONTROLLER] [WARN] Could not load baselines: {e}", file=sys.stderr)
        return {}

    def save_baselines(self):
        """Persists current baselines to data/sessions/app_baselines.json."""
        os.makedirs(os.path.dirname(self.baselines_path), exist_ok=True)
        try:
            with open(self.baselines_path, "w", encoding="utf-8") as f:
                json.dump(self.baselines, f, indent=2)
        except Exception as e:
            print(f"[CONTROLLER] [ERROR] Failed to save baselines: {e}", file=sys.stderr)

    def _get_context_key(self, app_name, context_mode):
        app_clean = str(app_name or "unknown").strip().lower()
        ctx_clean = str(context_mode or "general_productivity").strip().lower()
        return f"{app_clean}::{ctx_clean}"

    def get_baseline(self, app_name, context_mode):
        """
        Retrieves the baseline profile with fallback hierarchy:
        1. Exact (app_name, context_mode) match (e.g. chrome.exe::coding_problem_solving)
        2. Context-mode generic match (e.g. *::coding_problem_solving)
        3. App-generic match (e.g. chrome.exe::*)
        4. Global baseline fallback
        """
        exact_key = self._get_context_key(app_name, context_mode)
        if exact_key in self.baselines:
            return self.baselines[exact_key]
            
        ctx_key = f"*::{str(context_mode).lower()}"
        if ctx_key in self.baselines:
            return self.baselines[ctx_key]
            
        app_key = f"{str(app_name).lower()}::*"
        if app_key in self.baselines:
            return self.baselines[app_key]
            
        # Return fallback heuristic envelope
        return self._create_default_envelope(context_mode)

    def _create_default_envelope(self, context_mode):
        """Generates realistic default baseline envelopes when no prior data exists."""
        if context_mode == "coding_problem_solving":
            # LeetCode / Coding: high thinking pauses, code symbols, moderate bursts
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 5.5, "std": 2.0},
                    "thinking_pause_ratio": {"mean": 0.40, "std": 0.12},
                    "avg_burst_length": {"mean": 22.0, "std": 7.0},
                    "code_symbol_ratio": {"mean": 0.22, "std": 0.06},
                    "backspace_ratio": {"mean": 0.10, "std": 0.04},
                    "dwell_mean": {"mean": 0.095, "std": 0.020},
                    "flight_mean": {"mean": 0.165, "std": 0.040}
                }
            }
        elif context_mode == "ide_development":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 3.8, "std": 1.5},
                    "thinking_pause_ratio": {"mean": 0.28, "std": 0.10},
                    "avg_burst_length": {"mean": 28.0, "std": 8.0},
                    "code_symbol_ratio": {"mean": 0.25, "std": 0.06},
                    "backspace_ratio": {"mean": 0.11, "std": 0.04},
                    "dwell_mean": {"mean": 0.090, "std": 0.018},
                    "flight_mean": {"mean": 0.145, "std": 0.035}
                }
            }
        elif context_mode == "ai_chat_prompting":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 3.2, "std": 1.2},
                    "thinking_pause_ratio": {"mean": 0.22, "std": 0.08},
                    "avg_burst_length": {"mean": 45.0, "std": 15.0},
                    "code_symbol_ratio": {"mean": 0.06, "std": 0.03},
                    "backspace_ratio": {"mean": 0.08, "std": 0.03},
                    "dwell_mean": {"mean": 0.085, "std": 0.015},
                    "flight_mean": {"mean": 0.125, "std": 0.030}
                }
            }
        elif context_mode == "online_productivity":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 3.5, "std": 1.4},
                    "thinking_pause_ratio": {"mean": 0.25, "std": 0.08},
                    "avg_burst_length": {"mean": 38.0, "std": 12.0},
                    "code_symbol_ratio": {"mean": 0.08, "std": 0.03},
                    "backspace_ratio": {"mean": 0.09, "std": 0.03},
                    "dwell_mean": {"mean": 0.088, "std": 0.018},
                    "flight_mean": {"mean": 0.135, "std": 0.032}
                }
            }
        elif context_mode == "communication_and_social":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 2.2, "std": 0.8},
                    "thinking_pause_ratio": {"mean": 0.18, "std": 0.06},
                    "avg_burst_length": {"mean": 35.0, "std": 10.0},
                    "code_symbol_ratio": {"mean": 0.04, "std": 0.02},
                    "backspace_ratio": {"mean": 0.06, "std": 0.02},
                    "dwell_mean": {"mean": 0.084, "std": 0.015},
                    "flight_mean": {"mean": 0.120, "std": 0.028}
                }
            }
        elif context_mode == "media_consumption":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 4.5, "std": 2.0},
                    "thinking_pause_ratio": {"mean": 0.35, "std": 0.12},
                    "avg_burst_length": {"mean": 20.0, "std": 8.0},
                    "code_symbol_ratio": {"mean": 0.04, "std": 0.02},
                    "backspace_ratio": {"mean": 0.05, "std": 0.02},
                    "dwell_mean": {"mean": 0.092, "std": 0.020},
                    "flight_mean": {"mean": 0.150, "std": 0.035}
                }
            }
        elif context_mode == "terminal_command_line":
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 2.5, "std": 1.0},
                    "thinking_pause_ratio": {"mean": 0.20, "std": 0.08},
                    "avg_burst_length": {"mean": 16.0, "std": 5.0},
                    "code_symbol_ratio": {"mean": 0.18, "std": 0.05},
                    "backspace_ratio": {"mean": 0.09, "std": 0.04},
                    "dwell_mean": {"mean": 0.088, "std": 0.018},
                    "flight_mean": {"mean": 0.140, "std": 0.035}
                }
            }
        else:
            return {
                "sample_count": 5,
                "metrics": {
                    "avg_thinking_pause": {"mean": 2.8, "std": 1.2},
                    "thinking_pause_ratio": {"mean": 0.20, "std": 0.08},
                    "avg_burst_length": {"mean": 30.0, "std": 10.0},
                    "code_symbol_ratio": {"mean": 0.05, "std": 0.03},
                    "backspace_ratio": {"mean": 0.07, "std": 0.03},
                    "dwell_mean": {"mean": 0.090, "std": 0.020},
                    "flight_mean": {"mean": 0.140, "std": 0.035}
                }
            }

    def evaluate_micro_session(self, session_data):
        """
        Evaluates a completed or in-progress micro-session against the baseline
        for that exact application and task mode.
        
        Returns:
            anomaly_score: float in [0.0, 1.0] (0.0 = matches owner profile, 1.0 = sharp imposter anomaly)
            details: dict with metric-by-metric z-scores and reasoning.
        """
        app_name = session_data.get("app_name", "unknown")
        context_mode = session_data.get("context_mode") or classify_activity_context(app_name, session_data.get("window_title", ""))
        baseline = self.get_baseline(app_name, context_mode)
        metrics_baseline = baseline.get("metrics", {})
        
        # Extract observed metrics with safe defaults
        keystrokes = session_data.get("keystrokes", session_data.get("keystroke_count", 0))
        if keystrokes < 3:
            # Not enough typing data in this micro-session to evaluate reliably
            return 0.05, {"reason": "Insufficient keystrokes for micro-session inference", "context_mode": context_mode}
            
        dwell = float(session_data.get("dwell_mean", 0.0))
        flight = float(session_data.get("flight_mean", 0.0))
        avg_pause = float(session_data.get("avg_thinking_pause_sec", session_data.get("avg_thinking_pause", 0.0)))
        pause_ratio = float(session_data.get("thinking_pause_ratio", session_data.get("app_pause_ratio", 0.0)))
        burst_len = float(session_data.get("avg_burst_length", 20.0))
        symbol_ratio = float(session_data.get("code_symbol_ratio", session_data.get("app_special_ratio", 0.0)))
        backspace_ratio = float(session_data.get("backspace_ratio", session_data.get("app_backspace_ratio", 0.0)))
        
        # Calculate metric-specific z-scores: |obs - mean| / (std + eps)
        z_scores = {}
        deviations = {}
        
        def calc_z(obs, key, min_std=0.01):
            if key in metrics_baseline:
                m = metrics_baseline[key]["mean"]
                s = max(min_std, metrics_baseline[key]["std"])
                z = abs(obs - m) / s
                deviations[key] = round(obs - m, 4)
                return min(z, 6.0)
            return 0.5
            
        z_scores["dwell"] = calc_z(dwell, "dwell_mean", 0.01)
        z_scores["flight"] = calc_z(flight, "flight_mean", 0.015)
        z_scores["thinking_pause"] = calc_z(avg_pause, "avg_thinking_pause", 0.5)
        z_scores["pause_ratio"] = calc_z(pause_ratio, "thinking_pause_ratio", 0.05)
        z_scores["burst_len"] = calc_z(burst_len, "avg_burst_length", 2.0)
        z_scores["symbol_ratio"] = calc_z(symbol_ratio, "code_symbol_ratio", 0.02)
        z_scores["backspace_ratio"] = calc_z(backspace_ratio, "backspace_ratio", 0.02)
        
        # Context-weighted distance calculation
        if context_mode == "coding_problem_solving":
            # LeetCode / Coding: high weight on thinking pauses and code syntax symbols!
            weights = {
                "thinking_pause": 0.25,
                "symbol_ratio": 0.25,
                "burst_len": 0.20,
                "dwell": 0.10,
                "flight": 0.10,
                "backspace_ratio": 0.10
            }
        elif context_mode == "ide_development":
            weights = {
                "symbol_ratio": 0.25,
                "dwell": 0.20,
                "flight": 0.20,
                "burst_len": 0.15,
                "thinking_pause": 0.10,
                "backspace_ratio": 0.10
            }
        elif context_mode == "ai_chat_prompting":
            weights = {
                "burst_len": 0.25,
                "dwell": 0.20,
                "flight": 0.20,
                "symbol_ratio": 0.15,
                "thinking_pause": 0.10,
                "backspace_ratio": 0.10
            }
        else:
            weights = {
                "dwell": 0.25,
                "flight": 0.25,
                "burst_len": 0.15,
                "thinking_pause": 0.15,
                "symbol_ratio": 0.10,
                "backspace_ratio": 0.10
            }
            
        composite_distance = sum(weights.get(k, 0.1) * z_scores.get(k, 0.0) for k in weights)
        
        # Sigmoid mapping centered around distance threshold 2.2
        # Distance <= 1.2 -> anomaly < 0.10
        # Distance == 2.2 -> anomaly = 0.50
        # Distance >= 3.5 -> anomaly > 0.85
        anomaly_score = 1.0 / (1.0 + math.exp(-2.2 * (composite_distance - 2.2)))
        anomaly_score = max(0.01, min(0.99, anomaly_score))
        
        reasons = []
        if z_scores.get("thinking_pause", 0) > 2.5:
            reasons.append(f"Abnormal thinking pause in {context_mode} (z={z_scores['thinking_pause']:.1f})")
        if z_scores.get("symbol_ratio", 0) > 2.5:
            reasons.append(f"Syntax/code symbol mismatch (z={z_scores['symbol_ratio']:.1f})")
        if z_scores.get("burst_len", 0) > 2.5:
            reasons.append(f"Typing burst length deviation (z={z_scores['burst_len']:.1f})")
        if z_scores.get("dwell", 0) > 2.5 or z_scores.get("flight", 0) > 2.5:
            reasons.append("Biometric keystroke timing divergence")
            
        details = {
            "app_name": app_name,
            "context_mode": context_mode,
            "composite_distance": round(composite_distance, 3),
            "z_scores": {k: round(v, 2) for k, v in z_scores.items()},
            "deviations": deviations,
            "reasons": reasons,
            "baseline_samples": baseline.get("sample_count", 0)
        }
        
        return round(float(anomaly_score), 4), details

    def evaluate_telemetry_row(self, row):
        """
        Evaluates an individual 10-second telemetry row against the active context baseline.
        """
        app = row.get("active_app", "unknown")
        title = row.get("active_window", "")
        context = row.get("interaction_mode") or classify_activity_context(app, title)
        
        # Build synthetic session summary from row
        session_view = {
            "app_name": app,
            "window_title": title,
            "context_mode": context,
            "keystrokes": row.get("keystroke_count", 10),
            "dwell_mean": row.get("app_dwell_mean", row.get("dwell_mean", 0.09)),
            "flight_mean": row.get("app_flight_mean", row.get("flight_mean", 0.14)),
            "avg_thinking_pause_sec": row.get("avg_thinking_pause_sec", 3.0),
            "thinking_pause_ratio": row.get("app_pause_ratio", 0.20),
            "avg_burst_length": row.get("avg_burst_length", 25.0),
            "code_symbol_ratio": row.get("code_symbol_ratio", row.get("app_special_ratio", 0.10)),
            "backspace_ratio": row.get("backspace_ratio", row.get("app_backspace_ratio", 0.08))
        }
        
        score, details = self.evaluate_micro_session(session_view)
        return score, details

    def learn_from_session(self, session_data, verified=True):
        """
        Incrementally updates the baseline envelope for the given session using
        Exponential Moving Average (EMA) and running standard deviation.
        Only updates when the session is verified as the authentic owner.
        """
        if not verified:
            return
            
        app_name = session_data.get("app_name", "unknown")
        context_mode = session_data.get("context_mode") or classify_activity_context(
            app_name, session_data.get("window_title", "")
        )
        exact_key = self._get_context_key(app_name, context_mode)
        
        if exact_key not in self.baselines:
            self.baselines[exact_key] = {
                "app_name": app_name,
                "context_mode": context_mode,
                "sample_count": 0,
                "metrics": {},
                "first_seen": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
        entry = self.baselines[exact_key]
        n = entry["sample_count"]
        alpha = 1.0 / (n + 1) if n < 50 else 0.05
        
        metric_mappings = {
            "avg_thinking_pause": float(session_data.get("avg_thinking_pause_sec", session_data.get("avg_thinking_pause", 0.0))),
            "thinking_pause_ratio": float(session_data.get("thinking_pause_ratio", session_data.get("app_pause_ratio", 0.0))),
            "avg_burst_length": float(session_data.get("avg_burst_length", 20.0)),
            "code_symbol_ratio": float(session_data.get("code_symbol_ratio", session_data.get("app_special_ratio", 0.0))),
            "backspace_ratio": float(session_data.get("backspace_ratio", session_data.get("app_backspace_ratio", 0.0))),
            "dwell_mean": float(session_data.get("dwell_mean", 0.09)),
            "flight_mean": float(session_data.get("flight_mean", 0.14))
        }
        
        for k, val in metric_mappings.items():
            if val <= 0.0 and k in ("dwell_mean", "flight_mean", "avg_burst_length"):
                continue
            if k not in entry["metrics"]:
                entry["metrics"][k] = {"mean": round(val, 4), "std": round(max(0.01, val * 0.25), 4)}
            else:
                curr_mean = entry["metrics"][k]["mean"]
                curr_std = entry["metrics"][k]["std"]
                
                # Update running mean
                new_mean = (1 - alpha) * curr_mean + alpha * val
                # Update running variance estimate
                diff = abs(val - new_mean)
                new_std = (1 - alpha) * curr_std + alpha * max(0.005, diff)
                
                entry["metrics"][k]["mean"] = round(new_mean, 4)
                entry["metrics"][k]["std"] = round(new_std, 4)
                
        entry["sample_count"] += 1
        entry["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self.save_baselines()
        print(f"[CONTROLLER] Updated baseline for '{exact_key}' (total samples: {entry['sample_count']})", flush=True)

    def get_active_session_status(self):
        """Reads data/sessions/active_session.json and evaluates real-time anomaly score."""
        if not os.path.exists(self.active_session_path):
            return None
        try:
            with open(self.active_session_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            anomaly, details = self.evaluate_micro_session(data)
            data["controller_anomaly_score"] = anomaly
            data["controller_details"] = details
            return data
        except Exception:
            return None
