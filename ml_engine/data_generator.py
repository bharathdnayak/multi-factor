import os
import sys
import json
import time
import math
import random
import argparse
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.controller import BehavioralAIController, classify_activity_context
from ml_engine.train import train_models

# Profile definitions modeled on genuine developer workflows
ACTIVITY_PROFILES = {
    "chrome_leetcode": {
        "app_name": "chrome.exe",
        "window_titles": [
            "Two Sum - LeetCode - Google Chrome",
            "Longest Substring Without Repeating Characters - LeetCode - Google Chrome",
            "Median of Two Sorted Arrays - LeetCode - Google Chrome",
            "Trapping Rain Water - LeetCode - Google Chrome",
            "Binary Tree Maximum Path Sum - LeetCode - Google Chrome",
            "Course Schedule II - LeetCode - Google Chrome"
        ],
        "context_mode": "coding_problem_solving",
        # Cognitive metrics: Algorithmic pondering, high syntax symbols, deliberate bursts
        "dwell_mean": (0.088, 0.012),
        "flight_mean": (0.165, 0.025),
        "thinking_pause": (5.8, 1.8),         # Long thinking pauses (3-12 seconds)
        "thinking_pause_ratio": (0.42, 0.08),  # 35-50% of time thinking before typing
        "burst_length": (22.0, 6.5),          # 15-35 characters per code line/block
        "code_symbol_ratio": (0.24, 0.05),    # High density of {}[];:=+-*/<>
        "backspace_ratio": (0.10, 0.03),      # Frequent edits of code logic
        "mouse_scroll_count": (14, 5),        # Scrolling problem statement & test results
        "mouse_vel": (280.0, 45.0),
        "mouse_straight": (0.91, 0.04),
        "cpu_usage": (3.5, 1.2),
        "ram_mb": (480.0, 60.0)
    },
    "vscode_development": {
        "app_name": "code.exe",
        "window_titles": [
            "agent.py - Behavioral-Drift-Security - Visual Studio Code",
            "controller.py - Behavioral-Drift-Security - Visual Studio Code",
            "models.py - Behavioral-Drift-Security - Visual Studio Code",
            "drift_detector.py - Behavioral-Drift-Security - Visual Studio Code",
            "main.py - Major-Project - Visual Studio Code"
        ],
        "context_mode": "ide_development",
        # Cognitive metrics: Flow typing, autocomplete tabs, high syntax
        "dwell_mean": (0.085, 0.010),
        "flight_mean": (0.140, 0.020),
        "thinking_pause": (3.5, 1.2),
        "thinking_pause_ratio": (0.28, 0.06),
        "burst_length": (32.0, 8.0),
        "code_symbol_ratio": (0.26, 0.05),
        "backspace_ratio": (0.11, 0.03),
        "mouse_scroll_count": (8, 3),
        "mouse_vel": (320.0, 50.0),
        "mouse_straight": (0.93, 0.03),
        "cpu_usage": (4.8, 1.5),
        "ram_mb": (650.0, 80.0)
    },
    "ai_prompting": {
        "app_name": "chrome.exe",
        "window_titles": [
            "ChatGPT - OpenAI - Google Chrome",
            "Claude - Anthropic - Google Chrome",
            "Antigravity Agentic IDE - Google Chrome"
        ],
        "context_mode": "ai_chat_prompting",
        # Cognitive metrics: Natural language prompts, reading pauses, low code symbols
        "dwell_mean": (0.082, 0.009),
        "flight_mean": (0.125, 0.018),
        "thinking_pause": (2.8, 0.9),
        "thinking_pause_ratio": (0.22, 0.05),
        "burst_length": (55.0, 14.0),
        "code_symbol_ratio": (0.05, 0.02),
        "backspace_ratio": (0.07, 0.02),
        "mouse_scroll_count": (18, 6),
        "mouse_vel": (240.0, 40.0),
        "mouse_straight": (0.90, 0.04),
        "cpu_usage": (3.0, 1.0),
        "ram_mb": (420.0, 50.0)
    },
    "terminal_cli": {
        "app_name": "powershell.exe",
        "window_titles": [
            "Administrator: Windows PowerShell",
            "Windows PowerShell - git commit",
            "Windows PowerShell - python telemetry/agent.py"
        ],
        "context_mode": "terminal_command_line",
        # Cognitive metrics: Short command bursts, fast executions
        "dwell_mean": (0.086, 0.010),
        "flight_mean": (0.135, 0.022),
        "thinking_pause": (2.4, 0.8),
        "thinking_pause_ratio": (0.18, 0.05),
        "burst_length": (16.0, 4.5),
        "code_symbol_ratio": (0.18, 0.04),
        "backspace_ratio": (0.08, 0.03),
        "mouse_scroll_count": (2, 1),
        "mouse_vel": (180.0, 35.0),
        "mouse_straight": (0.88, 0.05),
        "cpu_usage": (2.0, 0.8),
        "ram_mb": (85.0, 15.0)
    },
    "tech_reading": {
        "app_name": "chrome.exe",
        "window_titles": [
            "python - Fast way to compute pairwise distance - Stack Overflow",
            "PEP 8 - Style Guide for Python Code | peps.python.org",
            "GitHub - PyTorch Model Training Docs"
        ],
        "context_mode": "technical_reading",
        # Cognitive metrics: Heavy scrolling, low keystrokes, long reading intervals
        "dwell_mean": (0.092, 0.015),
        "flight_mean": (0.170, 0.030),
        "thinking_pause": (6.5, 2.2),
        "thinking_pause_ratio": (0.50, 0.10),
        "burst_length": (12.0, 4.0),
        "code_symbol_ratio": (0.08, 0.03),
        "backspace_ratio": (0.06, 0.02),
        "mouse_scroll_count": (24, 8),
        "mouse_vel": (210.0, 40.0),
        "mouse_straight": (0.92, 0.03),
        "cpu_usage": (2.8, 0.9),
        "ram_mb": (450.0, 55.0)
    }
}


def sample_gaussian(params, lower_bound=0.0):
    mean, std = params
    val = float(np.random.normal(mean, std))
    return max(lower_bound, val)


def generate_single_session(profile_key=None, timestamp=None):
    """Generates a single realistic micro-session matching a genuine user workflow profile."""
    if profile_key is None:
        profile_key = random.choice(list(ACTIVITY_PROFILES.keys()))
        
    p = ACTIVITY_PROFILES[profile_key]
    ts = timestamp or time.time()
    
    elapsed = float(random.uniform(45.0, 300.0))
    keystroke_rate = float(random.uniform(1.2, 3.5))
    total_keys = max(10, int(elapsed * keystroke_rate))
    
    dwell = round(sample_gaussian(p["dwell_mean"], 0.05), 4)
    flight = round(sample_gaussian(p["flight_mean"], 0.08), 4)
    avg_pause = round(sample_gaussian(p["thinking_pause"], 1.5), 3)
    pause_ratio = round(min(0.85, sample_gaussian(p["thinking_pause_ratio"], 0.05)), 4)
    burst_len = round(sample_gaussian(p["burst_length"], 4.0), 1)
    code_sym_ratio = round(min(0.60, sample_gaussian(p["code_symbol_ratio"], 0.01)), 4)
    backspace_ratio = round(min(0.35, sample_gaussian(p["backspace_ratio"], 0.01)), 4)
    
    pauses_count = max(1, int((elapsed * pause_ratio) / max(1.0, avg_pause)))
    bursts_count = pauses_count + random.randint(0, 2)
    code_symbols = int(total_keys * code_sym_ratio)
    backspaces = int(total_keys * backspace_ratio)
    scrolls = max(0, int(sample_gaussian(p["mouse_scroll_count"], 0)))
    clicks = random.randint(2, 12)
    moves = random.randint(50, 400)
    
    title = random.choice(p["window_titles"])
    session_id = f"sess_gen_{int(ts)}_{random.randint(1000, 9999)}"
    
    session = {
        "session_id": session_id,
        "app_name": p["app_name"],
        "window_title": title,
        "context_mode": p["context_mode"],
        "start_time": ts,
        "end_time": ts + elapsed,
        "elapsed_seconds": round(elapsed, 2),
        "keystrokes": total_keys,
        "thinking_pause_count": pauses_count,
        "avg_thinking_pause_sec": avg_pause,
        "max_thinking_pause_sec": round(avg_pause * random.uniform(1.4, 2.5), 2),
        "thinking_pause_ratio": pause_ratio,
        "typing_burst_count": bursts_count,
        "avg_burst_length": burst_len,
        "code_symbol_count": code_symbols,
        "code_symbol_ratio": code_sym_ratio,
        "backspace_count": backspaces,
        "backspace_ratio": backspace_ratio,
        "dwell_mean": dwell,
        "flight_mean": flight,
        "mouse_moves": moves,
        "mouse_clicks": clicks,
        "mouse_scrolls": scrolls,
        "reading_scroll_ratio": round(scrolls / max(1, moves + scrolls), 4),
        "status": "completed",
        "recorded_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    }
    return session, p


def session_to_telemetry_row(session, profile, ts=None):
    """Converts a micro-session profile into standard 10s telemetry rows."""
    t = ts or session["end_time"]
    dwell = session["dwell_mean"]
    flight = session["flight_mean"]
    
    row = {
        "timestamp": t,
        "hour_of_day": time.localtime(t).tm_hour,
        "keystroke_count": random.randint(15, 60),
        "dwell_mean": dwell,
        "dwell_std": round(dwell * 0.15, 4),
        "flight_mean": flight,
        "flight_std": round(flight * 0.18, 4),
        "app_dwell_mean": dwell,
        "app_flight_mean": flight,
        "app_backspace_ratio": session["backspace_ratio"],
        "app_special_ratio": session["code_symbol_ratio"],
        "app_click_count": random.randint(1, 5),
        "app_scroll_count": random.randint(1, 8),
        "app_pause_ratio": session["thinking_pause_ratio"],
        "avg_thinking_pause_sec": session["avg_thinking_pause_sec"],
        "interaction_mode": session["context_mode"],
        "micro_session_id": session["session_id"],
        "mouse_events": random.randint(40, 120),
        "mouse_velocity_mean": round(sample_gaussian(profile["mouse_vel"], 50.0), 2),
        "mouse_acceleration_mean": round(sample_gaussian((15.0, 4.0), 2.0), 2),
        "mouse_jerk_mean": round(sample_gaussian((1.2, 0.4), 0.1), 3),
        "mouse_straightness_mean": round(min(1.0, sample_gaussian(profile["mouse_straight"], 0.7)), 3),
        "active_app": session["app_name"],
        "active_window": session["window_title"],
        "cpu_usage": round(sample_gaussian(profile["cpu_usage"], 0.5), 2),
        "ram_usage_mb": round(sample_gaussian(profile["ram_mb"], 20.0), 1)
    }
    return row


def bootstrap_dataset(num_sessions=1200, telemetry_multiplier=2, silent=False):
    """
    Generates a massive, realistic genuine user dataset across all primary daily applications
    (Chrome LeetCode, VS Code development, AI Prompting, Terminal, Technical Reading).
    Updates session history, builds statistical baseline envelopes, logs telemetry rows,
    and retrains the core ML models.
    """
    if not silent:
        print("=" * 65)
        print(f"   BOOTSTRAPPING {num_sessions} GENUINE BEHAVIORAL MICRO-SESSIONS")
        print("=" * 65)

    controller = BehavioralAIController()
    sessions_file = os.path.join(PROJECT_ROOT, "data", "sessions", "session_history.jsonl")
    telemetry_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    
    os.makedirs(os.path.dirname(sessions_file), exist_ok=True)
    
    now = time.time()
    # Spread timestamps back across the past 7 days
    start_ts = now - (7 * 24 * 3600)
    time_step = (7 * 24 * 3600) / float(num_sessions)
    
    session_lines = []
    telemetry_rows = []
    
    keys = list(ACTIVITY_PROFILES.keys())
    weights = [0.30, 0.30, 0.15, 0.15, 0.10]  # Realistic daily task distribution
    
    for i in range(num_sessions):
        chosen_key = random.choices(keys, weights=weights, k=1)[0]
        curr_ts = start_ts + (i * time_step)
        session, profile = generate_single_session(chosen_key, timestamp=curr_ts)
        
        session_lines.append(json.dumps(session) + "\n")
        controller.learn_from_session(session, verified=True)
        
        # Generate corresponding telemetry rows for ML engine training
        for _ in range(telemetry_multiplier):
            t_row = session_to_telemetry_row(session, profile, ts=curr_ts + random.uniform(5, 60))
            telemetry_rows.append(t_row)
            
    # Save sessions
    with open(sessions_file, "a", encoding="utf-8") as f:
        f.writelines(session_lines)
    if not silent:
        print(f"[OK] Appended {num_sessions} sessions to '{sessions_file}'")

    # Save baselines
    controller.save_baselines()
    if not silent:
        print(f"[OK] Saved baseline distributions across {len(controller.baselines)} application-task profiles.")

    # Save telemetry rows
    with open(telemetry_file, "a", encoding="utf-8") as f:
        for r in telemetry_rows:
            f.write(json.dumps(r) + "\n")
    if not silent:
        print(f"[OK] Appended {len(telemetry_rows)} telemetry rows to '{telemetry_file}'")

    # Train core ML models
    if not silent:
        print("[INFO] Retraining ML Models (One-Class SVM & Isolation Forest)...")
    train_models(telemetry_file, output_model_path=os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl"))
    if not silent:
        print("[SUCCESS] Dataset bootstrap and model retraining completed successfully!")


def run_continuous_drip(interval_seconds=15, silent=False):
    """
    Runs in the background, non-intrusively generating and logging genuine synthetic data
    at regular intervals without using hardware inputs or stealing focus.
    """
    if not silent:
        print(f"[INFO] Background Drip Generator active (interval: {interval_seconds}s). Press Ctrl+C to stop.")
    controller = BehavioralAIController()
    sessions_file = os.path.join(PROJECT_ROOT, "data", "sessions", "session_history.jsonl")
    telemetry_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    
    count = 0
    try:
        while True:
            session, profile = generate_single_session()
            t_row = session_to_telemetry_row(session, profile)
            
            # Save session
            with open(sessions_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(session) + "\n")
                
            # Update baseline
            controller.learn_from_session(session, verified=True)
            
            # Save telemetry
            with open(telemetry_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(t_row) + "\n")
                
            count += 1
            if not silent:
                print(f"[DRIP #{count}] Emitted genuine session for '{session['app_name']}' ({session['context_mode']})", flush=True)
                
            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        if not silent:
            print("[INFO] Background Drip Generator stopped.")


def generate_unauthorized_dataset(output_file=None, num_samples=120, silent=False):
    """
    Generates a realistic, highly anomalous unauthorized imposter dataset spanning 4 attack typologies:
    1. Frantic / Rapid Typer (erratic bursts, dwell ~0.045s, flight ~0.075s, high mouse jerk)
    2. Sluggish Hunt-and-Peck Imposter (dwell ~0.240s, flight ~0.390s, sluggish mouse)
    3. Rogue Process Attacker (mimikatz.exe, cmd.exe, powershell.exe, high CPU, abnormal hours)
    4. Cross-User Cognitive Imposter (LeetCode copy-pasting, 0 thinking pauses, 0 syntax symbols)
    """
    if output_file is None:
        output_file = os.path.join(PROJECT_ROOT, "data", "unauthorized_dataset.jsonl")
    elif not os.path.isabs(output_file):
        output_file = os.path.join(PROJECT_ROOT, output_file)
        
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    from ml_engine.evaluate_metrics import generate_imposter_telemetry
    from ml_engine.sequence_model import DeepSVDDDetector
    
    rows = generate_imposter_telemetry(num_samples=num_samples, seed=42)
    seq_det = DeepSVDDDetector()
    raw_imp = os.path.join(PROJECT_ROOT, "data", "raw", "imposter_keystrokes.csv")
    imp_seqs = seq_det.extract_raw_sequences(raw_imp) if os.path.exists(raw_imp) else []
    
    typology_labels = {
        0: "Frantic / Rapid Typist",
        1: "Sluggish Hunt-and-Peck Imposter",
        2: "Rogue Process Attacker (cmd/powershell)",
        3: "Cross-User Cognitive Imposter (LeetCode Copy-Paster)"
    }
    
    for i, r in enumerate(rows):
        typology = i % 4
        r["typology_id"] = typology
        r["typology_name"] = typology_labels.get(typology, "Unauthorized Intruder")
        r["is_authorized"] = False
        if len(imp_seqs) > 0:
            seq = imp_seqs[i % len(imp_seqs)]
            r["dwell_sequence"] = [round(float(v), 5) for v in seq[0]]
            r["flight_sequence"] = [round(float(v), 5) for v in seq[1]]
    
    with open(output_file, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
            
    if not silent:
        print(f"[SUCCESS] Generated {len(rows)} unauthorized intrusion records in '{output_file}'", flush=True)
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Factor Behavioral Dataset Generator & Intrusion Simulator")
    parser.add_argument("--bootstrap", action="store_true", help="Generate initial large genuine dataset (default: 1200 sessions) and train models")
    parser.add_argument("--sessions", type=int, default=1200, help="Number of micro-sessions to generate in bootstrap mode")
    parser.add_argument("--drip", action="store_true", help="Run continuously in background feeding genuine data at intervals")
    parser.add_argument("--interval", type=int, default=15, help="Interval in seconds for drip mode")
    parser.add_argument("--unauthorized", action="store_true", help="Generate dedicated unauthorized imposter intrusion dataset")
    parser.add_argument("--output", type=str, default=None, help="Custom output file path for generated dataset")
    parser.add_argument("--silent", action="store_true", help="Suppress console outputs")
    args = parser.parse_args()

    if args.unauthorized:
        generate_unauthorized_dataset(output_file=args.output, num_samples=args.sessions if args.sessions != 1200 else 120, silent=args.silent)
    elif args.drip:
        run_continuous_drip(interval_seconds=args.interval, silent=args.silent)
    elif args.bootstrap or len(sys.argv) == 1:
        bootstrap_dataset(num_sessions=args.sessions, silent=args.silent)
