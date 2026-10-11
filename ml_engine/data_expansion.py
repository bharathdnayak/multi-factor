"""
================================================================================
EXPANDED AUTHORIZED & MULTI-USER BEHAVIORAL DATASET GENERATOR (PHASE 2)
Department of Information Science & Engineering | Team 30
Behavioral Drift: Continuous Authentication & Honeypot Forensics
================================================================================

Generates a realistic, diverse, multi-session, multi-user behavioral dataset:
1. Enrolled Authorized Owner (Owner_Anush):
   - Multi-day / multi-hour sessions across diverse tasks:
     * Coding (VS Code / Python / C++)
     * Document Writing (Word / Markdown / Reports)
     * Web Research / Browsing (Docs, Stack Overflow, GitHub)
     * Terminal / Command Line (PowerShell, Git, CLI)
     * Technical Reading (Heavy scrolling, thinking pauses)
     * Task-Switching / Mixed Contexts
   - Natural variations:
     * Fast flow typing
     * Deliberate thinking pauses (3s - 15s)
     * Fatigue & evening slowdown (increased dwell & flight variability)
     * Normal errors and backspace revisions (5% - 25%)
     * Mouse movements: precision clicks, reading scrolls, ballistic movements, idle phases
     * Sensor realism: Realistic BLE RSSI fluctuations (-55 to -72 dBm, 0.7m to 2.2m)
2. Consented Multi-User Imposters & Hard Negatives:
   - 6 diverse imposter identities:
     * Imposter_Mimic_Near (Hard Negative: types at near-owner speed but with different rhythm)
     * Imposter_Fast (Fast ballistic typist)
     * Imposter_Sluggish (Hunt-and-peck typist)
     * Imposter_RogueCLI (Adversarial shell operator)
     * Teammate_Akash (Unregistered teammate: coding task)
     * Teammate_Pratheek (Unregistered teammate: docs task)
3. Synthetic Stress Testing:
   - 4 synthetic attack typologies kept strictly separate in data/synthetic_stress/
"""

import os
import sys
import json
import time
import math
import random
from typing import Dict, Any, List, Tuple, Optional
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.controller import classify_activity_context

EXPANDED_DATA_DIR = os.path.join(PROJECT_ROOT, "data", "expanded_behavioral")
EXPANDED_SESSIONS_DIR = os.path.join(EXPANDED_DATA_DIR, "sessions")
SYNTHETIC_STRESS_DIR = os.path.join(PROJECT_ROOT, "data", "synthetic_stress")


class BehavioralSessionSynthesizer:
    """
    Synthesizes rich, realistic multi-session behavioral telemetry
    grounded in human-computer interaction (HCI) distributions.
    """
    def __init__(self, output_dir: str = EXPANDED_SESSIONS_DIR):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_session(
        self,
        user_id: str,
        is_authorized: bool,
        task_mode: str,
        num_windows: int = 30,
        session_id: Optional[str] = None,
        base_timestamp: Optional[float] = None,
        typing_style: str = "normal",  # "normal", "fast", "fatigue", "deliberate", "erratic"
        device_profile: str = "desktop_standard",
        seed: Optional[int] = None
    ) -> Tuple[str, List[Dict[str, Any]]]:
        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)

        now = base_timestamp or (time.time() - random.uniform(3600, 7 * 86400))
        sess_id = session_id or f"sess_{user_id}_{task_mode}_{int(now)}_{random.randint(100, 999)}"
        sess_file = os.path.join(self.output_dir, f"{sess_id}.jsonl")

        # Base user characteristics
        if is_authorized:
            # Owner Anush baseline
            base_dwell = 0.088
            base_flight = 0.142
            base_mouse_vel = 275.0
            base_straight = 0.905
            
            # Behavioral modulation by typing style
            if typing_style == "fast":
                dwell_mu = base_dwell * 0.88
                flight_mu = base_flight * 0.85
                pause_ratio_mu = 0.18
                vel_mu = base_mouse_vel * 1.15
            elif typing_style == "fatigue":
                dwell_mu = base_dwell * 1.18
                flight_mu = base_flight * 1.25
                pause_ratio_mu = 0.38
                vel_mu = base_mouse_vel * 0.85
            elif typing_style == "deliberate":
                dwell_mu = base_dwell * 1.05
                flight_mu = base_flight * 1.12
                pause_ratio_mu = 0.45
                vel_mu = base_mouse_vel * 0.95
            else:
                dwell_mu = base_dwell
                flight_mu = base_flight
                pause_ratio_mu = 0.28
                vel_mu = base_mouse_vel

            dwell_sigma = dwell_mu * 0.14
            flight_sigma = flight_mu * 0.16
            straight_mu = base_straight
            straight_sigma = 0.035

        else:
            # Imposter profiles
            if typing_style == "near_owner":
                # Hard negative: closely mimics owner speed, differs in rhythm & kinematics
                dwell_mu = 0.091
                flight_mu = 0.148
                dwell_sigma = 0.024
                flight_sigma = 0.032
                vel_mu = 360.0
                straight_mu = 0.82
                straight_sigma = 0.06
                pause_ratio_mu = 0.15
            elif typing_style == "fast":
                dwell_mu = 0.052
                flight_mu = 0.078
                dwell_sigma = 0.012
                flight_sigma = 0.018
                vel_mu = 680.0
                straight_mu = 0.68
                straight_sigma = 0.09
                pause_ratio_mu = 0.06
            elif typing_style == "sluggish":
                dwell_mu = 0.225
                flight_mu = 0.365
                dwell_sigma = 0.040
                flight_sigma = 0.065
                vel_mu = 140.0
                straight_mu = 0.74
                straight_sigma = 0.08
                pause_ratio_mu = 0.10
            elif typing_style == "rogue":
                dwell_mu = 0.175
                flight_mu = 0.260
                dwell_sigma = 0.030
                flight_sigma = 0.045
                vel_mu = 520.0
                straight_mu = 0.65
                straight_sigma = 0.10
                pause_ratio_mu = 0.08
            else:
                # Teammate distinct profile
                dwell_mu = 0.155
                flight_mu = 0.235
                dwell_sigma = 0.028
                flight_sigma = 0.040
                vel_mu = 440.0
                straight_mu = 0.76
                straight_sigma = 0.07
                pause_ratio_mu = 0.14

        # Task context parameters
        if task_mode == "coding":
            app = "code.exe"
            win = "main.py - Visual Studio Code"
            context_mode = "ide_development"
            backspace_mu = 0.12
            special_mu = 0.24
            cpu_mu = 5.2
            ram_mu = 580.0
        elif task_mode == "docs":
            app = "winword.exe"
            win = "Technical_Report.docx - Word"
            context_mode = "general_productivity"
            backspace_mu = 0.08
            special_mu = 0.04
            cpu_mu = 3.6
            ram_mu = 410.0
        elif task_mode == "browsing":
            app = "chrome.exe"
            win = "Python Documentation - Google Chrome"
            context_mode = "general_productivity"
            backspace_mu = 0.05
            special_mu = 0.03
            cpu_mu = 4.1
            ram_mu = 490.0
        elif task_mode == "terminal":
            app = "powershell.exe"
            win = "Windows PowerShell"
            context_mode = "terminal_command_line"
            backspace_mu = 0.09
            special_mu = 0.18
            cpu_mu = 2.4
            ram_mu = 120.0
        elif task_mode == "technical_reading":
            app = "chrome.exe"
            win = "Stack Overflow - Question - Google Chrome"
            context_mode = "technical_reading"
            backspace_mu = 0.04
            special_mu = 0.06
            cpu_mu = 3.2
            ram_mu = 460.0
        elif task_mode == "rogue_cli":
            app = "cmd.exe"
            win = "Administrator: Command Prompt"
            context_mode = "terminal_command_line"
            backspace_mu = 0.03
            special_mu = 0.15
            cpu_mu = 42.0
            ram_mu = 620.0
        else:
            app = "notepad.exe"
            win = "Notes.txt"
            context_mode = "general_productivity"
            backspace_mu = 0.06
            special_mu = 0.04
            cpu_mu = 1.8
            ram_mu = 90.0

        rows = []
        rolling_dwell_seq = [round(float(np.random.normal(dwell_mu, dwell_sigma)), 4) for _ in range(30)]
        rolling_flight_seq = [round(float(np.random.normal(flight_mu, flight_sigma)), 4) for _ in range(30)]

        for i in range(num_windows):
            ts = int(now + i * 5)
            hour = time.localtime(ts).tm_hour

            # Idle window probability (higher in reading/browsing)
            is_idle = False
            if task_mode in ("technical_reading", "browsing") and random.random() < 0.20:
                is_idle = True
            elif random.random() < 0.06:
                is_idle = True

            if is_idle:
                keys = 0
                w_dwell = 0.0
                w_dwell_std = 0.0
                w_flight = 0.0
                w_flight_std = 0.0
                backspace_ratio = 0.0
                special_ratio = 0.0
                pause_ratio = 0.0
                avg_pause = 0.0
                mouse_events = random.randint(0, 15)
                m_vel = float(max(0.0, np.random.normal(vel_mu * 0.4, 30.0))) if mouse_events > 0 else 0.0
                straight = 1.0
                clicks = 0
                scrolls = random.randint(0, 4) if mouse_events > 0 else 0
            else:
                keys = max(4, int(np.random.normal(32, 10)))
                w_dwell = max(0.02, float(np.random.normal(dwell_mu, dwell_sigma * 0.6)))
                w_dwell_std = max(0.005, float(np.random.normal(dwell_sigma, dwell_sigma * 0.15)))
                w_flight = max(0.03, float(np.random.normal(flight_mu, flight_sigma * 0.6)))
                w_flight_std = max(0.01, float(np.random.normal(flight_sigma, flight_sigma * 0.15)))
                backspace_ratio = float(np.clip(np.random.normal(backspace_mu, 0.025), 0.0, 0.40))
                special_ratio = float(np.clip(np.random.normal(special_mu, 0.03), 0.0, 0.50))
                pause_ratio = float(np.clip(np.random.normal(pause_ratio_mu, 0.05), 0.0, 0.80))
                avg_pause = float(round(pause_ratio * 4.5, 3)) if pause_ratio > 0 else 0.0
                mouse_events = max(5, int(np.random.normal(55, 18)))
                m_vel = max(30.0, float(np.random.normal(vel_mu, 40.0)))
                straight = float(np.clip(np.random.normal(straight_mu, straight_sigma), 0.25, 0.99))
                clicks = random.randint(1, 6)
                scrolls = random.randint(1, 12) if task_mode in ("technical_reading", "browsing") else random.randint(0, 4)

                # Update rolling sequence
                for _ in range(min(5, keys)):
                    rolling_dwell_seq.pop(0)
                    rolling_flight_seq.pop(0)
                    rolling_dwell_seq.append(round(max(0.02, float(np.random.normal(w_dwell, w_dwell_std))), 4))
                    rolling_flight_seq.append(round(max(0.03, float(np.random.normal(w_flight, w_flight_std))), 4))

            # Environmental simulation with realistic RF fluctuations
            if is_authorized:
                # Owner phone present near desk with natural RSSI jitter (-57 to -68 dBm)
                # Occasional packet drop/fluctuation to NEAR
                rssi = float(np.random.normal(-62.0, 3.5))
                # Log-distance path loss: d = 10 ** ((-59 - rssi) / 20)
                dist_m = float(round(math.pow(10.0, (-59.0 - rssi) / 20.0), 2))
                dist_m = min(4.5, max(0.5, dist_m))
                ble_zone = "IMMEDIATE" if dist_m < 1.5 else "NEAR"
                untrusted_net = False
            else:
                # Imposter: in most cases walk-away takeover (phone out of range),
                # but in 25% of cases phone simulated nearby to strictly test biometrics
                if random.random() < 0.25:
                    rssi = float(np.random.normal(-64.0, 4.0))
                    dist_m = float(round(math.pow(10.0, (-59.0 - rssi) / 20.0), 2))
                    ble_zone = "NEAR"
                else:
                    rssi = -95.0
                    dist_m = float(round(random.uniform(7.5, 15.0), 2))
                    ble_zone = "OUT_OF_RANGE"
                untrusted_net = (task_mode == "rogue_cli")

            cpu_val = max(0.5, float(np.random.normal(cpu_mu, cpu_mu * 0.2)))
            ram_val = max(50.0, float(np.random.normal(ram_mu, 30.0)))

            row = {
                "timestamp": ts,
                "session_id": sess_id,
                "session_user_id": user_id,
                "is_authorized": is_authorized,
                "task_mode": task_mode,
                "typing_style": typing_style,
                "hour_of_day": hour,
                "keystroke_count": keys,
                "dwell_mean": round(w_dwell, 4),
                "dwell_std": round(w_dwell_std, 4),
                "flight_mean": round(w_flight, 4),
                "flight_std": round(w_flight_std, 4),
                "app_dwell_mean": round(w_dwell, 4),
                "app_flight_mean": round(w_flight, 4),
                "app_backspace_ratio": round(backspace_ratio, 4),
                "app_special_ratio": round(special_ratio, 4),
                "app_click_count": clicks,
                "app_scroll_count": scrolls,
                "app_pause_ratio": round(pause_ratio, 4),
                "avg_thinking_pause_sec": round(avg_pause, 3),
                "interaction_mode": context_mode,
                "mouse_events": mouse_events,
                "mouse_velocity_mean": round(m_vel, 2),
                "mouse_acceleration_mean": round(m_vel * 0.08, 2),
                "mouse_jerk_mean": round(m_vel * 0.012, 2),
                "mouse_straightness_mean": round(straight, 4),
                "active_app": app,
                "active_window": win,
                "cpu_usage": round(cpu_val, 2),
                "ram_usage_mb": round(ram_val, 1),
                "dwell_sequence": list(rolling_dwell_seq[:30]),
                "flight_sequence": list(rolling_flight_seq[:30]),
                "ble_proximity_state": ble_zone,
                "ble_estimated_distance_m": dist_m,
                "is_untrusted_network": untrusted_net
            }
            rows.append(row)

        with open(sess_file, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")

        return sess_file, rows


def generate_full_expanded_corpus() -> Dict[str, Any]:
    """
    Generates the complete expanded multi-user corpus:
    - 12 Authorized Owner sessions across tasks and typing styles
    - 10 Imposter sessions across 6 distinct personas (including hard negatives)
    - 4 Synthetic attack stress profiles
    """
    synth = BehavioralSessionSynthesizer(EXPANDED_SESSIONS_DIR)
    
    owner_sessions = []
    # 1. Authorized Owner Sessions (12 sessions)
    owner_configs = [
        # (task, typing_style, num_windows)
        ("coding", "normal", 35),
        ("coding", "fast", 30),
        ("coding", "fatigue", 30),
        ("docs", "normal", 35),
        ("docs", "deliberate", 30),
        ("browsing", "normal", 30),
        ("browsing", "fast", 25),
        ("terminal", "normal", 25),
        ("terminal", "fast", 25),
        ("technical_reading", "normal", 35),
        ("technical_reading", "deliberate", 30),
        ("coding", "normal", 40)
    ]

    base_time = time.time() - (10 * 86400)
    for idx, (task, style, n_win) in enumerate(owner_configs):
        sess_ts = base_time + idx * (18 * 3600)  # Spread across 10 days
        sess_file, rows = synth.generate_session(
            user_id="Owner_Anush",
            is_authorized=True,
            task_mode=task,
            num_windows=n_win,
            session_id=f"Owner_Anush_sess_{idx+1:02d}_{task}_{style}",
            base_timestamp=sess_ts,
            typing_style=style,
            seed=100 + idx
        )
        owner_sessions.append((sess_file, rows))

    # 2. Imposter Sessions (10 sessions across 6 identities)
    imposter_sessions = []
    imposter_configs = [
        # (user_id, task, typing_style, num_windows)
        ("Imposter_Mimic_Near", "coding", "near_owner", 30),      # Hard Negative 1
        ("Imposter_Mimic_Near", "docs", "near_owner", 30),        # Hard Negative 2
        ("Imposter_Fast", "browsing", "fast", 30),
        ("Imposter_Fast", "coding", "fast", 30),
        ("Imposter_Sluggish", "docs", "sluggish", 30),
        ("Imposter_Sluggish", "technical_reading", "sluggish", 25),
        ("Imposter_RogueCLI", "rogue_cli", "rogue", 30),
        ("Imposter_RogueCLI", "terminal", "rogue", 25),
        ("Teammate_Akash", "coding", "normal", 30),
        ("Teammate_Pratheek", "docs", "normal", 30)
    ]

    for idx, (uid, task, style, n_win) in enumerate(imposter_configs):
        sess_ts = base_time + (idx + 1) * (20 * 3600)
        sess_file, rows = synth.generate_session(
            user_id=uid,
            is_authorized=False,
            task_mode=task,
            num_windows=n_win,
            session_id=f"{uid}_sess_{idx+1:02d}_{task}",
            base_timestamp=sess_ts,
            typing_style=style,
            seed=200 + idx
        )
        imposter_sessions.append((sess_file, rows))

    # 3. Synthetic Attack Stress Profiles (in separate directory)
    os.makedirs(SYNTHETIC_STRESS_DIR, exist_ok=True)
    synth_stress = BehavioralSessionSynthesizer(SYNTHETIC_STRESS_DIR)
    stress_configs = [
        ("Synthetic_Frantic", "coding", "fast", 40),
        ("Synthetic_Sluggish", "docs", "sluggish", 40),
        ("Synthetic_RogueCLI", "rogue_cli", "rogue", 40),
        ("Synthetic_ZeroPause", "coding", "near_owner", 40)
    ]
    stress_sessions = []
    for idx, (uid, task, style, n_win) in enumerate(stress_configs):
        sess_file, rows = synth_stress.generate_session(
            user_id=uid,
            is_authorized=False,
            task_mode=task,
            num_windows=n_win,
            session_id=f"{uid}_stress_{idx+1:02d}",
            typing_style=style,
            seed=300 + idx
        )
        stress_sessions.append((sess_file, rows))

    total_owner_win = sum(len(r) for _, r in owner_sessions)
    total_imp_win = sum(len(r) for _, r in imposter_sessions)
    total_stress_win = sum(len(r) for _, r in stress_sessions)

    summary = {
        "owner_sessions": len(owner_sessions),
        "owner_windows": total_owner_win,
        "imposter_sessions": len(imposter_sessions),
        "imposter_windows": total_imp_win,
        "stress_sessions": len(stress_sessions),
        "stress_windows": total_stress_win,
        "total_behavioral_sessions": len(owner_sessions) + len(imposter_sessions),
        "total_behavioral_windows": total_owner_win + total_imp_win
    }
    print(f"[DATA EXPANSION] Successfully generated expanded behavioral corpus:")
    print(f"  -> Owner Sessions: {summary['owner_sessions']} ({summary['owner_windows']} windows)")
    print(f"  -> Imposter Sessions: {summary['imposter_sessions']} ({summary['imposter_windows']} windows)")
    print(f"  -> Synthetic Stress Sessions: {summary['stress_sessions']} ({summary['stress_windows']} windows)")
    return summary


if __name__ == "__main__":
    generate_full_expanded_corpus()
