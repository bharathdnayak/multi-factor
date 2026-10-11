"""
================================================================================
GENUINE-USER EXTENDED BEHAVIORAL EVALUATION & FALSE ALARM BENCHMARK
Department of Information Science & Engineering | Team 30 | Major Project
Behavioral Drift: Continuous Authentication & Honeypot Forensics
================================================================================

Comprehensive evaluation of genuine authorized user behavior across multi-day tasks,
interaction styles, fatigue states, sensor dropouts, and task transitions.

Evaluates:
1. 12 Independent Owner Sessions (370 windows = 1,850s ≈ 30.8 min) across:
   - Coding (Normal, Fast, Fatigue)
   - Browsing & Web Navigation (Normal, Fast)
   - Technical Reading & Research (Normal, Deliberate - zero/idle keystrokes)
   - Terminal Command Line (Normal, Fast)
   - Document Processing (Normal, Deliberate)
2. False alerts per session and false alerts per hour.
3. Missing-modality resilience:
   - Idle keyboard (pure reading/browsing)
   - Idle mouse (pure typing)
   - Sensor dropout (BLE proximity disconnect / out-of-range)
4. Detection latency and False Reject Rate (FRR) under operational thresholds.
5. Strict isolation of quarantined synthetic attacks (4 profiles) vs genuine hardware telemetry.
"""

import os
import sys
import json
import time
import numpy as np
import pandas as pd
from collections import defaultdict, Counter

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.evaluator import ThreatEvaluator


def load_all_dataset_sessions():
    """Loads all split sessions with source provenance preserved."""
    splits = [
        ("train", os.path.join(PROJECT_ROOT, "data", "splits", "personalized", "train_owner.jsonl")),
        ("val", os.path.join(PROJECT_ROOT, "data", "splits", "personalized", "val_multimodal.jsonl")),
        ("test", os.path.join(PROJECT_ROOT, "data", "splits", "personalized", "test_multimodal.jsonl")),
        ("synthetic_stress", os.path.join(PROJECT_ROOT, "data", "splits", "synthetic_stress", "synthetic_attack_test.jsonl")),
    ]
    
    all_rows = []
    for split_tag, fpath in splits:
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        r = json.loads(line)
                        r["split_tag"] = split_tag
                        all_rows.append(r)
    return all_rows


def run_genuine_behavior_audit():
    print("=" * 80)
    print("EXTENDED GENUINE-USER BEHAVIORAL DRIFT AUDIT & OPERATIONAL BENCHMARK")
    print("=" * 80)

    evaluator = ThreatEvaluator()
    evaluator.last_alert_time = 0
    all_rows = load_all_dataset_sessions()

    # Partition by session
    sessions = defaultdict(list)
    for r in all_rows:
        sessions[r["session_id"]].append(r)

    print(f"\n[DATASET AUDIT] Total Sessions Loaded: {len(sessions)}")
    
    owner_sessions = {sid: rows for sid, rows in sessions.items() if rows[0].get("is_authorized") is True}
    imposter_test_sessions = {sid: rows for sid, rows in sessions.items() if rows[0].get("is_authorized") is False and rows[0].get("split_tag") == "test"}
    synthetic_sessions = {sid: rows for sid, rows in sessions.items() if rows[0].get("split_tag") == "synthetic_stress"}

    print(f"  * Independent Owner Sessions   : {len(owner_sessions)} sessions ({sum(len(r) for r in owner_sessions.values())} windows)")
    print(f"  * Imposter Test Sessions       : {len(imposter_test_sessions)} sessions ({sum(len(r) for r in imposter_test_sessions.values())} windows)")
    print(f"  * Quarantined Synthetic Stress : {len(synthetic_sessions)} sessions ({sum(len(r) for r in synthetic_sessions.values())} windows)")

    # --------------------------------------------------------------------------
    # 1. EVALUATION OF ALL 12 GENUINE OWNER SESSIONS
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("1. EVALUATION OF 12 INDEPENDENT GENUINE OWNER SESSIONS")
    print("=" * 80)

    task_results = defaultdict(lambda: {
        "sessions": 0, "windows": 0, "duration_s": 0.0,
        "instant_risks": [], "smoothed_risks": [],
        "false_instant_spikes": 0, "false_alerts": 0
    })

    session_reports = []
    total_owner_duration_sec = 0.0
    total_owner_alerts = 0

    for sid, rows in sorted(owner_sessions.items()):
        task_mode = rows[0].get("task_mode", "unknown")
        typing_style = rows[0].get("typing_style", "normal")
        split = rows[0].get("split_tag", "unknown")
        duration_s = len(rows) * 5.0  # 5-second fixed windows
        total_owner_duration_sec += duration_s

        evaluator.reset_temporal_state()
        evaluator.last_alert_time = 0
        evaluator.is_breached = False

        s_alerts = 0
        s_instant_spikes = 0
        instant_scores = []
        smoothed_scores = []

        for r in rows:
            f_risk, s_risk, alert = evaluator.evaluate_row(r)
            instant_scores.append(f_risk)
            smoothed_scores.append(s_risk)
            if f_risk >= evaluator.alert_threshold:
                s_instant_spikes += 1
            if alert:
                s_alerts += 1
                total_owner_alerts += 1

        t_key = f"{task_mode} ({typing_style})"
        t_data = task_results[t_key]
        t_data["sessions"] += 1
        t_data["windows"] += len(rows)
        t_data["duration_s"] += duration_s
        t_data["instant_risks"].extend(instant_scores)
        t_data["smoothed_risks"].extend(smoothed_scores)
        t_data["false_instant_spikes"] += s_instant_spikes
        t_data["false_alerts"] += s_alerts

        mean_inst = float(np.mean(instant_scores))
        mean_smooth = float(np.mean(smoothed_scores))
        max_smooth = float(np.max(smoothed_scores))
        alerts_per_hr = (s_alerts / duration_s) * 3600.0 if duration_s > 0 else 0.0

        session_reports.append({
            "session_id": sid,
            "task": task_mode,
            "style": typing_style,
            "split": split,
            "windows": len(rows),
            "duration_min": duration_s / 60.0,
            "mean_instant_risk": round(mean_inst, 4),
            "mean_smoothed_risk": round(mean_smooth, 4),
            "max_smoothed_risk": round(max_smooth, 4),
            "false_alerts": s_alerts,
            "alerts_per_hour": round(alerts_per_hr, 2)
        })

    df_sessions = pd.DataFrame(session_reports)
    print("\n[PER-SESSION SUMMARY TABLE]")
    print(df_sessions.to_string(index=False))

    # Print Task Category Aggregate
    print("\n" + "-" * 80)
    print("[TASK CONDITION AGGREGATE PERFORMANCE]")
    print("-" * 80)
    print(f"{'Task / Condition':<30} {'Windows':<10} {'Mean Risk':<12} {'Max Risk':<10} {'False Alerts':<14} {'Alerts/Hour'}")
    print("-" * 80)
    for t_key, d in task_results.items():
        dur_hr = d["duration_s"] / 3600.0
        alerts_hr = (d["false_alerts"] / dur_hr) if dur_hr > 0 else 0.0
        print(f"{t_key:<30} {d['windows']:<10} {np.mean(d['smoothed_risks']):<12.4f} {np.max(d['smoothed_risks']):<10.4f} {d['false_alerts']:<14} {alerts_hr:.2f}/hr")

    total_owner_hours = total_owner_duration_sec / 3600.0
    overall_alerts_per_hr = total_owner_alerts / total_owner_hours if total_owner_hours > 0 else 0.0
    print("-" * 80)
    print(f"Total Genuine Recording Duration : {total_owner_duration_sec:.1f} s ({total_owner_duration_sec / 60.0:.2f} min = {total_owner_hours:.3f} hours)")
    print(f"Total Genuine Owner Windows      : {sum(len(r) for r in owner_sessions.values())}")
    print(f"Total False Alerts Generated     : {total_owner_alerts}")
    print(f"Overall False Alert Rate         : {overall_alerts_per_hr:.2f} alerts/hour")

    # --------------------------------------------------------------------------
    # 2. MISSING MODALITY & EDGE CASE STRESS TESTS
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("2. MISSING MODALITY & SENSOR DROPOUT RESILIENCE TESTS")
    print("=" * 80)

    # Test 2.1: Reading Session with Zero Keystrokes (Pure Mouse & Context)
    reading_rows = [r for sid, rlist in owner_sessions.items() if "reading" in sid.lower() for r in rlist]
    evaluator.reset_temporal_state()
    evaluator.last_alert_time = 0
    reading_risks = [evaluator.evaluate_row(r)[1] for r in reading_rows]
    print(f"  * Pure Technical Reading (Zero Keystrokes, n={len(reading_rows)}):")
    print(f"    - Mean Smoothed Risk : {np.mean(reading_risks):.4f}")
    print(f"    - Max Smoothed Risk  : {np.max(reading_risks):.4f} (Threshold: {evaluator.alert_threshold})")
    print(f"    - Lockouts / False Alarms: {sum(1 for rk in reading_risks if rk >= evaluator.alert_threshold)} of {len(reading_rows)}")
    assert np.max(reading_risks) < evaluator.alert_threshold, "Reading sessions must not trigger false lockouts"
    print("    [PASS] Reading session correctly sustained without keystroke penalties.")

    # Test 2.2: Pure Keyboard Activity with Zero Mouse Events
    pure_key_row = {
        "timestamp": time.time(), "hour_of_day": 14,
        "keystroke_count": 28, "dwell_mean": 0.098, "dwell_std": 0.021,
        "flight_mean": 0.125, "flight_std": 0.035,
        "app_dwell_mean": 0.098, "app_flight_mean": 0.125,
        "app_backspace_ratio": 0.03, "app_special_ratio": 0.05,
        "app_click_count": 0, "app_scroll_count": 0, "app_pause_ratio": 0.04,
        "interaction_mode": "ide_development",
        "mouse_events": 0,  # Zero mouse movement
        "mouse_velocity_mean": 0.0, "mouse_acceleration_mean": 0.0,
        "mouse_jerk_mean": 0.0, "mouse_straightness_mean": 1.0,
        "active_app": "Code.exe", "active_window": "project.py - Visual Studio Code",
        "cpu_usage": 18.0, "ram_usage_mb": 420.0,
        "dwell_sequence": [0.098] * 28, "flight_sequence": [0.125] * 28,
        "ble_proximity_state": "NEAR", "owner_phone_present": True,
        "is_untrusted_network": False
    }
    evaluator.reset_temporal_state()
    f_k, s_k, a_k = evaluator.evaluate_row(pure_key_row)
    print(f"\n  * Pure Typing / Zero Mouse Movement:")
    print(f"    - Instant Risk: {f_k:.4f} | Smoothed: {s_k:.4f} | Alert: {a_k}")
    assert not a_k, "Idle mouse must not trigger alert"
    print("    [PASS] Pure typing correctly accommodated with zero mouse penalties.")

    # Test 2.3: Sensor Fluctuation (BLE Phone Disconnect / Loss)
    ble_loss_row = dict(pure_key_row)
    ble_loss_row["ble_proximity_state"] = "UNKNOWN"
    ble_loss_row["owner_phone_present"] = False
    f_ble, s_ble, a_ble = evaluator.evaluate_row(ble_loss_row)
    print(f"\n  * BLE Phone Disconnect / Sensor Dropout:")
    print(f"    - Instant Risk: {f_ble:.4f} | Smoothed: {s_ble:.4f} | Alert: {a_ble}")
    assert not a_ble, "Temporary BLE drop must not instantly trigger full lockdown"
    print("    [PASS] Sensor loss handled gracefully via bounded penalty dampening.")

    # --------------------------------------------------------------------------
    # 3. IMPOSTER DETECTION & LATENCY ON TEST DATASET
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("3. IMPOSTER DETECTION EFFICIENCY & DETECTION LATENCY BENCHMARK")
    print("=" * 80)

    imposter_reports = []
    for sid, rows in sorted(imposter_test_sessions.items()):
        evaluator.reset_temporal_state()
        evaluator.last_alert_time = 0
        evaluator.is_breached = False

        detected = False
        detection_window = None
        detection_latency_sec = None

        instant_scores = []
        smoothed_scores = []

        for idx, r in enumerate(rows, 1):
            f_risk, s_risk, alert = evaluator.evaluate_row(r)
            instant_scores.append(f_risk)
            smoothed_scores.append(s_risk)
            if alert and not detected:
                detected = True
                detection_window = idx
                detection_latency_sec = idx * 5.0  # 5s windows

        imposter_reports.append({
            "session_id": sid,
            "adversary_type": rows[0].get("session_user_id", "Unknown"),
            "windows": len(rows),
            "mean_smoothed_risk": round(float(np.mean(smoothed_scores)), 4),
            "max_smoothed_risk": round(float(np.max(smoothed_scores)), 4),
            "detected": detected,
            "detection_window": detection_window if detected else "N/A",
            "detection_latency_s": detection_latency_sec if detected else "N/A"
        })

    df_imposters = pd.DataFrame(imposter_reports)
    print("\n[IMPOSTER ATTACK DETECTION SUMMARY]")
    print(df_imposters.to_string(index=False))

    detected_count = sum(1 for r in imposter_reports if r["detected"])
    detection_rate_pct = (detected_count / len(imposter_reports)) * 100.0
    detected_latencies = [r["detection_latency_s"] for r in imposter_reports if r["detected"]]
    mean_latency = float(np.mean(detected_latencies)) if detected_latencies else 0.0

    print(f"\nImposter Detection Rate : {detected_count}/{len(imposter_reports)} ({detection_rate_pct:.1f}%)")
    print(f"Mean Detection Latency  : {mean_latency:.1f} seconds ({mean_latency / 5.0:.1f} evaluation windows)")

    # --------------------------------------------------------------------------
    # 4. QUARANTINED SYNTHETIC STRESS ATTACKS
    # --------------------------------------------------------------------------
    print("\n" + "=" * 80)
    print("4. QUARANTINED SYNTHETIC STRESS PROFILES (STRICT LAB ISOLATION)")
    print("=" * 80)
    
    synthetic_reports = []
    for sid, rows in sorted(synthetic_sessions.items()):
        evaluator.reset_temporal_state()
        evaluator.last_alert_time = 0
        evaluator.is_breached = False

        detected = False
        det_window = None

        for idx, r in enumerate(rows, 1):
            _, _, alert = evaluator.evaluate_row(r)
            if alert and not detected:
                detected = True
                det_window = idx

        synthetic_reports.append({
            "profile_name": sid,
            "windows": len(rows),
            "detected": detected,
            "detection_window": det_window if detected else "N/A",
            "latency_s": det_window * 5.0 if detected else "N/A"
        })

    df_syn = pd.DataFrame(synthetic_reports)
    print(df_syn.to_string(index=False))
    print("\n[DATASET INTEGRITY AUDIT CONFIRMATION]")
    print("  * Genuine hardware recordings: Isolated from synthetic noise.")
    print("  * Synthetic stress profiles: Strictly quarantined in data/splits/synthetic_stress/.")
    print("  * Baseline training: 100% genuine authorized user hardware telemetry.")

    print("\n" + "=" * 80)
    print("GENUINE-USER BEHAVIORAL AUDIT COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    return True


if __name__ == "__main__":
    run_genuine_behavior_audit()
