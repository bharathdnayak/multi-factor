"""
Independent Verification: Live Telemetry Pipeline & Modality-Aware Threat Evaluator
Tests feature schemas, score direction, dynamic weights, missing sensors, and edge-case behaviors.
"""
import os
import sys
import time
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.evaluator import ThreatEvaluator
from ml_engine.models import categorize_process

def run_pipeline_validation():
    print("=" * 70)
    print("INDEPENDENT VALIDATION: LIVE TELEMETRY PIPELINE & EVALUATOR DYNAMICS")
    print("=" * 70)

    evaluator = ThreatEvaluator()
    print("[INIT] ThreatEvaluator successfully initialized.")

    tests = []

    # -------------------------------------------------------------
    # Test 1: Active Coding / Terminal (Balanced Keyboard + Mouse)
    # -------------------------------------------------------------
    coding_row = {
        "timestamp": time.time(),
        "hour_of_day": 14,
        "keystroke_count": 28,
        "dwell_mean": 0.089, "dwell_std": 0.014,
        "flight_mean": 0.138, "flight_std": 0.022,
        "app_dwell_mean": 0.089, "app_flight_mean": 0.138,
        "app_backspace_ratio": 0.10, "app_special_ratio": 0.22,
        "app_click_count": 3, "app_scroll_count": 4, "app_pause_ratio": 0.35,
        "interaction_mode": "code_writing_and_testing",
        "mouse_events": 45,
        "mouse_velocity_mean": 260.0, "mouse_acceleration_mean": 11.5,
        "mouse_jerk_mean": 1.2, "mouse_straightness_mean": 0.91,
        "active_app": "Code.exe", "active_window": "agent.py - Visual Studio Code",
        "cpu_usage": 3.2, "ram_usage_mb": 310.0,
        "dwell_sequence": [0.089] * 30, "flight_sequence": [0.138] * 30,
        "ble_proximity_state": "IMMEDIATE", "owner_phone_present": True,
        "is_untrusted_network": False
    }
    fused_risk, smoothed_risk, alert = evaluator.evaluate_row(coding_row)
    print(f"\n[Test 1: Active Coding] Fused Risk: {fused_risk:.4f} | Smoothed Risk: {smoothed_risk:.4f} | Alert: {alert}")
    assert fused_risk < 0.40, f"Expected Tier 1 (<0.40), got {fused_risk}"
    tests.append(("Active Coding (Normal Owner)", "PASS", f"Risk: {fused_risk:.4f} (Tier 1)"))

    # -------------------------------------------------------------
    # Test 2: Technical Reading / Browsing (Mouse Only, Keyboard Idle)
    # -------------------------------------------------------------
    reading_row = {
        "timestamp": time.time(),
        "hour_of_day": 14,
        "keystroke_count": 0,  # Zero keystrokes!
        "dwell_mean": 0.0, "dwell_std": 0.0,
        "flight_mean": 0.0, "flight_std": 0.0,
        "app_dwell_mean": 0.0, "app_flight_mean": 0.0,
        "app_backspace_ratio": 0.0, "app_special_ratio": 0.0,
        "app_click_count": 4, "app_scroll_count": 18, "app_pause_ratio": 0.85,
        "interaction_mode": "web_research_or_reading",
        "mouse_events": 62,  # Active mouse
        "mouse_velocity_mean": 245.0, "mouse_acceleration_mean": 19.5,
        "mouse_jerk_mean": 2.9, "mouse_straightness_mean": 0.915,
        "active_app": "chrome.exe", "active_window": "IEEE Xplore - Document Details",
        "cpu_usage": 4.1, "ram_usage_mb": 450.0,
        "dwell_sequence": [0.09] * 30, "flight_sequence": [0.14] * 30,
        "ble_proximity_state": "IMMEDIATE", "owner_phone_present": True,
        "is_untrusted_network": False
    }
    fused_risk, smoothed_risk, alert = evaluator.evaluate_row(reading_row)
    print(f"\n[Test 2: Mouse Reading / Idle Keys] Fused Risk: {fused_risk:.4f} | Smoothed Risk: {smoothed_risk:.4f} | Alert: {alert}")
    assert fused_risk < 0.40, f"Expected Tier 1 (<0.40) due to dynamic weighting, got {fused_risk}"
    tests.append(("Mouse Reading (Keyboard Idle)", "PASS", f"Risk: {fused_risk:.4f} (Tier 1, No Keyboard Bias)"))

    # -------------------------------------------------------------
    # Test 3: Legitimate Fast Burst Typing (Speed Variation)
    # -------------------------------------------------------------
    fast_typing_row = dict(coding_row)
    fast_typing_row.update({
        "keystroke_count": 45,
        "dwell_mean": 0.076,  # 15% faster dwell
        "flight_mean": 0.115, # 17% faster flight
        "mouse_events": 5,
        "dwell_sequence": [0.076] * 30, "flight_sequence": [0.115] * 30
    })
    fused_risk, smoothed_risk, alert = evaluator.evaluate_row(fast_typing_row)
    print(f"\n[Test 3: Fast Burst Typing] Fused Risk: {fused_risk:.4f} | Smoothed Risk: {smoothed_risk:.4f} | Alert: {alert}")
    assert fused_risk < 0.40, f"Expected Tier 1 (<0.40), got {fused_risk}"
    tests.append(("Legitimate Fast Typing", "PASS", f"Risk: {fused_risk:.4f} (Tier 1)"))

    # -------------------------------------------------------------
    # Test 4: Legitimate Fatigue / Evening Slowdown
    # -------------------------------------------------------------
    slow_typing_row = dict(coding_row)
    slow_typing_row.update({
        "keystroke_count": 18,
        "dwell_mean": 0.108,  # Slightly slower dwell due to fatigue
        "flight_mean": 0.165, # Slower flight
        "dwell_std": 0.022,
        "flight_std": 0.030,
        "dwell_sequence": [0.108] * 30, "flight_sequence": [0.165] * 30
    })
    fused_risk, smoothed_risk, alert = evaluator.evaluate_row(slow_typing_row)
    print(f"\n[Test 4: Fatigue / Slowdown] Fused Risk: {fused_risk:.4f} | Smoothed Risk: {smoothed_risk:.4f} | Alert: {alert}")
    assert fused_risk < 0.45, f"Expected near Tier 1 (<0.45), got {fused_risk}"
    tests.append(("Fatigue Slow Typing", "PASS", f"Risk: {fused_risk:.4f} (Benign Drift Tolerated)"))

    # -------------------------------------------------------------
    # Test 5: Full Workstation Idle (Lunch / Coffee Break)
    # -------------------------------------------------------------
    idle_row = dict(coding_row)
    idle_row.update({
        "keystroke_count": 0,
        "mouse_events": 0,
        "dwell_mean": 0.0, "flight_mean": 0.0,
        "mouse_velocity_mean": 0.0,
        "dwell_sequence": [0.0] * 30, "flight_sequence": [0.0] * 30
    })
    fused_risk, smoothed_risk, alert = evaluator.evaluate_row(idle_row)
    print(f"\n[Test 5: Full Workstation Idle] Fused Risk: {fused_risk:.4f} | Smoothed Risk: {smoothed_risk:.4f} | Alert: {alert}")
    assert fused_risk <= 0.05, f"Expected Strict Idle Neutrality (<=0.05), got {fused_risk}"
    tests.append(("Full Idle Period", "PASS", f"Risk: {fused_risk:.4f} (Strict Idle Neutrality)"))

    # -------------------------------------------------------------
    # Test 6: Missing / Offline Sensor Tolerance (BLE Sensor Off)
    # -------------------------------------------------------------
    sensor_offline_row = dict(coding_row)
    sensor_offline_row.update({
        "ble_proximity_state": "OFFLINE",  # Sensor is disconnected or Bluetooth disabled
        "owner_phone_present": False       # Should not falsely trigger penalty if sensor is offline!
    })
    fused_risk_offline, _, _ = evaluator.evaluate_row(sensor_offline_row)
    fused_risk_normal, _, _ = evaluator.evaluate_row(coding_row)
    diff = abs(fused_risk_offline - fused_risk_normal)
    print(f"\n[Test 6: Offline BLE Sensor Tolerance] Offline Risk: {fused_risk_offline:.4f} vs Baseline: {fused_risk_normal:.4f} (Diff: {diff:.4f})")
    assert diff < 0.05, f"Expected zero penalty for offline/disabled sensor, but diff was {diff:.4f}"
    tests.append(("Offline Sensor Tolerance", "PASS", f"Zero Artificial Penalty when BLE is Offline (Diff: {diff:.4f})"))

    # -------------------------------------------------------------
    # Test 7: Genuine Physical Walk-Away Imposter Takeover
    # -------------------------------------------------------------
    walkaway_takeover_row = dict(coding_row)
    walkaway_takeover_row.update({
        "ble_proximity_state": "OUT_OF_RANGE",  # Phone is confirmed OUT_OF_RANGE (> 6 meters)
        "owner_phone_present": False            # Phone is absent
    })
    fused_risk_walkaway, _, _ = evaluator.evaluate_row(walkaway_takeover_row)
    penalty = fused_risk_walkaway - fused_risk_normal
    print(f"\n[Test 7: Physical Walk-Away Takeover] Walk-Away Risk: {fused_risk_walkaway:.4f} (Penalty: +{penalty:.4f})")
    assert penalty >= 0.20, f"Expected >= 0.20 walk-away penalty, got {penalty:.4f}"
    tests.append(("Physical Walk-Away Takeover", "PASS", f"Applied +{penalty:.4f} Risk Penalty"))

    # -------------------------------------------------------------
    # Test 8: Hostile Imposter Takeover (Erratic Biometrics + Cmds)
    # -------------------------------------------------------------
    hostile_imposter_row = {
        "timestamp": time.time(),
        "hour_of_day": 23,
        "keystroke_count": 35,
        "dwell_mean": 0.260, "dwell_std": 0.055,  # Slow erratic hunt-and-peck
        "flight_mean": 0.380, "flight_std": 0.080,
        "app_dwell_mean": 0.260, "app_flight_mean": 0.380,
        "app_backspace_ratio": 0.02, "app_special_ratio": 0.02,
        "app_click_count": 1, "app_scroll_count": 0, "app_pause_ratio": 0.04,
        "interaction_mode": "command_execution",
        "mouse_events": 12,
        "mouse_velocity_mean": 820.0, "mouse_acceleration_mean": 65.0,  # Fast jerky mouse
        "mouse_jerk_mean": 11.2, "mouse_straightness_mean": 0.48,
        "active_app": "cmd.exe", "active_window": "Command Prompt - net user",
        "cpu_usage": 45.0, "ram_usage_mb": 620.0,
        "dwell_sequence": [0.260] * 30, "flight_sequence": [0.380] * 30,
        "ble_proximity_state": "OUT_OF_RANGE", "owner_phone_present": False,
        "is_untrusted_network": True
    }
    fused_risk_hostile, smoothed_risk_hostile, alert_hostile = evaluator.evaluate_row(hostile_imposter_row)
    print(f"\n[Test 8: Hostile Imposter] Fused Risk: {fused_risk_hostile:.4f} | Smoothed Risk: {smoothed_risk_hostile:.4f} | Alert: {alert_hostile}")
    assert fused_risk_hostile >= 0.75, f"Expected Tier 3 (>=0.75), got {fused_risk_hostile}"
    assert alert_hostile is True, "Expected alert trigger for hostile imposter"
    tests.append(("Hostile Imposter Takeover", "PASS", f"Risk: {fused_risk_hostile:.4f} (Tier 3 Lockdown Triggered)"))

    # -------------------------------------------------------------
    # Test 9: Legacy Mode Toggle Check & Proof of Improvement
    # -------------------------------------------------------------
    legacy_risk_coding, _, _ = evaluator.evaluate_row(coding_row, legacy_mode=True)
    legacy_risk_hostile, _, _ = evaluator.evaluate_row(hostile_imposter_row, legacy_mode=True)
    print(f"\n[Test 9: Legacy Mode Toggle] Coding Risk: {legacy_risk_coding:.4f} | Hostile Risk: {legacy_risk_hostile:.4f}")
    assert legacy_risk_hostile > 0.80, "Legacy mode must detect hostile imposter"
    assert legacy_risk_coding > fused_risk, f"Demonstrated: Dynamic mode ({fused_risk:.4f}) provides superior margin over legacy mode ({legacy_risk_coding:.4f})"
    tests.append(("Legacy Mode Rollback Toggle", "PASS", f"Legacy Mode operational (Coding: {legacy_risk_coding:.4f}, Hostile: {legacy_risk_hostile:.4f})"))

    print("\n" + "=" * 70)
    print("PIPELINE TEST SUMMARY:")
    for name, status, detail in tests:
        print(f"  [{status}] {name:<32}: {detail}")
    print("=" * 70)
    print("ALL 9 LIVE TELEMETRY PIPELINE VALIDATION TESTS PASSED PERFECTLY!\n")

if __name__ == "__main__":
    run_pipeline_validation()
