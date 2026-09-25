import os
import sys
import time
import json
import argparse

# Append project root directory to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.evaluator import ThreatEvaluator
from ml_engine.data_generator import generate_unauthorized_dataset

TYPOLOGY_NAMES = {
    0: "Frantic / Erratic Rapid Typist",
    1: "Sluggish Hunt-and-Peck Imposter",
    2: "Rogue System Context Attacker (cmd/powershell)",
    3: "Cross-User Cognitive Imposter (LeetCode Copy-Paster)"
}


def run_attack_simulation(dataset_file=None, count=5, delay=1.0, show_ui=True, pipe_to_daemon=False, typology=None):
    """
    Feeds unauthorized imposter telemetry into the Quad-Factor Continuous Authentication Evaluator.
    Demonstrates live intrusion detection, acute risk spikes, webcam capture, OTP dispatch,
    and automatic verification lock screen deployment.
    """
    print("=" * 75)
    print("      UNAUTHORIZED INTRUSION ATTACK & DETECTION SIMULATION")
    print("      Quad-Factor Continuous Authentication Security Engine")
    print("=" * 75)
    
    if dataset_file is None:
        dataset_file = os.path.join(PROJECT_ROOT, "data", "unauthorized_dataset.jsonl")
    elif not os.path.isabs(dataset_file):
        dataset_file = os.path.join(PROJECT_ROOT, dataset_file)
        
    if not os.path.exists(dataset_file):
        print(f"[INFO] Unauthorized dataset not found. Generating fresh attack dataset at '{dataset_file}'...")
        generate_unauthorized_dataset(output_file=dataset_file, num_samples=120, silent=False)
        
    # Load unauthorized rows
    rows = []
    with open(dataset_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
                    
    if not rows:
        print("[ERROR] No attack records could be loaded from dataset file.", file=sys.stderr)
        return False
        
    # Filter by typology if requested
    if typology is not None and typology != "all":
        typology_map = {
            "frantic": 0,
            "hunt_and_peck": 1,
            "rogue_process": 2,
            "cognitive_mismatch": 3
        }
        target_type = typology_map.get(typology.lower(), None)
        if target_type is not None:
            rows = [r for i, r in enumerate(rows) if i % 4 == target_type]
            print(f"[INFO] Filtered attack dataset to '{typology}' profile ({len(rows)} available records).")
            
    # Initialize the Live Threat Evaluator
    print("[INFO] Initializing Quad-Factor Threat Evaluator...")
    evaluator = ThreatEvaluator(threshold=0.55)
    
    print(f"\n[ATTACK] Streaming {count} unauthorized telemetry windows (Interval: {delay:.1f}s)...")
    print("-" * 75)
    
    breach_occurred = False
    telemetry_log_path = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    
    for step in range(min(count, len(rows))):
        attack_row = rows[step]
        typology_label = attack_row.get("typology_name", TYPOLOGY_NAMES.get(step % 4, "Unauthorized Intruder"))
        app_name = attack_row.get("active_app", "unknown")
        
        print(f"\n>> [WINDOW {step + 1}/{count}] Injecting: {typology_label} (App: {app_name})")
        
        # Optionally pipe into live telemetry log file for background daemon watchers
        if pipe_to_daemon:
            try:
                with open(telemetry_log_path, "a", encoding="utf-8") as tf:
                    tf.write(json.dumps(attack_row) + "\n")
            except Exception as e:
                print(f"[WARNING] Could not write to telemetry log: {e}", file=sys.stderr)
                
        # Evaluate row with Quad-Factor fusion
        f_risk, s_risk, triggered = evaluator.evaluate_row(attack_row)
        
        # Component factor breakdown
        try:
            svm_c, if_c = evaluator.models.score(attack_row)
            svdd_c = evaluator.evaluate_keystroke_sequence(attack_row)
            try:
                anomaly, _ = evaluator.controller.evaluate_telemetry_row(attack_row)
                ctrl_c = 1.0 - anomaly
            except Exception:
                ctrl_c = svm_c
        except Exception:
            svdd_c, svm_c, if_c, ctrl_c = 0.0, 0.0, 0.0, 0.0
            
        print(f"   Breakdown: Deep SVDD: {svdd_c:.2f} | OC-SVM: {svm_c:.2f} | IsoForest: {if_c:.2f} | Cognitive: {ctrl_c:.2f}")
        print(f"   Scoring:   Instant Risk = {f_risk:.4f} | Smoothed (30s) = {s_risk:.4f} (Alert Threshold: 0.55)")
        
        if f_risk >= 0.78:
            print("   Status:    >>> CRITICAL ANOMALY SPIKE DETECTED! <<<")
        elif f_risk >= 0.55:
            print("   Status:    [ELEVATED BEHAVIORAL DRIFT]")
        else:
            print("   Status:    [MONITORING]")
            
        if triggered:
            breach_occurred = True
            print("\n" + "=" * 75)
            print("   [CRITICAL BREACH] INTRUSION CONFIRMED! SYSTEM LOCKDOWN INITIATED")
            print("=" * 75)
            print(f"   Active OTP Code:         >>> {evaluator.active_otp} <<<")
            print(f"   Master Bypass Password:  >>> admin <<< (or 123456)")
            print("   Automated Responses:")
            print("     -> Webcam snapshot captured in data/forensics/")
            print("     -> Session OTP logged to models/.active_otp")
            print("     -> Verification lock screen triggered")
            print("=" * 75)
            
            if show_ui:
                print("\n[UI] Launching Verification Lock Screen on display...")
                print("[INFO] Enter the OTP above or 'admin' to unlock.")
                try:
                    from security.lock_handler import launch_verification_lock
                    launch_verification_lock(evaluator)
                except Exception as e:
                    print(f"[UI] [WARNING] Could not launch graphical lock screen: {e}")
            break
            
        time.sleep(delay)
        
    print("\n" + "-" * 75)
    if breach_occurred:
        print("[SUCCESS] Attack simulation successfully triggered the security breach pipeline!")
        return True
    else:
        print("[INFO] Attack simulation completed without triggering breach threshold.")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate Unauthorized Behavioral Intrusion Attack")
    parser.add_argument("--dataset", type=str, default=None, help="Path to unauthorized dataset JSONL file")
    parser.add_argument("--count", type=int, default=5, help="Number of unauthorized telemetry windows to inject (default: 5)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay in seconds between simulated windows (default: 1.0)")
    parser.add_argument("--typology", type=str, default="all", choices=["all", "frantic", "hunt_and_peck", "rogue_process", "cognitive_mismatch"], help="Specific intruder typology to simulate")
    parser.add_argument("--no-ui", action="store_true", help="Run in headless/console-only mode without opening full-screen PyQt6 lock UI")
    parser.add_argument("--pipe-to-daemon", action="store_true", help="Also append attack records to telemetry_data.jsonl for background daemons")
    args = parser.parse_args()

    run_attack_simulation(
        dataset_file=args.dataset,
        count=args.count,
        delay=args.delay,
        show_ui=not args.no_ui,
        pipe_to_daemon=args.pipe_to_daemon,
        typology=args.typology
    )
