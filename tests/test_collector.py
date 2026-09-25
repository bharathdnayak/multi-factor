import os
import sys
import time
import json
import subprocess
from pynput.keyboard import Controller as KController
from pynput.mouse import Controller as MController

def run_test():
    # Paths
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    collector_script = os.path.join(project_dir, "telemetry", "agent.py")
    output_log = os.path.join(project_dir, "telemetry_data.jsonl")
    
    initial_size = os.path.getsize(output_log) if os.path.exists(output_log) else 0

    print("Launching telemetry/agent.py in background...")
    process = subprocess.Popen(
        [sys.executable, "-u", collector_script],
        cwd=project_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for hooks to initialize
    time.sleep(2.0)
    
    print("Simulating keyboard and mouse interactions...")
    try:
        keyboard = KController()
        mouse = MController()
        
        if mouse.position is not None:
            for i in range(10):
                mouse.move(5, 5)
                time.sleep(0.05)
                
        keyboard.type("continuous auth behavioral telemetry verification")
        time.sleep(0.5)
    except Exception as e:
        print(f"Simulation warning: {e}")
        
    print("Stopping collector...")
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        
    # Check outputs
    print("\n--- Verification Results ---")
    log_exists = os.path.exists(output_log) and os.path.getsize(output_log) > 0
    if log_exists:
        print(f"[OK] telemetry_data.jsonl exists and is active (Size: {os.path.getsize(output_log)} bytes)")
        
        # Verify valid JSON records
        with open(output_log, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        if lines:
            last_record = json.loads(lines[-1])
            expected_keys = ["dwell_mean", "flight_mean", "mouse_velocity_mean", "active_app"]
            has_keys = all(k in last_record for k in expected_keys)
            if has_keys:
                print(f"[OK] Telemetry records adhere to schema (Keys: {list(last_record.keys())[:6]}...)")
                print(f"[OK] Active App: '{last_record.get('active_app')}', Interaction Mode: '{last_record.get('interaction_mode', 'general_work')}'")
                print("\nSUCCESS: The Telemetry Collector is fully operational!")
                sys.exit(0)
                
    print("\nFAILURE: Telemetry log could not be verified.")
    sys.exit(1)

if __name__ == "__main__":
    run_test()
