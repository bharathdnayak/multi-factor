import os
import sys
import time
import subprocess
from pynput.keyboard import Controller as KController
from pynput.mouse import Controller as MController

def run_test():
    # Paths
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    collector_script = os.path.join(project_dir, "telemetry", "agent.py")
    raw_data_dir = os.path.join(project_dir, "data", "raw")
    
    # Clean previous test files if they exist
    for f in ["keystrokes.csv", "mouse.csv", "context.csv"]:
        path = os.path.join(raw_data_dir, f)
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass

    print("Launching telemetry/agent.py in background...")
    # Launch agent.py with unbuffered output (-u)
    process = subprocess.Popen(
        [sys.executable, "-u", collector_script],
        cwd=project_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for startup
    time.sleep(3.0)
    
    print("Simulating keyboard and mouse events...")
    try:
        keyboard = KController()
        mouse = MController()
        
        # Check if cursor position is available
        if mouse.position is not None:
            # Simulate mouse movement
            for i in range(10):
                mouse.move(5, 5)
                time.sleep(0.1)
        else:
            print("Note: Non-interactive session, skipping mouse movement simulation.")
            
        # Try to type
        keyboard.type("test")
        time.sleep(0.5)
    except Exception as e:
        print(f"Simulation warning: {e}. Running verification on files created...")
    
    print("Stopping collector...")
    process.terminate()
    try:
        process.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        process.kill()
        
    # Check outputs
    print("\n--- Verification Results ---")
    files_ok = True
    for f in ["keystrokes.csv", "mouse.csv", "context.csv"]:
        path = os.path.join(raw_data_dir, f)
        if os.path.exists(path):
            print(f"[OK] {f} was successfully generated (Size: {os.path.getsize(path)} bytes)")
        else:
            print(f"[FAIL] {f} is missing or empty!")
            files_ok = False
            
    if files_ok:
        print("\nSUCCESS: The Telemetry Collector has initialized all output logging files successfully!")
        sys.exit(0)
    else:
        print("\nFAILURE: One or more logging channels failed.")
        sys.exit(1)

if __name__ == "__main__":
    run_test()
