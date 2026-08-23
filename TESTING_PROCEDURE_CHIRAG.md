# Testing Procedure - Chirag

This document provides a step-by-step guide to run, test, and verify the Multi-Factor Behavioral Drift Security system live on your local machine. Follow these instructions one-by-one to test all of the current features.

---

## Prerequisites
Ensure the dependencies are installed. Open a terminal in the project directory and run:
```bash
pip install -r requirements.txt
```

---

## Step 1: Initialize the Machine Learning Models
Before running the active monitors, you must generate a baseline model checkpoint:
1. Open your terminal in the project directory.
2. Run the simulation training script:
   ```bash
   python ml_engine/train.py --simulate
   ```
3. **Verify:** Confirm that `ml_engine/trained_models.pkl` and `model_performance.png` are created in the folder.

---

## Step 2: Start the Monitoring System
1. Double-click the file **`run_security_system.bat`** in the project root folder.
2. **Verify:** Two command prompt windows should open in parallel:
   * **Behavioral Telemetry Agent:** Hooking inputs and logging window context.
   * **Threat Evaluator Daemon:** Actively watching logs and scoring risks.

---

## Step 3: Test Normal Session (Low Risk)
1. Keep typing normally or move your mouse gently for 30 seconds.
2. **Verify:** Check the **Threat Evaluator Daemon** command prompt window. It should output risk scores every 10 seconds:
   * Biometric and Context Risk should remain low (**~0.0 to 0.2**).
   * Confidence ratings should remain high (**~0.8 to 1.0**).
   * No alerts or locks should trigger.

---

## Step 4: Simulate an Intruder (Trigger Anomaly)
Now, simulate unauthorized/erratic behavior for 30 seconds:
1. Shake the mouse cursor vigorously in quick, jittery curves.
2. Open a standard terminal program (like `cmd.exe` or `powershell.exe`) and type keys inside it.
3. **Verify:** In the **Threat Evaluator Daemon** window, the Risk scores will spike, and the 30-second moving average will begin rising.

---

## Step 5: Verify Active Threat Responses
Once the smoothed risk average crosses the threat threshold (`0.75`):
1. **Webcam Grabber:** The webcam indicator LED will flicker briefly. Check `data/forensics/`—a JPEG containing the captured photo of the "intruder" will be saved.
2. **Verification Lock Screen:** A borderless full-screen dark prompt will block the monitor, locking input focus and requesting a 6-digit OTP code.

---

## Step 6: Test Unlock & Deception Containment

### Option A: Verification and Restore (Owner Path)
1. Open the file `models/.active_otp` in notepad to read the 6-digit OTP generated for this breach.
2. Type the OTP code into the full-screen prompt and click **Verify & Unlock**.
3. **Verify:** The lock screen should exit, retrain the model to adapt to the behavioral drift, and restore standard desktop access.

### Option B: Honeypot Deception (Attacker Path)
1. Trigger a breach again to display the lock prompt.
2. Enter an incorrect code 3 times (or click **Bypass Prompt**).
3. **Verify:** The lock screen closes and spawns the **Honeypot Desktop** overlay.
4. **Mock Shell Check:** Inside the mock Command Prompt, run commands: `dir`, `ipconfig`, `whoami`, or write a file: `echo "malware" > hack.exe`.
5. **Sandbox Check:** Open `data/sandbox/` on your real desktop. You should find `hack.exe` was safely diverted to this sandboxed folder, keeping your filesystem protected.

---

## Step 7: Test Forensic Recovery Dashboard
1. While trapped in the **Honeypot Desktop**, press the global hotkey:
   ```
   Ctrl + Alt + Shift + U
   ```
2. **Verify:** An OTP verification prompt will pop up over the honeypot.
3. Enter the correct OTP code (from `models/.active_otp`).
4. **Verify:** The honeypot desktop closes and launches the **Forensic Recovery Dashboard** displaying:
   * The captured intruder photo.
   * The exact commands typed by the attacker in the mock shell.
   * The list of files created in the sandbox directory.
