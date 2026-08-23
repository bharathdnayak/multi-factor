# Testing Procedure Chirag

This guide outlines the step-by-step testing sequence to verify that all behavioral authentication, alerting, and active deception layers are functioning correctly on your Windows system.

---

## Step 1: Initialize the Baseline Models
Before running the live monitors, we must serialize a set of trained model weights. 
Open your Command Prompt or PowerShell in the project root directory and run:
```bash
python ml_engine/train.py --simulate
```
* **What this does:** Processes simulated telemetry data, auto-calibrates risk thresholds, and saves `ml_engine/trained_models.pkl` and a slide-ready separation plot `model_performance.png`.

---

## Step 2: Launch the Security Core
Double-click the **`run_security_system.bat`** file in the project folder. 
This will automatically launch two separate Command Prompt windows:
1. **Behavioral Telemetry Agent:** Hooks keyboard and mouse queues to log user dynamics.
2. **Threat Evaluator Daemon:** Tails the active telemetry logs in the background and scores them.

---

## Step 3: Observe Normal Activity (Low Risk)
Work normally on your computer for 30–40 seconds (type some text or move the mouse gently).
Observe the output in the **Threat Evaluator Daemon** command window. It will display a score update every 10 seconds:
* **Biometric & Context Risk:** Should remain very low (**~0.0 to 0.2**)
* **Confidence Rating:** Should remain high (**~0.80 to 1.0**)
* The session remains unlocked.

---

## Step 4: Simulate an Anomaly (Trigger Breach)
To test the detection threshold, simulate an unauthorized intruder session:
1. Move the mouse in rapid, jittery, erratic trajectories for 20-30 seconds.
2. Open a forbidden console window (like `cmd.exe` or `powershell.exe`) and type inside it.
3. Because the Isolation Forest expects standard developer windows (VS Code, browsers) and the SVM expects normal typing latencies, the anomaly rate will spike.

---

## Step 5: Verify Active Response Measures
As soon as the 30-second moving average risk crosses the threshold (`0.75`):
1. **Webcam Capture:** Your webcam LED will flicker briefly. The system silently captures your photo, runs frontal face detection, and saves the image to `data/forensics/intruder_*.jpg`.
2. **System Lock Screen:** A borderless, full-screen dark window blocks the screen, locking user input and demanding a 6-digit OTP code.

---

## Step 6: Test the Deception & Verification Channels

### Pathway A: Owner OTP Verification (Success Case)
1. Since email configurations are default templates, open `models/.active_otp` in Notepad to see the generated PIN.
2. Enter the PIN on the lock screen and click **Verify & Unlock**.
3. **Result:** The lock screen closes, triggers behavioral drift adaptation, and restores your session!

### Pathway B: Honeypot Deception Containment (Failure Case)
1. Trigger a breach again to display the lock screen.
2. Click the **Bypass Prompt** button or enter a wrong PIN 3 times.
3. **Result:** The lock screen closes and spawns the **Honeypot Desktop** overlay.
4. **Interact with the Shell:** Type commands in the mock cmd shell (e.g. `dir`, `ipconfig`, `whoami`).
5. **Sandbox Verification:** Type `echo "malicious payload" > exploit.txt`. Check your `data/sandbox/` folder on your real machine. You will see `exploit.txt` was safely redirected to the sandbox folder, protecting your real desktop!

### Pathway C: Forensic Analysis Recovery (Admin Bypass)
1. While trapped in the Honeypot Desktop, press the global bypass hotkey:
   `Ctrl + Alt + Shift + U`
2. An OTP verification dialog will pop up. Enter the active OTP from `models/.active_otp`.
3. **Result:** The deception desktop closes, and the **Forensic Recovery Dashboard** opens, showing the intruder's photo, logged command inputs, and sandboxed files!
