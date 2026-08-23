# Testing Procedure - Chirag

Hello Chirag! This is the ultimate step-by-step guide to run, test, and verify our **Continuous Authentication and Active Deception Security System**. 

We wrote this guide so that it is super simple to follow. Each member's task (Members 1, 2, 3, and 4) has its own clear testing steps and expectations!

---

## 🛠️ Step 0: Get Things Ready (Install Python Stuff)
Before we run anything, we need to download the Python code libraries that make this project run.
1. Open your Command Prompt (CMD) in the project directory.
2. Run this command:
   ```bash
   pip install -r requirements.txt
   ```
3. **Verify:** Check that the installation finishes successfully without errors.

---

## 👁️ Member 1: Test "The Spy" (Telemetry Hook Agent)
*This part captures how you interact with the computer (how fast you type and move the mouse) and writes it into a file.*

### How to Test:
1. Open a Command Prompt in the project folder and run:
   ```bash
   python telemetry/agent.py
   ```
2. Keep this window open. Now, move your mouse around and type some random words in any application (like Notepad or VS Code) for 15 seconds.
3. Check the command window. You will see lines starting with `[TELEMETRY]` printing out every 10 seconds!
4. Close the command window using `Ctrl + C` or by clicking the **X** button.

### What to Look For:
Open the newly created file named **`telemetry_data.jsonl`** in Notepad. You will see JSON data packets like this:
* `"dwell_mean"`: The average time you hold keys down (in seconds).
* `"flight_mean"`: The average time between key presses.
* `"mouse_velocity_mean"`: How fast you move the mouse cursor.
* `"active_app"`: The name of the window program you are currently using (e.g., `chrome.exe`).
* `"cpu_usage"`: The CPU usage of the active process.

---

## 🧠 Member 2: Test "The Brain" (Machine Learning Models)
*This part takes your baseline telemetry stats and teaches the models (One-Class SVM, Isolation Forest, and PyTorch 1D-CNN) what is "normal" for the owner.*

### How to Test:
1. Run the model simulation trainer script:
   ```bash
   python ml_engine/train.py --simulate
   ```
2. **Verify:** Confirm that a file named **`ml_engine/trained_models.pkl`** and a chart named **`model_performance.png`** are created in your folder.
3. Run the automated model separation verifier:
   ```bash
   python tests/verify_models.py
   ```

### What to Look For:
The verification script will print out scores for the Owner and an Imposter:
* **Owner Biometric Risk:** Should be low (**~0.0 to 0.2**).
* **Imposter Biometric Risk:** Should be high (**~0.8 to 1.0**).
* You should see **`ALL VERIFICATIONS PASSED SUCCESSFULLY!`** printed at the bottom. This means the model successfully tells the difference between the real user and an intruder!

---

## 🛡️ Member 3: Test "The Guard" (Threat Evaluation & Alerts)
*This part calculates threat scores based on the ML models, runs a 30-second moving average to smooth out false alarms, snaps an intruder photo, and sends an OTP.*

### How to Test:
1. We will run the automated security pipeline tests to simulate an intrusion breach:
   ```bash
   python tests/test_member3_pipeline.py
   ```

### What to Look For:
Look at the logs printed in your command window:
* First, it feeds normal records. The risk stays `0.0000`.
* Next, it feeds anomalous (imposter) records. 
* The first imposter row does *not* trigger an alert (this proves the 30-second moving average is smoothing out false alarms!).
* The second imposter row crosses the risk threshold, and you will see:
  * `[ALERT] BEHAVIORAL DRIFT BREACH DETECTED!`
  * `[WEBCAM] Forensic frame saved to 'data/forensics/intruder_*.jpg'` (Silent webcam snapshot).
  * `[OTP] Generated default configuration template` and generated code.

---

## 🎭 Member 4: Test "The Deceiver" (Lock Screen & Honey-Desktop)
*This is the interactive UI. If an intruder is detected, it locks the screen with a PyQt6 lock prompt. If bypassed or failed, it locks the attacker in a simulated fake desktop (Honeypot) that diverts all file writes safely.*

### How to Test the Deception Flow:

#### 1. Launch the Live System
Double-click the file **`run_security_system.bat`** in the project folder. This opens two CMD windows:
* One running the Telemetry hook.
* One running the Threat Evaluator watcher daemon.

#### 2. Trigger the Breach
To trigger the lock screen, act like an intruder for 30 seconds:
1. Open a terminal (like `cmd.exe` or `powershell.exe`) and type inside it.
2. Shake the mouse cursor vigorously in quick, jittery zig-zag lines.
3. The **Threat Evaluator Daemon** CMD window will show the risk scores spiking up.
4. **Active Alert:** Your webcam light will flash briefly, and a full-screen, borderless dark **Security Lock Screen** will overlay your desktop.

#### 3. Test the Owner Unlock (OTP Verification)
1. Open the file `models/.active_otp` in Notepad to see the generated 6-digit PIN.
2. Enter the PIN in the lock screen and click **Verify & Unlock**.
3. **Verify:** The lock screen will show a success message, adapt/retrain the models in the background, and return you safely to your normal desktop.

#### 4. Test the Honeypot Container (Deceive the Attacker)
1. Trigger the lock screen again.
2. Enter a wrong PIN 3 times (or click **Bypass Prompt**).
3. **Verify:** The lock screen will disappear, and the **Honeypot Desktop** overlay will open, showing decoy icons (My Documents, Secret Passwords) and an open command terminal (**Honey-Shell**).
4. **Test Command Interception:** Inside the mock Command Prompt, run commands:
   * Type `dir` to see mock secret files.
   * Type `type confidential_passwords.txt` to see decoy admin credentials.
   * Type `ipconfig` to see mock subnet profiles.
5. **Test Sandboxed File Writes:** Type this file-creation command:
   ```cmd
   echo "malicious payload" > malware.exe
   ```
6. Type `dir` again. You will see `malware.exe` appears in the listing.
7. Open the folder **`data/sandbox/`** on your real computer. You will see `malware.exe` was safely created inside this isolated folder, preventing any modifications to your real operating system!

#### 5. Test Forensic Recovery & Dashboard
1. While trapped inside the Honeypot Desktop, press this global hotkey combination:
   ```
   Ctrl + Alt + Shift + U
   ```
2. **Verify:** A verification window will pop up over the honeypot.
3. Enter the correct OTP code (from `models/.active_otp`).
4. **Verify:** The honeypot desktop will close, and the **Forensic Recovery Dashboard** will launch!
5. Check the dashboard layout:
   * **Left Panel:** Displays the captured picture of the intruder taken by the webcam, and a list of files modified by the attacker in the sandbox.
   * **Right Panel:** Displays the exact command logs of what the intruder typed inside the mock command shell.
   * Click **Close and Resume Session** to return back to your computer.

---

*Now you have tested the entire Member 1-4 pipeline! Everything is working successfully.*
