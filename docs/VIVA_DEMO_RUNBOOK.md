# Project Viva & Defense Demonstration Runbook

**Project Title:** Multi-Factor Behavioral Drift Continuous Authentication, Deception Simulation & Digital Forensics  
**Department:** Department of Information Science & Engineering (ISE)  
**Academic Target:** Final Project Viva, External Review Panel & Guide Evaluation  
**Presentation Strategy:** High-Reliability, Evidence-Backed, Live Interactive Demonstration  

---

## 1. Quick Pre-Flight Checklist (Run Before Evaluators Arrive)

Open PowerShell in the cloned project directory:
```powershell
cd "<path-to>\Behavioral-Drift-Security"
```

Execute the system doctor to verify environment readiness:
```powershell
.\bat\doctor.bat --no-pause
```
*Expected Output:* `[DOCTOR VERDICT] ALL CHECKS PASSED: System is operational.`

---

## 2. One-Click Coordinated Startup (`bat\VIVA_START.bat` / `bat\start_system.bat`)

Launch the coordinated Viva environment (pre-flight diagnostics + dedicated Supervisor/SOC terminal + readiness wait + 5-Stage Viva Runner):
```powershell
.\bat\VIVA_START.bat
```
*(Or launch only the production supervisor via `.\bat\start_system.bat` or double-click either `.bat` in Windows File Explorer.)*

### Immediate Observable State:
1. **Supervisor Console:** Shows 3 background workers running:
   - `Telemetry Sensor Agent` $\rightarrow$ PID `[ONLINE]`
   - `Threat Evaluator Daemon` $\rightarrow$ PID `[ONLINE]`
   - `Cyber-Ops Web Dashboard` $\rightarrow$ PID `[ONLINE]`
2. **Notification Tray:** A green security shield appears in the Windows taskbar.
3. **Web Browser:** Automatically opens to **`http://localhost:8000`**.

---

## 3. Step-by-Step Viva Demonstration Walkthrough

### Stage 1: Continuous Baseline Monitoring (Tier 1 Nominal)
- **Talking Point:** *"Our zero-trust system continuously monitors keystroke biometrics (dwell/flight times), mouse movement dynamics, and application context without recording sensitive keystrokes or disrupting the user."*
- **Action:**
  1. Open any application (e.g., VS Code or Notepad) and type normally for 15 seconds.
  2. Switch to the Web SOC console at `http://localhost:8000`.
- **Expected Observations:**
  - **Instant Risk:** Low ($\approx 0.05 - 0.22$, well below the 0.55 threshold).
  - **30s Smoothed Risk:** Low ($\approx 0.08 - 0.20$).
  - **Deep SVDD Embedding:** Displays `MATCH` in green with $\ge 95\%$ biometric confidence.
  - **System State Badge:** Displays `NORMAL` in emerald green.

---

### Stage 2: Simulated Imposter Intrusion (Tier 3 Acute Breach)
- **Talking Point:** *"When an unauthorized person takes over the workstation, their typing cadence and interaction kinematics deviate significantly from the registered baseline."*
- **Action:**
  1. On the Web SOC console, scroll to the bottom card: **Project Evaluation & Anomaly Simulation Control Center**.
  2. Click the **⚡ Acute Intrusion Spike** button (or **🐌 Sluggish Imposter Typing**).
- **Expected Observations:**
  - **Risk Trajectory Chart:** Spikes immediately into the critical red zone ($> 0.85$).
  - **Breach Alert Banner:** Flashes red across the top of the browser indicating breach status (`ACTIVE (CHECK ALERT)` without leaking plaintext OTP codes over the unauthenticated dashboard stream).
  - **Silent Optical Capture:** The webcam captures an intruder frame (`data/forensics/intruder_*.jpg`) and displays it in the forensics card.
  - **Telegram / Email Alert:** Live alerts are dispatched to the configured owner channel containing the intruder photo and OTP.
  - **Fullscreen Lock Screen:** The Windows desktop is immediately locked by the PyQt6 verification lock screen.

---

### Stage 3: Honeypot Deception & Attacker Quarantine
- **Talking Point:** *"Instead of simply terminating the session, our system diverts the adversary into a high-interaction, sandboxed Windows 11 deception environment to trap their motives and preserve forensically sound evidence."*
- **Action:**
  1. On the fullscreen Verification Lock Screen, enter 3 incorrect OTP attempts (or enable `ALLOW_DEMO_ESCAPE=1` only during local UI debugging to expose the demo shortcut button).
- **Expected Observations:**
  - The lock screen seamlessly transitions into the **Sandboxed Honeypot Desktop** (a realistic Windows 11 desktop with Start Menu, Taskbar, and system tray).
  - The attacker has zero access to the host operating system.

---

### Stage 4: Trapping Adversary Trajectory in the Sandbox
- **Talking Point:** *"Every interaction inside the honeypot—browser searches, decoy file views, and command execution—is silently tracked and categorized against MITRE ATT&CK tactics."*
- **Action:**
  1. Inside the Honeypot Desktop, open **Decoy Chrome**.
  2. Click on the pre-seeded bookmarks:
     - *Corporate Direct Deposit Portal:* Enter dummy credentials $\rightarrow$ trapped into forensic audit log.
     - *AWS Cloud Management:* Click "Extract Root Access Keys" $\rightarrow$ traps canary honey-token `AKIA5HONEYPOT7X92Q0`.
     - *GitHub Enterprise:* View production repository secrets $\rightarrow$ traps unauthorized credential collection event.
  3. Open **Decoy Windows Explorer** and navigate `C:\Users\<User>\Documents`.
  4. Open **Decoy Notepad**, edit a file, and save it $\rightarrow$ modifications are isolated inside the virtual filesystem.

---

### Stage 5: Authenticated Owner Recovery & Baseline Adaptation
- **Talking Point:** *"When the legitimate owner returns, they authenticate using the one-time cryptographic session OTP. The system invalidates the OTP and automatically adapts the baseline models to legitimate drift."*
- **Action:**
  1. On the Honeypot Desktop, Verification Lock Screen, or Web SOC **Verified Reset** modal, enter the authentic 6-digit session OTP (received via Alert Email / Telegram or stored locally in `models/.active_otp`, or your configured `EMERGENCY_RECOVERY_KEY`).
- **Expected Observations:**
  - Workstation access is restored immediately.
  - The active session OTP is cryptographically invalidated (single-use).
  - The ML engine triggers online adaptation retraining (`ml_engine/train.py`), updating the owner's baseline models.
  - The Web SOC console returns to `NORMAL` status.

---

### Stage 6: Executive AI Forensic PDF Report & Analyst Workbench
- **Talking Point:** *"The system automatically compiles all digital evidence into an executive forensic PDF report featuring dedicated Section 5 File & Directory Impact Analysis and sealed with a cryptographic SHA-256 tamper-evident digest."*
- **Action:**
  1. On the Web SOC console, click **📄 Download Executive Forensic PDF** (or click **🖥️ Open Forensic Desktop App** to show the PyQt6 Analyst Workbench).
  2. Open the downloaded PDF in your browser or PDF viewer.
- **Expected Observations in the PDF:**
  - **Cryptographic Seal:** Header displays the SHA-256 digital signature of the report.
  - **Surveillance Evidence:** Embedded high-resolution photo of the intruder.
  - **Section 5 File Impact Analysis:** Forensically confirmed file deletions table (pre-size, SHA-256 pre-hashes, source app) and unauthorized file modifications with rendered monospaced unified diff blocks (`--- before / +++ after`).
  - **Section 7 Risk Reconciliation:** Explains the two-stage defense model reconciling host biometric drift trigger (Threshold $\ge 0.55$) with honeypot activity floor.
  - **AI Threat Intelligence:** Persona classification (*"Financial Cybercriminal & Credential Harvester"*) and primary intent analysis.
  - **MITRE ATT&CK Mapping:** Explicit tactic tags (`T1485 - Data Destruction`, `T1552.001 - Credentials in Files`, `T1082 - System Information Discovery`, `T1059.001 - Command and Scripting Interpreter`).
  - **Forensic Event Log:** Chronological table of all decoy interactions and trapped credentials.

---

## 4. Alternative / Standalone Demonstration Paths

If you wish to demonstrate specific subsystems independently without running the full supervisor:

### Option A: Interactive Viva Demonstration CLI Runner
```powershell
.\bat\run_viva_demo.bat
```
*(Provides a guided 5-stage console demonstration with on-screen examiner talking points)*

### Option B: Unauthorized Intrusion & Lockout Simulator
```powershell
.\bat\simulate_unauthorized_attack.bat
```
*(Demonstrates acute risk escalation and lock screen deployment directly)*

### Option C: Native Desktop Forensic Analyst Workbench
```powershell
python dashboard/forensic_dashboard.py
```
*(Opens the standalone PyQt6 forensic workbench directly)*

### Option D: Standalone Sandboxed Honeypot Desktop
```powershell
python deception/honey_desktop.py
```
*(Opens the isolated Windows 11 honeypot directly)*

---

## 5. Clean Shutdown Procedure

When the demonstration is complete:
- **Method 1 (Recommended):** Right-click the **Green Shield Tray Icon** $\rightarrow$ click **🛑 Stop Services & Exit**.
- **Method 2:** In the terminal running `start_system.bat`, press `Ctrl+C` once.

Both methods terminate all background worker processes cleanly without leaving orphaned Python processes or locked port handles.

---

## 6. Emergency Viva Troubleshooting

| Problem During Presentation | Immediate Emergency Fix |
|---|---|
| **Port 8000 is reported as already in use** | Check running process on port 8000 (`netstat -ano | findstr :8000`) and stop the stale PID or launch with `.\VIVA_START.bat --port 8080`. |
| **Lock screen appears but you don't know the OTP** | Check your configured alert Email/Telegram channel or inspect the ephemeral local record (`Get-Content models\.active_otp`), or enter your configured `EMERGENCY_RECOVERY_KEY`. |
| **Projector / Screen resolution looks unusual** | The Honeypot Desktop and Lock Screen are designed to adapt to 1080p and 4K displays. Press the Windows key if you ever need to access the taskbar during demonstration. |
| **Ollama AI shows offline heuristic mode** | Explain to examiners: *"The system is designed with zero cloud dependency. When the local LLM daemon is offline, our deterministic rule-based expert heuristic engine automatically classifies the threat without interruption."* |
