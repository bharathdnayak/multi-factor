# Operational Runbook, Demonstration Guide & Troubleshooting Manual

**Project Title:** Multi-Factor Behavioral Drift Continuous Authentication, Deception Simulation & Digital Forensics  
**Department:** Department of Information Science & Engineering (ISE)  
**Target Audience:** Project Examiners, Evaluators, Faculty Guides, and System Operators  
**System Version:** Major Project Production Release  

---

## 1. Prerequisites & Environment Setup

### 1.1 System Requirements
- **Operating System:** Windows 10 / Windows 11 (64-bit).
- **Python Version:** Python 3.10 – 3.14 (Verified on Python 3.14.3).
- **Hardware:** Standard QWERTY keyboard, mouse/touchpad, and integrated or USB webcam (an automatic synthetic fallback is engaged if no camera hardware is present).
- **Optional Local LLM:** [Ollama](https://ollama.ai) running `qwen2.5:latest` or `llama3:latest` for offline local AI reasoning (the system automatically engages its built-in expert heuristic analyzer if Ollama is not installed or running).

### 1.2 Dependency Installation
Open PowerShell or Command Prompt in the repository root directory:

```powershell
# Navigate to project root
cd "<path-to>\Behavioral-Drift-Security"

# Install all primary and sub-package dependencies
pip install -r requirements.txt
```

### 1.3 Pre-Flight Portability & Health Verification
Execute the pre-flight verification script to ensure all dependencies, models, and directory structures are healthy:

```powershell
python scripts/validate_portability.py
```
*Expected Output:* Check passes with `0 FAILED` (optional Ollama/physical webcam warnings fall back gracefully).

---

## 2. One-Click System Startup (`VIVA_START.bat` / `start_system.bat`)

Start the coordinated viva environment (pre-flight check, supervisor, Web SOC, and 5-stage runner) or start the continuous defense daemon directly:

```powershell
# Coordinated Master Viva Launcher
.\VIVA_START.bat

# Or Continuous Defense Supervisor directly
python run_system.py
```

### What Happens During Startup:
1. **Micro-Service Orchestration:** The supervisor spawns three background worker processes:
   - **Worker 1 (`telemetry/agent.py`):** Low-level keyboard and mouse biometric sensor daemon.
   - **Worker 2 (`telemetry/evaluator.py`):** Quad-Factor Threat Evaluator & Continuous Authentication daemon.
   - **Worker 3 (`dashboard/app.py`):** Cyber-Ops Web SOC Console running on `http://localhost:8000`.
2. **System Tray Shield:** A crisp green security shield icon (`#27ae60`) appears in the Windows taskbar notification tray.
3. **Automated Browser Launch:** The supervisor polls the web server until healthy, then automatically launches your default web browser to `http://localhost:8000`.
4. **Log Redirection:** All console clutter is redirected to individual rotating log files in `data/logs/`.

### Startup Command-Line Options:
```powershell
# Run on a custom port
python run_system.py --port 8080

# Run in background without automatically launching the browser
python run_system.py --no-browser

# Run in headless mode without Qt system tray
python run_system.py --no-tray
```

---

## 3. Accessing Every Interface & Dashboard

The system features five coordinated interfaces for live operations, evaluation, and forensics:

| Interface | Access Method | Key Features |
|---|---|---|
| **Cyber-Ops Web SOC Console** | Navigate to `http://localhost:8000` in any web browser. | Real-time dual Chart.js streaming, biometric confidence gauges, live hardware stats, and anomaly simulation buttons. |
| **Desktop Forensic Analyst Workbench** | Right-click the **Green Shield Tray Icon** $\rightarrow$ **Open Forensic Desktop Dashboard**, or click **🖥️ Open Forensic Desktop App** on the Web Console. | Native PyQt6 application showing captured webcam photos, Ollama AI threat persona reasoning, and chronological interaction timeline. |
| **Sandboxed Honeypot Desktop** | Right-click the **Green Shield Tray Icon** $\rightarrow$ **Launch Honeypot Desktop**, or click **🪤 Launch Honeypot Desktop** on the Web Console, or fail 3 OTP attempts on the lock screen. | Isolated Windows 11 desktop simulation with Decoy Chrome (banking, AWS, GitHub), Decoy Explorer, Decoy Notepad, and Honeyshell. |
| **Verification Lock Screen** | Appears automatically when risk $\ge 0.78$ or sustained drift $\ge 0.55$. | Intercepts keyboard and mouse inputs, captures silent webcam photo, prompts for 6-digit session OTP or emergency key. |
| **Interactive Viva Demonstration Runner** | Right-click the **Green Shield Tray Icon** $\rightarrow$ **Run Interactive Viva Demonstration**, or run `python demo_viva_runner.py`. | Dedicated console interface coordinating a 5-stage live demonstration with verbal talking points for examiners. |

---

## 4. Live Viva Demonstration Guide

Follow this step-by-step walkthrough to demonstrate the system to examination panels, evaluators, or faculty guides:

### Step 1: Normal Owner Baseline (Tier 1)
1. Ensure `python run_system.py` is running and the Web Dashboard is open at `http://localhost:8000`.
2. Type naturally in any desktop application (e.g., VS Code or Notepad).
3. Observe the Web SOC:
   - **Instant Risk** stays low ($\approx 0.05 - 0.20$).
   - **30s Smoothed Risk** stays well below the 0.55 threshold.
   - **Deep SVDD Embedding** displays `MATCH` with $\approx 98\%$ confidence.
   - **Status Badge** shows `NORMAL` in emerald green.

### Step 2: Inject Simulated Imposter Takeover (Tier 3)
1. On the Web Dashboard, scroll down to the **Project Evaluation & Anomaly Simulation Control Center**.
2. Click the **⚡ Acute Intrusion Spike** button (or **🐌 Sluggish Imposter Typing**).
3. Observe the immediate coordinated reaction:
   - The **Temporal Risk Trajectory Chart** spikes sharply into the red critical zone ($> 0.85$).
   - The **Critical Breach Banner** flashes red indicating active lockdown (`ACTIVE (CHECK ALERT)` without leaking plaintext OTP codes in browser telemetry).
   - The **Silent Webcam** triggers, capturing an intruder facial frame and updating the forensics card.
   - The **Desktop Verification Lock Screen** pops fullscreen on Windows, locking the desktop.
   - A live security alert is dispatched via configured Email / Telegram with the webcam evidence photo and session OTP.

### Step 3: Adversary Deception & Honeypot Diversion
1. On the fullscreen Lock Screen, enter an incorrect OTP 3 times (unauthenticated bypass buttons and trivial defaults like `admin` are disabled/rejected by default; set `ALLOW_DEMO_ESCAPE=1` only for UI debugging).
2. The lock screen smoothly transitions into the **Sandboxed Honeypot Desktop** (Windows 11 desktop environment).
3. Demonstrate the decoy traps inside the honeypot:
   - **Decoy Chrome:** Open Chrome and click on the pre-seeded bookmarks:
     - *Corporate Direct Deposit Portal:* Enter arbitrary login credentials $\rightarrow$ trapped into forensic audit log.
     - *AWS Cloud Management:* Click "Extract Root Keys" $\rightarrow$ traps canary honey-token `AKIA5HONEYPOT7X92Q0`.
     - *GitHub Enterprise:* View production repository secrets $\rightarrow$ traps unauthorized access event.
   - **Decoy Windows Explorer:** Navigate folders in `C:\Users\<User>\Documents` and view decoy financial files.
   - **Decoy Notepad:** Edit or save files $\rightarrow$ modifications are trapped strictly inside the in-memory/JSON sandbox without touching host files.

### Step 4: Legitimate Owner Recovery & Model Adaptation
1. To restore workstation access from the honeypot, lock screen, or Web SOC **Verified Reset** modal, enter the authentic 6-digit OTP (from Alert Email/Telegram or `models/.active_otp`, or your configured `EMERGENCY_RECOVERY_KEY`).
2. The system verifies the cryptographic credential:
   - The honeypot/lock screen closes immediately.
   - The active session OTP is cryptographically invalidated (single-use).
   - The **Quad-Factor ML Engine** executes incremental adaptation retraining (`ml_engine/train.py`), learning the legitimate drift into the updated user baseline.
   - The Web SOC status returns to `NORMAL`.

### Step 5: Digital Forensics & Executive PDF Report
1. On the Web Dashboard, click **📄 Download Executive Forensic PDF** (or **⚡ Generate Fresh Report**).
2. The system compiles all collected telemetry, intruder facial photos, trapped decoy credentials, and local AI threat persona assessments into a publication-grade multi-page PDF.
3. Open the downloaded PDF and highlight for examiners:
   - The cryptographic **SHA-256 Digital Tamper-Evident Seal** in the document header.
   - The captured **Intruder Facial Snapshot**.
   - The **MITRE ATT&CK Tactic Mapping** (T1552.001, T1082, T1059.001).
   - The chronological forensic event audit log.

---

## 5. Troubleshooting Guide

### Issue 1: "Port 8000 is already IN USE"
- **Cause:** A previous instance of `uvicorn` or another web server is still bound to port 8000.
- **Solution:** 
  1. Terminate previous instances:
     ```powershell
     Get-Process -Name python | Stop-Process -Force
     ```
  2. Or launch `run_system.py` on an alternative port:
     ```powershell
     python run_system.py --port 8080
     ```

---

### Issue 2: Windows System Tray Icon Does Not Appear
- **Cause:** Running in an SSH session, headless container, or Windows Subsystem for Linux (WSL) without an active X-Server/Wayland display.
- **Solution:** Run directly inside native Windows PowerShell or Command Prompt. In headless testing environments, use `--no-tray`:
  ```powershell
  python run_system.py --no-tray
  ```

---

### Issue 3: Webcam Shows Placeholder or Capture Warning
- **Cause:** The workstation lacks an integrated/USB camera, or another application (Zoom, Teams) is locking the webcam device.
- **Solution:** 
  1. Close any video conferencing applications using the camera.
  2. The system is designed with a non-failing fallback: if the physical camera is unavailable, `webcam.py` returns `None` cleanly while the deception/dashboard layers fall back to a desktop wallpaper snapshot (`desktop_snapshot.png`) so forensic PDF generation continues uninterrupted.

---

### Issue 4: Telegram Security Alerts Not Delivering
- **Cause:** Telegram/SMTP credentials in `.env` or `security/config.json` are unconfigured or blocked by a firewall.
- **Solution:** 
  1. Inspect `.env` and `security/config.json` and ensure valid `bot_token` / `chat_id` or SMTP credentials are present.
  2. Note that alert failure never blocks the core authentication or honeypot engine. The ephemeral active OTP record is stored locally in `models/.active_otp` with a 300s TTL (never exposed in plaintext on `/api/status` or WebSocket broadcasts).

---

### Issue 5: Lock Screen Will Not Unlock / Forgot Session OTP
- **Cause:** Operator did not record the generated session OTP during a simulation.
- **Solution:**
  1. Inspect your configured Email / Telegram alert or inspect the active OTP file directly:
     ```powershell
     Get-Content models\.active_otp
     ```
  2. Or use the configured emergency recovery key in your environment (`$env:EMERGENCY_RECOVERY_KEY` or legacy `$env:MASTER_BYPASS_PASSWORD`).
  3. Note that trivial passwords (`admin`, `123456`) are deliberately blacklisted and rejected.

---

### Issue 6: Resetting Honeypot Sandbox State
- **Cause:** Attacker actions created synthetic test files that you wish to clear for a clean demonstration.
- **Solution:** Delete the sandbox state file; the Virtual File System will cleanly self-heal and re-seed defaults on next launch:
  ```powershell
  Remove-Item data\sandbox\virtual_fs_state.json -Force
  ```

---

### Issue 7: Local Ollama AI Shows "Offline Heuristic Mode"
- **Cause:** Ollama service is not running on `localhost:11434`.
- **Solution:** 
  1. If local Ollama is desired, start the service and pull the recommended model:
     ```powershell
     ollama serve
     ollama pull qwen2.5:latest
     ```
  2. If Ollama is not installed, no action is required—the system automatically falls back to its deterministic rule-based expert heuristic engine, generating complete MITRE ATT&CK classifications without interruption.

---

## 6. Clean System Shutdown

To cleanly terminate all running background micro-services without leaving orphaned processes:

- **Method A (Recommended):** Right-click the **Green Shield Tray Icon** in the Windows taskbar notification area $\rightarrow$ click **🛑 Stop Services & Exit**.
- **Method B:** Press `Ctrl+C` once in the terminal where `python run_system.py` is running.

Both methods trigger the supervisor's graceful shutdown procedure: child worker processes are notified, logs are flushed, and workstation security hooks are cleanly detached.
