# CHAPTER 4: IMPLEMENTATION DETAILS

## 4.1 Microservice Supervisor Architecture (`run_system.py`)
To prevent monolithic thread locks and ensure uninterrupted telemetry collection, the system is designed as three independent, cooperating micro-services coordinated by `SystemSupervisor`:
* **Worker 1 (Sensor Agent):** `python telemetry/agent.py` — runs in user space with low-overhead Windows OS hooks.
* **Worker 2 (Threat Evaluator):** `python telemetry/evaluator.py` — consumes streaming records, evaluates ML models, and executes ADWIN drift tests.
* **Worker 3 (Cyber-Ops Web Console):** `python -m uvicorn dashboard.app:app --host 0.0.0.0 --port 8000` — hosts the FastAPI ASGI WebSocket streaming server.

`SystemSupervisor` implements:
1. **Asynchronous Process Supervision:** Uses Python `subprocess.Popen` with dedicated non-blocking pipe sinks logging to `data/logs/agent.log`, `evaluator.log`, and `dashboard.log`.
2. **System Tray Integration:** Houses a `QSystemTrayIcon` in the Windows taskbar dynamically rendering a 64x64 vector security shield icon with status-dependent color states (Green = Nominal, Amber = Step-Up Challenge, Red = Lockdown).
3. **Fault-Tolerant Heartbeat Auto-Recovery:** Regularly verifies process PID liveness and restarts crashed worker instances automatically.
4. **Clean Multi-Process Shutdown:** Handles SIGINT (Ctrl+C) and Tray Exit signals, sending graceful termination signals followed by cleanup to prevent orphaned background processes or locked ports.

## 4.2 Low-Level Telemetry Acquisition (`telemetry/agent.py`)
### 4.2.1 Event Listener Hooks
Mouse and keyboard events are captured using asynchronous `pynput` hooks:
* **Key Press/Release Hook:** Computes millisecond timestamps for key down ($t_{down}$) and key up ($t_{up}$). Key characters are immediately converted to SHA-256 hashes to safeguard passwords and sensitive text.
* **Mouse Movement Hook:** Records coordinate tuples $(x, y, t)$ sampled at high frequency.
* **Intra-App Context Tracking:** Periodically queries the Windows Win32 API (`GetForegroundWindow` and `GetWindowThreadProcessId`) to extract the executable process name (e.g., `code.exe`, `chrome.exe`, `powershell.exe`).

### 4.2.2 Environmental BLE Sensor (`telemetry/environmental_sensor.py`)
Implements passive beacon scanning using the Windows BLE API (`winrt.windows.devices.bluetooth.advertisement`). Continuously tracks the RSSI of the owner's smartphone UUID and executes native Windows netsh WLAN audits (`netsh wlan show interfaces`) to detect untrusted network connections.

## 4.3 Quad-Factor Continuous Threat Evaluator (`telemetry/evaluator.py`)
Operates as a high-speed log-tailing daemon watching `telemetry_data.jsonl`.
* Implements a sliding temporal queue (`collections.deque(maxlen=3)`) to maintain the rolling 30-second multi-window risk history.
* Employs PyTorch for 1D-CNN Deep SVDD inference, evaluating 30-step keystroke embeddings in under 22 milliseconds.
* Integrates `MultivariateDriftMonitor` (`security/drift_detector.py`) running parallel ADWIN instances across Dwell Mean, Flight Mean, Mouse Velocity, and Threat Risk.

## 4.4 3-Tier Dynamic Risk Orchestrator (`security/risk_orchestrator.py`)
Implements the graduated defense response:
* **`StepUpToastWidget`:** Built with PyQt6 using `Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint`. Configured with `Qt.WidgetAttribute.WA_ShowWithoutActivating` to ensure that when medium risk is flagged, the toast card animates into the bottom-right corner without stealing keyboard focus from active development or typing tasks.
* **Verification Logic:** Allows the authentic owner to enter their 6-digit OTP or configured master bypass password (`admin`) to immediately restore Tier 1 nominal security. Three consecutive failed attempts automatically escalate the session to Tier 3.

## 4.5 1:1 Sandboxed Deception Honeypot (`deception/honey_desktop.py`)
Constructed to replicate the native Windows 10/11 desktop environment:
1. **Visual Emulation:** Captures native Windows desktop wallpaper, rendering it across a borderless fullscreen window with Device Pixel Ratio (DPR) 1.25 scaling.
2. **Interactive Decoy Chrome (`deception/decoy_chrome.py`):**
   - Bookmarks Bar routing to Decoy Corporate NetBanking (`https://bank.corp.internal/login`).
   - Decoy AWS Management Console displaying fake honey-token IAM keys: `AKIA5HONEYPOT7X92Q0`.
   - Omnibox URL keyword parser intercepting credential hunting attempts.
3. **HoneyShell Network Reconnaissance Trap:**
   - Emulates `cmd.exe` / `powershell.exe`. Intercepts `ping`, `arp -a`, `route print`, `whoami`, `ipconfig /all`.
   - Returns synthetic corporate subnets (192.168.1.0/24), enticing the intruder to spend time probing emulated hosts.
4. **Remote C2 Download Interception:**
   - Detects `curl` and `wget` commands downloading remote binaries.
   - Diverts downloads into `data/sandbox/`, quarantining threat files without executing host network requests.
5. **Centralized Forensic Tracker (`deception/forensic_tracker.py`):**
   - Thread-safe event recorder writing all actions to `data/forensics/session_actions.jsonl` and `honeypot_commands.log`.
   - Computes SHA-256 digital evidence hashes for strict chain-of-custody verification.

## 4.6 Offline AI Threat Forensics & Report Generator (`dashboard/pdf_generator.py`)
* **AI Threat Engine (`deception/ai_intent_analyzer.py`):** Interfaces with local offline Ollama API (`http://localhost:11434`) running `qwen2.5:3b`. Translates chronological attacker commands into formal MITRE ATT&CK tactics (T1087, T1059, T1552, T1105).
* **Forensic PDF Generator:** Employs `fpdf2` to produce dark-themed executive incident reports containing case IDs, intruder photos with face bounding boxes, chronological timelines, and digital evidence custody hashes.

## 4.7 Real-Time Cyber-Ops Web Dashboard (`dashboard/app.py`)
* Built with FastAPI and Uvicorn.
* Real-time WebSocket endpoint (`/ws/telemetry`) streaming live threat risk, component score breakdowns, and incident logs.
* Frontend built with clean modern cyber-tech styling, HTML5 Canvas gauge needles, and local `chart.min.js`.
