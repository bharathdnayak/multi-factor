import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image

def create_workflow_diagram(png_path, jpg_path):
    # Flowchart layout: 28 wide by 18 tall @ 300 DPI
    fig, ax = plt.subplots(figsize=(28, 18), dpi=300)
    fig.patch.set_facecolor('#0b0e14')
    ax.set_facecolor('#0b0e14')
    ax.set_xlim(0, 140)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Color Palette
    PRIMARY = '#38bdf8'     # Sky Blue (Telemetry)
    PURPLE  = '#c084fc'     # Purple (ML Daemon)
    DANGER  = '#f87171'     # Red (Breach & Camera)
    AMBER   = '#fbbf24'     # Amber (Honeypot)
    WARNING = '#fbbf24'     # Amber/Warning
    TEAL    = '#2dd4bf'     # Teal
    SUCCESS = '#34d399'     # Green (Verification & Recovery)
    CARD_BG = '#151b23'     # Dark Container
    BOX_BG  = '#1e2632'     # Process Box
    TEXT_W  = '#f8fafc'     # Pure White
    TEXT_M  = '#94a3b8'     # Muted Text

    # Header
    ax.text(70, 97.2, "CONTINUOUS BEHAVIORAL DRIFT SECURITY SYSTEM: END-TO-END WORKFLOW STRUCTURE",
            fontsize=21, fontweight='bold', color=TEXT_W, ha='center', va='center')
    ax.text(70, 94.8, "Procedural Execution Flowchart: Background Telemetry -> Multi-Model Scoring -> Active Breach Lock -> 1:1 Deception -> Forensic Audit",
            fontsize=11.5, color=PRIMARY, ha='center', va='center')

    # Helper: Stage Container
    def draw_container(x, y, w, h, title, subtitle, color):
        # Outer glow
        glow = patches.FancyBboxPatch((x-0.3, y-0.3), w+0.6, h+0.6,
                                      boxstyle="round,pad=0.4",
                                      facecolor=color, alpha=0.08, edgecolor='none')
        ax.add_patch(glow)
        card = patches.FancyBboxPatch((x, y), w, h,
                                     boxstyle="round,pad=0.4",
                                     facecolor=CARD_BG, edgecolor=color, linewidth=1.8, linestyle='--')
        ax.add_patch(card)
        # Header strip
        strip = patches.FancyBboxPatch((x, y + h - 4.2), w, 4.2,
                                       boxstyle="round,pad=0.2",
                                       facecolor=color, alpha=0.18, edgecolor='none')
        ax.add_patch(strip)
        ax.text(x + 1.2, y + h - 1.8, title, fontsize=11.5, fontweight='bold', color=color, va='center')
        ax.text(x + 1.2, y + h - 3.2, subtitle, fontsize=9.0, color=TEXT_M, va='center')

    # Helper: Process Box
    def draw_box(x, y, w, h, title, lines, color, bg=BOX_BG, is_bold_title=True):
        box = patches.FancyBboxPatch((x, y), w, h,
                                    boxstyle="round,pad=0.3",
                                    facecolor=bg, edgecolor=color, linewidth=1.5)
        ax.add_patch(box)
        ax.text(x + w/2, y + h - 1.3, title, fontsize=10.0, fontweight='bold' if is_bold_title else 'normal',
                color=color, ha='center', va='center')
        curr_y = y + h - 2.8
        for line in lines:
            if isinstance(line, tuple):
                txt, col = line
                ax.text(x + w/2, curr_y, txt, fontsize=8.8, color=col, ha='center', va='center')
            else:
                ax.text(x + w/2, curr_y, line, fontsize=8.8, color=TEXT_W, ha='center', va='center')
            curr_y -= 1.35

    # Helper: Decision Diamond
    def draw_diamond(cx, cy, w, h, title, subtitle, color):
        pts = [(cx, cy + h/2), (cx + w/2, cy), (cx, cy - h/2), (cx - w/2, cy)]
        diamond = patches.Polygon(pts, closed=True, facecolor='#231d14', edgecolor=color, linewidth=2.0)
        ax.add_patch(diamond)
        ax.text(cx, cy + 0.9, title, fontsize=9.8, fontweight='bold', color=color, ha='center', va='center')
        ax.text(cx, cy - 0.9, subtitle, fontsize=8.5, color=TEXT_W, ha='center', va='center')

    # Helper: Data Cylinder/Store
    def draw_datastore(x, y, w, h, title, subtitle, color):
        box = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3",
                                    facecolor='#141f2e', edgecolor=color, linewidth=1.6)
        ax.add_patch(box)
        ax.text(x + w/2, y + h - 1.2, f"[DATASTORE] {title}", fontsize=9.2, fontweight='bold', color=color, ha='center', va='center')
        ax.text(x + w/2, y + 1.2, subtitle, fontsize=8.5, color=TEXT_W, ha='center', va='center')

    # Helper: Connecting Arrow
    def draw_arrow(x1, y1, x2, y2, label="", color="#94a3b8", curve=0.0, label_pos=0.5, label_offset=(0, 0)):
        con = patches.ConnectionStyle(f"arc3,rad={curve}") if curve != 0.0 else "arc3,rad=0"
        arrow = patches.FancyArrowPatch((x1, y1), (x2, y2),
                                       connectionstyle=con,
                                       arrowstyle="-|>,head_width=4.5,head_length=6.0",
                                       color=color, linewidth=2.0)
        ax.add_patch(arrow)
        if label:
            mx = x1 + (x2 - x1) * label_pos + label_offset[0]
            my = y1 + (y2 - y1) * label_pos + label_offset[1]
            if curve != 0:
                my += curve * 10
            ax.text(mx, my, label, fontsize=8.5, fontweight='bold', color=color,
                    ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.25", facecolor='#0b0e14', edgecolor=color, alpha=0.95, linewidth=1.2))

    # =========================================================================
    # COLUMN 1: TELEMETRY COLLECTION & DATA PERSISTENCE (x: 4 to 28)
    # =========================================================================
    draw_container(3, 8, 25, 84, "STAGE 1: TELEMETRY STREAMING", "telemetry/agent.py (Window 1)", PRIMARY)
    
    draw_box(4.5, 76, 22, 10, "LOW-LEVEL OS HOOKS", [
        "pynput Key Press & Release",
        "pynput Mouse Position & Clicks",
        "pynput Multi-Axis Scroll Wheel",
        ("Raw millisecond event timestamps", TEXT_M)
    ], PRIMARY)

    draw_box(4.5, 62, 22, 11, "INTRA-APP BEHAVIOR PROFILER", [
        "Active Win32 Foreground App",
        "Keystroke Dwell & Flight Cadence",
        "Error Correction (Backspace Ratio)",
        "Special Shortcuts (Ctrl/Alt/Shift)",
        "Reading/Thinking Pause Cadence",
    ], PRIMARY)

    draw_box(4.5, 48, 22, 11, "KINEMATIC FEATURE EXTRACTION", [
        "Mouse Velocity Mean (px/s)",
        "Mouse Acceleration & Jerk Mean",
        "Trajectory Straightness Ratio",
        "System Context: CPU, RAM, Hour",
        "Categorize App: IDE/Browser/Term",
    ], PRIMARY)

    draw_datastore(4.5, 34, 22, 7, "telemetry_data.jsonl", "Rolling 10s Window Records", PRIMARY)
    draw_datastore(4.5, 23, 22, 7, "data/app_profiles.json", "App Dynamic Cadence Baseline", PRIMARY)

    draw_box(4.5, 11, 22, 9, "CONTINUOUS AGENT LOOP", [
        "10-Second Time Slices",
        "Clears In-Memory Event Buffers",
        "Self-Healing Hook Threads",
        ("Runs Transparent in Background", SUCCESS)
    ], PRIMARY)

    # Col 1 Internal Arrows
    draw_arrow(15.5, 76, 15.5, 73, "", PRIMARY)
    draw_arrow(15.5, 62, 15.5, 59, "", PRIMARY)
    draw_arrow(15.5, 48, 15.5, 41, "Flush 10s Window", PRIMARY, label_offset=(0, 0))
    draw_arrow(15.5, 34, 15.5, 30, "", PRIMARY)
    draw_arrow(15.5, 23, 15.5, 20, "", PRIMARY)

    # =========================================================================
    # COLUMN 2: MULTI-MODEL ML SCORING DAEMON (x: 32 to 58)
    # =========================================================================
    draw_container(31, 8, 27, 84, "STAGE 2: THREAT EVALUATOR DAEMON", "security/drift_detector.py (Window 2)", PURPLE)

    draw_box(32.5, 76, 24, 10, "LIVE LOG FILE TAILER", [
        "Watches 'telemetry_data.jsonl'",
        "f.seek(0, 2) Tail Position",
        "Instant Parsing on Append",
        ("Zero-Polling Event Trigger", TEXT_M)
    ], PURPLE)

    draw_box(32.5, 60, 24, 13, "TRI-ENGINE AI EVALUATION", [
        ("1. Biometric Model (One-Class SVM)", PRIMARY),
        "   11 Typing & Mouse Dynamics",
        ("2. Context Model (Isolation Forest)", AMBER),
        "   7 System & Environment Metrics",
        ("3. Sequence Net (PyTorch SVDD 1D-CNN)", PURPLE),
        "   30-Keystroke Temporal Hypersphere"
    ], PURPLE)

    draw_box(32.5, 44, 24, 13, "SCORE FUSION & TEMPORAL SMOOTHING", [
        "SVM Normality Score [0.0 - 1.0]",
        "IF Normality Score [0.0 - 1.0]",
        ("Fused Confidence = 0.6*SVM + 0.4*IF", WARNING),
        ("Instant Risk = 1.0 - Fused Confidence", TEXT_W),
        ("30-Second Moving Average (3 Windows)", TEAL),
        ("Smoothed Risk = Avg(Risk History)", TEAL)
    ], PURPLE)

    draw_diamond(44.5, 26, 23, 12, "Smoothed Risk >= 0.75?", "Anomaly Breach Test", DANGER)

    draw_box(32.5, 10.5, 24, 8, "NORMAL BEHAVIOR", [
        "Risk < 0.75 (Baseline Matched)",
        "Zero False Alarm Interruption",
        ("Transparent Monitoring", SUCCESS)
    ], SUCCESS)

    # Col 2 Internal Arrows
    draw_arrow(44.5, 76, 44.5, 73, "", PURPLE)
    draw_arrow(44.5, 60, 44.5, 57, "", PURPLE)
    draw_arrow(44.5, 44, 44.5, 32, "Update Moving Avg", PURPLE)
    draw_arrow(44.5, 20, 44.5, 18.5, "NO (Normal)", SUCCESS)

    # =========================================================================
    # COLUMN 3: ACTIVE INCIDENT RESPONSE & SECURITY LOCK (x: 62 to 92)
    # =========================================================================
    draw_container(61, 48, 30, 44, "STAGE 3: ACTIVE RESPONSE & LOCK", "security/lock_handler.py", DANGER)

    draw_box(63, 76, 26, 12, "INCIDENT ALERT ORCHESTRATOR", [
        ("1. Silent Webcam Snapshot Trigger", DANGER),
        "   OpenCV Face Detection (Haar Cascade)",
        "   Saves: data/forensics/intruder_*.jpg",
        ("2. Cryptographic 6-Digit OTP Dispatch", WARNING),
        "   Sends via SMTP Email & Twilio SMS",
        "   Saves: models/.active_otp & Console",
    ], DANGER)

    draw_box(63, 56, 26, 16, "FULLSCREEN VERIFICATION SCREEN", [
        "Captures Pre-Breach Desktop Snapshot",
        "Borderless Topmost Overlay (Blocks All Apps)",
        "Intercepts Alt+Tab, Esc, Task Switch",
        ("Authentication Input Field:", PRIMARY),
        "• 6-Digit OTP Dispatched Code",
        ("• Master Bypass: admin / 123456 / admin123", WARNING),
        ("Buttons: [Verify & Unlock] | [Bypass Prompt]", TEXT_M)
    ], DANGER)

    # =========================================================================
    # COLUMN 3 LOWER: 1:1 DECEPTION HONEYPOT (x: 62 to 92, y: 8 to 44)
    # =========================================================================
    draw_container(61, 8, 30, 37, "STAGE 4: 1:1 DECEPTION HONEYPOT", "deception/honey_desktop.py", AMBER)

    draw_box(63, 27, 26, 14, "DECEPTION REPLICATION ENGINE", [
        "Loads Pre-Breach Desktop Screenshot",
        "1:1 Pixel Fidelity with DPR 1.25 Scaling",
        ("Attacker Believes Computer Is Unlocked", SUCCESS),
        "Live Ticking Taskbar Clock Overlay",
        "Windows WaitCursor Spinning Wheel on Click",
        "Authentic 'Not Responding' Crash Dialogs",
    ], AMBER)

    draw_box(63, 11, 26, 12, "SANDBOXED HONEYSHELL TERMINAL", [
        "Central Floating CMD / PowerShell Window",
        "Recon Commands: whoami, dir, ps, net user",
        "Decoy Honey-Files: passwords.txt, net_topo.pdf",
        ("All Keystrokes & Commands Sequentially Logged", DANGER),
        "Target: data/forensics/honeypot_commands.log",
    ], AMBER)

    # =========================================================================
    # COLUMN 4: FORENSICS, VERIFICATION & ADAPTATION (x: 96 to 137)
    # =========================================================================
    draw_container(95, 8, 42, 84, "STAGE 5: VERIFICATION, FORENSICS & DRIFT ADAPTATION", "Incident Recovery & Calibration", SUCCESS)

    draw_diamond(116, 76, 26, 12, "User Authentication?", "Input: admin / 123456 / OTP", SUCCESS)

    draw_box(98, 54, 36, 14, "SESSION RESTORATION & DRIFT ADAPTATION", [
        ("IDENTITY CONFIRMED VIA OTP OR MASTER BYPASS", SUCCESS),
        "1. Dismisses Security Lock Screen Immediately",
        "2. Restores Active User Windows & Desktop Session",
        ("3. Adaptive Behavior Retraining (ml_engine/train.py):", PRIMARY),
        "   • Appends newly verified telemetry records",
        "   • Trims stale historic records (Limit: 2000)",
        "   • Recalibrates One-Class SVM & Isolation Forest Boundaries",
        "   • Adapts to Natural Typing Drift (Fatigue, Posture)",
    ], SUCCESS)

    draw_box(98, 32, 36, 18, "EMERGENCY OPERATOR RECOVERY", [
        ("LEGITIMATE OWNER HONEYPOT ESCAPE SHORTCUT", WARNING),
        ("   >>>  Ctrl + Alt + Shift + U  <<<", WARNING),
        "1. Intercepted by Global Keyboard Hook (pynput)",
        "2. Spawns Emergency Verification Modal",
        "3. Validates Master Bypass ('admin') or Session OTP",
        "4. Seamlessly Exits Honeypot Desktop",
        ("5. Launches Forensic Recovery Dashboard (PyQt6)", PRIMARY),
    ], PRIMARY)

    draw_box(98, 11, 36, 17, "FORENSIC RECOVERY DASHBOARD", [
        ("dashboard/forensic_dashboard.py", TEXT_M),
        ("1. Intruder Facial Evidence Audit", DANGER),
        "   High-res camera capture with detected face box",
        ("2. Sequential Honeypot Command Audit Log", PRIMARY),
        "   Complete timeline of all commands executed in honeyshell",
        ("3. Sandbox Dropped Malware & File Inspection", AMBER),
        "   Audits newly created/modified attacker files in data/sandbox/",
        ("4. System Hardening & Retrained Model Calibration", SUCCESS),
    ], SUCCESS)

    # =========================================================================
    # INTER-STAGE ARROWS & FLOW ROUTING (100% COLLISION FREE)
    # =========================================================================
    # Stream from Datastore to Tailer (Stage 1 -> Stage 2)
    draw_arrow(26.5, 37.5, 32.5, 80, "Live File Tail", PRIMARY, curve=0.25, label_offset=(0, 1.5))

    # Anomaly Breach -> Active Incident Response (Stage 2 -> Stage 3)
    draw_arrow(56, 26, 63, 82, "YES: Smoothed Risk >= 0.75", DANGER, curve=0.15, label_offset=(-2, 1.5))

    # Lock Screen -> Authentication Diamond (Stage 3 -> Stage 5)
    draw_arrow(89, 64, 103, 76, "User Enters Credentials", PRIMARY, curve=0.1)

    # Auth Diamond -> Yes (Restoration)
    draw_arrow(116, 70, 116, 68, "MATCH: 'admin' / OTP", SUCCESS)

    # Auth Diamond -> No / Bypass Button (Stage 3 -> Stage 4 Honeypot)
    draw_arrow(76, 56, 76, 41, "3 Failed Attempts OR Click 'Bypass Prompt'", AMBER)

    # Honeypot -> Emergency Operator Recovery (Stage 4 -> Stage 5)
    draw_arrow(89, 20, 98, 38, "Owner Hotkey: Ctrl+Alt+Shift+U", WARNING, curve=-0.1)

    # Recovery -> Forensic Dashboard
    draw_arrow(116, 32, 116, 28, "Forensic Audit Ready", SUCCESS)

    # Footer
    ax.text(70, 3.2, "Multi-Factor Behavioral Drift Security Workflow Architecture | End-to-End Runtime Pipeline",
            fontsize=11, color=TEXT_M, ha='center', va='center')
    ax.text(70, 1.4, f"Exported High-Resolution Diagram: {os.path.basename(png_path)} | Slide & Defense Ready",
            fontsize=9.5, color=PRIMARY, ha='center', va='center')

    plt.tight_layout()
    plt.savefig(png_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

    # Save high quality JPG
    img = Image.open(png_path).convert('RGB')
    img.save(jpg_path, 'JPEG', quality=95)
    print(f"[SUCCESS] Exported workflow diagram to:\n  PNG: {png_path}\n  JPG: {jpg_path}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    png = os.path.join(base_dir, "end_to_end_structure.png")
    jpg = os.path.join(base_dir, "end_to_end_structure.jpg")
    create_workflow_diagram(png, jpg)

    # Copy to brain artifacts
    artifact_dir = r"C:\Users\Dell\.gemini\antigravity\brain\4826f417-1abb-40be-b9af-d031b96ba56a"
    import shutil
    shutil.copy(png, os.path.join(artifact_dir, "end_to_end_structure.png"))
    shutil.copy(jpg, os.path.join(artifact_dir, "end_to_end_structure.jpg"))
