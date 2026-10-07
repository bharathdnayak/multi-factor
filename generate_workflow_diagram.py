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
    PURPLE  = '#c084fc'     # Purple (ML & ADWIN Daemon)
    DANGER  = '#f87171'     # Red (Breach & Camera)
    AMBER   = '#fbbf24'     # Amber (Honeypot & Tier 2)
    WARNING = '#fbbf24'     # Amber/Warning
    TEAL    = '#2dd4bf'     # Teal (Environmental & Web)
    SUCCESS = '#34d399'     # Green (Verification & Recovery)
    CARD_BG = '#151b23'     # Dark Container
    BOX_BG  = '#1e2632'     # Process Box
    TEXT_W  = '#f8fafc'     # Pure White
    TEXT_M  = '#94a3b8'     # Muted Text

    # Header
    ax.text(70, 97.4, "CONTINUOUS BEHAVIORAL DRIFT SECURITY SYSTEM: END-TO-END WORKFLOW ARCHITECTURE",
            fontsize=21, fontweight='bold', color=TEXT_W, ha='center', va='center')
    ax.text(70, 95.0, "Procedural Execution: Multi-Modal Sensors -> ADWIN Drift & 3-Tier Risk -> Step-Up MFA / Lockdown -> Sandboxed Deception -> AI Forensic Audit",
            fontsize=11.2, color=PRIMARY, ha='center', va='center')

    # Helper: Stage Container
    def draw_container(x, y, w, h, title, subtitle, color):
        glow = patches.FancyBboxPatch((x-0.3, y-0.3), w+0.6, h+0.6,
                                      boxstyle="round,pad=0.4",
                                      facecolor=color, alpha=0.08, edgecolor='none')
        ax.add_patch(glow)
        card = patches.FancyBboxPatch((x, y), w, h,
                                     boxstyle="round,pad=0.4",
                                     facecolor=CARD_BG, edgecolor=color, linewidth=1.8, linestyle='--')
        ax.add_patch(card)
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
        ax.text(x + w/2, y + h - 1.3, title, fontsize=9.8, fontweight='bold' if is_bold_title else 'normal',
                color=color, ha='center', va='center')
        curr_y = y + h - 2.8
        for line in lines:
            if isinstance(line, tuple):
                txt, col = line
                ax.text(x + w/2, curr_y, txt, fontsize=8.6, color=col, ha='center', va='center')
            else:
                ax.text(x + w/2, curr_y, line, fontsize=8.6, color=TEXT_W, ha='center', va='center')
            curr_y -= 1.32

    # Helper: Decision Diamond
    def draw_diamond(cx, cy, w, h, title, subtitle, color):
        pts = [(cx, cy + h/2), (cx + w/2, cy), (cx, cy - h/2), (cx - w/2, cy)]
        diamond = patches.Polygon(pts, closed=True, facecolor='#231d14', edgecolor=color, linewidth=2.0)
        ax.add_patch(diamond)
        ax.text(cx, cy + 0.9, title, fontsize=9.6, fontweight='bold', color=color, ha='center', va='center')
        ax.text(cx, cy - 0.9, subtitle, fontsize=8.4, color=TEXT_W, ha='center', va='center')

    # Helper: Data Cylinder/Store
    def draw_datastore(x, y, w, h, title, subtitle, color):
        box = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.3",
                                    facecolor='#141f2e', edgecolor=color, linewidth=1.6)
        ax.add_patch(box)
        ax.text(x + w/2, y + h - 1.2, f"[DATASTORE] {title}", fontsize=9.0, fontweight='bold', color=color, ha='center', va='center')
        ax.text(x + w/2, y + 1.2, subtitle, fontsize=8.4, color=TEXT_W, ha='center', va='center')

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
            ax.text(mx, my, label, fontsize=8.4, fontweight='bold', color=color,
                    ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.25", facecolor='#0b0e14', edgecolor=color, alpha=0.95, linewidth=1.2))

    # =========================================================================
    # COLUMN 1: TELEMETRY & ENVIRONMENTAL COLLECTION (x: 3 to 28)
    # =========================================================================
    draw_container(3, 8, 25, 84, "STAGE 1: MULTI-MODAL SENSORS", "telemetry/agent.py (Worker 1)", PRIMARY)
    
    draw_box(4.5, 76, 22, 10, "LOW-LEVEL OS HOOKS", [
        "pynput Key Press & Dwell Hook",
        "Inter-Key Latency (Flight Times)",
        "Mouse Velocity, Jerk & Straightness",
        ("Raw millisecond event timestamps", TEXT_M)
    ], PRIMARY)

    draw_box(4.5, 62, 22, 11, "ENVIRONMENTAL BLE SENSORS (TASK-8)", [
        "BLE Proximity RSSI Path Loss",
        "Smartphone In-Range Verification",
        ("Walk-Away Penalty: +0.25 Risk", WARNING),
        "WLAN SSID & 802.11 Encryption Audit",
        "System CPU & RAM Activity",
    ], TEAL)

    draw_box(4.5, 48, 22, 11, "INTRA-APP COGNITIVE PROFILER", [
        "Active Win32 Foreground Window",
        "Task Mode: Coding / Docs / Browse",
        "Typing Rhythm & Pause Ratio",
        "Backspace & Shortcut Frequency",
        "Output: telemetry_data.jsonl (10s)",
    ], PRIMARY)

    draw_datastore(4.5, 34, 22, 7, "telemetry_data.jsonl", "Continuous 10s Window Records", PRIMARY)
    draw_datastore(4.5, 23, 22, 7, "data/app_profiles.json", "Dynamic Application Baselines", PRIMARY)

    draw_box(4.5, 11, 22, 9, "CONTINUOUS AGENT DAEMON", [
        "10-Second Time Slices",
        "Clears In-Memory Event Buffers",
        "Self-Healing Hook Threads",
        ("Transparent Background Execution", SUCCESS)
    ], PRIMARY)

    # Col 1 Internal Arrows
    draw_arrow(15.5, 76, 15.5, 73, "", PRIMARY)
    draw_arrow(15.5, 62, 15.5, 59, "", PRIMARY)
    draw_arrow(15.5, 48, 15.5, 41, "Flush 10s Window", PRIMARY)
    draw_arrow(15.5, 34, 15.5, 30, "", PRIMARY)
    draw_arrow(15.5, 23, 15.5, 20, "", PRIMARY)

    # =========================================================================
    # COLUMN 2: QUAD-FACTOR ML & ADWIN DRIFT DAEMON (x: 31 to 58)
    # =========================================================================
    draw_container(31, 8, 27, 84, "STAGE 2: QUAD-FACTOR ML & ADWIN", "telemetry/evaluator.py (Worker 2)", PURPLE)

    draw_box(32.5, 76, 24, 10, "LIVE TELEMETRY CONSUMER", [
        "Watches 'telemetry_data.jsonl'",
        "Zero-Polling Instant Tail",
        "Pipes to FastAPI WebSocket Stream",
        ("Continuous Bayesian Ingestion", TEXT_M)
    ], PURPLE)

    draw_box(32.5, 60, 24, 13, "QUAD-FACTOR BIOMETRIC SCORING", [
        ("1. Deep SVDD 1D-CNN (Weight: 0.35)", PURPLE),
        "   30-Keystroke Temporal Hypersphere",
        ("2. Biometric OC-SVM (Weight: 0.35)", PRIMARY),
        "   11 Typing & Kinematic Features",
        ("3. Context Isolation Forest (W: 0.15)", AMBER),
        ("4. Cognitive AI Controller (W: 0.15)", TEAL)
    ], PURPLE)

    draw_box(32.5, 44, 24, 13, "ADWIN CONCEPT DRIFT MONITOR (TASK-3)", [
        ("Formal Adaptive Windowing Algorithm", WARNING),
        "Hoeffding-Bound Statistical Hypothesis",
        ("Monitors Dwell, Flight & Risk Scores", TEXT_W),
        ("Gradual Fatigue -> Trigger Adaptation", SUCCESS),
        ("Abrupt Mismatch -> Escalate Threat", DANGER),
        ("Smoothed Risk Pool across 30s History", TEAL)
    ], WARNING)

    draw_diamond(44.5, 26, 23, 12, "Evaluate Risk Policy", "Tier 1 / Tier 2 / Tier 3?", DANGER)

    draw_box(32.5, 10.5, 24, 8, "TIER 1: NOMINAL (< 0.40)", [
        "Risk < 0.40 (Baseline Matched)",
        "Zero Friction, Zero Interruption",
        ("Continuous Silent Protection", SUCCESS)
    ], SUCCESS)

    # Col 2 Internal Arrows
    draw_arrow(44.5, 76, 44.5, 73, "", PURPLE)
    draw_arrow(44.5, 60, 44.5, 57, "", PURPLE)
    draw_arrow(44.5, 44, 44.5, 32, "ADWIN & Risk Evaluation", PURPLE)
    draw_arrow(44.5, 20, 44.5, 18.5, "Tier 1 (< 0.40)", SUCCESS)

    # =========================================================================
    # COLUMN 3 UPPER: 3-TIER DYNAMIC RISK RESPONSE & LOCK (x: 61 to 91, y: 48 to 92)
    # =========================================================================
    draw_container(61, 48, 30, 44, "STAGE 3: 3-TIER RISK ORCHESTRATION", "security/risk_orchestrator.py (TASK-4)", DANGER)

    draw_box(63, 76, 26, 12, "TIER 2: STEP-UP CHALLENGE (0.40 - 0.75)", [
        ("Non-Blocking Desktop Toast Challenge", WARNING),
        "StepUpToastWidget (WA_ShowWithoutActivating)",
        "Preserves Active Typing & Workflow",
        ("Owner Verifies PIN/OTP -> Restores Tier 1", SUCCESS),
        ("3 Consecutive Fails -> Escalate to Tier 3", DANGER),
    ], WARNING)

    draw_box(63, 56, 26, 16, "TIER 3: AUTONOMOUS LOCKDOWN (> 0.75)", [
        ("1. Silent Webcam Snapshot Trigger", DANGER),
        "   OpenCV Haar-Cascade Face Bounding Box",
        ("2. Cryptographic 6-Digit OTP Dispatch", WARNING),
        "   Dispatched via Multi-Channel Alerting",
        ("3. Fullscreen Verification Lockdown", DANGER),
        "   Blocks shortcuts (Alt+Tab, Esc, Close)",
        ("   Master Bypass: 'admin' (Viva Recovery)", SUCCESS),
        ("   3 Failed Attempts / Bypass -> Deception", AMBER)
    ], DANGER)

    # =========================================================================
    # COLUMN 3 LOWER: 1:1 DECEPTION HONEYPOT (x: 61 to 91, y: 8 to 44)
    # =========================================================================
    draw_container(61, 8, 30, 37, "STAGE 4: 1:1 DECEPTION HONEYPOT", "deception/honey_desktop.py (TASK-6, 7)", AMBER)

    draw_box(63, 27, 26, 14, "DECOY CHROME & HONEY-TOKENS", [
        ("Corporate NetBanking Trap (/login)", DANGER),
        "Captures Fake Credentials (admin_corp)",
        ("Decoy AWS Console: Root API Keys", WARNING),
        "Honey-Token: AKIA5HONEYPOT7X92Q0",
        ("Leaked GitHub .env.production Secrets", WARNING),
        ("Live Ticking Clock & Windows WaitCursor", TEXT_M)
    ], AMBER)

    draw_box(63, 11, 26, 12, "HONEYSHELL & C2 INTERCEPTION (TASK-7)", [
        "Traps ping, arp -a, route print, whoami",
        "Synthetic Realistic Network Topology",
        ("Remote C2 Interception (curl/wget)", DANGER),
        ("Quarantined into data/sandbox/ (Zero Risk)", SUCCESS),
        ("Sequential Log: honeypot_commands.log", PRIMARY),
    ], AMBER)

    # =========================================================================
    # COLUMN 4: FORENSICS, AI INTENT & WEB CONSOLE (x: 95 to 137)
    # =========================================================================
    draw_container(95, 8, 42, 84, "STAGE 5: RECOVERY, AI FORENSICS & DASHBOARD", "Incident Recovery, Audit & Operations", SUCCESS)

    draw_diamond(116, 76, 26, 12, "User Authentication?", "Input: OTP or 'admin'", SUCCESS)

    draw_box(98, 54, 36, 14, "OWNER RECOVERY & MODEL ADAPTATION", [
        ("LEGITIMATE OWNER RECOVERY (Ctrl+Alt+Shift+U)", SUCCESS),
        "1. Verified via OTP or Master Bypass ('admin')",
        "2. Safely Exits Sandboxed Honeypot Desktop",
        ("3. Restores Authentic Desktop Session", SUCCESS),
        ("4. Online Model Adaptation (Retrains on Verified Drift)", PRIMARY),
        ("   Trims stale baseline -> updates OC-SVM & IsoForest", TEXT_M)
    ], SUCCESS)

    draw_box(98, 32, 36, 18, "OFFLINE OLLAMA AI INTENT & MITRE ATT&CK", [
        ("AI INTENT ANALYZER (qwen2.5:3b / Cyber Heuristics)", PURPLE),
        "• Classifies Attacker Typology & Persona Profile",
        ("• Formal MITRE ATT&CK Mapping:", TEAL),
        "  - T1087 (Account Discovery) | T1059 (Command Execution)",
        "  - T1552 (Unsecured Credentials) | T1105 (Ingress Tool Transfer)",
        ("• Assesses Strategic Intent & Severity Rating", TEXT_W),
        ("• Multi-Page Executive Forensic PDF Report (FPDF2)", SUCCESS),
        "  Includes Intruder Photo, Timeline, and SHA-256 Custody Hash"
    ], PURPLE)

    draw_box(98, 11, 36, 17, "REAL-TIME CYBER-OPS DASHBOARD & SUPERVISOR", [
        ("FASTAPI ASGI WEBSOCKET CONSOLE (TASK-1, 2)", TEAL),
        "• Live WebSocket Streaming (/ws/telemetry @ http://localhost:8000)",
        "• Real-Time Threat Gauge, Active App Badge & Incident Log",
        ("• Download Fresh Forensic PDF & View Intruder Snapshot", SUCCESS),
        ("UNIFIED PROCESS SUPERVISOR (run_system.py - TASK-11)", PRIMARY),
        "• Spawns Agent, Evaluator & Web; System Tray Shield Icon",
        ("INTERACTIVE LIVE VIVA RUNNER (demo_viva_runner.py - TASK-12)", WARNING),
        "• 5-Stage Automated Viva Demo Script with Examiner Talking Points"
    ], TEAL)

    # =========================================================================
    # INTER-COLUMN CONNECTING ARROWS
    # =========================================================================
    # Col 1 -> Col 2: Telemetry Flush
    draw_arrow(28, 76, 32.5, 76, "Telemetry Stream", PRIMARY)

    # Col 2 -> Col 3: Risk Decision
    draw_arrow(56.0, 32.0, 63.0, 78.0, "Tier 2 (0.40 - 0.75)", WARNING, curve=-0.12)
    draw_arrow(56.0, 26.0, 63.0, 60.0, "Tier 3 (> 0.75 Breach)", DANGER, curve=0.0)

    # Col 3 Upper -> Lower: Deception Trap
    draw_arrow(76.0, 56.0, 76.0, 41.0, "Failed 3x OR 'Bypass'", AMBER)

    # Col 3 Lower -> Col 4: Recovery Hotkey
    draw_arrow(91.0, 25.0, 98.0, 60.0, "Ctrl+Alt+Shift+U Recovery", SUCCESS, curve=0.15)

    # Col 3 Upper -> Col 4: Direct Auth
    draw_arrow(89.0, 64.0, 98.0, 64.0, "Verify OTP", SUCCESS)

    # Col 4 Internal Arrows
    draw_arrow(116.0, 70.0, 116.0, 68.0, "YES (Verified)", SUCCESS)
    draw_arrow(116.0, 54.0, 116.0, 50.0, "", SUCCESS)
    draw_arrow(116.0, 32.0, 116.0, 28.0, "", TEAL)

    # Metadata Footer
    ax.text(70, 2.5, "NMAMIT Information Science & Engineering | Major Project Team 30 | End-to-End Procedural Flowchart",
            fontsize=10.5, color=TEXT_M, ha='center', va='center')
    ax.text(70, 1.0, "Slide & Viva Defense Ready | Exported at 300 DPI Sub-Pixel Vector-Quality Resolution",
            fontsize=9.2, color=PRIMARY, ha='center', va='center')

    plt.tight_layout()
    os.makedirs(os.path.dirname(png_path) if os.path.dirname(png_path) else ".", exist_ok=True)
    plt.savefig(png_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

    img = Image.open(png_path)
    rgb_img = img.convert('RGB')
    rgb_img.save(jpg_path, quality=95)
    print(f"[SUCCESS] Exported updated 300 DPI Workflow Diagram to:\n  PNG: {png_path}\n  JPG: {jpg_path}")


if __name__ == "__main__":
    png = os.path.join(os.path.dirname(os.path.abspath(__file__)), "end_to_end_structure.png")
    jpg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "end_to_end_structure.jpg")
    create_workflow_diagram(png, jpg)
