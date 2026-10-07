import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image

def create_diagram(png_path, jpg_path):
    fig, ax = plt.subplots(figsize=(26, 16), dpi=300)
    fig.patch.set_facecolor('#0b0e14')
    ax.set_facecolor('#0b0e14')
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Modern Cyber-Tech Palette
    PRIMARY = '#58a6ff'       # Electric Blue
    SUCCESS = '#3fb950'       # Cyber Green
    WARNING = '#d29922'       # Cyber Amber
    DANGER  = '#f85149'        # Alert Red
    PURPLE  = '#bc8cff'        # Deep Violet
    TEAL    = '#39c5cf'          # Neon Teal
    BG_CARD = '#161b22'       # Dark Card Base
    TEXT_LIGHT = '#f0f6fc'    # Crisp White
    TEXT_MUTED = '#8b949e'    # Slate Gray

    # Main Banner
    ax.text(50, 97.0, "MULTI-FACTOR CONTINUOUS BEHAVIORAL DRIFT SECURITY SYSTEM",
            fontsize=22, fontweight='bold', color=TEXT_LIGHT, ha='center', va='center')
    ax.text(50, 94.4, "End-to-End Architecture: Continuous Biometrics | ADWIN Drift | 3-Tier Risk Orchestration | Deception Honeypot | AI Forensics",
            fontsize=11.5, color=PRIMARY, ha='center', va='center')

    def draw_card(x, y, w, h, stage_num, title, subtitle, color):
        # Outer glow
        glow = patches.FancyBboxPatch((x-0.25, y-0.25), w+0.5, h+0.5,
                                      boxstyle="round,pad=0.3",
                                      facecolor=color, alpha=0.12, edgecolor='none')
        ax.add_patch(glow)
        # Main card box
        card = patches.FancyBboxPatch((x, y), w, h,
                                     boxstyle="round,pad=0.3",
                                     facecolor=BG_CARD, edgecolor=color, linewidth=2.0)
        ax.add_patch(card)
        
        # Header banner box
        header = patches.FancyBboxPatch((x, y + h - 4.8), w, 4.8,
                                       boxstyle="round,pad=0.15",
                                       facecolor=color, alpha=0.20, edgecolor='none')
        ax.add_patch(header)
        
        # Header text
        ax.text(x + 1.2, y + h - 2.0, f"[{stage_num}] {title}",
                fontsize=12.2, fontweight='bold', color=color, va='center')
        ax.text(x + 1.2, y + h - 3.6, subtitle,
                fontsize=9.2, fontweight='bold', color=TEXT_MUTED, va='center')

    def draw_inner_box(x, y, w, h, text_list, accent_color, bg="#1c2128"):
        box = patches.FancyBboxPatch((x, y), w, h,
                                    boxstyle="round,pad=0.2",
                                    facecolor=bg, edgecolor=accent_color, linewidth=1.2)
        ax.add_patch(box)
        curr_y = y + h - 1.4
        for item in text_list:
            if isinstance(item, tuple):
                t, is_bold, sz, col = item
                ax.text(x + 1.0, curr_y, t, fontsize=sz, fontweight='bold' if is_bold else 'normal', color=col, va='center')
            else:
                ax.text(x + 1.0, curr_y, item, fontsize=9.0, color=TEXT_LIGHT, va='center')
            curr_y -= 1.38

    def draw_arrow(x1, y1, x2, y2, label="", color="#8b949e", style='-|>', curve=0.0, label_offset_y=1.0):
        con = patches.ConnectionStyle(f"arc3,rad={curve}") if curve != 0.0 else "arc3,rad=0"
        arrow = patches.FancyArrowPatch((x1, y1), (x2, y2),
                                       connectionstyle=con,
                                       arrowstyle=f"{style},head_width=4.5,head_length=6.0",
                                       color=color, linewidth=2.2)
        ax.add_patch(arrow)
        if label:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
            if curve != 0:
                my += curve * 12
            ax.text(mx, my + label_offset_y, label, fontsize=8.6, fontweight='bold', color=color,
                    ha='center', va='center',
                    bbox=dict(boxstyle="round,pad=0.25", facecolor='#0b0e14', edgecolor=color, alpha=0.95, linewidth=1.2))

    # ==================== ROW 1 (TOP) ====================
    # --- STAGE 1: TELEMETRY & ENVIRONMENTAL (TOP-LEFT) ---
    draw_card(3, 50, 29, 41, "1", "CONTINUOUS TELEMETRY & SENSORS", "telemetry/agent.py & environmental_sensor.py", PRIMARY)
    draw_inner_box(4.5, 76, 26, 8.5, [
        ("KEYSTROKE & MOUSE KINEMATICS", True, 9.8, PRIMARY),
        ("• Dwell Times & Inter-Key Flight Latency (ms)", False, 8.8, TEXT_LIGHT),
        ("• Mouse Velocity, Acceleration, Jerk & Straightness", False, 8.8, TEXT_LIGHT),
        ("• Privacy Protection: SHA-256 Hashed Raw Keys", False, 8.6, TEXT_MUTED),
    ], PRIMARY)
    draw_inner_box(4.5, 64.5, 26, 10.0, [
        ("ENVIRONMENTAL AMBIENT CONTEXT (TASK-8)", True, 9.8, TEAL),
        ("• BLE Proximity Path Loss: RSSI distance tracking", False, 8.8, TEXT_LIGHT),
        ("• Physical Walk-Away Detection (+0.25 Risk Penalty)", True, 9.0, WARNING),
        ("• Windows WLAN SSID & 802.11 Encryption Audit", False, 8.8, TEXT_LIGHT),
        ("• Background CPU & RAM Resource Footprint", False, 8.6, TEXT_MUTED),
    ], TEAL)
    draw_inner_box(4.5, 51.5, 26, 11.5, [
        ("COGNITIVE TASK MODE & CONTEXT PROFILER", True, 9.8, PRIMARY),
        ("• Win32 Active App Tracking (IDE, Browser, Terminal)", False, 8.8, TEXT_LIGHT),
        ("• Intra-App Typing Cadence & Thinking Pause Ratios", False, 8.8, TEXT_LIGHT),
        ("• Output Stream: telemetry_data.jsonl (10s intervals)", True, 9.0, SUCCESS),
    ], PRIMARY)

    # --- STAGE 2: ML SCORING & ADWIN DRIFT (TOP-MIDDLE) ---
    draw_card(35.5, 50, 29, 41, "2", "QUAD-FACTOR ML & ADWIN DRIFT", "ml_engine/models.py & security/drift_detector.py", PURPLE)
    draw_inner_box(37, 76, 26, 8.5, [
        ("DEEP SVDD 1D-CNN SEQUENCE EMBEDDINGS", True, 9.8, PURPLE),
        ("• 30-Event Keystroke Dwell/Flight Sequence Net", False, 8.8, TEXT_LIGHT),
        ("• Hypersphere Minimum Volume Metric Loss", False, 8.8, TEXT_LIGHT),
        ("• Sequence Biometric Confidence: Weight = 0.35", True, 8.8, WARNING),
    ], PURPLE)
    draw_inner_box(37, 64.5, 26, 10.0, [
        ("OC-SVM + ISOLATION FOREST + COGNITIVE", True, 9.8, PURPLE),
        ("• OC-SVM Biometric Dynamics (11 Features, W=0.35)", False, 8.8, TEXT_LIGHT),
        ("• Isolation Forest Context Dynamics (W=0.15)", False, 8.8, TEXT_LIGHT),
        ("• AI Cognitive Task Controller (W=0.15)", False, 8.8, TEXT_LIGHT),
        ("• Multi-Scale Sliding Window Pooling (30s history)", False, 8.6, TEXT_MUTED),
    ], PURPLE)
    draw_inner_box(37, 51.5, 26, 11.5, [
        ("ONLINE CONCEPT DRIFT: ADWIN (TASK-3)", True, 9.8, WARNING),
        ("• Formal Adaptive Windowing (Bifet & Gavaldà 2007)", False, 8.8, TEXT_LIGHT),
        ("• Hoeffding-Bound Statistical Hypothesis Testing", True, 9.0, WARNING),
        ("• Dual-Mode: Gradual Fatigue Drift vs. Abrupt Intrusion", False, 8.8, TEXT_LIGHT),
        ("• Monitors Risk, Dwell, Flight & Mouse Velocity", False, 8.6, TEXT_MUTED),
    ], WARNING)

    # --- STAGE 3: 3-TIER RISK ORCHESTRATION (TOP-RIGHT) ---
    draw_card(68, 50, 29, 41, "3", "3-TIER RISK ORCHESTRATION & LOCK", "security/risk_orchestrator.py & lock_handler.py", DANGER)
    draw_inner_box(68.8, 76, 27.4, 8.5, [
        ("3-TIER DYNAMIC RISK POLICY (TASK-4)", True, 9.8, DANGER),
        ("• Tier 1 (< 0.40): Silent Background Monitoring", True, 8.8, SUCCESS),
        ("• Tier 2 (0.40 - 0.75): Non-Blocking Step-Up MFA Challenge", True, 8.8, WARNING),
        ("• Tier 3 (> 0.75): Full Lockdown & Honeypot Diversion", True, 8.8, DANGER),
    ], DANGER)
    draw_inner_box(68.8, 64.5, 27.4, 10.0, [
        ("TIER 2: STEP-UP DESKTOP TOAST WIDGET", True, 9.8, WARNING),
        ("• Non-modal bottom-right card (WA_ShowWithoutActivating)", False, 8.8, TEXT_LIGHT),
        ("• Zero workflow disruption for legitimate working user", False, 8.8, TEXT_LIGHT),
        ("• Verify via PIN/OTP or Master Bypass restores Tier 1", True, 8.8, SUCCESS),
        ("• 3 consecutive failed attempts escalate to Tier 3", False, 8.6, TEXT_MUTED),
    ], WARNING)
    draw_inner_box(68.8, 51.5, 27.4, 11.5, [
        ("TIER 3: WORKSTATION LOCK & SILENT SURVEILLANCE", True, 9.8, DANGER),
        ("• Silent OpenCV Haar Cascade Webcam Capture", True, 9.0, DANGER),
        ("• Fullscreen Borderless Lockdown (Intercepts shortcuts)", False, 8.8, TEXT_LIGHT),
        ("• Cryptographic 6-digit Session OTP dispatched to phone", False, 8.8, TEXT_LIGHT),
        ("• Deception Trap: 3 failed attempts / 'Bypass' -> Honeypot", True, 9.0, WARNING),
    ], DANGER)

    # ==================== ROW 2 (BOTTOM) ====================
    # --- STAGE 4: WEB DASHBOARD & SUPERVISOR (BOTTOM-LEFT) ---
    draw_card(3, 7, 29, 39, "4", "CYBER-OPS DASHBOARD & SUPERVISOR", "dashboard/app.py & run_system.py (TASK-1,2,11)", TEAL)
    draw_inner_box(4.5, 30.0, 26, 11.0, [
        ("REAL-TIME FASTAPI WEBSOCKET DASHBOARD", True, 9.8, TEAL),
        ("• Live WebSocket Streaming (/ws/telemetry @ 10s)", True, 9.0, TEAL),
        ("• Live Risk Gauge, Factor Breakdown & Active Cognitive Mode", False, 8.8, TEXT_LIGHT),
        ("• Incident Feed, Intruder Snapshot & Forensic PDF Download", False, 8.8, TEXT_LIGHT),
        ("• Viva Anomaly Simulators (Sluggish, Acute, Script, Drift)", False, 8.6, TEXT_MUTED),
    ], TEAL)
    draw_inner_box(4.5, 18.5, 26, 10.5, [
        ("UNIFIED PROCESS SUPERVISOR (TASK-11)", True, 9.8, TEAL),
        ("• Orchestrates Worker 1 (Agent), 2 (Evaluator), 3 (Web)", True, 8.8, SUCCESS),
        ("• Windows System Tray: 64x64 Vector Security Shield Icon", False, 8.8, TEXT_LIGHT),
        ("• Auto-recovery heartbeats, rotating logs in data/logs/", False, 8.8, TEXT_LIGHT),
        ("• Graceful Ctrl+C and Tray Exit multi-process termination", False, 8.6, TEXT_MUTED),
    ], TEAL)
    draw_inner_box(4.5, 8.5, 26, 8.5, [
        ("ACADEMIC BENCHMARK GUARANTEES", True, 9.8, TEAL),
        ("• CMU Keystroke Benchmark (51 subjects): EER = 11.18%", True, 9.0, SUCCESS),
        ("• Multi-User Field Harvested Cohort: ROC-AUC = 0.9556", True, 9.0, SUCCESS),
        ("• Sub-50ms pipeline latency & 82MB runtime footprint", False, 8.6, TEXT_MUTED),
    ], TEAL)

    # --- STAGE 5: DECEPTION HONEYPOT & NETWORK RECON (BOTTOM-MIDDLE) ---
    draw_card(35.5, 7, 29, 39, "5", "1:1 SANDBOXED HONEYPOT DECEPTION", "deception/honey_desktop.py & decoy_chrome.py", WARNING)
    draw_inner_box(37, 30.0, 26, 11.0, [
        ("1:1 DESKTOP REPLICATION & DECOY APPS", True, 9.8, WARNING),
        ("• Replicates authentic Windows wallpaper, clock & taskbar", False, 8.8, TEXT_LIGHT),
        ("• Decoy Chrome: Corporate NetBanking Credential Trap", True, 9.0, WARNING),
        ("• Honey-Token AWS Root IAM Keys (AKIA5HONEYPOT7X92Q0)", True, 9.0, WARNING),
        ("• Leaked GitHub .env.production Secret Honey-Tokens", False, 8.6, TEXT_MUTED),
    ], WARNING)
    draw_inner_box(37, 18.5, 26, 10.5, [
        ("HONEYSHELL NETWORK RECON TRAPS (TASK-7)", True, 9.8, WARNING),
        ("• Traps ping, arp -a, route print, whoami, ipconfig, nmap", True, 8.8, WARNING),
        ("• Returns synthetically realistic emulated network topology", False, 8.8, TEXT_LIGHT),
        ("• Remote C2 Download Interception: curl / wget quarantined", True, 8.8, DANGER),
        ("• Zero host execution risk: diverted into data/sandbox/", False, 8.6, TEXT_MUTED),
    ], WARNING)
    draw_inner_box(37, 8.5, 26, 8.5, [
        ("TAMPER-EVIDENT FORENSIC RECORDER", True, 9.8, WARNING),
        ("• Records all keystrokes, folders, URLs, and shell input", False, 8.8, TEXT_LIGHT),
        ("• Structured storage: data/forensics/session_actions.jsonl", True, 8.8, PRIMARY),
        ("• Cryptographic SHA-256 Chain of Custody Hashes", False, 8.6, TEXT_MUTED),
    ], WARNING)

    # --- STAGE 6: FORENSICS & RECOVERY (BOTTOM-RIGHT) ---
    draw_card(68, 7, 29, 39, "6", "AI INTENT & FORENSIC INCIDENT AUDIT", "deception/ai_intent_analyzer.py & pdf_generator.py", SUCCESS)
    draw_inner_box(68.8, 30.0, 27.4, 11.0, [
        ("EMERGENCY OWNER RECOVERY & RESTORE", True, 9.8, SUCCESS),
        ("• Legitimate Owner Recovery Hotkey: Ctrl+Alt+Shift+U", True, 10.0, WARNING),
        ("• Verifies OTP PIN or Master Bypass Password ('admin')", False, 8.8, TEXT_LIGHT),
        ("• Safely terminates Honeypot sandbox & restores desktop", True, 9.0, SUCCESS),
        ("• Online Model Adaptation: retrains on verified drift", False, 8.6, TEXT_MUTED),
    ], SUCCESS)
    draw_inner_box(68.8, 18.5, 27.4, 10.5, [
        ("OFFLINE OLLAMA AI INTENT ANALYZER", True, 9.8, SUCCESS),
        ("• Local offline LLM (qwen2.5:3b) + Cyber Heuristic Engine", True, 8.8, SUCCESS),
        ("• Classifies Attacker Persona (e.g. Data Thief / Recon)", False, 8.8, TEXT_LIGHT),
        ("• Formal MITRE ATT&CK Mapping (T1087, T1059, T1552, T1105)", True, 8.8, TEAL),
        ("• Strategic Objective, Severity Rating & Containment Advice", False, 8.6, TEXT_MUTED),
    ], SUCCESS)
    draw_inner_box(68.8, 8.5, 27.4, 8.5, [
        ("EXECUTIVE FORENSIC PDF REPORT GENERATION", True, 9.8, SUCCESS),
        ("• Multi-Page Audit-Grade PDF (FPDF2) in data/forensics/", True, 9.0, SUCCESS),
        ("• Intruder webcam photo with Haar Cascade overlay box", False, 8.8, TEXT_LIGHT),
        ("• Chronological event timeline, SHA-256 hashes & legal seal", False, 8.6, TEXT_MUTED),
    ], SUCCESS)

    # ==================== CLEAN CONNECTING ARROWS ====================
    # Arrow 1: Stage 1 -> Stage 2 (10s Telemetry Stream)
    draw_arrow(32.0, 70.0, 35.5, 70.0, "10s Telemetry + BLE RSSI", PRIMARY, label_offset_y=1.2)

    # Arrow 2: Stage 2 -> Stage 3 (Dynamic Risk Escalation)
    draw_arrow(64.5, 70.0, 68.0, 70.0, "Risk >= 0.78 / ADWIN Abrupt", DANGER, label_offset_y=1.2)

    # Arrow 3: Stage 3 -> Stage 5 (Deception Diversion on Fail)
    draw_arrow(75.0, 50.0, 58.0, 46.0, "3 Failed Attempts OR 'Bypass Prompt'", WARNING, curve=-0.12, label_offset_y=1.2)

    # Arrow 4: Stage 5 -> Stage 6 (Recovery to Forensics)
    draw_arrow(64.5, 26.0, 68.8, 26.0, "Ctrl+Alt+Shift+U -> Verify", SUCCESS, label_offset_y=1.2)

    # Arrow 5: Stage 3 -> Legit Session Restored / Adapted (Loopback Badge)
    ax.annotate("Identity Verified: 'admin' or OTP\n-> Restores Session & Adapts Drift",
                xy=(82.5, 51.5), xytext=(82.5, 47.0),
                arrowprops=dict(facecolor=SUCCESS, edgecolor=SUCCESS, arrowstyle="->", lw=1.8),
                fontsize=8.5, fontweight='bold', color=SUCCESS, ha='center', va='top',
                bbox=dict(boxstyle="round,pad=0.25", facecolor='#0b0e14', edgecolor=SUCCESS, linewidth=1.2))

    # Bottom Metadata Line
    ax.text(50, 2.8, "NMAMIT ISE Department | Major Project Team 30 | Python 3.14 + PyQt6 + Scikit-Learn + PyTorch + FastAPI",
            fontsize=10.5, color=TEXT_MUTED, ha='center', va='center')
    ax.text(50, 1.2, "Publication & Defense Ready Architecture Diagram | 300 DPI Sub-Pixel Vector-Quality Fidelity",
            fontsize=9.5, color=PRIMARY, ha='center', va='center')

    plt.tight_layout()
    os.makedirs(os.path.dirname(png_path) if os.path.dirname(png_path) else ".", exist_ok=True)
    plt.savefig(png_path, dpi=300, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()

    # Export high-quality JPG as well
    img = Image.open(png_path)
    rgb_img = img.convert('RGB')
    rgb_img.save(jpg_path, quality=95)
    print(f"[OK] Exported updated 300 DPI Architecture Diagram to:\n  PNG: {png_path}\n  JPG: {jpg_path}")


if __name__ == "__main__":
    png = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture_diagram.png")
    jpg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture_diagram.jpg")
    create_diagram(png, jpg)
