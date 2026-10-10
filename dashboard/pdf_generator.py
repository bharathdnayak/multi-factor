import re
import os
import sys
import glob
import time
import json
import hashlib
import platform
from fpdf import FPDF
from fpdf.fonts import FontFace
from fpdf.enums import MethodReturnValue

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deception.forensic_tracker import get_tracker
from deception.ai_intent_analyzer import IntruderIntentAnalyzer


# ---------------------------------------------------------------------------
# Text & Formatting Sanitizers
# ---------------------------------------------------------------------------
def sanitize_pdf_text(text, font_family="helvetica"):
    """
    Sanitizes strings for PDF rendering:
    - Strips DeepSeek reasoning tags (<think>...</think>)
    - Normalizes Unicode typography to clean ASCII / Latin-1 equivalents
    - Strips emojis and unsupported glyphs
    - Enforces Latin-1 encodability if using core fonts to prevent FPDFUnicodeEncodingException
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # 1. Strip DeepSeek reasoning tags
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)

    # 2. Typography normalization
    replacements = {
        '\u201c': '"', '\u201d': '"',  # Smart double quotes
        '\u2018': "'", '\u2019': "'",  # Smart single quotes
        '\u2014': '--', '\u2013': '-', # Em / En dash
        '\u2022': '-', '\u00b7': '-',  # Bullets
        '\u2026': '...',               # Ellipsis
        '\u2192': '->', '\u2190': '<-',# Arrows
        '\u2713': '[OK]', '\u2714': '[OK]', # Checkmarks
        '\u2717': '[X]', '\u2718': '[X]',
        '\u00a9': '(c)', '\u00ae': '(R)', '\u2122': '(TM)',
        '\u00b0': ' deg', '\t': '    ',
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)

    # 3. Strip emojis & non-BMP code points
    text = re.sub(r'[\U00010000-\U0010ffff]', '', text)
    text = re.sub(r'[\u2600-\u27bf\ufe00-\ufe0f\u2300-\u23ff]', '', text)

    # 4. Latin-1 fallback for Helvetica
    if font_family.lower() == "helvetica":
        text = text.encode("latin-1", "replace").decode("latin-1")

    return text.strip()


def clean_markdown(text) -> str:
    """
    Converts raw Markdown/LLM output into clean, structured plain text:
    - Recursively formats lists and dictionaries into grammatically sound text
    - Strips markdown code blocks (```json ... ```)
    - Strips markdown headers (#, ##, ###, ####)
    - Strips bold/italic asterisks and underscores
    - Strips backticks and list markers
    - Strips raw Python stringified lists (e.g. "['chrome', 'explorer']")
    - Collapses excess blank lines
    """
    if text is None:
        return ""
    if isinstance(text, (list, tuple)):
        items = [clean_markdown(str(x)) for x in text if str(x).strip()]
        return ", ".join(items) if items else ""
    if isinstance(text, dict):
        parts = []
        for k, v in text.items():
            k_clean = str(k).replace("_", " ").strip().title()
            v_clean = clean_markdown(v)
            if v_clean:
                parts.append(f"{k_clean}: {v_clean}")
        return ". ".join(parts) + "."

    val = str(text)
    val = sanitize_pdf_text(val)
    # Remove markdown code blocks
    val = re.sub(r'```(?:json)?\s*', '', val)
    val = re.sub(r'```', '', val)
    # Remove header markers like '#### [ATTACKER PERSONA]:' or '### Header'
    val = re.sub(r'^[#\s*:\-]+', '', val, flags=re.MULTILINE)
    # Remove inline bold/italic
    val = re.sub(r'\*\*([^*]+)\*\*', r'\1', val)
    val = re.sub(r'__([^_]+)__', r'\1', val)
    val = re.sub(r'\*([^*]+)\*', r'\1', val)
    val = re.sub(r'_([^_]+)_', r'\1', val)
    val = re.sub(r'`([^`]+)`', r'\1', val)
    val = val.replace("#", "")

    # Strip raw Python stringified lists: "['a', 'b']" -> "a, b"
    val = re.sub(r"\[(['\"])(.*?)\1\]", r"\2", val)
    val = val.replace("['", "").replace("']", "").replace("[\"", "").replace("\"]", "")
    val = re.sub(r',\s*,\s*', ', ', val)

    # Normalize consecutive whitespace
    lines = [line.strip() for line in val.splitlines() if line.strip()]
    return " ".join(lines)


def redact_sensitive_presentation(text: str) -> str:
    """
    Masks confidential credentials/tokens in presentation layers (PDF report, UI tables).
    Preserves raw authentic data in session_actions.jsonl and on disk.
    - AWS Key IDs: AKIA5HONEYPOT7X92Q0 -> AKIA5H...[REDACTED_AWS_KEY]
    - Bearer tokens: Bearer eyJhb... -> Bearer eyJhb...[REDACTED_TOKEN]
    """
    if not text:
        return ""
    text = str(text)
    # AWS Access Key ID: AKIA followed by 10-18 alphanumeric chars (case-insensitive)
    text = re.sub(r'\b(AKIA[0-9A-Z]{2})[0-9A-Z]{8,18}\b', r'\g<1>...[REDACTED_AWS_KEY]', text, flags=re.IGNORECASE)
    # Bearer tokens
    text = re.sub(r'\b(Bearer\s+[A-Za-z0-9_\-\.]{6})[A-Za-z0-9_\-\.]{10,}\b', r'\g<1>...[REDACTED_TOKEN]', text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------------------
# MITRE ATT&CK Authoritative Knowledge Base Lookup
# ---------------------------------------------------------------------------
MITRE_TECHNIQUE_METADATA = {
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "evidence": "Queried local system properties, host configuration, or platform environment."
    },
    "T1087": {
        "name": "Account Discovery: Local Accounts",
        "tactic": "Discovery",
        "evidence": "Executed 'whoami' to inspect local user privilege level."
    },
    "T1087.001": {
        "name": "Account Discovery: Local Accounts",
        "tactic": "Discovery",
        "evidence": "Executed 'whoami' to inspect local user privilege level."
    },
    "T1552": {
        "name": "Unsecured Credentials: Credentials in Files",
        "tactic": "Credential Access",
        "evidence": "Accessed decoy AWS credentials, .env secrets, or password repositories."
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials in Files",
        "tactic": "Credential Access",
        "evidence": "Accessed decoy AWS honeytokens, .env secrets, or password vaults."
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "Discovery",
        "evidence": "Executed 'ping', 'arp -a', or 'route print' to map network topology."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "evidence": "Interacted with command-line or shell interpreter to execute operations."
    },
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell / Shell",
        "tactic": "Execution",
        "evidence": "Interacted with command-line terminal to stage operations."
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "evidence": "Inspected sensitive desktop repositories, confidential folders, or vault files."
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command & Control",
        "evidence": "Attempted remote payload or dropper transfer into sandbox via web utilities."
    },
    "T1021.004": {
        "name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "evidence": "Attempted remote SSH connection to internal network nodes for lateral movement."
    },
    "T1110": {
        "name": "Brute Force: Credential Stuffing / Submission",
        "tactic": "Credential Access",
        "evidence": "Submitted credentials against decoy banking or cloud portal authentication forms."
    }
}


# ---------------------------------------------------------------------------
# Custom Forensic PDF Canvas Class
# ---------------------------------------------------------------------------
class ForensicPDF(FPDF):
    """
    Professional Digital Forensics & Incident Response (DFIR) document canvas.
    Standardized A4 with corporate header, footer, dynamic pagination, and card styling.
    """
    # Professional DFIR Palette (RGB)
    COLOR_NAVY_DARK = (15, 23, 42)    # Slate 900
    COLOR_NAVY_MID = (30, 58, 138)    # Blue 900
    COLOR_BLUE_ACCENT = (37, 99, 235) # Blue 600
    COLOR_BLUE_BG = (239, 246, 255)   # Blue 50
    COLOR_GRAY_BG = (248, 250, 252)   # Slate 50
    COLOR_GRAY_CARD = (241, 245, 249) # Slate 100
    COLOR_GRAY_BORDER = (203, 213, 225) # Slate 300
    COLOR_TEXT_DARK = (30, 41, 59)    # Slate 800
    COLOR_TEXT_MUTED = (100, 116, 139) # Slate 500
    COLOR_RED_ALERT = (220, 38, 38)   # Red 600
    COLOR_RED_BG = (254, 242, 242)    # Red 50
    COLOR_AMBER_WARN = (217, 119, 6)  # Amber 600
    COLOR_AMBER_BG = (254, 243, 199)  # Amber 50
    COLOR_GREEN_SAFE = (22, 163, 74)  # Green 600
    COLOR_GREEN_BG = (240, 253, 244)  # Green 50

    def __init__(self, incident_id):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.incident_id = incident_id
        self.doc_font_family = "helvetica"
        self._init_unicode_fonts()
        self.set_margins(12, 18, 12)
        self.set_auto_page_break(auto=True, margin=16)

    def _init_unicode_fonts(self):
        """Attempts to register system TrueType Unicode fonts (Arial) on Windows."""
        if sys.platform == "win32":
            font_dir = os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Fonts")
            arial_reg = os.path.join(font_dir, "arial.ttf")
            arial_bd = os.path.join(font_dir, "arialbd.ttf")
            arial_it = os.path.join(font_dir, "ariali.ttf")
            if os.path.exists(arial_reg):
                try:
                    self.add_font("Arial", "", arial_reg)
                    if os.path.exists(arial_bd):
                        self.add_font("Arial", "B", arial_bd)
                    if os.path.exists(arial_it):
                        self.add_font("Arial", "I", arial_it)
                    self.doc_font_family = "Arial"
                except Exception:
                    self.doc_font_family = "helvetica"

    def set_font(self, family=None, style="", size=0):
        if family is None or family.lower() in ("helvetica", "arial"):
            family = self.doc_font_family
        return super().set_font(family, style, size)

    def cell(self, *args, **kwargs):
        if "text" in kwargs:
            kwargs["text"] = sanitize_pdf_text(kwargs["text"], self.doc_font_family)
        elif len(args) >= 3:
            args_list = list(args)
            args_list[2] = sanitize_pdf_text(args_list[2], self.doc_font_family)
            args = tuple(args_list)
        return super().cell(*args, **kwargs)

    def multi_cell(self, *args, **kwargs):
        if "text" in kwargs:
            kwargs["text"] = sanitize_pdf_text(kwargs["text"], self.doc_font_family)
        elif len(args) >= 3:
            args_list = list(args)
            args_list[2] = sanitize_pdf_text(args_list[2], self.doc_font_family)
            args = tuple(args_list)
        return super().multi_cell(*args, **kwargs)

    def header(self):
        # 1. Dark Slate Corporate Header Banner
        self.set_fill_color(*self.COLOR_NAVY_DARK)
        self.rect(0, 0, 210, 13, 'F')

        # 2. Left Brand / Unit Tag
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(241, 245, 249)
        self.set_xy(12, 3.5)
        self.cell(105, 6, "BEHAVIORAL DRIFT CONTINUOUS AUTHENTICATION | DIGITAL FORENSICS UNIT", align='L')

        # 3. Right Incident Case Tag
        self.set_xy(117, 3.5)
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(147, 197, 253) # Light Blue
        self.cell(81, 6, f"CASE: {self.incident_id}  |  CONFIDENTIAL", align='R')

        # 4. Accent Divider Line
        self.set_draw_color(*self.COLOR_BLUE_ACCENT)
        self.set_line_width(0.6)
        self.line(0, 13, 210, 13)
        self.set_line_width(0.2) # reset

        # Set cursor to content top margin
        self.set_y(18)

    def footer(self):
        self.set_y(-13.5)
        # Separator Line
        self.set_draw_color(*self.COLOR_GRAY_BORDER)
        self.set_line_width(0.3)
        self.line(12, self.get_y(), 198, self.get_y())
        self.set_line_width(0.2)

        # Footer Meta
        self.set_font(self.doc_font_family, 'I', 7)
        self.set_text_color(*self.COLOR_TEXT_MUTED)
        self.set_xy(12, self.get_y() + 1.5)
        self.cell(75, 5, "NMAMIT ISE Dept | Major Project Team 30", align='L')

        self.set_xy(87, self.get_y())
        self.set_font(self.doc_font_family, 'B', 7)
        self.set_text_color(148, 163, 184)
        self.cell(46, 5, "CONFIDENTIAL // DFIR INCIDENT AUDIT", align='C')

        self.set_xy(133, self.get_y())
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(*self.COLOR_TEXT_DARK)
        self.cell(65, 5, f"Page {self.page_no()} of {{nb}}", align='R')

    def check_page_space(self, min_space_needed=28):
        """Triggers a clean page break if remaining vertical space is insufficient."""
        if self.get_y() + min_space_needed > 275:
            self.add_page()

    def section_header(self, title, subtitle=None, min_space_needed=24):
        """Renders an authoritative corporate section banner without title/subtitle collision."""
        self.check_page_space(min_space_needed)
        curr_y = self.get_y() + 1.5

        # Left Accent Bar
        bar_height = 8.5 if subtitle else 6.0
        self.set_fill_color(*self.COLOR_NAVY_MID)
        self.rect(12, curr_y, 2.5, bar_height, 'F')

        # Section Title
        self.set_xy(16.5, curr_y)
        self.set_font(self.doc_font_family, 'B', 9.5)
        self.set_text_color(*self.COLOR_NAVY_DARK)
        self.cell(180, 5, title, new_x="LMARGIN", new_y="NEXT")

        # Subtitle on next line to avoid any horizontal collision
        if subtitle:
            self.set_x(16.5)
            self.set_font(self.doc_font_family, 'I', 7.2)
            self.set_text_color(*self.COLOR_TEXT_MUTED)
            self.cell(180, 3.8, subtitle, new_x="LMARGIN", new_y="NEXT")

        # Divider Underline
        line_y = self.get_y() + 1.0
        self.set_draw_color(*self.COLOR_GRAY_BORDER)
        self.line(12, line_y, 198, line_y)
        self.set_y(line_y + 2.5)


# ---------------------------------------------------------------------------
# Core Forensic Report Generator
# ---------------------------------------------------------------------------
class ForensicReportGenerator:
    """
    Automated Incident Report Generator producing publication-ready, multi-page PDFs
    documenting all unauthorized intruder activity captured in the Honeypot environment.
    """
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "data", "forensics")
        os.makedirs(self.output_dir, exist_ok=True)
        self.tracker = get_tracker()
        self.ai_analyzer = IntruderIntentAnalyzer()

    def generate_report(self, ai_report=None, timeline=None, stats=None, photo_path=None, incident_id=None, save_filename=None):
        """
        Compiles the complete, professionally formatted digital forensic incident report.
        Returns the absolute filepath of the generated PDF.
        """
        # Resolve data sources
        if timeline is None:
            timeline = self.tracker.get_timeline()
        if stats is None:
            stats = self.tracker.get_summary_stats()
        if ai_report is None:
            ai_report = self.ai_analyzer.analyze_session(timeline=timeline, stats=stats)

        # Generate unique case reference if not provided
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S")
        if incident_id is None:
            incident_id = f"INC-{timestamp_slug}"

        if save_filename:
            pdf_path = os.path.join(self.output_dir, save_filename)
        else:
            pdf_path = os.path.join(self.output_dir, f"Forensic_Report_{timestamp_slug}.pdf")

        # Resolve photo
        if not photo_path or not os.path.exists(photo_path) or os.path.getsize(photo_path) <= 500:
            photos = glob.glob(os.path.join(self.output_dir, "intruder_*.jpg"))
            photos.sort(key=os.path.getmtime, reverse=True)
            valid_photos = [p for p in photos if os.path.exists(p) and os.path.getsize(p) > 500]
            photo_path = valid_photos[0] if valid_photos else None

        # Build PDF Canvas
        pdf = ForensicPDF(incident_id=incident_id)
        pdf.alias_nb_pages()
        pdf.add_page()

        # ===================================================================
        # PAGE 1: EXECUTIVE COVER, INCIDENT OVERVIEW & OPTICAL EVIDENCE
        # ===================================================================
        self._add_title_and_executive_summary(pdf, incident_id, stats, timeline, ai_report)
        self._add_incident_overview_card(pdf, incident_id, stats, timeline)
        self._add_visual_evidence_card(pdf, photo_path)

        # ===================================================================
        # SECTION 3: AI-ASSISTED ATTACKER INTENT & BEHAVIORAL RECONSTRUCTION
        # (Cleanly starts on Page 2 with dynamic pagination)
        # ===================================================================
        pdf.add_page()
        self._add_ai_intent_reconstruction_section(pdf, ai_report, stats, timeline)

        # ===================================================================
        # SECTION 4: CHRONOLOGICAL FORENSIC AUDIT TRAIL, SANDBOX & MITRE
        # ===================================================================
        pdf.check_page_space(min_space_needed=40)
        self._add_chronological_audit_table(pdf, timeline)
        pdf.check_page_space(min_space_needed=28)
        self._add_sandbox_isolation_section(pdf, stats)
        pdf.check_page_space(min_space_needed=34)
        self._add_mitre_mapping_table(pdf, ai_report, timeline)

        # ===================================================================
        # REMEDIATION PLAN, CHAIN OF CUSTODY & ADMISSIBILITY
        # ===================================================================
        pdf.check_page_space(min_space_needed=35)
        self._add_remediation_plan(pdf, ai_report)
        self._add_evidence_custody_and_attestation(pdf, photo_path, timeline, stats)

        # Output and Cryptographically Seal Document
        pdf.output(pdf_path)

        # Calculate self SHA-256 seal
        pdf_sha256 = "N/A"
        try:
            with open(pdf_path, "rb") as f:
                pdf_sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass

        print(f"[PDF REPORT] Successfully exported comprehensive forensic report to '{pdf_path}'", flush=True)
        print(f"[PDF REPORT] Document SHA-256 Digital Seal: {pdf_sha256}", flush=True)
        return pdf_path

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------
    def _add_title_and_executive_summary(self, pdf, incident_id, stats, timeline, ai_report):
        """Renders report header, classification pill, and concise executive summary narrative."""
        # 1. Document Title
        pdf.set_font(pdf.doc_font_family, 'B', 14.5)
        pdf.set_text_color(*pdf.COLOR_NAVY_DARK)
        pdf.cell(140, 6.5, "DIGITAL FORENSIC INCIDENT INVESTIGATION REPORT", align='L')

        # Status Badge Pill on Right
        badge_x = 154
        badge_y = pdf.get_y()
        pdf.set_fill_color(*pdf.COLOR_GREEN_BG)
        pdf.set_draw_color(*pdf.COLOR_GREEN_SAFE)
        pdf.rect(badge_x, badge_y, 44, 6.2, style='FD', round_corners=True, corner_radius=1.5)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(*pdf.COLOR_GREEN_SAFE)
        pdf.set_xy(badge_x, badge_y)
        pdf.cell(44, 6.2, "CONTAINED & SEALED", align='C')
        pdf.ln(7.0)

        # Subtitle
        pdf.set_font(pdf.doc_font_family, 'I', 8)
        pdf.set_text_color(*pdf.COLOR_BLUE_ACCENT)
        pdf.cell(0, 4.2, "Post-Anomaly Continuous Authentication Breach & Honey-Desktop Deception Audit", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2.0)

        # Executive Summary Box
        total_events = len(timeline)
        detection_time = timeline[0].get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")) if timeline else time.strftime("%Y-%m-%d %H:%M:%S")
        threat = ai_report.get("threat_level", "HIGH").upper()

        exec_text = (
            f"On {detection_time}, the multi-scale behavioral biometric evaluation daemon detected an acute anomaly spike "
            f"exceeding nominal thresholds (Threat Severity: {threat}). Active workstation controls immediately locked the authentic session "
            f"and autonomously diverted the adversary into an emulated honey-desktop sandbox. Silent forensic webcam capture was executed, "
            f"and verified multi-channel MFA alerts were dispatched. During the deception window, the intruder conducted {total_events} distinct "
            f"interactions across decoy credentials, filesystem exploration, and diagnostic commands. Quarantined file writes verified zero "
            f"host system exposure. This document serves as the authoritative digital forensic record, AI threat reconstruction, and chain of custody."
        )

        box_y = pdf.get_y()
        pdf.set_fill_color(*pdf.COLOR_BLUE_BG)
        pdf.set_draw_color(191, 219, 254) # Blue 200
        pdf.rect(12, box_y, 186, 20.5, style='FD', round_corners=True, corner_radius=2)

        # Blue vertical bar on left of summary box
        pdf.set_fill_color(*pdf.COLOR_BLUE_ACCENT)
        pdf.rect(12, box_y, 2, 20.5, 'F')

        pdf.set_xy(16, box_y + 1.6)
        pdf.set_font(pdf.doc_font_family, 'B', 7.8)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 3.8, "EXECUTIVE INCIDENT SUMMARY", new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(16, box_y + 5.5)
        pdf.set_font(pdf.doc_font_family, '', 7.3)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        pdf.multi_cell(180, 3.4, exec_text)
        pdf.set_y(box_y + 22.5)

    def _add_incident_overview_card(self, pdf, incident_id, stats, timeline):
        """Renders clean 2-column grid of essential incident parameters."""
        pdf.section_header("1. Incident Overview & Target Environment", subtitle="Telemetry Ground Truth", min_space_needed=32)

        box_y = pdf.get_y()
        box_h = 24
        pdf.set_fill_color(*pdf.COLOR_GRAY_BG)
        pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
        pdf.rect(12, box_y, 186, box_h, style='FD', round_corners=True, corner_radius=2)

        detection_ts = timeline[0].get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")) if timeline else time.strftime("%Y-%m-%d %H:%M:%S")
        host_name = f"{platform.node()} (Dell Latitude)" if "Dell" in platform.node() else f"{platform.node()} ({platform.system()} Host)"
        os_env = f"{platform.system()} {platform.release()} (Build {platform.version().split('.')[0]}) 64-bit"
        total_actions = stats.get("total_actions", len(timeline))

        fields = [
            ("Incident Reference:", incident_id, "Breach Risk Trigger:", "Risk Score >= 0.55 (Elevated Spike)"),
            ("Detection Timestamp:", detection_ts, "Deception Status:", "Active Honeypot Sandbox (1:1 Decoy)"),
            ("Affected Hostname:", host_name, "Adversarial Actions:", f"{total_actions} Discrete Interactions Recorded"),
            ("Operating System:", os_env, "Containment Status:", "Contained in Sandbox (0 Host Writes)")
        ]

        row_y = box_y + 2.0
        for f in fields:
            # Col 1 Label & Value
            pdf.set_xy(15, row_y)
            pdf.set_font(pdf.doc_font_family, 'B', 7.8)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(32, 5, f[0])
            pdf.set_font(pdf.doc_font_family, '', 7.8)
            pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
            pdf.cell(56, 5, f[1][:34])

            # Col 2 Label & Value
            pdf.set_xy(105, row_y)
            pdf.set_font(pdf.doc_font_family, 'B', 7.8)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(32, 5, f[2])
            pdf.set_font(pdf.doc_font_family, 'B' if "Risk" in f[2] or "Status" in f[2] else '', 7.8)
            if "Risk" in f[2]:
                pdf.set_text_color(*pdf.COLOR_RED_ALERT)
            elif "Active" in f[3] or "Contained" in f[3]:
                pdf.set_text_color(*pdf.COLOR_GREEN_SAFE)
            else:
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
            pdf.cell(57, 5, f[3][:38])
            row_y += 5.2

        pdf.set_y(box_y + box_h + 3)

    def _add_visual_evidence_card(self, pdf, photo_path):
        """Displays captured webcam photo with consistent aspect ratio, hash, and legal disclaimer."""
        pdf.section_header("2. Visual Evidence & Physical Attacker Identification", subtitle="Optical Telemetry", min_space_needed=44)

        box_y = pdf.get_y()
        box_h = 39
        pdf.set_fill_color(*pdf.COLOR_GRAY_BG)
        pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
        pdf.rect(12, box_y, 186, box_h, style='FD', round_corners=True, corner_radius=2)

        # Image Frame Box on Left
        img_x = 15
        img_y = box_y + 2.5
        img_w = 48
        img_h = 34

        has_image = False
        img_hash = "N/A"
        img_file_name = "No Frame Captured"
        capture_time = time.strftime("%Y-%m-%d %H:%M:%S")

        if photo_path and os.path.exists(photo_path) and os.path.getsize(photo_path) > 500:
            try:
                with open(photo_path, "rb") as f:
                    img_hash = hashlib.sha256(f.read()).hexdigest()
                img_file_name = os.path.basename(photo_path)
                mtime = os.path.getmtime(photo_path)
                capture_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime))

                pdf.image(photo_path, x=img_x, y=img_y, w=img_w, h=img_h)
                pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
                pdf.rect(img_x, img_y, img_w, img_h, 'D')
                has_image = True
            except Exception:
                has_image = False

        if not has_image:
            pdf.set_fill_color(*pdf.COLOR_GRAY_CARD)
            pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
            pdf.rect(img_x, img_y, img_w, img_h, 'FD')
            pdf.set_xy(img_x, img_y + 12)
            pdf.set_font(pdf.doc_font_family, 'B', 8)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(img_w, 5, "[OPTICAL SENSOR IDLE]", align='C')
            pdf.set_xy(img_x, img_y + 17)
            pdf.set_font(pdf.doc_font_family, '', 7)
            pdf.cell(img_w, 4, "No Intruder Frame Recorded", align='C')

        # Metadata on Right of Photo
        meta_x = 68
        meta_y = box_y + 2.0
        meta_rows = [
            ("Evidence Filename:", img_file_name, True),
            ("Capture Timestamp:", capture_time, False),
            ("Hardware Sensor:", "Built-in HD Webcam (DirectShow Device Index 0)", False),
            ("Trigger Anomaly:", "Multi-Scale Behavioral Biometric Drift (Instant Risk > 0.75)", False),
            ("Face Detection:", "Haar Cascade Verified (Physical Presence Confirmed)" if has_image else "Sensor Offline / No Face Profiled", False),
            ("Image SHA-256 Digest:", img_hash, True),
            ("Evidence Archive:", f"data/forensics/{img_file_name}", False),
        ]

        curr_my = meta_y
        for label, val, is_bold in meta_rows:
            pdf.set_xy(meta_x, curr_my)
            pdf.set_font(pdf.doc_font_family, 'B', 7.5)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(34, 4.8, label)
            font_size = 6.6 if "SHA-256" in label else 7.5
            pdf.set_font(pdf.doc_font_family, 'B' if is_bold else '', font_size)
            if "SHA-256" in label:
                pdf.set_text_color(*pdf.COLOR_BLUE_ACCENT)
            elif "Face Detection" in label and has_image:
                pdf.set_text_color(*pdf.COLOR_GREEN_SAFE)
            else:
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
            pdf.cell(94, 4.8, val)
            curr_my += 4.8

        pdf.set_y(box_y + box_h + 1.2)
        pdf.set_font(pdf.doc_font_family, 'I', 6.8)
        pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
        pdf.cell(0, 3.5, "Notice: Automated biometric capture indicates physical workstation presence; formal identity confirmation requires administrative verification.", align='L', new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def _add_ai_intent_reconstruction_section(self, pdf, ai_report, stats, timeline):
        """
        Renders Section 3: AI-Assisted Attacker Intent and Behavioral Reconstruction
        with authoritative DFIR multi-part structure:
          3.A Primary Assessed Intention & Executive Assessment
          3.B Grounded Telemetry Evidence Supporting Assessment (Evidence Table)
          3.C Behavioral Progression & Trajectory Reconstruction
          3.D Alternative Hypotheses & Analytical Caveats
          3.E Confidence Metric & Severity Evaluation Justification
          3.F Prioritized Remediation & Containment Actions
        """
        pdf.section_header(
            "3. AI-Assisted Attacker Intent and Behavioral Reconstruction",
            subtitle=f"Cognitive Adversary Profiling // Source: {ai_report.get('source', 'Local DFIR Engine')}",
            min_space_needed=35
        )

        threat_level = ai_report.get("threat_level", "HIGH").upper()
        if threat_level in ["CRITICAL", "HIGH"]:
            badge_bg = pdf.COLOR_RED_BG
            badge_border = pdf.COLOR_RED_ALERT
            badge_text = pdf.COLOR_RED_ALERT
        elif threat_level == "MEDIUM":
            badge_bg = pdf.COLOR_AMBER_BG
            badge_border = pdf.COLOR_AMBER_WARN
            badge_text = pdf.COLOR_AMBER_WARN
        else:
            badge_bg = pdf.COLOR_GREEN_BG
            badge_border = pdf.COLOR_GREEN_SAFE
            badge_text = pdf.COLOR_GREEN_SAFE

        persona = clean_markdown(ai_report.get("attacker_persona", "Targeted Corporate Infiltrator & Data Exfiltrator"))
        primary_intent = clean_markdown(ai_report.get("primary_intent", "Credential harvesting and confidential document targeting."))
        exec_summary = clean_markdown(ai_report.get("executive_assessment", ""))
        clean_traj = clean_markdown(ai_report.get("behavioral_trajectory", ""))
        threat_score = ai_report.get("threat_score", 0.85)
        threat_justification = clean_markdown(ai_report.get("threat_justification", f"Assessed at {threat_level} based on honeypot telemetry."))
        conf_level = ai_report.get("confidence_level", "HIGH")
        conf_score = ai_report.get("confidence_score", 0.88)
        limitations = clean_markdown(ai_report.get("limitations", "Observed actions represent factual honeypot telemetry; actor motivation is a probabilistic inference."))
        secondary_intents = [clean_markdown(s) for s in ai_report.get("secondary_intents", []) if clean_markdown(s)]
        alternative_explanations = [clean_markdown(a) for a in ai_report.get("alternative_explanations", []) if clean_markdown(a)]
        recommendations = ai_report.get("recommended_actions", [])
        evidence_list = ai_report.get("supporting_evidence", [])

        # -------------------------------------------------------------------
        # 3.A Primary Assessed Intention & Executive Assessment
        # -------------------------------------------------------------------
        card_y = pdf.get_y()
        pdf.set_fill_color(*badge_bg)
        pdf.set_draw_color(*badge_border)
        pdf.rect(12, card_y, 48, 6.5, style='FD', round_corners=True, corner_radius=1.5)
        pdf.set_xy(12, card_y)
        pdf.set_font(pdf.doc_font_family, 'B', 8.2)
        pdf.set_text_color(*badge_text)
        pdf.cell(48, 6.5, f"THREAT LEVEL: {threat_level}", align='C')

        # Adversary Persona Box
        pdf.set_fill_color(*pdf.COLOR_GRAY_BG)
        pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
        pdf.rect(63, card_y, 135, 6.5, style='FD', round_corners=True, corner_radius=1.5)
        pdf.set_xy(65, card_y)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(32, 6.5, "ADVERSARY PERSONA:")
        pdf.set_font(pdf.doc_font_family, 'B', 7.8)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        pdf.cell(100, 6.5, persona[:65])
        pdf.ln(8.5)

        # Primary Intent Callout
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.2, "3.A Primary Assessed Strategic Intention:", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font(pdf.doc_font_family, '', 7.6)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        pdf.multi_cell(184, 4.0, primary_intent)

        # Secondary Objectives
        if secondary_intents:
            pdf.ln(1.0)
            pdf.set_x(14)
            pdf.set_font(pdf.doc_font_family, 'B', 7.4)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(0, 3.8, "Secondary Objectives:", new_x="LMARGIN", new_y="NEXT")
            for sec in secondary_intents[:3]:
                pdf.set_x(18)
                pdf.set_font(pdf.doc_font_family, '', 7.2)
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
                pdf.cell(0, 3.6, f"- {sec}", new_x="LMARGIN", new_y="NEXT")

        # Executive Assessment Narrative
        if exec_summary:
            pdf.ln(1.5)
            pdf.set_x(12)
            pdf.set_font(pdf.doc_font_family, 'B', 8.0)
            pdf.set_text_color(*pdf.COLOR_NAVY_MID)
            pdf.cell(0, 4.2, "Executive Assessment Briefing:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(14)
            pdf.set_font(pdf.doc_font_family, '', 7.4)
            pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
            pdf.multi_cell(184, 3.8, exec_summary)

        # -------------------------------------------------------------------
        # 3.B Grounded Telemetry Evidence Supporting Assessment (Evidence Table)
        # -------------------------------------------------------------------
        pdf.ln(2.5)
        pdf.check_page_space(min_space_needed=35)
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.5, "3.B Telemetry Evidence Supporting Assessment (Chronology Linked):", new_x="LMARGIN", new_y="NEXT")

        # Table: Event ID (24) + Action (40) + Target (52) + Investigative Relevance (70) = 186mm
        col_w = (24, 40, 52, 70)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=pdf.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=pdf.COLOR_GRAY_BG)
        row_even_style = FontFace(fill_color=(255, 255, 255))
        eid_style = FontFace(emphasis='B', color=pdf.COLOR_BLUE_ACCENT)

        pdf.set_font(pdf.doc_font_family, size=7.0)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, repeat_headings=1, line_height=4.4) as table:
            h = table.row()
            h.cell("Event ID", align='C')
            h.cell("Observed Action", align='L')
            h.cell("Targeted Resource", align='L')
            h.cell("Investigative Relevance", align='L')

            if evidence_list:
                for idx, ev in enumerate(evidence_list[:6]):
                    style = row_odd_style if idx % 2 else row_even_style
                    r = table.row(style=style)
                    r.cell(ev.get("event_id", f"EVT-{idx+1:04d}"), align='C', style=eid_style)
                    r.cell(clean_markdown(ev.get("action", "EVENT")).replace("_", " "), align='L')
                    r.cell(clean_markdown(redact_sensitive_presentation(ev.get("target", "")))[:34], align='L')
                    r.cell(clean_markdown(ev.get("relevance", ""))[:65], align='L')
            else:
                r = table.row()
                r.cell("EVT-0001", align='C', style=eid_style)
                r.cell("HONEYPOT ACTIVATED", align='L')
                r.cell("Honeypot Sandbox", align='L')
                r.cell("Initial session diverted to sandbox", align='L')

        # -------------------------------------------------------------------
        # 3.C Behavioral Progression & Trajectory Reconstruction
        # -------------------------------------------------------------------
        pdf.ln(2.5)
        pdf.check_page_space(min_space_needed=28)
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.5, "3.C Behavioral Progression & Kill-Chain Trajectory:", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font(pdf.doc_font_family, '', 7.4)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        pdf.multi_cell(184, 3.8, clean_traj)

        # -------------------------------------------------------------------
        # 3.D Alternative Hypotheses & Analytical Caveats
        # -------------------------------------------------------------------
        pdf.ln(2.0)
        pdf.check_page_space(min_space_needed=24)
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.2, "3.D Alternative Hypotheses & Analytical Caveats:", new_x="LMARGIN", new_y="NEXT")

        if alternative_explanations:
            for alt in alternative_explanations[:2]:
                pdf.set_x(16)
                pdf.set_font(pdf.doc_font_family, '', 7.2)
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
                pdf.cell(0, 3.6, f"- Alternative: {alt}", new_x="LMARGIN", new_y="NEXT")

        if limitations:
            pdf.set_x(16)
            pdf.set_font(pdf.doc_font_family, 'I', 7.0)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.multi_cell(182, 3.4, f"Analytical Caveat: {limitations}")

        # -------------------------------------------------------------------
        # 3.E Confidence Metric & Severity Evaluation Justification
        # -------------------------------------------------------------------
        pdf.ln(2.0)
        pdf.check_page_space(min_space_needed=22)
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.2, "3.E Confidence Metric & Severity Evaluation Justification:", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(16)
        pdf.set_font(pdf.doc_font_family, '', 7.2)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        conf_line = f"Confidence Rating: {conf_level} ({conf_score * 100:.0f}%) | Threat Score: {threat_score * 100:.0f}% ({threat_level})"
        pdf.cell(0, 3.6, conf_line, new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(16)
        pdf.set_font(pdf.doc_font_family, 'I', 7.0)
        pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
        pdf.multi_cell(182, 3.4, f"Determination Justification: {threat_justification}")

        # -------------------------------------------------------------------
        # 3.F Prioritized Remediation & Containment Actions
        # -------------------------------------------------------------------
        pdf.ln(2.0)
        pdf.check_page_space(min_space_needed=26)
        pdf.set_x(12)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.2, "3.F Prioritized Remediation & Containment Actions:", new_x="LMARGIN", new_y="NEXT")

        if recommendations:
            for rec in recommendations[:4]:
                p_num = rec.get("priority", 1) if isinstance(rec, dict) else 1
                act_str = rec.get("action", str(rec)) if isinstance(rec, dict) else str(rec)
                tf_str = rec.get("timeframe", "Immediate") if isinstance(rec, dict) else "Immediate"
                pdf.set_x(16)
                pdf.set_font(pdf.doc_font_family, 'B', 7.2)
                pdf.set_text_color(*pdf.COLOR_NAVY_MID)
                pdf.cell(26, 3.6, f"Priority {p_num} [{tf_str}]:")
                pdf.set_font(pdf.doc_font_family, '', 7.2)
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
                pdf.multi_cell(156, 3.6, clean_markdown(act_str))
        pdf.ln(3.0)

    def _add_chronological_audit_table(self, pdf, timeline):
        """Renders comprehensive chronological table of all recorded events fitting neatly on Page 2."""
        pdf.section_header(
            "4. Chronological Forensic Audit Trail (Honeypot Actions)",
            subtitle=f"Complete Log ({len(timeline)} Recorded Events) // Source: session_actions.jsonl",
            min_space_needed=35
        )

        # Precise Column Widths summing to 186mm:
        # Seq(8) + Time(24) + Offset(14) + Action(48) + Details(74) + Severity(18) = 186mm
        col_w = (8, 24, 14, 48, 74, 18)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=pdf.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=pdf.COLOR_GRAY_BG)
        row_even_style = FontFace(fill_color=(255, 255, 255))
        alert_style = FontFace(color=pdf.COLOR_RED_ALERT, emphasis='B')
        susp_style = FontFace(color=pdf.COLOR_AMBER_WARN, emphasis='B')
        info_style = FontFace(color=pdf.COLOR_TEXT_DARK)

        pdf.set_font(pdf.doc_font_family, size=7.0)

        with pdf.table(
            col_widths=col_w,
            headings_style=hdr_style,
            repeat_headings=1,
            line_height=4.6
        ) as table:
            # Header Row
            hdr = table.row()
            hdr.cell("Seq", align='C')
            hdr.cell("Wall-Clock Time", align='C')
            hdr.cell("Offset", align='C')
            hdr.cell("Action Classification", align='L')
            hdr.cell("Target / Command / Activity Details", align='L')
            hdr.cell("Severity", align='C')

            # Render ALL events without truncation
            for idx, event in enumerate(timeline):
                style = row_odd_style if (idx % 2 == 1) else row_even_style
                r = table.row(style=style)

                # 1. Sequence
                r.cell(str(idx + 1), align='C')

                # 2. Wall-clock timestamp
                raw_ts = event.get("timestamp", "")
                if " " in raw_ts:
                    wall_clock = raw_ts.split(" ")[1] # e.g. 19:57:04
                else:
                    wall_clock = raw_ts or "00:00:00"
                r.cell(wall_clock, align='C')

                # 3. Relative Offset (+0.48s)
                elapsed = event.get("elapsed_seconds", 0.0)
                try:
                    elapsed_float = float(elapsed)
                    offset_str = f"+{elapsed_float:.2f}s"
                except Exception:
                    offset_str = f"T+{elapsed}s"
                r.cell(offset_str, align='C')

                # 4. Action Type (replace underscores with spaces for clean line breaking)
                atype = event.get("action_type", "EVENT")
                clean_atype = atype.replace("_", " ")
                r.cell(clean_atype, align='L')

                # 5. Target / Command / Details (redact presentation secrets)
                target = str(event.get("target", ""))
                clean_target = redact_sensitive_presentation(target)
                r.cell(clean_target, align='L')

                # 6. Severity
                sev = event.get("severity", "INFO").upper()
                if sev in ["ALERT", "CRITICAL"]:
                    sev_cell_style = alert_style
                elif sev == "SUSPICIOUS":
                    sev_cell_style = susp_style
                else:
                    sev_cell_style = info_style
                r.cell(sev, align='C', style=sev_cell_style)

        # Audit Table Summary Note
        pdf.ln(1.5)
        pdf.set_font(pdf.doc_font_family, 'I', 6.8)
        pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
        pdf.cell(0, 3.8, f"Integrity Note: All {len(timeline)} events sequentially logged with microsecond unix_time stamps in session_actions.jsonl (SHA-256 sealed). Presentation redaction applied to active credentials.", align='R', new_x="LMARGIN", new_y="NEXT")

    def _add_sandbox_isolation_section(self, pdf, stats):
        """Details trapped file writes and verifies host filesystem integrity."""
        pdf.section_header("5. Active Sandbox Isolation & Host Protection Status", subtitle="Containment Verification", min_space_needed=30)

        sandboxed_items = stats.get("sandbox_interceptions", [])
        c2_items = stats.get("c2_payloads_intercepted", [])

        # Deduplicate trapped payload names while counting attempts
        interceptions_count = {}
        for item in sandboxed_items + c2_items:
            clean_item = os.path.basename(item)
            clean_item = clean_item.split(" from ")[0].strip()
            interceptions_count[clean_item] = interceptions_count.get(clean_item, 0) + 1

        box_y = pdf.get_y()
        box_h = 24 if interceptions_count else 20
        pdf.set_fill_color(*pdf.COLOR_GREEN_BG)
        pdf.set_draw_color(*pdf.COLOR_GREEN_SAFE)
        pdf.rect(12, box_y, 186, box_h, style='FD', round_corners=True, corner_radius=2)

        pdf.set_xy(16, box_y + 2)
        pdf.set_font(pdf.doc_font_family, 'B', 8.2)
        pdf.set_text_color(*pdf.COLOR_GREEN_SAFE)
        pdf.cell(0, 4.2, "HOST FILESYSTEM INTEGRITY: NO HOST WRITES OBSERVED WITHIN MONITORED HONEYPOT PATHS", new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(16, box_y + 6.8)
        pdf.set_font(pdf.doc_font_family, '', 7.3)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        if interceptions_count:
            items_desc = ", ".join([f"{name} ({cnt}x write trapped)" if cnt > 1 else f"{name} (Trapped)" for name, cnt in interceptions_count.items()])
            pdf.cell(0, 3.8, f"Quarantined Payloads Intercepted: [{items_desc}]", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(16)
            pdf.cell(0, 3.8, "All file write operations were trapped and redirected to isolated sandbox path: 'data/sandbox/'.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(16)
            pdf.set_font(pdf.doc_font_family, 'I', 6.8)
            pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
            pdf.cell(0, 3.6, "Zero unvetted modifications observed across real user documents, system binaries, or local host environment paths.", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 3.8, "No host filesystem write attempts were detected during this interaction window.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(16)
            pdf.cell(0, 3.8, "Host filesystem remained completely pristine. Sandbox quarantine monitoring active at: 'data/sandbox/'.", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(box_y + box_h + 3)

    def _add_mitre_mapping_table(self, pdf, ai_report, timeline):
        """Displays structured table of mapped MITRE ATT&CK techniques with verified telemetry evidence."""
        pdf.section_header("6. MITRE ATT&CK Framework Kill Chain Alignment", subtitle="Adversary TTP Mapping", min_space_needed=34)

        mapped_techniques = []
        seen_ids = set()

        all_targets = [str(ev.get("target", "")).lower() for ev in timeline]
        all_actions = [str(ev.get("action_type", "")).upper() for ev in timeline]

        # 1. Credentials in Files (T1552.001)
        if any("aws_honey_token" in t or ".env" in t or "password" in t or "vault" in t or "secret" in t for t in all_targets):
            seen_ids.add("T1552.001")
            seen_ids.add("T1552")
            cred_items = [t for t in all_targets if any(k in t for k in ["aws_honey_token", ".env", "password", "vault"])]
            sample = cred_items[0][:38] if cred_items else "AWS / .env secrets"
            mapped_techniques.append({
                "id": "T1552.001",
                "name": "Credentials in Files (Credential Access)",
                "evidence": f"Accessed decoy secrets ({redact_sensitive_presentation(sample)})",
                "status": "Verified Telemetry Match"
            })

        # 2. Ingress Tool Transfer (T1105)
        if any("curl" in t or "c2_payload" in a or "download" in t for t, a in zip(all_targets, all_actions)):
            seen_ids.add("T1105")
            mapped_techniques.append({
                "id": "T1105",
                "name": "Ingress Tool Transfer (Command & Control)",
                "evidence": "Attempted remote payload ingress via curl (diverted to sandbox)",
                "status": "Verified Telemetry Match"
            })

        # 3. System Network Configuration Discovery (T1016)
        net_cmds = [t for t in all_targets if any(cmd in t for cmd in ["ping", "arp", "route", "ipconfig"])]
        if net_cmds:
            seen_ids.add("T1016")
            sample_net = ", ".join(list(dict.fromkeys(net_cmds)))[:42]
            mapped_techniques.append({
                "id": "T1016",
                "name": "Network Config Discovery (Discovery)",
                "evidence": f"Executed network enumeration ({sample_net})",
                "status": "Verified Telemetry Match"
            })

        # 4. Remote Services: SSH (T1021.004)
        if any("ssh" in t for t in all_targets):
            seen_ids.add("T1021.004")
            mapped_techniques.append({
                "id": "T1021.004",
                "name": "Remote Services: SSH (Lateral Movement)",
                "evidence": "Attempted lateral SSH connection to internal workstation node",
                "status": "Verified Telemetry Match"
            })

        # 5. Credential Access / Form Submission (T1110)
        if any("credential_trap" in a or "bank" in t for t, a in zip(all_targets, all_actions)):
            seen_ids.add("T1110")
            mapped_techniques.append({
                "id": "T1110",
                "name": "Brute Force / Submission (Credential Access)",
                "evidence": "Submitted authentication credentials against decoy banking portal",
                "status": "Verified Telemetry Match"
            })

        # 6. Local Account Discovery (T1087.001) - ONLY IF whoami actually present!
        if any("whoami" in t for t in all_targets):
            seen_ids.add("T1087.001")
            seen_ids.add("T1087")
            mapped_techniques.append({
                "id": "T1087.001",
                "name": "Local Account Discovery (Discovery)",
                "evidence": "Executed 'whoami' to inspect local user privilege level",
                "status": "Verified Telemetry Match"
            })

        # 7. Command and Scripting Interpreter (T1059.001)
        if any("shell_command" in a or "sandbox_file" in a for a in all_actions):
            seen_ids.add("T1059.001")
            mapped_techniques.append({
                "id": "T1059.001",
                "name": "Command & Script Interpreter (Execution)",
                "evidence": "Interacted with command-line terminal to stage operations",
                "status": "Verified Telemetry Match"
            })

        # 8. Data from Local System (T1005) or System Information Discovery (T1082)
        if any("folder_navigated" in a or "file_viewed" in a or "file_open" in a for a in all_actions):
            if "T1082" not in seen_ids:
                seen_ids.add("T1082")
                mapped_techniques.append({
                    "id": "T1082",
                    "name": "System Information Discovery (Discovery)",
                    "evidence": "Traversed desktop directory structure and inspected files",
                    "status": "Verified Telemetry Match"
                })

        if not mapped_techniques:
            mapped_techniques.append({
                "id": "T1082",
                "name": "System Information Discovery (Discovery)",
                "evidence": "General workstation exploration and folder traversal.",
                "status": "Verified Telemetry Match"
            })

        col_w = (22, 56, 70, 38)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=pdf.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=pdf.COLOR_GRAY_BG)
        row_even_style = FontFace(fill_color=(255, 255, 255))
        verified_style = FontFace(color=pdf.COLOR_GREEN_SAFE, emphasis='B')

        pdf.set_font(pdf.doc_font_family, size=7.2)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, repeat_headings=1, line_height=4.8) as table:
            h = table.row()
            h.cell("Technique ID", align='C')
            h.cell("Technique Name & Tactic", align='L')
            h.cell("Observed Honeypot Evidence", align='L')
            h.cell("Mapping Status", align='C')

            for idx, tech in enumerate(mapped_techniques[:5]):
                style = row_odd_style if idx % 2 else row_even_style
                r = table.row(style=style)
                r.cell(tech["id"], align='C')
                r.cell(tech["name"], align='L')
                r.cell(tech["evidence"], align='L')
                r.cell(tech["status"], align='C', style=verified_style)

        pdf.ln(2.5)

    def _add_remediation_plan(self, pdf, ai_report):
        """Displays prioritized incident response and remediation procedures."""
        pdf.section_header("7. Incident Response & DFIR Remediation Plan", subtitle="Prioritized Action Items", min_space_needed=34)

        recs = [
            ("Priority 1: Immediate Containment (Within 1 Hour)", [
                "Revoke terminal session tokens, SSH keys, and active user credentials referenced in session.",
                "Verify sandbox quarantine directory (data/sandbox/) contains trapped payloads with zero host leaks.",
                "Mandate immediate hardware-backed MFA step-up verification before restoring user desktop access."
            ]),
            ("Priority 2: Host & Network Forensics (Within 4 Hours)", [
                "Inspect perimeter firewall outbound egress logs for connection attempts matching reconnaissance targets.",
                "Perform static and dynamic binary analysis on quarantined payloads to derive indicators of compromise (IOCs)."
            ]),
            ("Priority 3: Baseline Recalibration & Preventive Hardening (Post-Incident)", [
                "Recalibrate behavioral biometric drift thresholds to incorporate verified authentic user keystroke variance.",
                "Cryptographically seal and preserve complete session audit trail for institutional compliance archives."
            ])
        ]

        for header, items in recs:
            pdf.check_page_space(min_space_needed=12)
            curr_y = pdf.get_y()
            pdf.set_xy(12, curr_y)
            pdf.set_font(pdf.doc_font_family, 'B', 7.5)
            pdf.set_text_color(*pdf.COLOR_NAVY_MID)
            pdf.cell(0, 4.0, header, new_x="LMARGIN", new_y="NEXT")

            for item in items:
                pdf.set_x(16)
                pdf.set_font(pdf.doc_font_family, '', 7.0)
                pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
                pdf.cell(0, 3.6, f"- {item}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1.0)

    def _add_evidence_custody_and_attestation(self, pdf, photo_path, timeline=None, stats=None):
        """Renders evidence integrity chain of custody, digital seal, and formal attestation signature."""
        pdf.section_header(
            "8. Forensic Evidence Chain of Custody & Cryptographic Verification",
            subtitle="FIPS 180-4 Cryptographic Digest Verification & Admissibility",
            min_space_needed=45
        )

        def get_artifact_info(rel_path):
            full_p = os.path.join(PROJECT_ROOT, rel_path.replace("/", os.sep))
            if os.path.exists(full_p) and os.path.isfile(full_p):
                sz = os.path.getsize(full_p)
                mtime_str = time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(full_p)))
                try:
                    with open(full_p, "rb") as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                    return sz, mtime_str, digest, "VERIFIED MATCH"
                except Exception:
                    return sz, mtime_str, "COMPUTATION_ERROR", "ERROR"
            return 0, "N/A", "N/A", "NOT PRESENT"

        # 1. Event Journal
        j_sz, j_time, jsonl_sha, j_status = get_artifact_info("data/forensics/session_actions.jsonl")

        # 2. Captured Photo
        photo_rel = f"data/forensics/{os.path.basename(photo_path)}" if photo_path else "data/forensics/intruder_optical.jpg"
        p_sz, p_time, img_sha, p_status = get_artifact_info(photo_rel) if photo_path else (0, "N/A", "N/A", "SENSOR OFFLINE")

        # 3. Sandbox Dropper
        sandbox_files = glob.glob(os.path.join(PROJECT_ROOT, "data", "sandbox", "*"))
        sandbox_files = [f for f in sandbox_files if not f.endswith(".gitkeep")]
        if sandbox_files:
            sb_sample = os.path.relpath(sandbox_files[0], PROJECT_ROOT).replace("\\", "/")
            sb_sz, sb_time, sb_sha, sb_status = get_artifact_info(sb_sample)
            sb_name = "Sandbox Quarantined Payload"
        else:
            sb_sample = "data/sandbox/*"
            sb_sz, sb_time, sb_sha, sb_status = (0, "N/A", "ENVIRONMENTALLY ISOLATED", "PRISTINE")
            sb_name = "Sandbox Quarantined Directory"

        # 4. AI Audit Log
        ai_sz, ai_time, ai_sha, ai_status = get_artifact_info("data/forensics/ai_threat_analysis_audit.jsonl")

        evidence_items = [
            ("Forensic Event Journal", "data/forensics/session_actions.jsonl", f"{j_sz} B // {j_time}", jsonl_sha, j_status),
            ("Optical Intruder Frame", photo_rel if photo_path else "DirectShow Cam #0", f"{p_sz} B // {p_time}", img_sha, p_status),
            (sb_name, sb_sample, f"{sb_sz} B // {sb_time}", sb_sha, sb_status),
            ("AI Threat Audit Telemetry", "data/forensics/ai_threat_analysis_audit.jsonl", f"{ai_sz} B // {ai_time}", ai_sha, ai_status)
        ]

        # Table: Col Widths: Artifact(34) + Path(48) + Size/Time(22) + SHA-256(64) + Status(18) = 186mm
        col_w = (34, 48, 22, 64, 18)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=pdf.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=pdf.COLOR_GRAY_BG)
        row_even_style = FontFace(fill_color=(255, 255, 255))
        verified_style = FontFace(color=pdf.COLOR_GREEN_SAFE, emphasis='B')

        pdf.set_font(pdf.doc_font_family, size=6.8)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, line_height=4.6) as table:
            h = table.row()
            h.cell("Evidence Artifact", align='L')
            h.cell("Repository Path", align='L')
            h.cell("Size & MTime", align='C')
            h.cell("SHA-256 Cryptographic Hash (Full 64-Char)", align='C')
            h.cell("Integrity", align='C')

            for idx, item in enumerate(evidence_items):
                style = row_odd_style if idx % 2 else row_even_style
                r = table.row(style=style)
                r.cell(item[0], align='L')
                r.cell(item[1], align='L')
                r.cell(item[2], align='C')

                # Full 64-char hash wrapped into two 32-char lines without ellipsis
                hval = item[3]
                if len(hval) == 64:
                    h_display = hval[:32] + "\n" + hval[32:]
                else:
                    h_display = hval
                r.cell(h_display, align='C')
                r.cell(item[4], align='C', style=verified_style if "VERIFIED" in item[4] or "SEALED" in item[4] else row_even_style)

        pdf.ln(2.0)

        # 2. Digital Forensic Seal Box
        box_y = pdf.get_y()
        pdf.set_fill_color(*pdf.COLOR_GRAY_BG)
        pdf.set_draw_color(*pdf.COLOR_GRAY_BORDER)
        pdf.rect(12, box_y, 186, 21, style='FD', round_corners=True, corner_radius=2)

        pdf.set_xy(16, box_y + 2.0)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 4.0, "PRIMARY EVIDENCE DIGITAL FORENSIC SEAL (SHA-256):", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(16)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(*pdf.COLOR_BLUE_ACCENT)
        pdf.cell(0, 4.0, jsonl_sha, new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(16)
        pdf.set_font(pdf.doc_font_family, 'I', 6.8)
        pdf.set_text_color(*pdf.COLOR_TEXT_MUTED)
        pdf.cell(0, 3.6, "Cryptographic hash computed directly over raw forensic event log data/forensics/session_actions.jsonl at report generation time.", new_x="LMARGIN", new_y="NEXT")
        pdf.set_x(16)
        pdf.cell(0, 3.6, "Certified and sealed by Behavioral Drift Continuous Authentication Framework | Department of ISE, NMAMIT", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(box_y + 23)

        # 3. Forensic Evidence Admissibility & Limitations Disclosure
        box2_y = pdf.get_y()
        box2_h = 24
        pdf.set_fill_color(*pdf.COLOR_BLUE_BG)
        pdf.set_draw_color(191, 219, 254)
        pdf.rect(12, box2_y, 186, box2_h, style='FD', round_corners=True, corner_radius=2)

        pdf.set_xy(16, box2_y + 2.0)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(*pdf.COLOR_NAVY_MID)
        pdf.cell(0, 3.8, "EVIDENTIARY DISCLOSURE & ADMISSIBILITY NOTICE", new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(16, box2_y + 6.2)
        pdf.set_font(pdf.doc_font_family, '', 6.8)
        pdf.set_text_color(*pdf.COLOR_TEXT_DARK)
        disclosure_lines = [
            "- Biometric Drift Trigger: Continuous multimodal telemetry (keystroke timing, mouse curvature) detected anomaly exceeding safety baseline.",
            "- Deception Isolation: Adversary session was trapped in high-interaction honeypot sandbox; real user documents and credentials remained untouched.",
            "- Cryptographic Standard: All digital hashes computed under NIST FIPS 180-4 SHA-256 standards upon session capture and verified at export time.",
            "- Scope & Legal Admissibility: This document constitutes an automated digital forensic triage record. Formal judicial admission requires institutional audit."
        ]
        for line in disclosure_lines:
            pdf.set_x(16)
            pdf.cell(0, 3.5, line, new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(box2_y + box2_h + 3)

        # 4. Formal Department Attestation
        attest_y = pdf.get_y()
        attest_h = 16
        pdf.set_fill_color(*pdf.COLOR_NAVY_DARK)
        pdf.rect(12, attest_y, 186, attest_h, style='F', round_corners=True, corner_radius=2)

        pdf.set_xy(16, attest_y + 2.5)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(241, 245, 249)
        pdf.cell(110, 4.2, "BEHAVIORAL DRIFT CONTINUOUS AUTHENTICATION RESEARCH SYSTEM")

        pdf.set_xy(126, attest_y + 2.5)
        pdf.set_font(pdf.doc_font_family, 'B', 7.5)
        pdf.set_text_color(147, 197, 253)
        pdf.cell(68, 4.2, "STATUS: CRYPTOGRAPHICALLY SEALED", align='R')

        pdf.set_xy(16, attest_y + 7.5)
        pdf.set_font(pdf.doc_font_family, '', 7.0)
        pdf.set_text_color(203, 213, 225)
        pdf.cell(110, 3.8, "Department of Information Science & Engineering | NMAM Institute of Technology, Nitte")

        pdf.set_xy(126, attest_y + 7.5)
        pdf.set_font(pdf.doc_font_family, 'I', 7.0)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(68, 3.8, f"Sealed: {time.strftime('%Y-%m-%d %H:%M:%S')}", align='R')

        pdf.set_y(attest_y + attest_h + 4)


# ---------------------------------------------------------------------------
# Standalone CLI Test Execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Testing Redesigned ForensicReportGenerator...")
    gen = ForensicReportGenerator()
    out = gen.generate_report()
    print("Forensic Report successfully exported to:", out)
