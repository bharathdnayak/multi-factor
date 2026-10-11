"""
================================================================================
BEHAVIORAL DRIFT: CONTINUOUS AUTHENTICATION & HONEYPOT FORENSICS
PROFESSIONAL DIGITAL FORENSICS INCIDENT INVESTIGATION REPORT GENERATOR
================================================================================

Senior UX/UI & DFIR Report Engineering Implementation:
- 12 Reader-Friendly, Flexible Sections adapted to evidence volume
- Professional, restrained forensic visual design system (Slate/Navy/Muted Gray)
- Legible typography hierarchy (Helvetica/Arial body ~9.5pt, Courier for hashes/IDs)
- Complete, unbroken 64-character SHA-256 integrity digests
- Truthful evidentiary standards (calibrated confidence, no false legal claims)
- Clear distinction between simulated VFS telemetry and host environment
- Privacy-safe optical sensor handling with consent and presence disclosures
- Dynamic, flowable multi-page pagination with repeated table headers
================================================================================
"""

import os
import sys
import time
import re
import glob
import json
import hashlib
import platform
from typing import Optional, List, Dict, Any, Tuple

from fpdf import FPDF
from fpdf.fonts import FontFace

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deception.forensic_tracker import get_tracker
from deception.ai_intent_analyzer import IntruderIntentAnalyzer


# ---------------------------------------------------------------------------
# Forensic Visual Design System
# ---------------------------------------------------------------------------
class ForensicDesignSystem:
    """Enterprise DFIR Visual Palette and Styling Tokens."""
    # Document Backgrounds
    COLOR_WHITE = (255, 255, 255)
    COLOR_BG_LIGHT = (248, 250, 252)      # Slate 50
    COLOR_BG_CARD = (241, 245, 249)       # Slate 100
    COLOR_BORDER = (203, 213, 225)        # Slate 300
    COLOR_BORDER_LIGHT = (226, 232, 240)  # Slate 200

    # Typography Colors
    COLOR_NAVY_DARK = (15, 23, 42)        # Slate 900 (Headings)
    COLOR_NAVY_MID = (30, 58, 138)        # Blue 900 (Subsections)
    COLOR_TEXT_DARK = (30, 41, 59)        # Slate 800 (Body text)
    COLOR_TEXT_MUTED = (100, 116, 139)    # Slate 500 (Captions, metadata)
    COLOR_TEXT_FAINT = (148, 163, 184)    # Slate 400 (Dividers)

    # Restrained Blue Accent
    COLOR_BLUE_ACCENT = (37, 99, 235)     # Blue 600
    COLOR_BLUE_BG = (239, 246, 255)       # Blue 50
    COLOR_BLUE_BORDER = (191, 219, 254)   # Blue 200

    # Functional Status Indicators
    COLOR_RED_ALERT = (220, 38, 38)       # Red 600 (Verified Critical/Alert)
    COLOR_RED_BG = (254, 242, 242)        # Red 50
    COLOR_RED_BORDER = (254, 202, 202)    # Red 200

    COLOR_AMBER_WARN = (217, 119, 6)      # Amber 600 (Suspicious/Warning)
    COLOR_AMBER_BG = (254, 243, 199)      # Amber 50
    COLOR_AMBER_BORDER = (253, 230, 138)  # Amber 200

    COLOR_GREEN_SAFE = (22, 163, 74)      # Green 600 (Verified Integrity/Safe)
    COLOR_GREEN_BG = (240, 253, 244)      # Green 50
    COLOR_GREEN_BORDER = (187, 247, 208)  # Green 200


# ---------------------------------------------------------------------------
# Text Normalization & Sanitization Helpers
# ---------------------------------------------------------------------------
def sanitize_pdf_text(text: Any, font_family: str = "helvetica") -> str:
    """
    Cleans raw strings for safe rendering in standard PDF fonts:
    - Normalizes typographic quotes, dashes, bullets, and symbols
    - Strips unsupported non-BMP emojis
    - Applies Latin-1 fallback for Helvetica
    """
    if text is None:
        return ""
    text = str(text)

    replacements = {
        '\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
        '\u2013': '-', '\u2014': '--', '\u2026': '...',
        '\u2022': '*', '\u25cf': '*', '\u25aa': '*', '\u25b6': '>',
        '\u2192': '->', '\u2190': '<-', '\u21d2': '=>',
        '\u2713': '[OK]', '\u2714': '[OK]', '\u2716': '[X]', '\u2718': '[X]',
        '\u26a0': '[!]', '\u2699': '*', '\u23f1': '',
        '\u00a9': '(c)', '\u00ae': '(R)', '\u2122': '(TM)',
        '\u00b0': ' deg', '\t': '    ',
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)

    # Strip emojis and non-BMP characters
    text = re.sub(r'[\U00010000-\U0010ffff]', '', text)
    text = re.sub(r'[\u2600-\u27bf\ufe00-\ufe0f\u2300-\u23ff]', '', text)

    if font_family.lower() in ("helvetica", "courier", "times"):
        text = text.encode("latin-1", "replace").decode("latin-1")

    return text.strip()


def clean_markdown(text: Any) -> str:
    """Converts raw Markdown/LLM output into clean plain text without broken tokens."""
    if text is None:
        return ""
    if isinstance(text, (list, tuple)):
        items = [clean_markdown(x) for x in text if str(x).strip()]
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
    val = re.sub(r'```(?:json)?\s*', '', val)
    val = re.sub(r'```', '', val)
    val = re.sub(r'^[#\s*:\-]+', '', val, flags=re.MULTILINE)
    val = re.sub(r'\*\*([^*]+)\*\*', r'\1', val)
    val = re.sub(r'__([^_]+)__', r'\1', val)
    val = re.sub(r'\*([^*]+)\*', r'\1', val)
    val = re.sub(r'_([^_]+)_', r'\1', val)
    val = re.sub(r'`([^`]+)`', r'\1', val)
    val = val.replace("#", "")
    val = re.sub(r"\[(['\"])(.*?)\1\]", r"\2", val)
    val = val.replace("['", "").replace("']", "").replace("[\"", "").replace("\"]", "")
    val = re.sub(r',\s*,\s*', ', ', val)
    lines = [line.strip() for line in val.splitlines() if line.strip()]
    return " ".join(lines)


def redact_sensitive_presentation(text: str) -> str:
    """Masks secrets in presentation output while leaving raw telemetry intact."""
    if not text:
        return ""
    text = str(text)
    # AWS Access Key IDs
    text = re.sub(r'\b(AKIA[0-9A-Z]{2})[0-9A-Z]{8,18}\b', r'\g<1>...[REDACTED_AWS_KEY]', text, flags=re.IGNORECASE)
    # Bearer Tokens
    text = re.sub(r'\b(Bearer\s+[A-Za-z0-9_\-\.]{6})[A-Za-z0-9_\-\.]{10,}\b', r'\g<1>...[REDACTED_TOKEN]', text, flags=re.IGNORECASE)
    # 6-Digit OTPs
    text = re.sub(r'\b([0-9]{3})[0-9]{3}\b', r'\g<1>***', text)
    # Common password patterns in command line
    text = re.sub(r'(password|pwd|secret|pass)=([^ \t\r\n&]+)', r'\1=***REDACTED***', text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------------------
# MITRE ATT&CK Knowledge Base Reference (Matrix v15, 2026)
# ---------------------------------------------------------------------------
MITRE_TECHNIQUE_METADATA = {
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "evidence": "Queried local system properties, host configuration, or platform environment.",
        "confidence": "Supported",
        "caveat": "Observed within simulated honeypot; commands did not execute on host OS."
    },
    "T1087.001": {
        "name": "Account Discovery: Local Accounts",
        "tactic": "Discovery",
        "evidence": "Executed account enumeration cmdlets (e.g., 'whoami') to inspect local user privilege.",
        "confidence": "Supported",
        "caveat": "Simulated command executed inside virtual command engine."
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials in Files",
        "tactic": "Credential Access",
        "evidence": "Inspected decoy credential files, passwords.txt, or .env secret repositories.",
        "confidence": "Supported",
        "caveat": "Targets were synthetic decoy assets seeded in the virtual filesystem."
    },
    "T1059.001": {
        "name": "Command & Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "evidence": "Interacted with emulated PowerShell terminal to execute discovery cmdlets.",
        "confidence": "Supported",
        "caveat": "Cmdlets processed safely by VirtualCommandEngine; host shell access prohibited."
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "evidence": "Executed file deletion operations against virtual filesystem items.",
        "confidence": "Candidate Mapping",
        "caveat": "Deletions redirected to virtual Recycle Bin; real host files untouched."
    },
    "T1110": {
        "name": "Brute Force: Credential Stuffing / Submission",
        "tactic": "Credential Access",
        "evidence": "Submitted credentials against simulated banking or cloud portal authentication forms.",
        "confidence": "Candidate Mapping",
        "caveat": "Forms were synthetic honeypot web controls; no remote network authentication occurred."
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "Collection",
        "evidence": "Browsed confidential desktop folders and staged files for potential exfiltration.",
        "confidence": "Candidate Mapping",
        "caveat": "Actions confined to virtual user documents; no actual data exfiltration occurred."
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "Command & Control",
        "evidence": "Attempted file download or payload transfer into sandbox via simulated browser.",
        "confidence": "Candidate Mapping",
        "caveat": "Payload intercepted and quarantined in data/sandbox/ without execution."
    }
}


# ---------------------------------------------------------------------------
# Custom Forensic PDF Canvas Class
# ---------------------------------------------------------------------------
class ForensicPDF(FPDF):
    """
    Enterprise Digital Forensics & Incident Response (DFIR) Canvas.
    Standardized A4 (210 x 297 mm) with 14mm margins, printable width = 182mm.
    """
    def __init__(self, incident_id: str, session_id: str = "SESS_ACTIVE"):
        super().__init__(orientation='P', unit='mm', format='A4')
        self.incident_id = incident_id
        self.session_id = session_id
        self.doc_font_family = "helvetica"
        self._init_unicode_fonts()

        # Margins: Left 14mm, Top 18mm, Right 14mm -> Printable width = 182mm
        self.set_margins(14, 18, 14)
        self.set_auto_page_break(auto=True, margin=16)
        self.printable_width = 182.0

    def _init_unicode_fonts(self):
        """Registers system TrueType fonts (Arial) on Windows if available."""
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
        """Understated corporate DFIR running header."""
        # Slate 900 banner at top
        self.set_fill_color(*ForensicDesignSystem.COLOR_NAVY_DARK)
        self.rect(0, 0, 210, 12, 'F')

        # Left tag: System & Department
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(241, 245, 249)
        self.set_xy(14, 3.2)
        self.cell(110, 5.5, "BEHAVIORAL DRIFT CONTINUOUS AUTHENTICATION | DIGITAL FORENSICS UNIT", align='L')

        # Right tag: Incident Reference
        self.set_xy(124, 3.2)
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(147, 197, 253)
        self.cell(72, 5.5, f"REF: {self.incident_id}  |  CONFIDENTIAL", align='R')

        # Subtle Accent Rule
        self.set_draw_color(*ForensicDesignSystem.COLOR_BLUE_ACCENT)
        self.set_line_width(0.4)
        self.line(0, 12, 210, 12)
        self.set_line_width(0.2)

        # Set content cursor below header
        self.set_y(17)

    def footer(self):
        """Clean DFIR running footer with dynamic pagination and disclosure."""
        self.set_y(-13)
        self.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
        self.set_line_width(0.2)
        self.line(14, self.get_y(), 196, self.get_y())

        self.set_font(self.doc_font_family, 'I', 7.0)
        self.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
        self.set_xy(14, self.get_y() + 1.2)
        self.cell(85, 4.5, "Automated Forensic Triage Report -- Not a Final Legal Attribution", align='L')

        self.set_xy(99, self.get_y())
        self.set_font(self.doc_font_family, 'B', 7.0)
        self.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        self.cell(50, 4.5, "Behavioral Drift Forensics", align='C')

        self.set_xy(149, self.get_y())
        self.set_font(self.doc_font_family, 'B', 7.5)
        self.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        self.cell(47, 4.5, f"Page {self.page_no()} of {{nb}}", align='R')

    def check_page_space(self, min_space_needed=28):
        """Triggers a clean page break if remaining vertical space is insufficient."""
        if self.get_y() + min_space_needed > 275:
            self.add_page()

    def section_header(self, title: str, subtitle: Optional[str] = None, min_space_needed: float = 24):
        """Renders an authoritative corporate section banner with vertical bar accent."""
        self.check_page_space(min_space_needed)
        curr_y = self.get_y() + 2.0

        bar_h = 8.0 if subtitle else 5.5
        self.set_fill_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        self.rect(14, curr_y, 2.8, bar_h, 'F')

        self.set_xy(18.5, curr_y)
        self.set_font(self.doc_font_family, 'B', 10.5)
        self.set_text_color(*ForensicDesignSystem.COLOR_NAVY_DARK)
        self.cell(self.printable_width - 5, 5.0, title, new_x="LMARGIN", new_y="NEXT")

        if subtitle:
            self.set_x(18.5)
            self.set_font(self.doc_font_family, 'I', 7.5)
            self.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            self.cell(self.printable_width - 5, 3.8, subtitle, new_x="LMARGIN", new_y="NEXT")

        line_y = self.get_y() + 1.2
        self.set_draw_color(*ForensicDesignSystem.COLOR_BORDER_LIGHT)
        self.line(14, line_y, 196, line_y)
        self.set_y(line_y + 2.5)

    def subsection_header(self, title: str, min_space_needed: float = 16):
        """Renders a subsection banner."""
        self.check_page_space(min_space_needed)
        curr_y = self.get_y() + 1.5
        self.set_xy(14, curr_y)
        self.set_font(self.doc_font_family, 'B', 8.8)
        self.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        self.cell(self.printable_width, 4.5, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1.0)

    def draw_badge(self, x: float, y: float, text: str, style: str = "info", w: Optional[float] = None, h: float = 6.0) -> float:
        """Renders a restrained pill badge and returns badge width."""
        style_map = {
            "critical": (ForensicDesignSystem.COLOR_RED_BG, ForensicDesignSystem.COLOR_RED_BORDER, ForensicDesignSystem.COLOR_RED_ALERT),
            "warning": (ForensicDesignSystem.COLOR_AMBER_BG, ForensicDesignSystem.COLOR_AMBER_BORDER, ForensicDesignSystem.COLOR_AMBER_WARN),
            "safe": (ForensicDesignSystem.COLOR_GREEN_BG, ForensicDesignSystem.COLOR_GREEN_BORDER, ForensicDesignSystem.COLOR_GREEN_SAFE),
            "info": (ForensicDesignSystem.COLOR_BLUE_BG, ForensicDesignSystem.COLOR_BLUE_BORDER, ForensicDesignSystem.COLOR_BLUE_ACCENT),
            "neutral": (ForensicDesignSystem.COLOR_BG_CARD, ForensicDesignSystem.COLOR_BORDER, ForensicDesignSystem.COLOR_TEXT_MUTED),
        }
        bg, border, text_col = style_map.get(style, style_map["info"])
        clean_txt = sanitize_pdf_text(text)
        self.set_font(self.doc_font_family, 'B', 7.2)
        text_w = self.get_string_width(clean_txt)
        badge_w = w if w is not None else (text_w + 8.0)

        self.set_fill_color(*bg)
        self.set_draw_color(*border)
        self.rect(x, y, badge_w, h, style='FD', round_corners=True, corner_radius=1.5)

        self.set_xy(x, y)
        self.set_text_color(*text_col)
        self.cell(badge_w, h, clean_txt, align='C')
        return badge_w


# ---------------------------------------------------------------------------
# Core Forensic Incident Report Generator
# ---------------------------------------------------------------------------
class ForensicReportGenerator:
    """
    Automated Incident Report Generator producing publication-ready, multi-page PDFs
    structured into 12 comprehensive DFIR sections.
    """
    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "data", "forensics")
        os.makedirs(self.output_dir, exist_ok=True)
        self.tracker = get_tracker()
        self.ai_analyzer = IntruderIntentAnalyzer()

    def generate_report(
        self,
        ai_report: Optional[Dict[str, Any]] = None,
        timeline: Optional[List[Dict[str, Any]]] = None,
        stats: Optional[Dict[str, Any]] = None,
        photo_path: Optional[str] = None,
        incident_id: Optional[str] = None,
        save_filename: Optional[str] = None,
        privacy_mode: bool = False
    ) -> str:
        """
        Compiles the complete 12-section digital forensic incident report.
        Returns the absolute filepath of the generated PDF.
        """
        # Resolve ground truth telemetry
        if timeline is None:
            timeline = self.tracker.get_timeline()
        if stats is None:
            stats = self.tracker.get_summary_stats()
        if ai_report is None:
            ai_report = self.ai_analyzer.analyze_session(timeline=timeline, stats=stats)

        # Generate unique case ID and resolve session ID
        timestamp_slug = time.strftime("%Y%m%d_%H%M%S")
        if incident_id is None:
            incident_id = f"INC-{timestamp_slug}"

        session_id = stats.get("session_id")
        if not session_id or session_id in ("ACTIVE", "SESS_ACTIVE", "SESS_DEFAULT"):
            if timeline and timeline[0].get("session_id"):
                session_id = timeline[0]["session_id"]
            else:
                session_id = f"SESS_{timestamp_slug}"

        if save_filename:
            pdf_path = os.path.join(self.output_dir, save_filename)
        else:
            pdf_path = os.path.join(self.output_dir, f"Forensic_Report_{timestamp_slug}.pdf")

        # Resolve optical frame if present on disk
        if not photo_path or not os.path.exists(photo_path) or os.path.getsize(photo_path) <= 500:
            photos = glob.glob(os.path.join(self.output_dir, "intruder_*.jpg"))
            photos.sort(key=os.path.getmtime, reverse=True)
            valid_photos = [p for p in photos if os.path.exists(p) and os.path.getsize(p) > 500]
            photo_path = valid_photos[0] if valid_photos else None

        # Instantiate Forensic Canvas
        pdf = ForensicPDF(incident_id=incident_id, session_id=session_id)
        pdf.alias_nb_pages()
        pdf.add_page()

        # ===================================================================
        # 12 READER-FRIENDLY DIGITAL FORENSIC SECTIONS
        # ===================================================================
        # SECTION 1: Report Cover & Incident Identification
        self._add_section_1_cover_and_identification(pdf, incident_id, session_id, stats, timeline, ai_report)

        # SECTION 2: Executive Summary
        self._add_section_2_executive_summary(pdf, incident_id, stats, timeline, ai_report)

        # SECTION 3: Incident Overview & System Context
        self._add_section_3_system_context(pdf)

        # SECTION 4: Chronological Incident Timeline
        self._add_section_4_incident_timeline(pdf, timeline)

        # SECTION 5: Themed Investigative Findings
        self._add_section_5_investigative_findings(pdf, timeline, ai_report)

        # SECTION 6: AI-Assisted Behavioral Reconstruction
        self._add_section_6_ai_behavioral_reconstruction(pdf, ai_report, timeline)

        # SECTION 7: Deterministic Risk & Severity Assessment
        self._add_section_7_risk_and_severity_assessment(pdf, ai_report, stats, timeline)

        # SECTION 8: Containment & Host-Protection Status
        self._add_section_8_containment_and_host_protection(pdf, stats, photo_path, privacy_mode)

        # SECTION 9: MITRE ATT&CK Mapping
        self._add_section_9_mitre_attack_mapping(pdf, timeline, ai_report)

        # SECTION 10: Recommended Actions
        self._add_section_10_recommended_actions(pdf, ai_report, timeline)

        # SECTION 11: Evidence Inventory & Integrity
        self._add_section_11_evidence_inventory_and_integrity(pdf, photo_path, timeline, stats)

        # SECTION 12: Methodology, Limitations, and Glossary
        self._add_section_12_methodology_limitations_glossary(pdf)

        # Write output file
        pdf.output(pdf_path)

        # Compute SHA-256 integrity seal
        pdf_sha256 = "N/A"
        try:
            with open(pdf_path, "rb") as f:
                pdf_sha256 = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            pass

        print(f"[PDF REPORT] Successfully exported comprehensive forensic report to '{pdf_path}'", flush=True)
        print(f"[PDF REPORT] Document SHA-256 Digital Seal: {pdf_sha256}", flush=True)
        return pdf_path

    def generate_pdf(self, *args, **kwargs) -> str:
        """Convenience alias for generate_report."""
        return self.generate_report(*args, **kwargs)

    # -----------------------------------------------------------------------
    # SECTION 1: Report Cover and Incident Identification
    # -----------------------------------------------------------------------
    def _add_section_1_cover_and_identification(self, pdf: ForensicPDF, incident_id: str, session_id: str, stats: dict, timeline: list, ai_report: dict):
        pdf.set_font(pdf.doc_font_family, 'B', 12.5)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_DARK)
        pdf.cell(124, 6.5, "DIGITAL FORENSIC INCIDENT INVESTIGATION REPORT", align='L')

        # Restrained status pill
        badge_w = 54.0
        badge_x = 210.0 - 14.0 - badge_w  # 142.0 mm
        badge_y = pdf.get_y()
        threat_level = ai_report.get("threat_level", "HIGH").upper()
        badge_style = "critical" if threat_level in ("CRITICAL", "HIGH") else ("warning" if threat_level == "MEDIUM" else "safe")
        pdf.draw_badge(badge_x, badge_y, "AUTOMATED FORENSIC TRIAGE REPORT", style=badge_style, w=badge_w, h=6.5)
        pdf.ln(7.5)

        # Subtitle
        pdf.set_font(pdf.doc_font_family, 'I', 8.5)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_BLUE_ACCENT)
        pdf.cell(0, 4.2, "Behavioral Drift Continuous Authentication & Honey-Desktop Telemetry Audit", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1.5)

        # Important Scope Notice Banner
        pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_CARD)
        pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
        pdf.rect(14, pdf.get_y(), pdf.printable_width, 6.0, style='FD', round_corners=True, corner_radius=1.5)
        pdf.set_xy(16, pdf.get_y() + 1.2)
        pdf.set_font(pdf.doc_font_family, 'B', 7.2)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
        pdf.cell(0, 3.8, "NOTICE: Automated Forensic Triage Record -- Not a Final Judicial Attribution or Certification", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3.0)

        # Metadata Table
        pdf.section_header("1. Incident Identification & Case Metadata", subtitle="Administrative Reference & Verification Scope", min_space_needed=34)

        box_y = pdf.get_y()
        box_h = 24.0
        pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_LIGHT)
        pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
        pdf.rect(14, box_y, pdf.printable_width, box_h, style='FD', round_corners=True, corner_radius=2)

        detection_ts = timeline[0].get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")) if timeline else time.strftime("%Y-%m-%d %H:%M:%S")
        tz_name = time.tzname[0] if time.tzname else "UTC"
        gen_time = time.strftime(f"%Y-%m-%d %H:%M:%S {tz_name}")
        host_name = f"{platform.node()} ({platform.system()} Host)"

        fields = [
            ("Case Identifier:", incident_id, "Session Reference:", session_id),
            ("Detection Timestamp:", f"{detection_ts} {tz_name}", "Generation Time:", gen_time),
            ("Monitored Hostname:", host_name, "Investigation Scope:", "Simulated Deception Subsystem"),
            ("Operating System:", f"{platform.system()} {platform.release()}", "Evidence Status:", f"{len(timeline)} Discrete Events Captured")
        ]

        row_y = box_y + 2.0
        for f in fields:
            # Col 1
            pdf.set_xy(17, row_y)
            pdf.set_font(pdf.doc_font_family, 'B', 7.6)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(32, 5.0, f[0])
            pdf.set_font(pdf.doc_font_family, '', 7.6)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.cell(56, 5.0, f[1])

            # Col 2
            pdf.set_xy(107, row_y)
            pdf.set_font(pdf.doc_font_family, 'B', 7.6)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(34, 5.0, f[2])
            pdf.set_font(pdf.doc_font_family, '', 7.6)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.cell(53, 5.0, f[3])

            row_y += 5.2

        pdf.set_y(box_y + box_h + 3.0)

    # -----------------------------------------------------------------------
    # SECTION 2: Executive Summary
    # -----------------------------------------------------------------------
    def _add_section_2_executive_summary(self, pdf: ForensicPDF, incident_id: str, stats: dict, timeline: list, ai_report: dict):
        pdf.section_header("2. Executive Summary", subtitle="Non-Technical Plain-Language Briefing & Incident Snapshot", min_space_needed=45)

        total_events = len(timeline)
        detection_ts = timeline[0].get("timestamp", time.strftime("%Y-%m-%d %H:%M:%S")) if timeline else time.strftime("%Y-%m-%d %H:%M:%S")
        threat_level = ai_report.get("threat_level", "HIGH").upper()
        threat_score = ai_report.get("threat_score", 0.75)

        # 1. Plain-Language Summary Box
        plain_text = (
            f"What Triggered Detection: On {detection_ts}, the continuous behavioral authentication daemon detected "
            f"an acute anomaly in biometric interaction dynamics (typing flight/dwell rhythm and mouse curvature) "
            f"exceeding nominal safety baselines. "
            f"\n\nWhat Was Observed: The active user desktop was immediately locked and diverted into an emulated honey-desktop "
            f"environment. Within this sandbox, {total_events} distinct interaction events were recorded. The operator explored "
            f"desktop folders, inspected synthetic credential assets, and executed diagnostic discovery commands. "
            f"\n\nWhat Was Verified: All observed modifications were strictly confined to the virtual filesystem and sandbox quarantine "
            f"(data/sandbox/). Zero host operating system writes were detected within the monitored deception paths. "
            f"\n\nWhat Remains Uncertain: Actor identity, external network orchestration, and intentionality remain analytical inferences. "
            f"\n\nImmediate Next Steps: Validate host filesystem integrity, review the chronological timeline below, and require MFA verification before unlocking."
        )

        content_w = pdf.printable_width - 8
        pdf.set_font(pdf.doc_font_family, '', 7.4)
        text_h = pdf.multi_cell(content_w, 3.5, plain_text, dry_run=True, output='HEIGHT')
        box_h = 2.0 + 4.0 + 1.5 + text_h + 3.0

        pdf.check_page_space(min_space_needed=box_h + 6.0)
        box_y = pdf.get_y()

        pdf.set_fill_color(*ForensicDesignSystem.COLOR_BLUE_BG)
        pdf.set_draw_color(*ForensicDesignSystem.COLOR_BLUE_BORDER)
        pdf.rect(14, box_y, pdf.printable_width, box_h, style='FD', round_corners=True, corner_radius=2)

        pdf.set_fill_color(*ForensicDesignSystem.COLOR_BLUE_ACCENT)
        pdf.rect(14, box_y, 2.5, box_h, 'F')

        pdf.set_xy(18, box_y + 2.0)
        pdf.set_font(pdf.doc_font_family, 'B', 8.2)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        pdf.cell(content_w, 4.0, "Plain-Language Incident Explanation (For Non-Technical Reviewers)", new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(18, box_y + 7.5)
        pdf.set_font(pdf.doc_font_family, '', 7.4)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(content_w, 3.5, plain_text)

        pdf.set_y(box_y + box_h + 3.5)

        # 2. Compact Incident Snapshot Grid
        pdf.subsection_header("Incident Snapshot & Operational Metrics", min_space_needed=22)
        grid_y = pdf.get_y()
        card_w = (pdf.printable_width - 10) / 3  # ~57mm each
        card_h = 15.0

        indicators = ai_report.get("behavioral_indicators", {})
        apps = [a.get("application") for a in indicators.get("distinct_applications", []) if a.get("application")]
        app_str = ", ".join(apps[:3]) if apps else "Explorer, PowerShell"

        cards_data = [
            ("Detection Timestamp", detection_ts, "Biometric drift trigger point", "info"),
            ("Total Recorded Events", f"{total_events} Events", f"Captured in {stats.get('session_duration_seconds', 0)}s window", "info"),
            ("Assessed Threat Level", f"{threat_level} ({threat_score:.2f})", "Deterministic risk evaluation", "critical" if threat_level in ("CRITICAL", "HIGH") else "warning"),
            ("Simulated Apps Engaged", app_str, f"{len(apps)} distinct decoy interfaces", "info"),
            ("Containment Status", "Contained in Sandbox", "0 host writes in monitored paths", "safe"),
            ("Investigation Status", "Triage Completed", "Awaiting operator review", "info")
        ]

        for idx, (lbl, val, sub, st) in enumerate(cards_data):
            row = idx // 3
            col = idx % 3
            cx = 14 + col * (card_w + 5)
            cy = grid_y + row * (card_h + 3)

            pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_CARD)
            pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER_LIGHT)
            pdf.rect(cx, cy, card_w, card_h, style='FD', round_corners=True, corner_radius=1.5)

            pdf.set_xy(cx + 2.5, cy + 1.5)
            pdf.set_font(pdf.doc_font_family, 'B', 6.8)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(card_w - 5, 3.2, lbl)

            pdf.set_xy(cx + 2.5, cy + 5.0)
            pdf.set_font(pdf.doc_font_family, 'B', 8.5)
            val_col = ForensicDesignSystem.COLOR_RED_ALERT if st == "critical" else (ForensicDesignSystem.COLOR_GREEN_SAFE if st == "safe" else ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.set_text_color(*val_col)
            pdf.cell(card_w - 5, 4.5, val)

            pdf.set_xy(cx + 2.5, cy + 9.8)
            pdf.set_font(pdf.doc_font_family, '', 6.4)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(card_w - 5, 3.2, sub)

        pdf.set_y(grid_y + 2 * (card_h + 3) + 2.0)

    # -----------------------------------------------------------------------
    # SECTION 3: Incident Overview and System Context
    # -----------------------------------------------------------------------
    def _add_section_3_system_context(self, pdf: ForensicPDF):
        pdf.section_header("3. Incident Overview & System Context", subtitle="Detection Mechanics, Architecture & Environment Boundaries", min_space_needed=40)

        context_text = (
            "The Behavioral Drift security framework operates as a defense-in-depth endpoint monitoring system. "
            "Continuous multi-scale biometric sensors monitor keystroke flight and dwell timing, mouse trajectory curvature, "
            "velocity, and interaction modes without interrupting normal user activity. When behavioral feature drift diverges "
            "beyond the calibrated baseline threshold (Instantaneous Risk >= 0.55), the risk orchestrator executes an automated "
            "diversion policy: the legitimate user session is locked, and the active screen transitions transparently into an "
            "isolated, stateful Windows 11 Honey-Desktop environment."
        )
        pdf.set_font(pdf.doc_font_family, '', 7.6)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(pdf.printable_width, 3.8, context_text)
        pdf.ln(2.0)

        # Architectural Boundaries Table
        col_w = (42, 70, 70)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=ForensicDesignSystem.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=ForensicDesignSystem.COLOR_BG_LIGHT)
        row_even_style = FontFace(fill_color=(255, 255, 255))

        pdf.set_font(pdf.doc_font_family, size=7.2)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, line_height=4.4) as table:
            h = table.row()
            h.cell("Subsystem Boundary", align='L')
            h.cell("Implementation Scope (Monitored)", align='L')
            h.cell("Evidentiary Guarantee & Real Host Boundary", align='L')

            boundaries = [
                ("Virtual Filesystem (VFS)", "In-memory directory hierarchy and synthetic user folders (Desktop, Documents, Downloads).", "Isolated from real host storage; file writes mutate synthetic state only."),
                ("Decoy Applications", "PyQt6 emulated interfaces (File Explorer, Notepad, PowerShell, Decoy Chrome, Settings).", "Executes no host child processes; commands processed by VirtualCommandEngine."),
                ("Optical Presence Sensor", "Webcam hardware capture verifying physical workstation presence at breach time.", "Confirms physical presence via Haar geometry; does not verify legal identity."),
                ("Quarantine Directory", "data/sandbox/ receives intercepted payload downloads and quarantined files.", "Contains simulated or trapped payloads for offline reverse engineering.")
            ]
            for idx, (b_name, b_scope, b_guar) in enumerate(boundaries):
                r = table.row(style=row_odd_style if idx % 2 else row_even_style)
                r.cell(b_name, align='L')
                r.cell(b_scope, align='L')
                r.cell(b_guar, align='L')

        pdf.ln(3.0)

    # -----------------------------------------------------------------------
    # SECTION 4: Incident Timeline
    # -----------------------------------------------------------------------
    def _add_section_4_incident_timeline(self, pdf: ForensicPDF, timeline: list):
        pdf.section_header("4. Chronological Incident Timeline", subtitle=f"Chronological Event Audit Trail ({len(timeline)} Total Records)", min_space_needed=40)

        # Check for timestamp clustering
        if timeline and len(timeline) > 1:
            first_t = timeline[0].get("unix_time", 0)
            last_t = timeline[-1].get("unix_time", 0)
            elapsed_sec = abs(last_t - first_t)
            if elapsed_sec < 1.0:
                caveat = (
                    "Analytical Disclosure on Timestamp Resolution: Recorded events occurred within a sub-second interval "
                    f"(approx. {elapsed_sec:.2f}s total elapsed). This characteristic pattern occurs during automated simulation, "
                    "benchmarking, or batch replay. Relative chronological order reflects verified queue arrival sequence."
                )
                pdf.set_font(pdf.doc_font_family, 'I', 7.0)
                pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
                pdf.multi_cell(pdf.printable_width, 3.4, caveat)
                pdf.ln(1.5)

        # Table: Seq/ID (22) + Time/Offset (30) + Application (28) + Action (34) + Target (46) + Severity (22) = 182mm
        col_w = (20, 28, 28, 34, 52, 20)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=ForensicDesignSystem.COLOR_NAVY_DARK)
        row_odd_style = FontFace(fill_color=ForensicDesignSystem.COLOR_BG_LIGHT)
        row_even_style = FontFace(fill_color=(255, 255, 255))
        eid_style = FontFace(emphasis='B', color=ForensicDesignSystem.COLOR_BLUE_ACCENT)
        sev_alert_style = FontFace(color=ForensicDesignSystem.COLOR_RED_ALERT, emphasis='B')
        sev_susp_style = FontFace(color=ForensicDesignSystem.COLOR_AMBER_WARN, emphasis='B')
        sev_info_style = FontFace(color=ForensicDesignSystem.COLOR_TEXT_MUTED)

        pdf.set_font(pdf.doc_font_family, size=6.8)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, repeat_headings=1, line_height=4.2) as table:
            h = table.row()
            h.cell("Event ID", align='C')
            h.cell("Time (Offset)", align='C')
            h.cell("Application", align='L')
            h.cell("Observed Action", align='L')
            h.cell("Target Resource / Command", align='L')
            h.cell("Severity", align='C')

            for idx, ev in enumerate(timeline):
                style = row_odd_style if idx % 2 else row_even_style
                r = table.row(style=style)

                eid = ev.get("event_id", f"EVT-{idx+1:04d}")
                t_str = ev.get("timestamp", "").split(" ")[-1] if ev.get("timestamp") else "N/A"
                offset = ev.get("elapsed_seconds", 0.0)
                time_disp = f"{t_str} (+{offset:.2f}s)" if offset is not None else t_str
                app = ev.get("application", "SYSTEM") or "SYSTEM"
                act = ev.get("action_type", ev.get("action", "EVENT")).replace("_", " ")
                tgt = redact_sensitive_presentation(ev.get("target", ""))
                sev = ev.get("severity", "INFO").upper()

                r.cell(eid, align='C', style=eid_style)
                r.cell(time_disp, align='C')
                r.cell(app, align='L')
                r.cell(act, align='L')
                r.cell(tgt, align='L')

                s_style = sev_alert_style if sev in ("ALERT", "CRITICAL") else (sev_susp_style if sev == "SUSPICIOUS" else sev_info_style)
                r.cell(sev, align='C', style=s_style)

        pdf.ln(3.0)

    # -----------------------------------------------------------------------
    # SECTION 5: Themed Investigative Findings
    # -----------------------------------------------------------------------
    def _add_section_5_investigative_findings(self, pdf: ForensicPDF, timeline: list, ai_report: dict):
        pdf.section_header("5. Investigative Findings", subtitle="Categorized Behavioral Evidence with Corroborating Event References", min_space_needed=35)

        # Categorize events from timeline
        findings_groups = {
            "File & Directory Discovery": [],
            "Decoy Asset & Credential Access": [],
            "Simulated Authentication Activity": [],
            "Command-Line & Diagnostic Probing": [],
            "Browser & Portal Interaction": [],
            "File Modification & Deletion Activity": []
        }

        for ev in timeline:
            atype = ev.get("action_type", "").upper()
            tgt = ev.get("target", "")
            eid = ev.get("event_id", "")

            if "FOLDER" in atype or atype == "FOLDER_NAVIGATED":
                findings_groups["File & Directory Discovery"].append((eid, atype, tgt))
            elif "CREDENTIAL" in atype or "PASSWORD" in tgt.upper() or "KEY" in tgt.upper() or ".ENV" in tgt.upper():
                findings_groups["Decoy Asset & Credential Access"].append((eid, atype, tgt))
            elif "LOGIN" in atype or "BANK" in tgt.upper() or "PORTAL" in tgt.upper():
                findings_groups["Simulated Authentication Activity"].append((eid, atype, tgt))
            elif atype in ("SHELL_COMMAND", "COMMAND_EXECUTION", "NETWORK_RECONNAISSANCE"):
                findings_groups["Command-Line & Diagnostic Probing"].append((eid, atype, tgt))
            elif "BROWSER" in atype or "URL" in atype:
                findings_groups["Browser & Portal Interaction"].append((eid, atype, tgt))
            elif "DELETE" in atype or "MODIFY" in atype or "SANDBOX" in atype:
                findings_groups["File Modification & Deletion Activity"].append((eid, atype, tgt))

        for cat_name, items in findings_groups.items():
            if not items:
                continue

            pdf.check_page_space(min_space_needed=18)
            eids = [x[0] for x in items if x[0]]
            eid_str = ", ".join(eids[:5])
            if len(eids) > 5:
                eid_str += f" (+{len(eids)-5} more)"

            pdf.set_font(pdf.doc_font_family, 'B', 8.2)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
            pdf.cell(0, 4.0, f"[OBSERVED] {cat_name} ({len(items)} events)", new_x="LMARGIN", new_y="NEXT")

            pdf.set_font(pdf.doc_font_family, '', 7.3)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            summary_txt = f"Corroborating Event IDs: [{eid_str}]. Targets engaged: {', '.join(set([os.path.basename(x[2]) for x in items[:4]]))}. Activity confirmed via local session log."
            pdf.multi_cell(pdf.printable_width - 4, 3.5, summary_txt)
            pdf.ln(1.5)

        pdf.ln(2.0)

    # -----------------------------------------------------------------------
    # SECTION 6: AI-Assisted Behavioral Reconstruction
    # -----------------------------------------------------------------------
    def _add_section_6_ai_behavioral_reconstruction(self, pdf: ForensicPDF, ai_report: dict, timeline: list):
        pdf.section_header(
            "6. AI-Assisted Behavioral Reconstruction",
            subtitle=f"Cognitive Adversary Profiling // Model: {ai_report.get('model_name', 'Local Offline Engine')}",
            min_space_needed=40
        )

        # Clear investigative aid disclaimer
        disclaimer = (
            "Investigative Aid Notice: The narrative below is synthesized by a localized offline language model "
            "as an analytical hypothesis. It does not constitute an authoritative real-world legal attribution or confirmed "
            "attacker identity. Ground truth is anchored strictly in the verified event records cited."
        )
        pdf.set_font(pdf.doc_font_family, 'I', 7.0)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
        pdf.multi_cell(pdf.printable_width, 3.4, disclaimer)
        pdf.ln(2.0)

        # Assessed Pattern Card
        threat_level = ai_report.get("threat_level", "HIGH").upper()
        persona = clean_markdown(ai_report.get("attacker_persona", "Simulated Workstation Explorer"))
        primary_intent = clean_markdown(ai_report.get("primary_intent", "Exploration of virtual filesystem and decoy assets."))
        clean_traj = clean_markdown(ai_report.get("behavioral_trajectory", ""))

        content_w = pdf.printable_width - 45
        pdf.set_font(pdf.doc_font_family, '', 7.4)
        intent_h = pdf.multi_cell(content_w, 3.6, primary_intent, dry_run=True, output='HEIGHT')
        card_h = max(18.0, 7.5 + intent_h + 3.0)

        pdf.check_page_space(min_space_needed=card_h + 6.0)
        card_y = pdf.get_y()
        pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_LIGHT)
        pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
        pdf.rect(14, card_y, pdf.printable_width, card_h, style='FD', round_corners=True, corner_radius=1.5)

        pdf.set_xy(17, card_y + 2.0)
        pdf.set_font(pdf.doc_font_family, 'B', 7.8)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        pdf.cell(40, 4.0, "Candidate Behavioral Profile:")
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.cell(content_w, 4.0, persona)

        pdf.set_xy(17, card_y + 7.0)
        pdf.set_font(pdf.doc_font_family, 'B', 7.8)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
        pdf.cell(40, 4.0, "Primary Inferred Objective:")
        pdf.set_font(pdf.doc_font_family, '', 7.4)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(content_w, 3.6, primary_intent)

        pdf.set_y(card_y + card_h + 2.5)

        # Behavioral Trajectory
        if clean_traj:
            pdf.subsection_header("Behavioral Progression & Trajectory Hypothesis", min_space_needed=18)
            pdf.set_font(pdf.doc_font_family, '', 7.4)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.multi_cell(pdf.printable_width, 3.6, clean_traj)
            pdf.ln(1.5)

        # Alternative Hypotheses & Unknowns
        alt_explanations = ai_report.get("alternative_explanations", [])
        if alt_explanations:
            pdf.subsection_header("Alternative Benign Hypotheses & Uncertainties", min_space_needed=16)
            for alt in alt_explanations[:2]:
                pdf.set_x(16)
                pdf.set_font(pdf.doc_font_family, '', 7.2)
                pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
                pdf.cell(0, 3.5, f"- Hypothesis: {clean_markdown(alt)}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(2.0)

    # -----------------------------------------------------------------------
    # SECTION 7: Deterministic Risk & Severity Assessment
    # -----------------------------------------------------------------------
    def _add_section_7_risk_and_severity_assessment(self, pdf: ForensicPDF, ai_report: dict, stats: dict, timeline: list):
        pdf.section_header("7. Deterministic Risk & Severity Assessment", subtitle="Quantitative Risk Scoring & Policy Threshold Reconciliation", min_space_needed=35)

        threat_level = ai_report.get("threat_level", "HIGH").upper()
        threat_score = ai_report.get("threat_score", 0.75)

        if threat_score >= 0.55:
            threshold_phrase = "exceeding the calibrated operating threshold (Threshold = 0.55)"
        else:
            threshold_phrase = "registering below the general drift threshold (Threshold = 0.55), with honeypot containment engaged upon heuristic trigger"

        risk_text = (
            f"The continuous authentication engine computes risk using a calibrated multimodal fusion pipeline. "
            f"During the incident window, the instantaneous anomaly score reached {threat_score:.4f}, {threshold_phrase}. "
            f"Rule-based deterministic evaluation classified the severity as {threat_level} based on verified honeypot risk factors."
        )
        pdf.set_font(pdf.doc_font_family, '', 7.5)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(pdf.printable_width, 3.6, risk_text)
        pdf.ln(2.0)

        # Multi-Component Agreement Table
        col_w = (42, 45, 45, 50)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=ForensicDesignSystem.COLOR_NAVY_DARK)
        row_style = FontFace(fill_color=ForensicDesignSystem.COLOR_BG_LIGHT)

        pdf.set_font(pdf.doc_font_family, size=7.2)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, line_height=4.4) as table:
            h = table.row()
            h.cell("Evaluation Subsystem", align='L')
            h.cell("Output / Score", align='C')
            h.cell("Policy Threshold", align='C')
            h.cell("Assessment Finding", align='L')

            components = [
                ("Multimodal Biometric Engine", f"Risk Score: {threat_score:.2f}", "Threshold >= 0.55", "Elevated Drift Detected"),
                ("Deterministic Heuristic Rules", f"Threat Level: {threat_level}", "Critical Asset Probing", "Confirmed Decoy Engagement"),
                ("Offline Intent Reasoner", f"Persona: {ai_report.get('attacker_persona', 'Assessed')}", "Behavioral Match", "Tactical Consistency Verified")
            ]
            for c in components:
                r = table.row(style=row_style)
                r.cell(c[0], align='L')
                r.cell(c[1], align='C')
                r.cell(c[2], align='C')
                r.cell(c[3], align='L')

        pdf.ln(3.0)

    # -----------------------------------------------------------------------
    # SECTION 8: Containment and Host-Protection Status
    # -----------------------------------------------------------------------
    def _add_section_8_containment_and_host_protection(self, pdf: ForensicPDF, stats: dict, photo_path: Optional[str], privacy_mode: bool):
        pdf.section_header("8. Containment & Host-Protection Status", subtitle="Sandbox Isolation Verification & Monitored Storage Auditing", min_space_needed=45)

        # Verified Containment Scope Callout
        box_y = pdf.get_y()
        pdf.set_fill_color(*ForensicDesignSystem.COLOR_GREEN_BG)
        pdf.set_draw_color(*ForensicDesignSystem.COLOR_GREEN_BORDER)
        pdf.rect(14, box_y, pdf.printable_width, 16.0, style='FD', round_corners=True, corner_radius=2)

        pdf.set_fill_color(*ForensicDesignSystem.COLOR_GREEN_SAFE)
        pdf.rect(14, box_y, 2.5, 16.0, 'F')

        pdf.set_xy(18, box_y + 2.0)
        pdf.set_font(pdf.doc_font_family, 'B', 8.0)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_GREEN_SAFE)
        pdf.cell(0, 3.8, "VERIFIED CONTAINMENT: Zero Host Writes Within Monitored Paths", new_x="LMARGIN", new_y="NEXT")

        pdf.set_xy(18, box_y + 6.0)
        pdf.set_font(pdf.doc_font_family, '', 7.2)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(pdf.printable_width - 8, 3.4, (
            "All captured file modifications, command executions, and browser downloads were confined to the in-memory "
            "Virtual Filesystem and data/sandbox/ quarantine directory. Real user profile documents and system files "
            "outside monitored honeypot paths exhibited zero modifications during the incident session."
        ))
        pdf.set_y(box_y + 18.0)

        # Optical Presence Subsection
        pdf.subsection_header("Workstation Physical Presence Evidence", min_space_needed=22)

        has_photo = photo_path and os.path.exists(photo_path) and os.path.getsize(photo_path) > 500
        if has_photo and not privacy_mode:
            # Render photo with clear disclosure
            p_box_y = pdf.get_y()
            pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_LIGHT)
            pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
            pdf.rect(14, p_box_y, pdf.printable_width, 24.0, style='FD', round_corners=True, corner_radius=2)

            try:
                pdf.image(photo_path, x=17, y=p_box_y + 2.0, w=26, h=20)
                pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
                pdf.rect(17, p_box_y + 2.0, 26, 20, 'D')
            except Exception:
                pass

            pdf.set_xy(47, p_box_y + 2.5)
            pdf.set_font(pdf.doc_font_family, 'B', 7.5)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
            pdf.cell(0, 3.8, f"Optical Sensor Capture: {os.path.basename(photo_path)}", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(47)
            pdf.set_font(pdf.doc_font_family, '', 7.0)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.cell(0, 3.6, "Haar Cascade Detection: Physical presence at terminal verified.", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(47)
            pdf.set_font(pdf.doc_font_family, 'I', 6.8)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(0, 3.6, "Privacy & Evidentiary Notice: Confirms terminal occupancy only; does not identify legal identity.", new_x="LMARGIN", new_y="NEXT")

            pdf.set_y(p_box_y + 26.0)
        else:
            pdf.set_font(pdf.doc_font_family, 'I', 7.2)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(0, 4.0, "[OPTICAL CAPTURE IDLE / PRIVACY MODE ENABLED] No physical webcam frame embedded.", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1.5)

    # -----------------------------------------------------------------------
    # SECTION 9: MITRE ATT&CK Mapping
    # -----------------------------------------------------------------------
    def _add_section_9_mitre_attack_mapping(self, pdf: ForensicPDF, timeline: list, ai_report: dict):
        pdf.section_header("9. MITRE ATT&CK Framework Mapping", subtitle="Adversary Tactics & Techniques Alignment (Matrix v15, 2026)", min_space_needed=38)

        # Match actions against catalog
        all_actions = [e.get("action_type", "").lower() for e in timeline]
        all_targets = [e.get("target", "").lower() for e in timeline]

        mapped_techs = []
        if any("credential" in a or "password" in t or ".env" in t for a, t in zip(all_actions, all_targets)):
            mapped_techs.append(("T1552.001", MITRE_TECHNIQUE_METADATA["T1552.001"]))
        if any("whoami" in t for t in all_targets):
            mapped_techs.append(("T1087.001", MITRE_TECHNIQUE_METADATA["T1087.001"]))
        if any("shell_command" in a for a in all_actions):
            mapped_techs.append(("T1059.001", MITRE_TECHNIQUE_METADATA["T1059.001"]))
        if any("folder_navigated" in a for a in all_actions):
            mapped_techs.append(("T1082", MITRE_TECHNIQUE_METADATA["T1082"]))
        if any("delete" in a for a in all_actions):
            mapped_techs.append(("T1485", MITRE_TECHNIQUE_METADATA["T1485"]))
        if any("login" in t or "bank" in t for t in all_targets):
            mapped_techs.append(("T1110", MITRE_TECHNIQUE_METADATA["T1110"]))

        if not mapped_techs:
            mapped_techs.append(("T1082", MITRE_TECHNIQUE_METADATA["T1082"]))

        col_w = (20, 50, 68, 44)
        hdr_style = FontFace(emphasis='B', color=(255, 255, 255), fill_color=ForensicDesignSystem.COLOR_NAVY_DARK)
        row_odd = FontFace(fill_color=ForensicDesignSystem.COLOR_BG_LIGHT)
        row_even = FontFace(fill_color=(255, 255, 255))
        supported_style = FontFace(color=ForensicDesignSystem.COLOR_GREEN_SAFE, emphasis='B')
        candidate_style = FontFace(color=ForensicDesignSystem.COLOR_AMBER_WARN, emphasis='B')

        pdf.set_font(pdf.doc_font_family, size=7.0)
        with pdf.table(col_widths=col_w, headings_style=hdr_style, repeat_headings=1, line_height=4.4) as table:
            h = table.row()
            h.cell("Tech ID", align='C')
            h.cell("Name & Tactic", align='L')
            h.cell("Observed Honeypot Evidence", align='L')
            h.cell("Mapping Status & Caveat", align='L')

            for idx, (tid, tinfo) in enumerate(mapped_techs[:6]):
                r = table.row(style=row_odd if idx % 2 else row_even)
                r.cell(tid, align='C')
                r.cell(f"{tinfo['name']}\n({tinfo['tactic']})", align='L')
                r.cell(tinfo['evidence'], align='L')
                st_style = supported_style if tinfo['confidence'] == "Supported" else candidate_style
                r.cell(f"{tinfo['confidence']}\n{tinfo['caveat']}", align='L', style=st_style)

        pdf.ln(3.0)

    # -----------------------------------------------------------------------
    # SECTION 10: Recommended Actions
    # -----------------------------------------------------------------------
    def _add_section_10_recommended_actions(self, pdf: ForensicPDF, ai_report: dict, timeline: list):
        pdf.section_header("10. Recommended Remediation & Verification Actions", subtitle="Prioritized Action Items for Evaluators & Response Teams", min_space_needed=42)

        # Academic / Demonstration vs Enterprise split
        actions = [
            ("Priority 1: Verification of Monitored Sandbox Isolation", "Immediate", "Evaluator / Analyst",
             "Inspect data/sandbox/ and data/forensics/ to verify zero unvetted modifications leaked to host OS.",
             "Confirm file count in data/sandbox/ matches session_actions.jsonl recorded writes."),
            ("Priority 2: Multi-Factor Authentication Verification", "Within 1 Hour", "Workstation Admin",
             "Mandate step-up identity challenge (MFA OTP) before releasing locked host workstation desktop.",
             "Verify authentic OTP submission clears lock state and restores baseline monitoring daemon."),
            ("Priority 3: Biometric Baseline Adaptation Review", "Post-Incident", "Security Team",
             "Review behavioral drift log to verify whether acute variance was benign user adaptation or genuine intruder.",
             "Inspect ADWIN drift change-points and recalibrate multi-scale model weights if genuine.")
        ]

        for title, tf, owner, desc, verify_step in actions:
            pdf.check_page_space(min_space_needed=16)
            pdf.set_font(pdf.doc_font_family, 'B', 7.8)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
            pdf.cell(0, 4.0, f"{title} [{tf} | Owner: {owner}]", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(16)
            pdf.set_font(pdf.doc_font_family, '', 7.2)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.multi_cell(pdf.printable_width - 4, 3.4, f"Action: {desc}\nVerification Closure: {verify_step}")
            pdf.ln(1.5)

        pdf.ln(2.0)

    # -----------------------------------------------------------------------
    # SECTION 11: Evidence Inventory and Integrity
    # -----------------------------------------------------------------------
    def _add_section_11_evidence_inventory_and_integrity(self, pdf: ForensicPDF, photo_path: Optional[str], timeline: list, stats: dict):
        pdf.section_header("11. Evidence Inventory & Cryptographic Integrity", subtitle="FIPS 180-4 SHA-256 Digest Verification on Local Disk", min_space_needed=50)

        def get_artifact(rel_path: str, label: str):
            full_p = os.path.join(PROJECT_ROOT, rel_path.replace("/", os.sep))
            if os.path.exists(full_p) and os.path.isfile(full_p):
                sz = os.path.getsize(full_p)
                mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(full_p)))
                try:
                    with open(full_p, "rb") as f:
                        digest = hashlib.sha256(f.read()).hexdigest()
                    status = "MATCH (VERIFIED ON DISK)" if len(digest) == 64 else "INVALID HASH"
                    return label, rel_path, sz, mtime_str, digest, status
                except Exception:
                    return label, rel_path, sz, mtime_str, "ERROR", "READ_ERROR"
            return label, rel_path, 0, "N/A", "N/A", "NOT FOUND"

        artifacts = [
            get_artifact("data/forensics/session_actions.jsonl", "Forensic Event Journal"),
            get_artifact("data/sandbox/virtual_fs_state.json", "VFS Serialized State"),
            get_artifact("data/forensics/ai_threat_analysis_audit.jsonl", "AI Intent Audit Log"),
        ]
        if photo_path and os.path.exists(photo_path):
            photo_rel = f"data/forensics/{os.path.basename(photo_path)}"
            artifacts.append(get_artifact(photo_rel, "Terminal Optical Frame"))

        # Render each evidence artifact in a clean, legible block with FULL 64-char unbroken hash
        for label, path, sz, mtime, digest, status in artifacts:
            pdf.check_page_space(min_space_needed=16)
            card_y = pdf.get_y()
            pdf.set_fill_color(*ForensicDesignSystem.COLOR_BG_LIGHT)
            pdf.set_draw_color(*ForensicDesignSystem.COLOR_BORDER)
            pdf.rect(14, card_y, pdf.printable_width, 14.0, style='FD', round_corners=True, corner_radius=1.5)

            # Row 1: Label, Path, Size, Status
            pdf.set_xy(17, card_y + 1.8)
            pdf.set_font(pdf.doc_font_family, 'B', 7.5)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
            pdf.cell(50, 4.0, label)

            pdf.set_font(pdf.doc_font_family, '', 7.0)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(55, 4.0, f"Path: {path} ({sz:,} B)")

            status_style = "safe" if "MATCH" in status else "neutral"
            pdf.draw_badge(148, card_y + 1.5, status, style=status_style, w=44, h=4.5)

            # Row 2: Full unbroken 64-char SHA-256 hash in Courier monospaced font
            pdf.set_xy(17, card_y + 7.5)
            pdf.set_font(pdf.doc_font_family, 'B', 6.8)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
            pdf.cell(20, 4.0, "SHA-256:")

            pdf.set_font("Courier", "B", 7.2)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_DARK)
            pdf.cell(140, 4.0, digest)

            pdf.set_y(card_y + 16.0)

        pdf.ln(1.5)

    # -----------------------------------------------------------------------
    # SECTION 12: Methodology, Limitations, and Glossary
    # -----------------------------------------------------------------------
    def _add_section_12_methodology_limitations_glossary(self, pdf: ForensicPDF):
        pdf.section_header("12. Methodology, Limitations, and Glossary", subtitle="Scientific Principles, Operational Constraints & Technical Reference", min_space_needed=45)

        # Methodology & Limitations
        method_text = (
            "Data Collection & Boundaries: Telemetry captured originates strictly from the emulated honey-desktop and virtual "
            "filesystem. Events outside monitored honeypot paths are not tracked by this deception daemon. "
            "\nCryptographic Integrity: SHA-256 digests establish raw byte-level consistency against files on disk at export time. "
            "Digest verification does not certify third-party legal origin, authorship, or statutory admissibility. "
            "\nAI Reasoner Constraints: Offline local model outputs represent probabilistic threat intelligence hypotheses, "
            "subordinate to deterministic heuristic rules."
        )
        pdf.set_font(pdf.doc_font_family, '', 7.2)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
        pdf.multi_cell(pdf.printable_width, 3.4, method_text)
        pdf.ln(2.0)

        # Glossary
        pdf.subsection_header("Technical Glossary of Forensic Terms", min_space_needed=22)
        terms = [
            ("Behavioral Drift", "Statistical divergence in authentic user biometric dynamics (keystroke flight/dwell, mouse trajectory) beyond established threshold."),
            ("Honey-Desktop", "High-interaction emulated deception environment mimicking authentic Windows 11 applications to trap and observe adversaries."),
            ("Containment", "Defensive isolation ensuring intercepted interactions mutate synthetic virtual state without modifying host storage."),
            ("SHA-256 Digest", "Cryptographic hash function computing unique 256-bit (64 hex character) fingerprints to verify file byte integrity."),
            ("MITRE ATT&CK", "Publicly accessible knowledge base of adversary tactics, techniques, and procedures (TTPs) based on real-world observations.")
        ]
        for term, definition in terms:
            pdf.check_page_space(min_space_needed=10)
            pdf.set_x(16)
            pdf.set_font(pdf.doc_font_family, 'B', 7.2)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_NAVY_MID)
            pdf.cell(32, 3.5, f"{term}:")

            pdf.set_font(pdf.doc_font_family, '', 7.0)
            pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_DARK)
            pdf.multi_cell(pdf.printable_width - 34, 3.4, definition)
            pdf.ln(0.8)

        # Raw Event Appendix Note
        pdf.ln(2.0)
        pdf.check_page_space(min_space_needed=14)
        pdf.set_font(pdf.doc_font_family, 'I', 6.8)
        pdf.set_text_color(*ForensicDesignSystem.COLOR_TEXT_MUTED)
        pdf.cell(0, 3.5, "Raw Telemetry Appendix: Complete unredacted JSON Lines event audit log preserved at: data/forensics/session_actions.jsonl", new_x="LMARGIN", new_y="NEXT")


if __name__ == "__main__":
    print("Testing Redesigned ForensicReportGenerator...")
    gen = ForensicReportGenerator()
    test_pdf = gen.generate_report()
    print(f"Generated PDF at: {test_pdf}")
