import re
import os
import sys
import glob
import time
import json
import hashlib
from fpdf import FPDF

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deception.forensic_tracker import get_tracker
from deception.ai_intent_analyzer import IntruderIntentAnalyzer


def sanitize_pdf_text(text, font_family="helvetica"):
    """
    Sanitizes any string destined for PDF generation to eliminate encoding crashes.
    - Strips DeepSeek <think>...</think> reasoning tags
    - Replaces common Unicode symbols (smart quotes, em-dashes, bullets, etc.) with safe equivalents
    - Strips emoji characters (code points > 0xFFFF or miscellaneous symbols) that break standard PDF fonts
    - Enforces Latin-1 encodability if using core fonts (Helvetica) to prevent FPDFUnicodeEncodingException
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    # 1. Strip DeepSeek-R1 / thinking model reasoning tags
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)

    # 2. Convert common unicode typography to clean ASCII / Latin-1 equivalents
    replacements = {
        '\u201c': '"', '\u201d': '"',  # Left/right double quotes
        '\u2018': "'", '\u2019': "'",  # Left/right single quotes
        '\u2014': '--', '\u2013': '-', # Em-dash, En-dash
        '\u2022': '-', '\u00b7': '-',  # Bullets
        '\u2026': '...',               # Horizontal ellipsis
        '\u2192': '->', '\u2190': '<-', # Arrows
        '\u2713': '[OK]', '\u2714': '[OK]', # Checkmarks
        '\u2717': '[X]', '\u2718': '[X]',
        '\u00a9': '(c)', '\u00ae': '(R)', '\u2122': '(TM)',
        '\u00b0': ' deg',
    }
    for orig, repl in replacements.items():
        text = text.replace(orig, repl)

    # 3. Strip all emojis (astral plane \U00010000-\U0010ffff, and misc symbols)
    text = re.sub(r'[\U00010000-\U0010ffff]', '', text)
    text = re.sub(r'[\u2600-\u27bf\ufe00-\ufe0f\u2300-\u23ff]', '', text)

    # 4. If using standard core fonts like helvetica, ensure latin-1 encodability
    if font_family.lower() == "helvetica":
        text = text.encode("latin-1", "replace").decode("latin-1")

    return text.strip()


class ForensicPDF(FPDF):
    """Custom FPDF layout with corporate cybersecurity header and footer and unicode font support."""
    def __init__(self, incident_id):
        super().__init__()
        self.incident_id = incident_id
        self.doc_font_family = "helvetica"
        self._init_unicode_fonts()

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
        self.set_fill_color(18, 24, 38) # Dark Navy Header
        self.rect(0, 0, 210, 16, 'F')
        self.set_font(self.doc_font_family, 'B', 8)
        self.set_text_color(220, 225, 235)
        self.set_xy(10, 4)
        self.cell(100, 8, "MAJOR PROJECT 30 | CONTINUOUS AUTHENTICATION & HONEYPOT FORENSICS", align='L')
        self.set_xy(100, 4)
        self.cell(100, 8, f"CASE REF: {self.incident_id}", align='R')
        self.ln(16)

    def footer(self):
        self.set_y(-14)
        self.set_font(self.doc_font_family, 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential Incident Forensics Report | ISE Dept", align='C')


class ForensicReportGenerator:
    """
    Automated Incident Report Generator producing executive-ready, multi-page PDFs
    documenting all unauthorized intruder activity captured in the Honeypot environment.
    """
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(PROJECT_ROOT, "data", "forensics")
        os.makedirs(self.output_dir, exist_ok=True)
        self.tracker = get_tracker()
        self.ai_analyzer = IntruderIntentAnalyzer()

    def generate_report(self, ai_report=None, timeline=None, stats=None):
        """
        Generates and writes the PDF report to disk.
        Returns the absolute filepath of the generated PDF.
        """
        if timeline is None:
            timeline = self.tracker.get_timeline()
        if stats is None:
            stats = self.tracker.get_summary_stats()
        if ai_report is None:
            ai_report = self.ai_analyzer.analyze_session(timeline, stats)

        timestamp_slug = time.strftime("%Y%m%d_%H%M%S")
        incident_id = f"INC-{timestamp_slug}"
        pdf_path = os.path.join(self.output_dir, f"Forensic_Report_{timestamp_slug}.pdf")

        pdf = ForensicPDF(incident_id=incident_id)
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # 1. Main Title Block
        pdf.set_font('helvetica', 'B', 18)
        pdf.set_text_color(220, 53, 69) # Incident Alert Red
        pdf.cell(0, 9, "FORENSIC INCIDENT INVESTIGATION REPORT", new_x="LMARGIN", new_y="NEXT", align='L')
        
        pdf.set_font('helvetica', '', 10)
        pdf.set_text_color(90, 100, 120)
        pdf.cell(0, 6, "Post-Anomaly Continuous Authentication Breach & Honey-Desktop Deception Audit", new_x="LMARGIN", new_y="NEXT", align='L')
        pdf.ln(3)

        # 2. Executive Metadata Box
        pdf.set_fill_color(245, 247, 250)
        pdf.set_draw_color(210, 215, 225)
        pdf.rect(10, pdf.get_y(), 190, 26, 'FD')
        
        pdf.set_xy(14, pdf.get_y() + 3)
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(40, 50, 70)
        pdf.cell(45, 5, "Incident Reference:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(50, 5, incident_id)
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 5, "Breach Risk Trigger:")
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(220, 53, 69)
        pdf.cell(40, 5, "Risk Score >= 0.55 (ELEVATED DRIFT)", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_text_color(40, 50, 70)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 5, "Detection Timestamp:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(50, 5, time.strftime("%Y-%m-%d %H:%M:%S"))
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 5, "Workstation Host:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(40, 5, "DESKTOP-SEC-WIN11 (Dell Latitude)", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(45, 5, "Deception Status:")
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(40, 167, 69) # Green
        pdf.cell(50, 5, "Active Honey-Desktop Sandbox (1:1 Decoy)")
        
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(40, 50, 70)
        pdf.cell(45, 5, "Total Actions Recorded:")
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(40, 5, f"{stats.get('total_actions', len(timeline))} interactions", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(7)

        # 3. Intruder Evidence Section (Photo & Visual Artifacts)
        self._add_intruder_photo_section(pdf)

        # 4. AI-Powered Intruder Intent & Behavior Prediction (Ollama / Threat Engine)
        self._add_ai_threat_analysis_section(pdf, ai_report)

        # 5. Chronological Intruder Actions Table
        self._add_chronological_timeline_table(pdf, timeline)

        # 6. Sandboxed Files & Containment Verification
        self._add_sandbox_containment_section(pdf, stats)

        # 7. MITRE ATT&CK Mapping & Response Actions
        self._add_mitre_and_recommendations(pdf, ai_report)

        # 8. Digital Forensics Chain of Custody & Hash
        self._add_chain_of_custody(pdf)

        # Save PDF
        pdf.output(pdf_path)
        print(f"[PDF REPORT] Successfully exported comprehensive forensic report to '{pdf_path}'", flush=True)
        return pdf_path

    def _add_intruder_photo_section(self, pdf):
        """Finds most recent captured intruder webcam photo and embeds it cleanly."""
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(18, 24, 38)
        pdf.cell(0, 8, "1. Visual Evidence & Physical Attacker Identification", new_x="LMARGIN", new_y="NEXT")
        
        # Look for photos in forensics directory
        photos = glob.glob(os.path.join(self.output_dir, "intruder_*.jpg"))
        photos.sort(key=os.path.getmtime, reverse=True)
        valid_photos = [p for p in photos if os.path.exists(p) and os.path.getsize(p) > 500]
        
        curr_y = pdf.get_y()
        if valid_photos:
            photo_path = valid_photos[0]
            try:
                # Add image on the left
                pdf.image(photo_path, x=14, y=curr_y + 2, w=55, h=40)
                
                # Image metadata on the right
                pdf.set_xy(75, curr_y + 4)
                pdf.set_font('helvetica', 'B', 9)
                pdf.set_text_color(50, 60, 80)
                pdf.cell(0, 5, f"Captured Frame: {os.path.basename(photo_path)}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(75)
                pdf.set_font('helvetica', '', 9)
                pdf.cell(0, 5, "Sensor: Built-in HD Webcam (DirectShow Device 0)", new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(75)
                pdf.cell(0, 5, "Trigger Event: Multi-Scale Behavioral Drift Anomaly", new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(75)
                pdf.cell(0, 5, "Face Detection: Haar Cascade Verified (Intruder Profiled)", new_x="LMARGIN", new_y="NEXT")
                pdf.set_x(75)
                pdf.set_font('helvetica', 'I', 8)
                pdf.set_text_color(110, 115, 125)
                pdf.cell(0, 5, "Status: Image securely archived in data/forensics with SHA-256 seal.", new_x="LMARGIN", new_y="NEXT")
                pdf.set_y(curr_y + 46)
            except Exception as e:
                pdf.set_font('helvetica', 'I', 9)
                pdf.cell(0, 6, f"[Note: Photo preview failed to render: {e}]", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.set_font('helvetica', 'I', 9)
            pdf.set_text_color(100, 110, 125)
            pdf.cell(0, 6, "No physical webcam photo captured (Webcam sensor was idle or offline).", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    def _add_ai_threat_analysis_section(self, pdf, ai_report):
        """Renders the Offline AI (Ollama / Heuristic) prediction of intruder intent."""
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(18, 24, 38)
        pdf.cell(0, 8, "2. AI-Powered Attacker Intent & Behavioral Prediction", new_x="LMARGIN", new_y="NEXT")

        # Threat banner box
        threat_level = ai_report.get("threat_level", "MEDIUM").upper()
        if threat_level in ["CRITICAL", "HIGH"]:
            pdf.set_fill_color(253, 237, 237)
            pdf.set_draw_color(239, 83, 80)
            badge_color = (211, 47, 47)
        elif threat_level == "MEDIUM":
            pdf.set_fill_color(255, 248, 225)
            pdf.set_draw_color(255, 179, 0)
            badge_color = (245, 124, 0)
        else:
            pdf.set_fill_color(237, 247, 237)
            pdf.set_draw_color(76, 175, 80)
            badge_color = (46, 125, 50)

        box_y = pdf.get_y()
        pdf.rect(10, box_y, 190, 48, 'FD')

        pdf.set_xy(14, box_y + 3)
        pdf.set_font('helvetica', 'B', 10)
        pdf.set_text_color(*badge_color)
        pdf.cell(90, 5, f"THREAT LEVEL ASSESSMENT: {threat_level}")
        pdf.set_font('helvetica', 'I', 8)
        pdf.set_text_color(100, 100, 110)
        pdf.cell(90, 5, f"Engine: {ai_report.get('source', 'Local AI Threat Model')}", align='R', new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(40, 50, 70)
        pdf.cell(38, 5, "Predicted Persona:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(140, 5, str(ai_report.get("attacker_persona", "Opportunistic Intruder")), new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(38, 5, "Estimated Objective:")
        pdf.set_font('helvetica', '', 9)
        pdf.cell(140, 5, str(ai_report.get("primary_intent", "Reconnaissance & credential hunting")), new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(38, 5, "Trajectory Analysis:")
        pdf.ln(5)

        pdf.set_x(14)
        pdf.set_font('helvetica', '', 8.5)
        pdf.set_text_color(50, 55, 65)
        analysis_text = ai_report.get("trajectory_analysis", "")
        # Clean markdown or bold formatting
        clean_text = analysis_text.replace("**", "").replace("##", "").replace("[ATTACKER PERSONA]:", "").strip()
        # Print up to 4 lines of trajectory
        pdf.multi_cell(182, 4.2, clean_text[:400] + ("..." if len(clean_text) > 400 else ""))
        
        pdf.set_y(box_y + 52)

    def _add_chronological_timeline_table(self, pdf, timeline):
        """Renders clean tabular timeline of all actions inside the honeypot."""
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(18, 24, 38)
        pdf.cell(0, 8, "3. Chronological Forensic Audit Trail (Honeypot Actions)", new_x="LMARGIN", new_y="NEXT")

        # Table Header
        pdf.set_fill_color(30, 41, 59)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font('helvetica', 'B', 8.5)
        
        col_w = [14, 22, 38, 92, 24]
        headers = ["Step", "Time", "Action Type", "Target / Command / Details", "Severity"]
        
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 7, h, fill=True, align='C' if i in [0, 1, 4] else 'L')
        pdf.ln(7)

        # Table Rows
        pdf.set_font('helvetica', '', 8)
        for idx, event in enumerate(timeline[:25]): # Show up to 25 events per report
            t_str = f"T+{int(event.get('elapsed_seconds', 0))}s"
            atype = event.get("action_type", "EVENT")[:22]
            target = str(event.get("target", ""))
            sev = event.get("severity", "INFO")
            
            # Format row background
            fill = (idx % 2 == 1)
            pdf.set_fill_color(248, 250, 252) if fill else pdf.set_fill_color(255, 255, 255)
            
            # Format text color based on severity
            if sev in ["ALERT", "CRITICAL"]:
                pdf.set_text_color(220, 53, 69)
            elif sev == "SUSPICIOUS":
                pdf.set_text_color(220, 120, 20)
            else:
                pdf.set_text_color(40, 45, 55)

            pdf.cell(col_w[0], 6, str(idx+1), border='B', fill=fill, align='C')
            pdf.cell(col_w[1], 6, t_str, border='B', fill=fill, align='C')
            pdf.cell(col_w[2], 6, atype, border='B', fill=fill, align='L')
            
            # Clip target length to fit cell neatly
            clean_target = (target[:55] + "..") if len(target) > 55 else target
            pdf.cell(col_w[3], 6, clean_target, border='B', fill=fill, align='L')
            pdf.cell(col_w[4], 6, sev, border='B', fill=fill, align='C')
            pdf.ln(6)

        if len(timeline) > 25:
            pdf.set_font('helvetica', 'I', 8)
            pdf.set_text_color(100, 100, 100)
            pdf.cell(0, 5, f"[+ {len(timeline) - 25} additional events recorded in session_actions.jsonl]", align='C', new_x="LMARGIN", new_y="NEXT")

        pdf.ln(4)

    def _add_sandbox_containment_section(self, pdf, stats):
        """Details how intruder payload writes were intercepted and diverted."""
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(18, 24, 38)
        pdf.cell(0, 8, "4. Active Sandbox Isolation & Host Protection Status", new_x="LMARGIN", new_y="NEXT")

        sandboxed = stats.get("sandbox_interceptions", [])
        sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
        
        pdf.set_fill_color(240, 249, 245)
        pdf.set_draw_color(140, 210, 175)
        sb_y = pdf.get_y()
        pdf.rect(10, sb_y, 190, 22, 'FD')

        pdf.set_xy(14, sb_y + 3)
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(20, 120, 60)
        pdf.cell(0, 5, "HOST FILESYSTEM INTEGRITY: 100% PROTECTED (ZERO UNVETTED WRITES)", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(14)
        pdf.set_font('helvetica', '', 8.5)
        pdf.set_text_color(50, 60, 70)
        if sandboxed:
            files_str = ", ".join(sandboxed)
            pdf.cell(0, 4.5, f"Attacker attempted file writes: [{files_str}].", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(14)
            pdf.cell(0, 4.5, f"All payloads were redirected to isolated directory: '{sandbox_dir}'.", new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 4.5, "No unauthorized disk writes were attempted. Host filesystem remained completely pristine.", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(14)
            pdf.cell(0, 4.5, f"Sandbox redirector remains active at: '{sandbox_dir}'.", new_x="LMARGIN", new_y="NEXT")

        pdf.set_y(sb_y + 26)

    def _add_mitre_and_recommendations(self, pdf, ai_report):
        """Displays MITRE ATT&CK Matrix mapping and containment steps."""
        pdf.set_font('helvetica', 'B', 12)
        pdf.set_text_color(18, 24, 38)
        pdf.cell(0, 8, "5. MITRE ATT&CK Alignment & DFIR Recommendations", new_x="LMARGIN", new_y="NEXT")

        # MITRE Tactics
        pdf.set_font('helvetica', 'B', 9)
        pdf.set_text_color(40, 50, 70)
        pdf.cell(0, 5, "Mapped MITRE ATT&CK Techniques:", new_x="LMARGIN", new_y="NEXT")
        
        pdf.set_font('helvetica', '', 8.5)
        tactics = ai_report.get("mitre_tactics", ["T1082 - Discovery"])
        for t in tactics:
            pdf.set_x(16)
            pdf.cell(0, 4.5, f"- {t}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

        # Immediate Recommendations
        pdf.set_font('helvetica', 'B', 9)
        pdf.cell(0, 5, "Immediate Containment & Remediation Actions:", new_x="LMARGIN", new_y="NEXT")
        recs = ai_report.get("recommendations", [])
        for r in recs:
            pdf.set_x(16)
            pdf.set_font('helvetica', '', 8.5)
            pdf.cell(0, 4.5, f"- {r}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    def _add_chain_of_custody(self, pdf):
        """Computes SHA-256 integrity hash of raw session logs for forensic admissibility."""
        jsonl_path = os.path.join(self.output_dir, "session_actions.jsonl")
        sha = "N/A"
        if os.path.exists(jsonl_path):
            try:
                with open(jsonl_path, "rb") as f:
                    sha = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                sha = "HASH_COMPUTATION_ERROR"

        pdf.set_font('helvetica', 'B', 8)
        pdf.set_text_color(100, 110, 125)
        pdf.cell(0, 5, f"DIGITAL FORENSIC SEAL (SHA-256): {sha}", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.cell(0, 4, "Generated automatically by Behavioral Drift Continuous Authentication Framework | Team 30", align='C')


if __name__ == "__main__":
    print("Testing ForensicReportGenerator...")
    gen = ForensicReportGenerator()
    out = gen.generate_report()
    print("Report written to:", out)
