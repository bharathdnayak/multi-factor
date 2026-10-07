import sys
import os
import glob
import json
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QTextEdit, QPushButton, QFrame, QSplitter, QMessageBox, QScrollArea
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QPixmap, QCursor

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from deception.ai_intent_analyzer import IntruderIntentAnalyzer
from dashboard.pdf_generator import ForensicReportGenerator
from deception.forensic_tracker import get_tracker


class ForensicDashboard(QWidget):
    """
    Verification and Forensic Recovery Dashboard.
    Loaded after owner recovery, displaying:
    1. Captured intruder webcam photo with Haar Cascade bounding box
    2. AI-Powered Attacker Intent Prediction (via local Ollama / Threat Heuristics)
    3. Chronological Honeypot activity logs (Chrome searches, folder navigations, shell commands)
    4. Sandboxed file interceptions (zero host damage verification)
    5. Direct button to export the comprehensive Forensic PDF Report.
    """
    def __init__(self):
        super().__init__()
        self.forensics_dir = os.path.join(project_dir, "data", "forensics")
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_path = os.path.join(self.forensics_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
        self.ai_analyzer = IntruderIntentAnalyzer()
        self.latest_pdf_path = None
        
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Forensic Recovery & Incident Report Dashboard | Major Project 30")
        self.resize(1080, 680)
        self.setStyleSheet("""
            QWidget {
                background-color: #121620;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel#header_lbl {
                color: #ff4757;
                font-size: 22px;
                font-weight: bold;
                padding-bottom: 8px;
            }
            QLabel#sub_lbl {
                color: #8b949e;
                font-size: 12px;
                padding-bottom: 8px;
                border-bottom: 2px solid #252d3d;
            }
            QLabel#panel_lbl {
                color: #00d2d3;
                font-size: 13px;
                font-weight: bold;
                margin-bottom: 4px;
            }
            QTextEdit {
                background-color: #0c0f17;
                color: #38ef7d;
                font-family: 'Consolas', monospace;
                font-size: 11px;
                border: 1px solid #252d3d;
                border-radius: 6px;
                padding: 6px;
            }
            QPushButton#export_btn {
                background-color: #e84118;
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                padding: 8px 16px;
                border-radius: 5px;
                border: none;
            }
            QPushButton#export_btn:hover {
                background-color: #c23616;
            }
            QPushButton#ai_btn {
                background-color: #6c5ce7;
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                padding: 8px 16px;
                border-radius: 5px;
                border: none;
            }
            QPushButton#ai_btn:hover {
                background-color: #5849be;
            }
            QPushButton#close_btn {
                background-color: #2ed573;
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                padding: 8px 20px;
                border-radius: 5px;
                border: none;
            }
            QPushButton#close_btn:hover {
                background-color: #26af5f;
            }
            QFrame#AiCard {
                background-color: #1a202c;
                border: 1px solid #2d3748;
                border-radius: 6px;
                padding: 8px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        # Header Title
        header = QLabel("🛡️ DETECTED INCIDENT REPORT & FORENSIC INTELLIGENCE")
        header.setObjectName("header_lbl")
        layout.addWidget(header)

        sub_header = QLabel("Post-Anomaly Continuous Authentication Breach Audit | Workstation: DESKTOP-SEC-WIN11")
        sub_header.setObjectName("sub_lbl")
        layout.addWidget(sub_header)

        # AI Prediction Summary Card
        self.ai_card = QFrame()
        self.ai_card.setObjectName("AiCard")
        ai_layout = QVBoxLayout()
        ai_layout.setContentsMargins(12, 10, 12, 10)
        ai_layout.setSpacing(4)
        
        ai_header_row = QHBoxLayout()
        ai_title = QLabel("🤖 AI-PREDICTED INTRUDER INTENT & BEHAVIORAL PROFILE")
        ai_title.setStyleSheet("color: #a29bfe; font-weight: bold; font-size: 13px;")
        ai_header_row.addWidget(ai_title)
        
        self.threat_badge = QLabel("THREAT: ANALYZING...")
        self.threat_badge.setStyleSheet("background-color: #e84118; color: #ffffff; font-weight: bold; padding: 3px 8px; border-radius: 4px; font-size: 11px;")
        ai_header_row.addWidget(self.threat_badge)
        ai_header_row.addStretch()
        ai_layout.addLayout(ai_header_row)

        self.ai_summary_lbl = QLabel("Running offline behavioral intent assessment...")
        self.ai_summary_lbl.setStyleSheet("color: #e2e8f0; font-size: 12px; margin-top: 4px;")
        self.ai_summary_lbl.setWordWrap(True)
        ai_layout.addWidget(self.ai_summary_lbl)

        self.ai_card.setLayout(ai_layout)
        layout.addWidget(self.ai_card)

        # Main Splitter: Left (Photo + Sandbox) | Right (Full Audit Trail & Shell Logs)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel
        left_panel = QFrame()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 8, 0)
        left_layout.setSpacing(8)

        img_title = QLabel("INTRUDER CAPTURED WEBCAM SNAPSHOT")
        img_title.setObjectName("panel_lbl")
        left_layout.addWidget(img_title)

        self.image_display = QLabel()
        self.image_display.setStyleSheet("background-color: #0c0f17; border: 1px solid #252d3d; border-radius: 6px;")
        self.image_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_display.setFixedSize(380, 240)
        self.load_intruder_image()
        left_layout.addWidget(self.image_display)

        # Sandboxed file list
        sandbox_title = QLabel("SANDBOXED FILE CREATIONS (data/sandbox/)")
        sandbox_title.setObjectName("panel_lbl")
        left_layout.addWidget(sandbox_title)

        self.sandbox_list = QTextEdit()
        self.sandbox_list.setReadOnly(True)
        self.sandbox_list.setFixedHeight(120)
        self.load_sandbox_files()
        left_layout.addWidget(self.sandbox_list)

        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)

        # Right Panel - Full Forensic Audit Trail
        right_panel = QFrame()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(8, 0, 0, 0)
        right_layout.setSpacing(8)

        log_title = QLabel("CHRONOLOGICAL FORENSIC AUDIT TRAIL (ALL INTERACTIONS)")
        log_title.setObjectName("panel_lbl")
        right_layout.addWidget(log_title)

        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.load_activity_logs()
        right_layout.addWidget(self.log_console)

        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)

        layout.addWidget(splitter, 1)

        # Footer Actions Row
        footer_layout = QHBoxLayout()
        footer_layout.setSpacing(10)

        # Run AI prediction button
        self.ai_btn = QPushButton("🤖 Re-Run AI Prediction (Ollama)")
        self.ai_btn.setObjectName("ai_btn")
        self.ai_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.ai_btn.clicked.connect(self.run_ai_analysis)
        footer_layout.addWidget(self.ai_btn)

        # Export PDF report button
        self.export_btn = QPushButton("📄 Export Forensic PDF Report")
        self.export_btn.setObjectName("export_btn")
        self.export_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.export_btn.clicked.connect(self.export_pdf_report)
        footer_layout.addWidget(self.export_btn)

        footer_layout.addStretch()

        self.close_btn = QPushButton("✓ Close and Resume Session")
        self.close_btn.setObjectName("close_btn")
        self.close_btn.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.close_btn.clicked.connect(self.close)
        footer_layout.addWidget(self.close_btn)

        layout.addLayout(footer_layout)
        self.setLayout(layout)

        # Trigger AI analysis initially
        self.run_ai_analysis()

    def load_intruder_image(self):
        """Finds and loads the latest intruder capture photo."""
        search_path = os.path.join(self.forensics_dir, "intruder_*.jpg")
        image_files = sorted(glob.glob(search_path))
        
        if image_files:
            latest_image = image_files[-1]
            pixmap = QPixmap(latest_image)
            scaled_pix = pixmap.scaled(self.image_display.size(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.image_display.setPixmap(scaled_pix)
            print(f"[FORENSICS] Loaded intruder picture: '{os.path.basename(latest_image)}'", flush=True)
        else:
            self.image_display.setText("No intruder snapshot captured.\n(Webcam not found or sensor offline)")

    def load_sandbox_files(self):
        """Displays sandboxed file writes intercepted during the CURRENT active session."""
        stats = self.tracker.get_summary_stats()
        sandboxed_files = stats.get("sandbox_interceptions", [])
        if sandboxed_files:
            self.sandbox_list.setText("\n".join([f"📁 [INTERCEPTED] {f} -> Quarantined in sandbox" for f in sandboxed_files]))
        elif os.path.exists(self.sandbox_dir) and os.listdir(self.sandbox_dir):
            files = os.listdir(self.sandbox_dir)
            self.sandbox_list.setText("\n".join([f"📁 [QUARANTINED] {f} -> Stored safely in sandbox" for f in files]))
        else:
            self.sandbox_list.setText("No file writes intercepted in current session.\nHost filesystem remains 100% pristine.")

    def load_activity_logs(self):
        """Loads recorded events strictly for the CURRENT session."""
        timeline = self.tracker.get_timeline()
        lines_formatted = []
        for ev in timeline:
            t = ev.get("timestamp", "")
            atype = ev.get("action_type", "")
            target = ev.get("target", "")
            sev = ev.get("severity", "INFO")
            lines_formatted.append(f"[{t}] [{sev}] [{atype}] {target}")

        if lines_formatted:
            self.log_console.setText("\n".join(lines_formatted))
        else:
            self.log_console.setText("No honeypot interaction events recorded in this session yet.")

    def run_ai_analysis(self):
        """Invokes offline AI intent analyzer (Ollama / Heuristics) and updates the UI."""
        self.ai_summary_lbl.setText("Analyzing behavioral trajectory across opened folders, searches, and commands...")
        QApplication.processEvents()
        
        timeline = self.tracker.get_timeline()
        stats = self.tracker.get_summary_stats()
        report = self.ai_analyzer.analyze_session(timeline=timeline, stats=stats)
        self.latest_ai_report = report
        persona = report.get("attacker_persona", "Opportunistic Explorer")
        intent = report.get("primary_intent", "Reconnaissance & credential hunting")
        threat = report.get("threat_level", "MEDIUM").upper()
        engine = report.get("source", "Local AI Threat Model")

        # Update Badge Color
        if threat in ["CRITICAL", "HIGH"]:
            self.threat_badge.setStyleSheet("background-color: #e84118; color: #ffffff; font-weight: bold; padding: 3px 8px; border-radius: 4px; font-size: 11px;")
        elif threat == "MEDIUM":
            self.threat_badge.setStyleSheet("background-color: #f39c12; color: #ffffff; font-weight: bold; padding: 3px 8px; border-radius: 4px; font-size: 11px;")
        else:
            self.threat_badge.setStyleSheet("background-color: #2ed573; color: #ffffff; font-weight: bold; padding: 3px 8px; border-radius: 4px; font-size: 11px;")
            
        self.threat_badge.setText(f"THREAT LEVEL: {threat}")

        summary_text = (
            f"<b>Attacker Persona:</b> {persona}<br>"
            f"<b>Estimated Objective:</b> {intent}<br>"
            f"<b>Analysis Engine:</b> {engine}"
        )
        self.ai_summary_lbl.setText(summary_text)

    def export_pdf_report(self):
        """Generates comprehensive PDF report for the active session and prompts user to open it."""
        try:
            self.export_btn.setText("Generating PDF...")
            QApplication.processEvents()
            
            gen = ForensicReportGenerator()
            timeline = self.tracker.get_timeline()
            stats = self.tracker.get_summary_stats()
            ai_report = getattr(self, "latest_ai_report", None)
            
            pdf_path = gen.generate_report(ai_report=ai_report, timeline=timeline, stats=stats)
            self.latest_pdf_path = pdf_path
            
            self.export_btn.setText("📄 Export Forensic PDF Report")
            
            msg = QMessageBox(self)
            msg.setWindowTitle("Forensic Report Exported")
            msg.setText(f"<b>Comprehensive Forensic PDF Report Generated Successfully!</b><br><br>Saved to:<br><code>{pdf_path}</code>")
            open_btn = msg.addButton("Open PDF", QMessageBox.ButtonRole.ActionRole)
            msg.addButton("OK", QMessageBox.ButtonRole.AcceptRole)
            msg.exec()
            
            if msg.clickedButton() == open_btn:
                try:
                    if sys.platform == "win32":
                        os.startfile(pdf_path)
                    else:
                        subprocess.Popen(["xdg-open", pdf_path])
                except Exception as e:
                    print(f"[FORENSICS] Error opening PDF: {e}", file=sys.stderr)
        except Exception as e:
            self.export_btn.setText("📄 Export Forensic PDF Report")
            QMessageBox.critical(self, "PDF Export Error", f"Failed to generate forensic report: {e}")


def launch_forensic_dashboard():
    """Starts the Forensic Dashboard PyQt6 event loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    dash = ForensicDashboard()
    dash.show()
    
    app.exec()


if __name__ == "__main__":
    launch_forensic_dashboard()
