import sys
import os
import glob
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QFrame, QSplitter
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QPixmap

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

class ForensicDashboard(QWidget):
    """
    Verification and Forensic Recovery Dashboard.
    Loaded after successful owner OTP check, displaying captured intruder pictures
    and mock session shell action logs.
    """
    def __init__(self):
        super().__init__()
        self.forensics_dir = os.path.join(project_dir, "data", "forensics")
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_path = os.path.join(self.forensics_dir, "honeypot_commands.log")
        
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Forensic Recovery & Incident Report Dashboard")
        self.resize(950, 600)
        self.setStyleSheet("""
            QWidget {
                background-color: #1b1e28;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel#header_lbl {
                color: #ff4757;
                font-size: 24px;
                font-weight: bold;
                padding-bottom: 10px;
                border-bottom: 2px solid #2d3748;
            }
            QLabel#panel_lbl {
                color: #00a8ff;
                font-size: 16px;
                font-weight: bold;
                margin-bottom: 5px;
            }
            QTextEdit {
                background-color: #0f111a;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                border: 1px solid #2d3748;
                border-radius: 4px;
                padding: 8px;
            }
            QPushButton#close_btn {
                background-color: #00a8ff;
                color: #ffffff;
                font-weight: bold;
                font-size: 15px;
                padding: 10px 20px;
                border-radius: 4px;
                border: none;
            }
            QPushButton#close_btn:hover {
                background-color: #0088cc;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)

        # Header Title
        header = QLabel("🛡️ DETECTED INCIDENT REPORT & FORENSICS")
        header.setObjectName("header_lbl")
        layout.addWidget(header)

        # Main splitter panels
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel - Intruder Image Panel
        left_panel = QFrame()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        img_title = QLabel("INTRUDER CAPTURED SESSION SNAPSHOT")
        img_title.setObjectName("panel_lbl")
        left_layout.addWidget(img_title)
        
        self.image_display = QLabel()
        self.image_display.setFrameStyle(QFrame.Shape.Panel | QFrame.Shadow.Sunken)
        self.image_display.setStyleSheet("background-color: #0f111a; border: 1px solid #2d3748; border-radius: 4px;")
        self.image_display.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_display.setFixedSize(400, 300)
        
        self.load_intruder_image()
        left_layout.addWidget(self.image_display)
        
        # Sandboxed file list
        sandbox_title = QLabel("SANDBOXED FILE ATTEMPTS (data/sandbox/)")
        sandbox_title.setObjectName("panel_lbl")
        left_layout.addWidget(sandbox_title)
        
        self.sandbox_list = QTextEdit()
        self.sandbox_list.setReadOnly(True)
        self.sandbox_list.setPlaceholderText("No files created by attacker.")
        self.load_sandbox_files()
        left_layout.addWidget(self.sandbox_list)

        left_panel.setLayout(left_layout)
        splitter.addWidget(left_panel)

        # Right Panel - Command execution logs
        right_panel = QFrame()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        log_title = QLabel("HONEY-SHELL COMMAND SEQUENCE EXECUTION LOGS")
        log_title.setObjectName("panel_lbl")
        right_layout.addWidget(log_title)
        
        self.log_console = QTextEdit()
        self.log_console.setReadOnly(True)
        self.log_console.setPlaceholderText("No command shell activity logged.")
        self.load_command_logs()
        right_layout.addWidget(self.log_console)
        
        right_panel.setLayout(right_layout)
        splitter.addWidget(right_panel)

        layout.addWidget(splitter)

        # Footer close button
        footer_layout = QHBoxLayout()
        footer_layout.addStretch()
        self.close_btn = QPushButton("Close and Resume Session")
        self.close_btn.setObjectName("close_btn")
        self.close_btn.clicked.connect(self.close)
        footer_layout.addWidget(self.close_btn)
        
        layout.addLayout(footer_layout)
        self.setLayout(layout)

    def load_intruder_image(self):
        """Finds and loads the latest intruder capture photo."""
        search_path = os.path.join(self.forensics_dir, "intruder_*.jpg")
        image_files = sorted(glob.glob(search_path))
        
        if image_files:
            latest_image = image_files[-1]
            pixmap = QPixmap(latest_image)
            # Scale pixmap to fit inside fixed container safely
            scaled_pix = pixmap.scaled(self.image_display.size(), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            self.image_display.setPixmap(scaled_pix)
            print(f"[FORENSICS] Loaded intruder picture: '{os.path.basename(latest_image)}'", flush=True)
        else:
            self.image_display.setText("No intruder snapshot captured.\n(Webcam not found or disabled)")

    def load_sandbox_files(self):
        """Scans sandbox folder and lists file paths modified by intruder."""
        if os.path.exists(self.sandbox_dir):
            files = os.listdir(self.sandbox_dir)
            if files:
                self.sandbox_list.setText("\n".join([f"📁 [CREATED/MODIFIED] {f}" for f in files]))
                return
        self.sandbox_list.setText("No file writes intercepted in sandbox directory.")

    def load_command_logs(self):
        """Loads and formats honeypot command logs."""
        if os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.log_console.setText(content)
                return
            except Exception:
                pass
        self.log_console.setText("No honeypot command entries logged.")

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
