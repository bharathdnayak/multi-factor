import sys
import os
import time

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor, QPalette

class VerificationLockScreen(QWidget):
    """
    Full-screen borderless verification prompt locking the interface.
    Asks the owner to input the 6-digit OTP code dispatched to their phone/email.
    """
    def __init__(self, evaluator):
        super().__init__()
        self.evaluator = evaluator
        self.failed_attempts = 0
        
        # 1. Grab clean snapshot of user's active desktop/apps BEFORE the lock screen overlays it
        try:
            screen = QApplication.primaryScreen()
            if screen:
                snapshot = screen.grabWindow(0)
                snapshot_dir = os.path.join(project_dir, "data", "forensics")
                os.makedirs(snapshot_dir, exist_ok=True)
                snapshot_path = os.path.join(snapshot_dir, "desktop_snapshot.png")
                snapshot.save(snapshot_path, "PNG")
                print(f"[DECEPTION] Preserved pre-breach desktop snapshot to '{snapshot_path}'", flush=True)
        except Exception as e:
            print(f"[DECEPTION] [WARNING] Could not capture pre-breach desktop: {e}", flush=True)

        self.init_ui()

    def init_ui(self):
        # Configure window behavior
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)
        
        # Make full screen
        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)
        
        # Dark tech styling
        self.setStyleSheet("""
            QWidget {
                background-color: #121824;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel#warning_title {
                color: #ff4757;
                font-weight: bold;
                font-size: 28px;
            }
            QLabel#sub_title {
                color: #a4b0be;
                font-size: 16px;
            }
            QLineEdit {
                background-color: #1e272e;
                border: 2px solid #57606f;
                border-radius: 6px;
                padding: 10px;
                font-size: 22px;
                color: #ffffff;
                qproperty-alignment: 'AlignCenter';
                max-width: 250px;
            }
            QLineEdit:focus {
                border: 2px solid #ff4757;
            }
            QPushButton#verify_btn {
                background-color: #2ed573;
                color: #ffffff;
                font-weight: bold;
                font-size: 16px;
                padding: 12px 24px;
                border-radius: 6px;
                border: none;
            }
            QPushButton#verify_btn:hover {
                background-color: #26af5f;
            }
            QPushButton#bypass_btn {
                background-color: #ff4757;
                color: #ffffff;
                font-weight: bold;
                font-size: 16px;
                padding: 12px 24px;
                border-radius: 6px;
                border: none;
            }
            QPushButton#bypass_btn:hover {
                background-color: #ff2a3b;
            }
            QLabel#status_lbl {
                font-size: 15px;
                font-weight: bold;
            }
        """)

        # Main Layout
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(25)
        
        # Header/Warning
        warning_icon = QLabel("⚠️")
        warning_icon.setFont(QFont("Arial", 64))
        warning_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning_icon)
        
        title = QLabel("SECURITY LOCK: UNUSUAL DRIFT DETECTED")
        title.setObjectName("warning_title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        sub = QLabel("Desktop interactions do not match the registered owner's baseline patterns.\n"
                     "An OTP code has been dispatched to the owner's phone/email to verify identity.")
        sub.setObjectName("sub_title")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)
        
        # OTP input field
        self.otp_input = QLineEdit()
        self.otp_input.setMaxLength(6)
        self.otp_input.setPlaceholderText("Enter 6-digit OTP")
        self.otp_input.setEchoMode(QLineEdit.EchoMode.Normal)
        layout.addWidget(self.otp_input)
        
        # Button Row
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(15)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.verify_btn = QPushButton("Verify & Unlock")
        self.verify_btn.setObjectName("verify_btn")
        self.verify_btn.clicked.connect(self.check_otp)
        btn_layout.addWidget(self.verify_btn)
        
        self.bypass_btn = QPushButton("Bypass Prompt")
        self.bypass_btn.setObjectName("bypass_btn")
        self.bypass_btn.clicked.connect(self.trigger_deception)
        btn_layout.addWidget(self.bypass_btn)
        
        layout.addLayout(btn_layout)
        
        # Status Label
        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("status_lbl")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_lbl)
        
        self.setLayout(layout)

    def check_otp(self):
        entered_otp = self.otp_input.text().strip()
        
        # Check against evaluator
        is_valid = self.evaluator.verify_otp_and_reset(entered_otp)
        
        if is_valid:
            self.status_lbl.setStyleSheet("color: #2ed573;")
            self.status_lbl.setText("Identity Verified! Restoring session...")
            QApplication.processEvents()
            time.sleep(1.5)
            self.close()
        else:
            self.failed_attempts += 1
            self.status_lbl.setStyleSheet("color: #ff4757;")
            self.status_lbl.setText(f"Invalid code. Remaining attempts: {3 - self.failed_attempts}")
            self.otp_input.clear()
            
            if self.failed_attempts >= 3:
                self.status_lbl.setText("Attempts exhausted. Initiating Honeypot Containment...")
                QApplication.processEvents()
                time.sleep(1.5)
                self.trigger_deception()

    def trigger_deception(self):
        """Closes verification screen and launches PyQt6 Sandboxed Honeypot Desktop."""
        self.close()
        from deception.honey_desktop import launch_honey_desktop
        launch_honey_desktop()

    def keyPressEvent(self, event):
        # Override key press event to intercept Esc key and system shortcuts
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        # Prevent manual window closure
        if self.evaluator.is_breached and self.failed_attempts < 3:
            event.ignore()
        else:
            event.accept()

def launch_verification_lock(evaluator):
    """Entrypoint function to run the PyQt6 lock screen application loop."""
    # Ensure there is a QApplication running
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    lock_window = VerificationLockScreen(evaluator)
    lock_window.showFullScreen()
    
    # Process events to let the UI display
    app.exec()

if __name__ == "__main__":
    # Test script run
    from security.drift_detector import ThreatEvaluator
    evaluator = ThreatEvaluator()
    evaluator.is_breached = True
    evaluator.active_otp = "123456"
    evaluator._save_active_otp("123456")
    launch_verification_lock(evaluator)
