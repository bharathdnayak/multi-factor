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
        self._force_close = False
        
        # 1. Prepare clean authentic desktop wallpaper for Honeypot replication
        try:
            snapshot_dir = os.path.join(project_dir, "data", "forensics")
            os.makedirs(snapshot_dir, exist_ok=True)
            snapshot_path = os.path.join(snapshot_dir, "desktop_snapshot.png")
            
            # Prioritize authentic Windows desktop wallpaper so terminal windows are never captured
            wallpaper_path = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Themes\TranscodedWallpaper')
            if os.path.exists(wallpaper_path):
                screen = QApplication.primaryScreen()
                geom = screen.geometry() if screen else None
                dpr = screen.devicePixelRatio() if screen else 1.0
                target_w = int(geom.width() * dpr) if geom else 1920
                target_h = int(geom.height() * dpr) if geom else 1080
                
                from PyQt6.QtGui import QPixmap, QPainter
                from PyQt6.QtCore import Qt
                wall = QPixmap(wallpaper_path)
                if not wall.isNull():
                    scaled_wall = wall.scaled(target_w, target_h, Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation)
                    canvas = QPixmap(target_w, target_h)
                    painter = QPainter(canvas)
                    ox = max(0, (scaled_wall.width() - target_w) // 2)
                    oy = max(0, (scaled_wall.height() - target_h) // 2)
                    painter.drawPixmap(0, 0, scaled_wall, ox, oy, target_w, target_h)
                    painter.end()
                    canvas.save(snapshot_path, "PNG")
                    print(f"[DECEPTION] Preserved clean authentic Windows wallpaper to '{snapshot_path}'", flush=True)
            else:
                # Fallback to dark Windows background
                from PyQt6.QtGui import QPixmap, QColor
                canvas = QPixmap(1920, 1080)
                canvas.fill(QColor("#0d1117"))
                canvas.save(snapshot_path, "PNG")
        except Exception as e:
            print(f"[DECEPTION] [WARNING] Could not prepare desktop wallpaper: {e}", flush=True)

        self.init_ui()

    def init_ui(self):
        # Configure window behavior (top-level fullscreen modal)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
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
                font-size: 20px;
                color: #ffffff;
                qproperty-alignment: 'AlignCenter';
                max-width: 380px;
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
                     "Enter the 6-digit OTP code dispatched to owner (or Master Bypass: admin)")
        sub.setObjectName("sub_title")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(sub)
        
        # OTP input field
        self.otp_input = QLineEdit()
        self.otp_input.setMaxLength(32)
        self.otp_input.setPlaceholderText("Enter OTP or Bypass Password")
        self.otp_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.otp_input.returnPressed.connect(self.check_otp)
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
            time.sleep(1.0)
            self._force_close = True
            self.close()
            app = QApplication.instance()
            if app:
                app.quit()
        else:
            self.failed_attempts += 1
            self.status_lbl.setStyleSheet("color: #ff4757;")
            self.status_lbl.setText(f"Invalid code. Remaining attempts: {3 - self.failed_attempts}")
            self.otp_input.clear()
            
            if self.failed_attempts >= 3:
                self.status_lbl.setStyleSheet("color: #2ed573;")
                self.status_lbl.setText("Session verified. Signing in to Windows...")
                QApplication.processEvents()
                time.sleep(0.8)
                self.trigger_deception()

    def trigger_deception(self):
        """Closes verification screen and seamlessly renders PyQt6 Sandboxed Honeypot Desktop."""
        self._force_close = True
        self.close()
        from deception.honey_desktop import HoneypotDesktop
        global _active_honeypot_instance
        _active_honeypot_instance = HoneypotDesktop()
        _active_honeypot_instance.showFullScreen()

    def keyPressEvent(self, event):
        # Override key press event to intercept Esc key and system shortcuts
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        # Prevent manual window closure unless verified or transitioning
        if getattr(self, '_force_close', False):
            event.accept()
        elif self.evaluator.is_breached and self.failed_attempts < 3:
            event.ignore()
        else:
            event.accept()

# Global reference to prevent garbage collection of UI instances
_active_lock_window = None
_active_honeypot_instance = None

def launch_verification_lock(evaluator):
    """Entrypoint function to run the PyQt6 lock screen application loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    app.setQuitOnLastWindowClosed(False)
    
    global _active_lock_window
    _active_lock_window = VerificationLockScreen(evaluator)
    _active_lock_window.showFullScreen()
    
    app.exec()

if __name__ == "__main__":
    # Test script run
    from security.drift_detector import ThreatEvaluator
    evaluator = ThreatEvaluator()
    evaluator.is_breached = True
    evaluator.active_otp = "123456"
    evaluator._save_active_otp("123456")
    launch_verification_lock(evaluator)
