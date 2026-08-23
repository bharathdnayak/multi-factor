import sys
import os
import time
import threading
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QFrame, QGridLayout
from PyQt6.QtCore import Qt, QSize, QObject, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QBrush, QPixmap
from pynput import keyboard

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

class HotkeySignals(QObject):
    """Signals to communicate safely from background keyboard threads to the UI thread."""
    trigger_lock = pyqtSignal()

class HoneyShell(QFrame):
    """
    Mock Terminal Emulator (Honeypot Command Prompt).
    Intercepts attacker commands, outputs fake directory structures,
    logs operations to forensics log, and diverts writes to sandbox folder.
    """
    def __init__(self, sandbox_dir, log_dir):
        super().__init__()
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.current_dir = "C:\\Users\\Administrator"
        
        # Virtual mock filesystem
        self.virtual_fs = {
            "C:\\Users\\Administrator": ["Documents", "Downloads", "Desktop"],
            "C:\\Users\\Administrator\\Desktop": ["confidential_passwords.txt", "network_map.pdf", "Terminal.lnk"],
            "C:\\Users\\Administrator\\Documents": ["project_requirements.docx", "database_backup.sql"]
        }
        
        self.init_ui()

    def init_ui(self):
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background-color: #0c0c0c;
                border: 2px solid #3c3c3c;
                border-radius: 4px;
            }
            QTextEdit {
                background-color: #0c0c0c;
                color: #00ff00;
                font-family: 'Consolas', monospace;
                font-size: 14px;
                border: none;
            }
            QLineEdit {
                background-color: #0c0c0c;
                color: #ffffff;
                font-family: 'Consolas', monospace;
                font-size: 14px;
                border: none;
                padding-left: 5px;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(2)
        
        # Title bar
        title_bar = QHBoxLayout()
        title_bar.setContentsMargins(5, 2, 5, 2)
        lbl = QLabel("Command Prompt (Administrator)")
        lbl.setStyleSheet("color: #cccccc; font-weight: bold; border: none; font-size: 11px;")
        title_bar.addWidget(lbl)
        title_bar.addStretch()
        
        close_btn = QPushButton("X")
        close_btn.setFixedSize(QSize(20, 16))
        close_btn.setStyleSheet("color: #ffffff; background-color: #d63031; font-weight: bold; border: none; font-size: 10px;")
        close_btn.clicked.connect(self.hide_prompt_fake)
        title_bar.addWidget(close_btn)
        
        layout.addLayout(title_bar)
        
        # Display Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        
        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(0)
        self.prompt_lbl = QLabel(f"{self.current_dir}>")
        self.prompt_lbl.setStyleSheet("color: #ffffff; font-family: 'Consolas', monospace; font-size: 14px; border: none;")
        input_row.addWidget(self.prompt_lbl)
        
        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.process_command)
        input_row.addWidget(self.input_field)
        
        layout.addLayout(input_row)
        self.setLayout(layout)
        
        # Print welcome banner
        self.console.append("Microsoft Windows [Version 10.0.19045.3803]\n(c) Microsoft Corporation. All rights reserved.\n")

    def hide_prompt_fake(self):
        self.console.append(f"\n{self.current_dir}> [Access Denied: Administrative Session Lock Active]")

    def log_action(self, cmd_raw):
        """Saves command sequence logs to the forensics file."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {cmd_raw}\n")
        except Exception:
            pass

    def process_command(self):
        cmd_raw = self.input_field.text().strip()
        self.input_field.clear()
        
        if not cmd_raw:
            return
            
        self.console.append(f"{self.current_dir}> {cmd_raw}")
        
        # Log command forensics
        self.log_action(cmd_raw)
        
        # Command Parsing
        parts = cmd_raw.split()
        base_cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        response = ""
        
        if base_cmd in ["dir", "ls"]:
            response = self._handle_dir()
        elif base_cmd == "cd":
            response = self._handle_cd(args)
        elif base_cmd in ["cat", "type"]:
            response = self._handle_type(args)
        elif base_cmd in ["echo", "write"]:
            response = self._handle_echo(cmd_raw)
        elif base_cmd in ["clear", "cls"]:
            self.console.clear()
            return
        elif base_cmd == "ipconfig":
            response = ("\nWindows IP Configuration\n\n"
                        "Ethernet adapter Ethernet0:\n"
                        "   Connection-specific DNS Suffix  . : gateway.lan\n"
                        "   Link-local IPv6 Address . . . . . : fe80::4c2b:d1ff:feca:51b2%4\n"
                        "   IPv4 Address. . . . . . . . . . . : 192.168.1.142\n"
                        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1")
        elif base_cmd in ["whoami"]:
            response = "desktop-main\\administrator"
        elif base_cmd == "help":
            response = "Supported Commands: help, cd, dir, ls, type, cat, echo, ipconfig, whoami, cls, clear"
        else:
            response = f"'{base_cmd}' is not recognized as an internal or external command,\noperable program or batch file."
            
        if response:
            self.console.append(response + "\n")
            
        self.console.ensureCursorVisible()

    def _handle_dir(self):
        items = self.virtual_fs.get(self.current_dir, [])
        if not items:
            return " Directory of " + self.current_dir + "\n\n0 File(s)             0 bytes\n0 Dir(s)        85,124,192 bytes free"
            
        res = f" Directory of {self.current_dir}\n\n"
        for idx, item in enumerate(items):
            if "." in item:
                res += f"2026-08-23  14:02             4,192 {item}\n"
            else:
                res += f"2026-08-23  14:02    <DIR>          {item}\n"
        res += f"\n               {len(items)} File(s)         4,192 bytes"
        return res

    def _handle_cd(self, args):
        if not args:
            return self.current_dir
            
        target = args[0]
        if target == "..":
            if "\\" in self.current_dir:
                parts = self.current_dir.split("\\")
                if len(parts) > 1:
                    self.current_dir = "\\".join(parts[:-1])
            self.prompt_lbl.setText(f"{self.current_dir}>")
            return ""
            
        check_path = self.current_dir + "\\" + target
        if check_path in self.virtual_fs or check_path.replace("\\\\", "\\") in self.virtual_fs:
            self.current_dir = check_path.replace("\\\\", "\\")
            self.prompt_lbl.setText(f"{self.current_dir}>")
            return ""
            
        return f"The system cannot find the path specified: '{target}'"

    def _handle_type(self, args):
        if not args:
            return "Command syntax is incorrect."
        target = args[0]
        
        if "password" in target.lower():
            return ("=== ADMIN CREDENTIALS STORE ===\n"
                    "github_token = ghp_Z58d83Ka92Lq93Kasl38Adk2JqpO11283\n"
                    "production_db_password = pg_sec_root_9921_cluster\n"
                    "aws_access_key = AKIAIOSFODNN7EXAMPLE\n"
                    "aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        elif "map" in target.lower() or "project" in target.lower():
            return "CONFIDENTIAL: System architecture specification - Internal Use Only."
        elif "backup" in target.lower() or "database" in target.lower():
            return "DATABASE DUMP -- INSERT INTO users VALUES (1, 'admin', '$2b$12$K.zWlD...');"
        else:
            chk = os.path.join(self.sandbox_dir, target)
            if os.path.exists(chk):
                try:
                    with open(chk, "r") as f:
                        return f.read()
                except Exception:
                    pass
            return f"The system cannot find the file specified: '{target}'"

    def _handle_echo(self, raw_cmd):
        if ">" not in raw_cmd:
            parts = raw_cmd.split()
            return " ".join(parts[1:]) if len(parts) > 1 else ""
            
        try:
            cmd_part, file_part = raw_cmd.split(">", 1)
            text = cmd_part.replace("echo", "", 1).strip()
            if text.startswith("'") or text.startswith('"'):
                text = text[1:-1]
                
            filename = file_part.strip()
            
            # Divert file write to Sandbox folder
            sandbox_path = os.path.join(self.sandbox_dir, filename)
            os.makedirs(self.sandbox_dir, exist_ok=True)
            
            with open(sandbox_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
                
            items = self.virtual_fs.get(self.current_dir, [])
            if filename not in items:
                items.append(filename)
                self.virtual_fs[self.current_dir] = items
                
            print(f"[DECEPTION] Redirected write payload to sandbox file '{sandbox_path}'", flush=True)
            return ""
        except Exception as e:
            return f"Error writing file: {e}"


class HoneypotDesktop(QWidget):
    """
    Deception environment. Grabs a screenshot of the user's desktop
    prior to layout display, and runs a topmost overlay overlaying it.
    
    Includes global Ctrl+Alt+Shift+U hotkey hook to verify identity.
    """
    def __init__(self):
        super().__init__()
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_dir = os.path.join(project_dir, "data", "forensics")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # 1. Grab Desktop Screenshot before display
        screen = QApplication.primaryScreen()
        if screen:
            self.screenshot = screen.grabWindow(0)
        else:
            self.screenshot = QPixmap()
            
        self.init_ui()
        self.init_hotkey()

    def init_ui(self):
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)
        
        screen_geom = QApplication.primaryScreen().geometry()
        self.setGeometry(screen_geom)
        
        # Set screenshot as layout background
        palette = self.palette()
        palette.setBrush(QPalette.ColorRole.Window, QBrush(self.screenshot))
        self.setPalette(palette)
        
        # Desktop layout
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        desktop_grid = QGridLayout()
        desktop_grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        desktop_grid.setHorizontalSpacing(40)
        desktop_grid.setVerticalSpacing(30)
        
        shortcuts = [
            ("📁", "My Documents"),
            ("🗑️", "Recycle Bin"),
            ("🌐", "Google Chrome"),
            ("🔒", "Secret Passwords"),
            ("💻", "Control Panel")
        ]
        
        for idx, (icon, name) in enumerate(shortcuts):
            col = 0
            row = idx
            
            icon_layout = QVBoxLayout()
            icon_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            btn = QPushButton(icon)
            btn.setStyleSheet("background: transparent; border: none; font-size: 36px;")
            btn.clicked.connect(self.icon_clicked)
            icon_layout.addWidget(btn)
            
            lbl = QLabel(name)
            lbl.setStyleSheet("color: #ffffff; font-size: 11px; font-weight: bold; text-shadow: 1px 1px 2px #000000;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_layout.addWidget(lbl)
            
            desktop_grid.addLayout(icon_layout, row, col)
            
        main_layout.addLayout(desktop_grid)
        
        # Spawns mock CMD Terminal Prompt
        self.terminal = HoneyShell(self.sandbox_dir, self.log_dir)
        self.terminal.setFixedSize(QSize(750, 480))
        
        term_layout = QHBoxLayout()
        term_layout.addWidget(self.terminal)
        main_layout.addLayout(term_layout)
        
        # Taskbar
        taskbar = QFrame()
        taskbar.setFixedHeight(40)
        taskbar.setStyleSheet("background-color: #1a1a1a; border-top: 1px solid #2d2d2d;")
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(10, 0, 10, 0)
        
        start_btn = QLabel("❖")
        start_btn.setFont(QFont("Arial", 16))
        start_btn.setStyleSheet("color: #00a8ff; font-weight: bold;")
        tb_layout.addWidget(start_btn)
        tb_layout.addStretch()
        
        time_lbl = QLabel(time.strftime("%H:%M  %Y-%m-%d"))
        time_lbl.setStyleSheet("color: #ffffff; font-size: 11px;")
        tb_layout.addWidget(time_lbl)
        
        taskbar.setLayout(tb_layout)
        main_layout.addWidget(taskbar)
        
        self.setLayout(main_layout)

    def icon_clicked(self):
        self.terminal.console.append("\n[SECURITY] Shortcut folder access locked. Launch terminal shell to access details.")

    def init_hotkey(self):
        """Starts a background pynput listener watching for Ctrl+Alt+Shift+U."""
        self.signals = HotkeySignals()
        self.signals.trigger_lock.connect(self.show_verification_prompt)
        
        def run_listener(sig):
            def on_activate():
                sig.trigger_lock.emit()
            
            with keyboard.GlobalHotKeys({'<ctrl>+<alt>+<shift>+u': on_activate}) as h:
                h.join()
                
        t = threading.Thread(target=run_listener, args=(self.signals,), daemon=True)
        t.start()

    def show_verification_prompt(self):
        """Signal target. Displays verification input window."""
        print("[DECEPTION] Verification hotkey triggered! Spawning Verification Dialog.", flush=True)
        from security.drift_detector import ThreatEvaluator
        from security.lock_handler import VerificationLockScreen
        
        # Instantiate a standard OTP prompt
        evaluator = ThreatEvaluator()
        evaluator.is_breached = True
        
        self.lock_prompt = VerificationLockScreen(evaluator)
        # Redefine the lock screen's trigger_deception method to just close the prompt
        # so it doesn't try to open another honeypot desktop
        self.lock_prompt.trigger_deception = self.lock_prompt.close
        
        # Override the check_otp success logic to unlock self too
        original_check = self.lock_prompt.check_otp
        
        def wrapped_check():
            entered = self.lock_prompt.otp_input.text().strip()
            ok = evaluator.verify_otp_and_reset(entered)
            if ok:
                self.lock_prompt.status_lbl.setText("Identity Verified! Opening Forensics Dashboard...")
                QApplication.processEvents()
                time.sleep(1.2)
                self.lock_prompt.close()
                self.close() # Close deception desktop
                
                # Launch Forensics Recovery Dashboard
                from dashboard.forensic_dashboard import launch_forensic_dashboard
                launch_forensic_dashboard()
            else:
                self.lock_prompt.failed_attempts += 1
                self.lock_prompt.status_lbl.setText(f"Invalid code. Attempts: {3 - self.lock_prompt.failed_attempts}")
                self.lock_prompt.otp_input.clear()
                if self.lock_prompt.failed_attempts >= 3:
                    self.lock_prompt.close()
                    
        self.lock_prompt.check_otp = wrapped_check
        self.lock_prompt.show()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        # Intercept Alt+F4 closures
        event.ignore()

def launch_honey_desktop():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    desktop_window = HoneypotDesktop()
    desktop_window.showFullScreen()
    
    app.exec()

if __name__ == "__main__":
    launch_honey_desktop()
