import sys
import os
import time

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QFrame, QGridLayout
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont, QColor, QPalette, QBrush, QImage

class HoneyShell(QFrame):
    """
    Mock Terminal Emulator (Honeypot Command Prompt).
    Intercepts attacker commands, outputs fake directory structures,
    and diverts any file creation/write operations to data/sandbox/
    """
    def __init__(self, sandbox_dir):
        super().__init__()
        self.sandbox_dir = sandbox_dir
        self.current_dir = "C:\\Users\\Administrator"
        
        # In-memory virtual mock filesystem
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

    def process_command(self):
        cmd_raw = self.input_field.text().strip()
        self.input_field.clear()
        
        if not cmd_raw:
            return
            
        self.console.append(f"{self.current_dir}> {cmd_raw}")
        
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
        elif base_cmd in ["help"]:
            response = "Supported Commands: help, cd, dir, ls, type, cat, echo, ipconfig, whoami, cls, clear"
        else:
            response = f"'{base_cmd}' is not recognized as an internal or external command,\noperable program or batch file."
            
        if response:
            self.console.append(response + "\n")
            
        # Scroll console to bottom
        self.console.ensureCursorVisible()

    def _handle_dir(self):
        items = self.virtual_fs.get(self.current_dir, [])
        if not items:
            return " Directory of " + self.current_dir + "\n\n0 File(s)             0 bytes\n0 Dir(s)        85,124,192 bytes free"
            
        res = f" Directory of {self.current_dir}\n\n"
        for idx, item in enumerate(items):
            if "." in item:
                # Mock File
                res += f"2026-08-23  14:02             4,192 {item}\n"
            else:
                # Mock Dir
                res += f"2026-08-23  14:02    <DIR>          {item}\n"
        res += f"\n               {len(items)} File(s)         4,192 bytes"
        return res

    def _handle_cd(self, args):
        if not args:
            return self.current_dir
            
        target = args[0]
        # Simple relative/absolute cd parsing
        if target == "..":
            # Parent directory
            if "\\" in self.current_dir:
                parts = self.current_dir.split("\\")
                if len(parts) > 1:
                    self.current_dir = "\\".join(parts[:-1])
            self.prompt_lbl.setText(f"{self.current_dir}>")
            return ""
            
        # Build path
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
        
        # Mocking content of confidential passwords
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
            # Check sandbox folder for written files
            chk = os.path.join(self.sandbox_dir, target)
            if os.path.exists(chk):
                try:
                    with open(chk, "r") as f:
                        return f.read()
                except Exception:
                    pass
            return f"The system cannot find the file specified: '{target}'"

    def _handle_echo(self, raw_cmd):
        # Parses echo text > filename
        if ">" not in raw_cmd:
            # Just echo back
            parts = raw_cmd.split()
            return " ".join(parts[1:]) if len(parts) > 1 else ""
            
        try:
            cmd_part, file_part = raw_cmd.split(">", 1)
            text = cmd_part.replace("echo", "", 1).strip()
            # Remove quotes
            if text.startswith("'") or text.startswith('"'):
                text = text[1:-1]
                
            filename = file_part.strip()
            
            # Divert file write to Sandbox folder!
            sandbox_path = os.path.join(self.sandbox_dir, filename)
            os.makedirs(self.sandbox_dir, exist_ok=True)
            
            with open(sandbox_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
                
            # Add to local virtual directory listings so they see it in 'dir'
            items = self.virtual_fs.get(self.current_dir, [])
            if filename not in items:
                items.append(filename)
                self.virtual_fs[self.current_dir] = items
                
            print(f"[DECEPTION] Intercepted write payload. Redirected to '{sandbox_path}'", flush=True)
            return ""
        except Exception as e:
            return f"Error writing file: {e}"


class HoneypotDesktop(QWidget):
    """
    Full-screen borderless deception desktop environment overlay.
    Spawns mock shortcut icons and auto-opens the HoneyShell cmd prompt
    to contain the intruder's interactions.
    """
    def __init__(self):
        super().__init__()
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        self.init_ui()

    def init_ui(self):
        # Configure window behavior
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)
        
        # Make full screen
        screen = QApplication.primaryScreen().geometry()
        self.setGeometry(screen)
        
        # Style layout background (deep dark gray mimicking standard lock screen background/desktop)
        self.setStyleSheet("""
            QWidget#MainContainer {
                background-color: #2c3e50;
            }
            QLabel#ShortcutIcon {
                color: #ffffff;
                font-size: 11px;
                font-weight: bold;
            }
            QPushButton#IconBtn {
                background: transparent;
                border: none;
            }
        """)
        
        self.setObjectName("MainContainer")
        
        # Grid layout for desktop icons
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        desktop_grid = QGridLayout()
        desktop_grid.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        desktop_grid.setHorizontalSpacing(40)
        desktop_grid.setVerticalSpacing(30)
        
        # Define mock desktop shortcuts
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
            btn.setObjectName("IconBtn")
            btn.setFont(QFont("Arial", 36))
            btn.clicked.connect(self.icon_clicked)
            icon_layout.addWidget(btn)
            
            lbl = QLabel(name)
            lbl.setObjectName("ShortcutIcon")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            icon_layout.addWidget(lbl)
            
            desktop_grid.addLayout(icon_layout, row, col)
            
        main_layout.addLayout(desktop_grid)
        
        # Spawns mock CMD Terminal Prompt in center of honeypot
        self.terminal = HoneyShell(self.sandbox_dir)
        self.terminal.setFixedSize(QSize(750, 480))
        
        # Center terminal layout
        term_layout = QHBoxLayout()
        term_layout.addWidget(self.terminal)
        main_layout.addLayout(term_layout)
        
        # Bottom Taskbar
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
        # Redirect clicked mockup shortcuts to opening or writing to console
        self.terminal.console.append("\n[SECURITY] Shortcut folder access locked. Launch terminal shell to access details.")

    def keyPressEvent(self, event):
        # Intercept escape sequences
        if event.key() == Qt.Key.Key_Escape:
            event.ignore()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        # Keep window trapped, prevent standard Alt+F4 closure
        event.ignore()

def launch_honey_desktop():
    """Entrypoint function to run the PyQt6 Honey-Desktop application loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    desktop_window = HoneypotDesktop()
    desktop_window.showFullScreen()
    
    app.exec()

if __name__ == "__main__":
    launch_honey_desktop()
