import sys
import os
import time
import threading
import psutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QSize, QPoint, QObject, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QColor, QPixmap, QPainter, QCursor
from pynput import keyboard

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

class HotkeySignals(QObject):
    """Signals to communicate safely from background keyboard threads to the UI thread."""
    trigger_lock = pyqtSignal()

class HoneyShell(QFrame):
    """
    Authentic Windows Floating Terminal Emulator (Honeypot PowerShell / CMD).
    Draggable anywhere on top of the replicated desktop.
    Intercepts attacker commands, outputs realistic processes & files,
    logs actions to forensics, and diverts writes to the sandbox.
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.current_dir = "C:\\Windows\\system32"
        self.drag_position = QPoint()
        
        # Virtual mock filesystem
        self.virtual_fs = {
            "C:\\Windows\\system32": ["cmd.exe", "powershell.exe", "taskmgr.exe", "drivers", "config"],
            "C:\\Users\\Administrator": ["Documents", "Downloads", "Desktop"],
            "C:\\Users\\Administrator\\Desktop": ["passwords.txt", "network_topology.pdf", "Terminal.lnk"],
            "C:\\Users\\Administrator\\Documents": ["project_source.zip", "database_backup.sql"]
        }
        
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(QSize(820, 520))
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setStyleSheet("""
            QFrame#TerminalContainer {
                background-color: #0c0c0c;
                border: 1px solid #3c3c3c;
                border-radius: 8px;
            }
            QFrame#TitleBar {
                background-color: #1f1f1f;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 1px solid #2d2d2d;
            }
            QLabel#TitleLabel {
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton#TitleBtn {
                background: transparent;
                color: #a0a0a0;
                border: none;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
                width: 32px;
                height: 24px;
            }
            QPushButton#TitleBtn:hover {
                background-color: #333333;
                color: #ffffff;
            }
            QPushButton#CloseBtn:hover {
                background-color: #e81123;
                color: #ffffff;
                border-top-right-radius: 8px;
            }
            QTextEdit {
                background-color: #0c0c0c;
                color: #cccccc;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding: 6px;
            }
            QLineEdit {
                background-color: #0c0c0c;
                color: #ffffff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding-left: 2px;
            }
        """)
        
        self.setObjectName("TerminalContainer")
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # 1. Authentic Windows Title Bar (Draggable)
        self.title_bar = QFrame()
        self.title_bar.setObjectName("TitleBar")
        self.title_bar.setFixedHeight(30)
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(10, 0, 0, 0)
        tb_layout.setSpacing(4)
        
        icon_lbl = QLabel("💻")
        icon_lbl.setStyleSheet("font-size: 12px;")
        tb_layout.addWidget(icon_lbl)
        
        self.title_lbl = QLabel("Administrator: Windows PowerShell")
        self.title_lbl.setObjectName("TitleLabel")
        tb_layout.addWidget(self.title_lbl)
        tb_layout.addStretch()
        
        min_btn = QPushButton("─")
        min_btn.setObjectName("TitleBtn")
        min_btn.clicked.connect(self.hide_fake)
        tb_layout.addWidget(min_btn)
        
        max_btn = QPushButton("□")
        max_btn.setObjectName("TitleBtn")
        tb_layout.addWidget(max_btn)
        
        close_btn = QPushButton("✕")
        close_btn.setObjectName("TitleBtn")
        close_btn.setProperty("class", "CloseBtn")
        close_btn.clicked.connect(self.close_fake)
        tb_layout.addWidget(close_btn)
        
        self.title_bar.setLayout(tb_layout)
        layout.addWidget(self.title_bar)
        
        # 2. Console History Area
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console)
        
        # 3. Input Prompt Row
        input_container = QFrame()
        input_container.setStyleSheet("background-color: #0c0c0c; padding-left: 6px; padding-bottom: 6px;")
        input_row = QHBoxLayout()
        input_row.setContentsMargins(0, 0, 6, 0)
        input_row.setSpacing(4)
        
        self.prompt_lbl = QLabel(f"PS {self.current_dir}>")
        self.prompt_lbl.setStyleSheet("color: #ffffff; font-family: 'Consolas', monospace; font-size: 13px; border: none;")
        input_row.addWidget(self.prompt_lbl)
        
        self.input_field = QLineEdit()
        self.input_field.returnPressed.connect(self.process_command)
        input_row.addWidget(self.input_field)
        
        input_container.setLayout(input_row)
        layout.addWidget(input_container)
        
        self.setLayout(layout)
        
        # PowerShell initial banner
        self.console.append("Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nInstall the latest PowerShell for new features and improvements! https://aka.ms/PSWindows\n")

    def mousePressEvent(self, event):
        """Allows dragging the terminal window anywhere on top of the replicated desktop."""
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_position = event.globalPosition().toPoint() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        """Updates terminal position during drag."""
        if event.buttons() == Qt.MouseButton.LeftButton and hasattr(self, 'drag_position'):
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def hide_fake(self):
        self.console.append(f"\n[Process Warning] Background diagnostic shell cannot be minimized during system check.\n")

    def close_fake(self):
        self.console.append(f"\n[Access Denied] Administrative session termination restricted by Group Policy.\n")

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
            
        self.console.append(f"PS {self.current_dir}> {cmd_raw}")
        self.log_action(cmd_raw)
        
        parts = cmd_raw.split()
        base_cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        response = ""
        
        if base_cmd in ["dir", "ls", "get-childitem"]:
            response = self._handle_dir()
        elif base_cmd == "cd":
            response = self._handle_cd(args)
        elif base_cmd in ["cat", "type", "get-content"]:
            response = self._handle_type(args)
        elif base_cmd in ["echo", "write-output"]:
            response = self._handle_echo(cmd_raw)
        elif base_cmd in ["tasklist", "ps", "get-process"]:
            response = self._handle_tasklist()
        elif base_cmd in ["clear", "cls"]:
            self.console.clear()
            return
        elif base_cmd == "ipconfig":
            response = ("\nWindows IP Configuration\n\n"
                        "Ethernet adapter Ethernet0:\n"
                        "   Connection-specific DNS Suffix  . : localdomain\n"
                        "   Link-local IPv6 Address . . . . . : fe80::4c2b:d1ff:feca:51b2%4\n"
                        "   IPv4 Address. . . . . . . . . . . : 192.168.1.142\n"
                        "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                        "   Default Gateway . . . . . . . . . : 192.168.1.1")
        elif base_cmd in ["whoami"]:
            response = "desktop-sec\\administrator"
        elif base_cmd in ["hostname"]:
            response = "DESKTOP-SEC-WIN11"
        elif base_cmd in ["net", "net.exe"]:
            if args and args[0].lower() == "user":
                response = "\nUser accounts for \\\\DESKTOP-SEC-WIN11\n\n-------------------------------------------------------------------------------\nAdministrator            DefaultAccount           Guest\nOwner                    WDAGUtilityAccount\nThe command completed successfully."
            else:
                response = "The syntax of this command is: NET [ ACCOUNTS | COMPUTER | CONFIG | GROUP | USER ]"
        elif base_cmd in ["help"]:
            response = "Supported Diagnostic Commands: tasklist, Get-Process, cd, dir, ls, type, cat, echo, ipconfig, whoami, hostname, net user, cls, clear"
        else:
            response = f"{base_cmd} : The term '{base_cmd}' is not recognized as the name of a cmdlet, function, script file, or operable program.\nCheck the spelling of the name, or if a path was included, verify that the path is correct and try again."
            
        if response:
            self.console.append(response + "\n")
            
        self.console.ensureCursorVisible()

    def _handle_tasklist(self):
        """Generates realistic process output using the user's actual running system processes!"""
        output = [
            f"{'Image Name':<30} {'PID':<8} {'Session Name':<16} {'Mem Usage':<12}",
            f"{'='*30} {'='*8} {'='*16} {'='*12}"
        ]
        try:
            count = 0
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    name = proc.info['name'] or "System"
                    pid = str(proc.info['pid'])
                    mem = proc.info['memory_info']
                    mem_str = f"{int(mem.rss / 1024):,} K" if mem else "4,096 K"
                    output.append(f"{name:<30} {pid:<8} {'Console':<16} {mem_str:<12}")
                    count += 1
                    if count >= 25:
                        break
                except Exception:
                    continue
        except Exception:
            output.append(f"{'explorer.exe':<30} {'4812':<8} {'Console':<16} {'124,592 K':<12}")
            output.append(f"{'code.exe':<30} {'8920':<8} {'Console':<16} {'382,104 K':<12}")
            output.append(f"{'chrome.exe':<30} {'11244':<8} {'Console':<16} {'491,220 K':<12}")
            output.append(f"{'powershell.exe':<30} {'6104':<8} {'Console':<16} {'58,212 K':<12}")
            
        return "\n".join(output)

    def _handle_dir(self):
        items = self.virtual_fs.get(self.current_dir, [])
        if not items:
            return f"\n    Directory: {self.current_dir}\n\nMode                 LastWriteTime         Length Name\n----                 -------------         ------ ----\n"
            
        res = f"\n    Directory: {self.current_dir}\n\nMode                 LastWriteTime         Length Name\n----                 -------------         ------ ----\n"
        for item in items:
            if "." in item:
                res += f"-a---          {time.strftime('%m/%d/%Y  %I:%M %p')}           4096 {item}\n"
            else:
                res += f"d----          {time.strftime('%m/%d/%Y  %I:%M %p')}                {item}\n"
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
            self.prompt_lbl.setText(f"PS {self.current_dir}>")
            return ""
            
        check_path = self.current_dir + "\\" + target
        check_normalized = check_path.replace("\\\\", "\\")
        if check_normalized in self.virtual_fs:
            self.current_dir = check_normalized
            self.prompt_lbl.setText(f"PS {self.current_dir}>")
            return ""
            
        return f"Cannot find path '{target}' because it does not exist."

    def _handle_type(self, args):
        if not args:
            return "Cannot bind argument to parameter 'Path' because it is null."
        target = args[0]
        
        if "password" in target.lower():
            return ("=== PRIVILEGED CREDENTIALS VAULT ===\n"
                    "github_token            = ghp_Z58d83Ka92Lq93Kasl38Adk2JqpO11283\n"
                    "db_production_master    = pg_sec_root_9921_cluster\n"
                    "aws_secret_key          = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    "domain_admin_ntlm_hash  = 8846f7eaee8fb117ad06bdd830b7586c")
        elif "topology" in target.lower() or "network" in target.lower():
            return "INTERNAL INFRASTRUCTURE: Subnet 10.0.4.0/24 -> Gateway 10.0.4.1 (Firewall Active)"
        elif "backup" in target.lower() or "database" in target.lower():
            return "-- SQL DUMP: TABLE accounts (id INT, username VARCHAR, role VARCHAR, hash VARCHAR);"
        else:
            chk = os.path.join(self.sandbox_dir, target)
            if os.path.exists(chk):
                try:
                    with open(chk, "r") as f:
                        return f.read()
                except Exception:
                    pass
            return f"Cannot find path '{target}' because it does not exist."

    def _handle_echo(self, raw_cmd):
        if ">" not in raw_cmd:
            parts = raw_cmd.split()
            return " ".join(parts[1:]) if len(parts) > 1 else ""
            
        try:
            cmd_part, file_part = raw_cmd.split(">", 1)
            text = cmd_part.replace("echo", "", 1).replace("write-output", "", 1).strip()
            if text.startswith("'") or text.startswith('"'):
                text = text[1:-1]
                
            filename = file_part.strip()
            
            # Divert attacker file payload safely to isolated Sandbox directory
            sandbox_path = os.path.join(self.sandbox_dir, filename)
            os.makedirs(self.sandbox_dir, exist_ok=True)
            
            with open(sandbox_path, "w", encoding="utf-8") as f:
                f.write(text + "\n")
                
            items = self.virtual_fs.get(self.current_dir, [])
            if filename not in items:
                items.append(filename)
                self.virtual_fs[self.current_dir] = items
                
            print(f"[DECEPTION] Intercepted payload write. Diverted to sandbox '{sandbox_path}'", flush=True)
            return ""
        except Exception as e:
            return f"Error writing file: {e}"


class HoneypotDesktop(QWidget):
    """
    Full-Screen Deception Overlay replicating the user's active window/desktop 1:1.
    Renders the exact pre-breach screenshot (with all open apps, browser tabs, VS Code, and taskbar),
    displaying an authentic draggable floating PowerShell terminal over it.
    
    Includes global Ctrl+Alt+Shift+U hotkey hook to verify identity and recover forensics.
    """
    def __init__(self, snapshot_path=None):
        super().__init__()
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_dir = os.path.join(project_dir, "data", "forensics")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        # 1. Load exact pre-breach screenshot of the user's desktop with all open apps
        if snapshot_path is None:
            snapshot_path = os.path.join(self.log_dir, "desktop_snapshot.png")
            
        if os.path.exists(snapshot_path):
            self.screenshot = QPixmap(snapshot_path)
            print(f"[DECEPTION] Replicating exact active desktop from snapshot '{snapshot_path}'", flush=True)
        else:
            screen = QApplication.primaryScreen()
            self.screenshot = screen.grabWindow(0) if screen else QPixmap()
            print("[DECEPTION] Captured live desktop state for honeypot replication.", flush=True)

        self.init_ui()
        self.init_hotkey()

    def init_ui(self):
        # Frameless, topmost overlay covering the primary display
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)
        screen_geom = QApplication.primaryScreen().geometry()
        self.setGeometry(screen_geom)
        
        # Non-intrusive Explorer 'Not Responding' status banner
        self.notice_banner = QLabel("⚠️ Windows Explorer is not responding. Use administrative terminal to diagnose.", self)
        self.notice_banner.setStyleSheet("""
            background-color: #2b2b2b;
            color: #f1f2f6;
            font-family: 'Segoe UI', sans-serif;
            font-size: 12px;
            font-weight: 500;
            padding: 8px 16px;
            border: 1px solid #485460;
            border-radius: 6px;
        """)
        self.notice_banner.adjustSize()
        self.notice_banner.move(screen_geom.width() - self.notice_banner.width() - 30, 30)
        self.notice_banner.hide()

        # Floating Draggable Honey-Shell Terminal positioned centrally
        self.terminal = HoneyShell(self.sandbox_dir, self.log_dir, parent=self)
        center_x = max(20, (screen_geom.width() - self.terminal.width()) // 2)
        center_y = max(20, (screen_geom.height() - self.terminal.height()) // 2)
        self.terminal.move(center_x, center_y)

    def paintEvent(self, event):
        """Paints the replicated screenshot of the user's actual desktop with 100% pixel fidelity."""
        painter = QPainter(self)
        if hasattr(self, 'screenshot') and not self.screenshot.isNull():
            painter.drawPixmap(self.rect(), self.screenshot)
        else:
            painter.fillRect(self.rect(), QColor("#1e1e1e"))
        super().paintEvent(event)

    def mousePressEvent(self, event):
        """
        When the attacker clicks on the replicated open apps in the background,
        shows a realistic Windows Explorer Not Responding prompt and focuses the terminal.
        """
        # Only handle clicks directly on the replicated desktop background
        if event.pos() not in self.terminal.geometry():
            self.notice_banner.show()
            # Bring terminal to top and focus
            self.terminal.raise_()
            self.terminal.input_field.setFocus()
            # Hide banner after 3 seconds
            QTimer.singleShot(3500, self.notice_banner.hide)
        super().mousePressEvent(event)

    def init_hotkey(self):
        """Starts background pynput listener watching for Ctrl+Alt+Shift+U."""
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
        
        evaluator = ThreatEvaluator()
        evaluator.is_breached = True
        
        self.lock_prompt = VerificationLockScreen(evaluator)
        self.lock_prompt.trigger_deception = self.lock_prompt.close
        
        original_check = self.lock_prompt.check_otp
        
        def wrapped_check():
            entered = self.lock_prompt.otp_input.text().strip()
            ok = evaluator.verify_otp_and_reset(entered)
            if ok:
                self.lock_prompt.status_lbl.setText("Identity Verified! Opening Forensics Dashboard...")
                QApplication.processEvents()
                time.sleep(1.0)
                self.lock_prompt.close()
                self.close()
                
                # Launch Forensics Recovery Dashboard
                from dashboard.forensic_dashboard import launch_forensic_dashboard
                launch_forensic_dashboard()
            else:
                self.lock_prompt.failed_attempts += 1
                self.lock_prompt.status_lbl.setText(f"Invalid code. Attempts remaining: {3 - self.lock_prompt.failed_attempts}")
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
        event.ignore()

def launch_honey_desktop(snapshot_path=None):
    """Entrypoint function to run the PyQt6 Honey-Desktop application loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    desktop_window = HoneypotDesktop(snapshot_path=snapshot_path)
    desktop_window.showFullScreen()
    
    app.exec()

if __name__ == "__main__":
    launch_honey_desktop()
