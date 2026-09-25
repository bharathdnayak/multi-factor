import sys
import os
import time
import threading
import psutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QFrame, QDialog
)
from PyQt6.QtCore import Qt, QSize, QPoint, QObject, pyqtSignal, QTimer, QRect
from PyQt6.QtGui import QFont, QColor, QPixmap, QPainter, QCursor, QIcon
from pynput import keyboard

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

class HotkeySignals(QObject):
    """Signals to communicate safely from background keyboard threads to the UI thread."""
    trigger_lock = pyqtSignal()

class HistoryLineEdit(QLineEdit):
    """QLineEdit with Up/Down arrow key command history navigation."""
    def __init__(self, parent_shell):
        super().__init__()
        self.shell = parent_shell

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Up:
            self.shell.navigate_history(-1)
            event.accept()
            return
        elif event.key() == Qt.Key.Key_Down:
            self.shell.navigate_history(1)
            event.accept()
            return
        super().keyPressEvent(event)

class WindowsGhostingDialog(QDialog):
    """
    Authentic Windows 'Program Not Responding' dialog matching Windows 10/11 system UI.
    """
    def __init__(self, app_name="Application", parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self.setWindowTitle(f"{app_name} (Not Responding)")
        self.setFixedSize(430, 175)
        self.setStyleSheet("""
            QDialog {
                background-color: #fbfbfb;
                color: #202020;
                font-family: 'Segoe UI', Tahoma, sans-serif;
            }
            QLabel {
                color: #202020;
                font-size: 12px;
            }
            QPushButton {
                background-color: #e5e5e5;
                border: 1px solid #707070;
                padding: 6px 14px;
                border-radius: 3px;
                font-size: 12px;
                color: #000000;
            }
            QPushButton:hover {
                background-color: #e5f1fb;
                border-color: #0078d7;
            }
            QPushButton:pressed {
                background-color: #cce4f7;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 14)
        layout.setSpacing(10)
        
        top_layout = QHBoxLayout()
        icon_lbl = QLabel("⚠️")
        icon_lbl.setStyleSheet("font-size: 26px; margin-right: 12px;")
        top_layout.addWidget(icon_lbl)
        
        text_layout = QVBoxLayout()
        title_lbl = QLabel(f"<b>{app_name} is not responding</b>")
        title_lbl.setStyleSheet("font-size: 13px; color: #003399;")
        desc_lbl = QLabel("If you close the program, you might lose unsaved information.<br>Windows is waiting for the program to respond.")
        desc_lbl.setWordWrap(True)
        text_layout.addWidget(title_lbl)
        text_layout.addWidget(desc_lbl)
        top_layout.addLayout(text_layout)
        layout.addLayout(top_layout)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        close_btn = QPushButton("Close the program")
        close_btn.clicked.connect(self.accept)
        wait_btn = QPushButton("Wait for the program to respond")
        wait_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        btn_layout.addWidget(wait_btn)
        layout.addLayout(btn_layout)
        
        self.setLayout(layout)

class TaskbarClockOverlay(QLabel):
    """
    Dynamically renders a live, ticking system clock in the exact bottom-right
    Windows taskbar location, eliminating the frozen-clock forensic giveaway.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-family: 'Segoe UI Variable Text', 'Segoe UI', Tahoma, sans-serif;
                font-size: 11px;
                font-weight: 400;
                background-color: transparent;
                padding-right: 10px;
            }
        """)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)
        self.update_time()

    def update_time(self):
        try:
            time_part = time.strftime("%I:%M %p").lstrip('0')
            date_part = time.strftime("%d-%m-%Y")
            self.setText(f"{time_part}\n{date_part}")
        except Exception:
            self.setText(time.strftime("%H:%M\n%Y-%m-%d"))

class HoneyShell(QFrame):
    """
    Authentic Windows Floating Terminal Emulator (Honeypot PowerShell / CMD).
    Draggable anywhere on top of the replicated desktop.
    Features Up/Down command history, maximize/restore, authentic systeminfo,
    whoami, tasklist (real processes), and diverted file sandbox writes.
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.current_dir = "C:\\Windows\\system32"
        self.drag_position = QPoint()
        self.is_maximized = False
        self.normal_geom = None
        
        # Command History Navigation
        self.history = []
        self.history_index = -1
        
        # Virtual mock filesystem
        self.virtual_fs = {
            "C:\\Windows\\system32": ["cmd.exe", "powershell.exe", "taskmgr.exe", "drivers", "config", "netstat.exe"],
            "C:\\Users\\Administrator": ["Documents", "Downloads", "Desktop"],
            "C:\\Users\\Administrator\\Desktop": ["passwords.txt", "network_topology.pdf", "Terminal.lnk"],
            "C:\\Users\\Administrator\\Documents": ["project_source.zip", "database_backup.sql"]
        }
        
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(QSize(840, 530))
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
                width: 34px;
                height: 26px;
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
        tb_layout.setSpacing(2)
        
        icon_lbl = QLabel("💻")
        icon_lbl.setStyleSheet("font-size: 12px; margin-right: 4px;")
        tb_layout.addWidget(icon_lbl)
        
        self.title_lbl = QLabel("Administrator: Windows PowerShell")
        self.title_lbl.setObjectName("TitleLabel")
        tb_layout.addWidget(self.title_lbl)
        tb_layout.addStretch()
        
        min_btn = QPushButton("─")
        min_btn.setObjectName("TitleBtn")
        min_btn.clicked.connect(self.hide_fake)
        tb_layout.addWidget(min_btn)
        
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("TitleBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        tb_layout.addWidget(self.max_btn)
        
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
        
        self.input_field = HistoryLineEdit(self)
        self.input_field.returnPressed.connect(self.process_command)
        input_row.addWidget(self.input_field)
        
        input_container.setLayout(input_row)
        layout.addWidget(input_container)
        
        self.setLayout(layout)
        
        # PowerShell initial banner
        self.console.append("Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\nInstall the latest PowerShell for new features and improvements! https://aka.ms/PSWindows\n")

    def mousePressEvent(self, event):
        """Allows dragging the terminal window anywhere on top of the replicated desktop."""
        if event.button() == Qt.MouseButton.LeftButton and not self.is_maximized:
            self.drag_position = event.globalPosition().toPoint() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        """Updates terminal position during drag."""
        if event.buttons() == Qt.MouseButton.LeftButton and hasattr(self, 'drag_position') and not self.is_maximized:
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def toggle_maximize(self):
        """Toggles between centered window and maximized window (keeping taskbar visible)."""
        if not self.is_maximized:
            self.normal_geom = self.geometry()
            parent_rect = self.parent().rect() if self.parent() else QApplication.primaryScreen().geometry()
            # Leave 48px at the bottom so the taskbar and live clock remain visible
            self.setGeometry(0, 0, parent_rect.width(), parent_rect.height() - 48)
            self.max_btn.setText("❐")
            self.is_maximized = True
        else:
            if self.normal_geom:
                self.setGeometry(self.normal_geom)
            else:
                self.setFixedSize(QSize(840, 530))
            self.max_btn.setText("□")
            self.is_maximized = False

    def navigate_history(self, delta):
        """Cycles through previous commands when Up/Down arrow is pressed."""
        if not self.history:
            return
            
        new_index = self.history_index + delta
        if 0 <= new_index < len(self.history):
            self.history_index = new_index
            self.input_field.setText(self.history[self.history_index])
        elif new_index >= len(self.history):
            self.history_index = len(self.history)
            self.input_field.clear()

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
            
        # Store in command history for Up/Down arrow navigation
        self.history.append(cmd_raw)
        self.history_index = len(self.history)
        
        self.console.append(f"PS {self.current_dir}> {cmd_raw}")
        self.log_action(cmd_raw)
        
        parts = cmd_raw.split()
        base_cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        response = ""
        
        if base_cmd in ["dir", "ls", "get-childitem"]:
            response = self._handle_dir(args)
        elif base_cmd == "cd":
            response = self._handle_cd(args)
        elif base_cmd in ["cat", "type", "get-content"]:
            response = self._handle_type(args)
        elif base_cmd in ["echo", "write-output"]:
            response = self._handle_echo(cmd_raw)
        elif base_cmd in ["tasklist", "ps", "get-process"]:
            response = self._handle_tasklist()
        elif base_cmd in ["systeminfo"]:
            response = self._handle_systeminfo()
        elif base_cmd in ["netstat"]:
            response = self._handle_netstat(args)
        elif base_cmd in ["whoami"]:
            response = self._handle_whoami(args)
        elif base_cmd in ["hostname"]:
            response = "DESKTOP-SEC-WIN11"
        elif base_cmd in ["clear", "cls"]:
            self.console.clear()
            return
        elif base_cmd in ["ipconfig"]:
            response = self._handle_ipconfig(args)
        elif base_cmd in ["net", "net.exe"]:
            if args and args[0].lower() == "user":
                response = "\nUser accounts for \\\\DESKTOP-SEC-WIN11\n\n-------------------------------------------------------------------------------\nAdministrator            DefaultAccount           Guest\nOwner                    WDAGUtilityAccount\nThe command completed successfully."
            elif args and args[0].lower() == "localgroup":
                response = "\nMembers of local group Administrators:\n\n-------------------------------------------------------------------------------\nAdministrator\nOwner\nThe command completed successfully."
            else:
                response = "The syntax of this command is: NET [ ACCOUNTS | COMPUTER | CONFIG | GROUP | USER ]"
        elif base_cmd in ["help", "Get-Help"]:
            response = "Supported Diagnostic Commands: tasklist, Get-Process, systeminfo, netstat, cd, dir, ls, type, cat, echo, ipconfig, whoami, hostname, net user, cls, clear"
        else:
            response = f"{base_cmd} : The term '{base_cmd}' is not recognized as the name of a cmdlet, function, script file, or operable program.\nCheck the spelling of the name, or if a path was included, verify that the path is correct and try again."
            
        if response:
            self.console.append(response + "\n")
            
        self.console.ensureCursorVisible()

    def _handle_systeminfo(self):
        """Generates realistic Windows 11 systeminfo matching current architecture."""
        total_ram = f"{int(psutil.virtual_memory().total / (1024*1024)):,} MB" if hasattr(psutil, 'virtual_memory') else "16,248 MB"
        return (
            "\nHost Name:                 DESKTOP-SEC-WIN11\n"
            "OS Name:                   Microsoft Windows 11 Pro\n"
            "OS Version:                10.0.22631 N/A Build 22631\n"
            "OS Manufacturer:           Microsoft Corporation\n"
            "OS Configuration:          Standalone Workstation\n"
            "OS Build Type:             Multiprocessor Free\n"
            "System Manufacturer:       Dell Inc.\n"
            "System Model:              Latitude 5430\n"
            "System Type:               x64-based PC\n"
            "Processor(s):              1 Processor(s) Installed.\n"
            "                           [01]: Intel64 Family 6 Model 140 Stepping 1 GenuineIntel ~2.80GHz\n"
            "BIOS Version:              Dell Inc. 1.14.0, 11/14/2023\n"
            "Windows Directory:         C:\\Windows\n"
            "System Directory:          C:\\Windows\\system32\n"
            "Boot Device:               \\Device\\HarddiskVolume1\n"
            "System Locale:             en-us;English (United States)\n"
            "Input Locale:              en-us;English (United States)\n"
            f"Total Physical Memory:     {total_ram}\n"
            "Available Physical Memory: 7,412 MB\n"
            "Virtual Memory: Max Size:  20,344 MB\n"
            "Virtual Memory: Available: 9,120 MB\n"
            "Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed."
        )

    def _handle_whoami(self, args):
        if args and any("/all" in a.lower() or "-all" in a.lower() for a in args):
            return (
                "\nUSER INFORMATION\n----------------\n"
                "User Name              SID\n"
                "====================== ====================================================\n"
                "desktop-sec\\admin     S-1-5-21-3921829102-1928371928-291823910-1001\n\n"
                "PRIVILEGES INFORMATION\n----------------------\n"
                "Privilege Name                Description                          State\n"
                "============================= ==================================== ========\n"
                "SeShutdownPrivilege           Shut down the system                 Enabled\n"
                "SeChangeNotifyPrivilege       Bypass traverse checking             Enabled\n"
                "SeUndockPrivilege             Remove computer from docking station Enabled\n"
                "SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled"
            )
        return "desktop-sec\\administrator"

    def _handle_netstat(self, args):
        return (
            "\nActive Connections\n\n"
            "  Proto  Local Address          Foreign Address        State           PID\n"
            "  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       940\n"
            "  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\n"
            "  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       4812\n"
            "  TCP    127.0.0.1:5357         0.0.0.0:0              LISTENING       4\n"
            "  TCP    192.168.1.142:52114    52.178.17.2:443        ESTABLISHED     8920\n"
            "  TCP    192.168.1.142:52115    142.250.190.46:443     ESTABLISHED     11244"
        )

    def _handle_ipconfig(self, args):
        is_all = args and any("/all" in a.lower() or "-all" in a.lower() for a in args)
        if is_all:
            return (
                "\nWindows IP Configuration\n\n"
                "   Host Name . . . . . . . . . . . . : DESKTOP-SEC-WIN11\n"
                "   Primary Dns Suffix  . . . . . . . : localdomain\n"
                "   Node Type . . . . . . . . . . . . : Hybrid\n"
                "   IP Routing Enabled. . . . . . . . : No\n"
                "   WINS Proxy Enabled. . . . . . . . : No\n\n"
                "Ethernet adapter Ethernet0:\n"
                "   Connection-specific DNS Suffix  . : localdomain\n"
                "   Description . . . . . . . . . . . : Intel(R) Ethernet Connection (14) I219-LM\n"
                "   Physical Address. . . . . . . . . : 00-15-5D-82-4A-1B\n"
                "   DHCP Enabled. . . . . . . . . . . : Yes\n"
                "   Autoconfiguration Enabled . . . . : Yes\n"
                "   IPv4 Address. . . . . . . . . . . : 192.168.1.142(Preferred)\n"
                "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
                "   Default Gateway . . . . . . . . . : 192.168.1.1\n"
                "   DNS Servers . . . . . . . . . . . : 192.168.1.1\n"
                "                                       8.8.8.8"
            )
        return (
            "\nWindows IP Configuration\n\n"
            "Ethernet adapter Ethernet0:\n"
            "   Connection-specific DNS Suffix  . : localdomain\n"
            "   IPv4 Address. . . . . . . . . . . : 192.168.1.142\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n"
            "   Default Gateway . . . . . . . . . : 192.168.1.1"
        )

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
                    if count >= 30:
                        break
                except Exception:
                    continue
        except Exception:
            output.append(f"{'explorer.exe':<30} {'4812':<8} {'Console':<16} {'124,592 K':<12}")
            output.append(f"{'code.exe':<30} {'8920':<8} {'Console':<16} {'382,104 K':<12}")
            output.append(f"{'chrome.exe':<30} {'11244':<8} {'Console':<16} {'491,220 K':<12}")
            output.append(f"{'powershell.exe':<30} {'6104':<8} {'Console':<16} {'58,212 K':<12}")
            
        return "\n".join(output)

    def _handle_dir(self, args=None):
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
    incorporating sub-pixel DPR sharpness, a live ticking taskbar clock overlay,
    authentic Windows Not Responding ghosting dialogs, and a floating PowerShell terminal.
    
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
            
        screen = QApplication.primaryScreen()
        dpr = screen.devicePixelRatio() if screen else 1.0
        
        if os.path.exists(snapshot_path):
            self.screenshot = QPixmap(snapshot_path)
            self.screenshot.setDevicePixelRatio(dpr)
            print(f"[DECEPTION] Replicating exact active desktop from snapshot '{snapshot_path}' (DPR: {dpr})", flush=True)
        else:
            self.screenshot = screen.grabWindow(0) if screen else QPixmap()
            if not self.screenshot.isNull():
                self.screenshot.setDevicePixelRatio(dpr)
            print(f"[DECEPTION] Captured live desktop state for honeypot replication (DPR: {dpr}).", flush=True)

        self.click_count = 0
        self.init_ui()
        self.init_hotkey()

    def init_ui(self):
        # Frameless, topmost overlay covering the primary display
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint | Qt.WindowType.SubWindow)
        screen_geom = QApplication.primaryScreen().geometry()
        self.setGeometry(screen_geom)
        
        # 2. Live Taskbar Clock Overlay (eliminates the frozen clock forensic giveaway!)
        self.clock_overlay = TaskbarClockOverlay(self)
        self.clock_overlay.setFixedSize(110, 42)
        # Position in exact bottom right corner of taskbar
        self.clock_overlay.move(screen_geom.width() - 115, screen_geom.height() - 44)

        # 3. Floating Draggable Honey-Shell Terminal positioned centrally
        self.terminal = HoneyShell(self.sandbox_dir, self.log_dir, parent=self)
        center_x = max(20, (screen_geom.width() - self.terminal.width()) // 2)
        center_y = max(20, (screen_geom.height() - self.terminal.height()) // 2)
        self.terminal.move(center_x, center_y)

    def paintEvent(self, event):
        """Paints the replicated screenshot of the user's actual desktop with 100% pixel fidelity."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        if hasattr(self, 'screenshot') and not self.screenshot.isNull():
            painter.drawPixmap(self.rect(), self.screenshot)
        else:
            painter.fillRect(self.rect(), QColor("#1e1e1e"))
        super().paintEvent(event)

    def mousePressEvent(self, event):
        """
        When the attacker clicks on the replicated open apps in the background,
        shows authentic Windows WaitCursor and spawns the Windows Not Responding dialog.
        """
        if event.pos() not in self.terminal.geometry():
            self.click_count += 1
            
            # 1. Briefly change cursor to Windows spinning circle / hourglass
            QApplication.setOverrideCursor(QCursor(Qt.CursorShape.WaitCursor))
            
            def restore_cursor():
                QApplication.restoreOverrideCursor()
                if self.click_count >= 2:
                    # Determine active app name from running processes for authenticity
                    detected_app = "Visual Studio Code"
                    try:
                        for p in psutil.process_iter(['name']):
                            pname = p.info['name'].lower()
                            if "chrome" in pname:
                                detected_app = "Google Chrome"
                                break
                            elif "code" in pname:
                                detected_app = "Visual Studio Code"
                                break
                    except Exception:
                        pass
                        
                    dlg = WindowsGhostingDialog(app_name=detected_app, parent=self)
                    dlg.exec()
                    self.click_count = 0
                
                # Refocus the administrative terminal
                self.terminal.raise_()
                self.terminal.input_field.setFocus()
                
            QTimer.singleShot(1100, restore_cursor)
            
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
