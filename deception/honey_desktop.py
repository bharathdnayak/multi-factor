import sys
import os
import time
import threading
import psutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QFrame, QDialog, QGridLayout,
    QScrollArea, QMenu
)
from PyQt6.QtCore import Qt, QSize, QPoint, QObject, pyqtSignal, QTimer, QRect
from PyQt6.QtGui import QFont, QColor, QPixmap, QPainter, QCursor, QIcon, QPen, QBrush
from pynput import keyboard

# Append project root
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_dir not in sys.path:
    sys.path.insert(0, project_dir)

from deception.forensic_tracker import get_tracker
from deception.decoy_chrome import DecoyChrome
from deception.virtual_fs import (
    get_vfs, PathUtils, VirtualFileSystem, VirtualFile, VirtualDirectory, VirtualClipboard
)
from deception.window_manager import get_window_manager, DecoyWindowManager
from deception.command_engine import VirtualCommandEngine
from deception.decoy_notepad import DecoyNotepad
from deception.decoy_explorer import DecoyExplorer

# Re-exports for backwards compatibility across tests and existing scripts
__all__ = [
    "HoneypotDesktop",
    "DecoyExplorer",
    "DecoyNotepad",
    "HoneyShell",
    "DecoyChrome",
    "Windows11StartMenu",
    "HoneypotVerificationDialog",
    "DesktopIconWidget",
    "TaskbarWidget",
    "launch_honey_desktop"
]


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


class TaskbarClockOverlay(QLabel):
    """
    Dynamically renders a live, ticking system clock matching Windows 11 system taskbar.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-family: 'Segoe UI Variable Text', 'Segoe UI', Tahoma, sans-serif;
                font-size: 11px;
                font-weight: 400;
                background-color: transparent;
                padding: 0 4px;
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
                background-color: #e0eef9;
                border-color: #0078d7;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(14)
        
        msg_lbl = QLabel(f"The program '{app_name}' is not responding.\nWindows can check for a solution when you go online.")
        msg_lbl.setWordWrap(True)
        layout.addWidget(msg_lbl)
        
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        close_btn = QPushButton("Close the program")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)
        
        wait_btn = QPushButton("Wait for the program to respond")
        wait_btn.clicked.connect(self.reject)
        btn_layout.addWidget(wait_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)


class Windows11StartMenu(QFrame):
    """
    Authentic Windows 11 Centered Start Menu popup.
    Features pinned applications, active VirtualFileSystem search integration,
    and power/lock options triggering clean identity verification exit.
    """
    def __init__(self, parent_desktop, parent=None):
        super().__init__(parent)
        self.desktop = parent_desktop
        self.vfs = get_vfs()
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(480, 460)
        self.setStyleSheet("""
            QFrame#StartMenuContainer {
                background-color: #202020;
                border: 1px solid #383838;
                border-radius: 10px;
            }
            QLineEdit#SearchField {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 13px;
                border: 1px solid #444444;
                border-radius: 16px;
                padding: 6px 16px;
            }
            QLabel#SectionHeader {
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton#AppBtn {
                background-color: transparent;
                color: #e2e8f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                border: none;
                border-radius: 6px;
                padding: 8px 4px;
            }
            QPushButton#AppBtn:hover {
                background-color: #2d3748;
            }
            QFrame#UserFooter {
                background-color: #1a1a1a;
                border-bottom-left-radius: 10px;
                border-bottom-right-radius: 10px;
                border-top: 1px solid #2d2d2d;
            }
            QPushButton#ActionBtn {
                background-color: #2a2a2a;
                color: #00d2d3;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: bold;
                border: 1px solid #3d3d3d;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton#ActionBtn:hover {
                background-color: #383838;
                color: #ffffff;
            }
        """)
        self.setObjectName("StartMenuContainer")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 0)
        layout.setSpacing(12)
        
        # Search bar
        self.search = QLineEdit()
        self.search.setObjectName("SearchField")
        self.search.setPlaceholderText("🔍 Type here to search")
        self.search.textChanged.connect(self.on_search_changed)
        layout.addWidget(self.search)
        
        # Pinned Header
        self.hdr = QLabel("Pinned")
        self.hdr.setObjectName("SectionHeader")
        layout.addWidget(self.hdr)
        
        # Grid of apps
        self.grid = QGridLayout()
        self.grid.setSpacing(10)
        
        apps = [
            ("💻", "PowerShell", self.launch_powershell),
            ("📁", "File Explorer", self.launch_explorer),
            ("🌐", "Google Chrome", self.launch_edge),
            ("📄", "Passwords", self.launch_notepad),
            ("⚙️", "Settings", self.launch_settings),
            ("📝", "Notepad", self.launch_notepad)
        ]
        
        for idx, (icon, name, handler) in enumerate(apps):
            r = idx // 3
            c = idx % 3
            btn = QPushButton(f"{icon}\n{name}")
            btn.setObjectName("AppBtn")
            btn.setFixedSize(130, 60)
            btn.clicked.connect(handler)
            self.grid.addWidget(btn, r, c)
            
        layout.addLayout(self.grid)
        layout.addStretch()
        
        # Footer
        footer = QFrame()
        footer.setObjectName("UserFooter")
        footer.setFixedHeight(50)
        f_layout = QHBoxLayout()
        f_layout.setContentsMargins(16, 0, 16, 0)
        
        user_lbl = QLabel("👤  Dell (Administrator)")
        user_lbl.setStyleSheet("color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 12px; font-weight: 500;")
        f_layout.addWidget(user_lbl)
        f_layout.addStretch()
        
        exit_btn = QPushButton("🔓 Exit Honeypot")
        exit_btn.setObjectName("ActionBtn")
        exit_btn.clicked.connect(self.trigger_exit)
        f_layout.addWidget(exit_btn)
        
        footer.setLayout(f_layout)
        layout.addWidget(footer)
        
        self.setLayout(layout)

    def on_search_changed(self, text: str):
        q = text.strip()
        if not q:
            self.hdr.setText("Pinned")
            return
        
        # Query virtual filesystem for search matches
        results = self.vfs.search(q, root_path="C:\\Users\\Dell", recursive=True)
        if results:
            self.hdr.setText(f"Best match ({len(results)} found in C:\\Users\\Dell)")
        else:
            self.hdr.setText(f"No results found for '{q}'")

    def launch_powershell(self):
        self.hide()
        self.desktop.open_terminal()

    def launch_explorer(self):
        self.hide()
        self.desktop.open_explorer()

    def launch_notepad(self):
        self.hide()
        self.desktop.open_notepad()

    def launch_edge(self):
        self.hide()
        self.desktop.open_chrome()

    def launch_settings(self):
        self.hide()
        self.desktop.show_verification_prompt()

    def trigger_exit(self):
        self.hide()
        self.desktop.show_verification_prompt()


class HoneypotVerificationDialog(QDialog):
    """
    Windows Security Identity Verification & Forensic Recovery Dialog.
    Allows authentic session unlock via Master Bypass Password or OTP PIN,
    and provides an Emergency Exit option so users never get permanently locked out.
    """
    def __init__(self, parent_desktop):
        super().__init__(parent_desktop)
        self.desktop = parent_desktop
        self.failed_attempts = 0
        self.init_ui()

    def init_ui(self):
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.CustomizeWindowHint | Qt.WindowType.WindowTitleHint)
        self.setWindowTitle("Windows Security - Identity Verification")
        self.setFixedSize(460, 260)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e1e2d;
                color: #e2e8f0;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel#Title {
                color: #00d2d3;
                font-size: 16px;
                font-weight: bold;
            }
            QLabel#Sub {
                color: #a4b0be;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #151522;
                border: 2px solid #3c3c54;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 16px;
                color: #ffffff;
            }
            QLineEdit:focus {
                border-color: #00d2d3;
            }
            QPushButton#VerifyBtn {
                background-color: #2ed573;
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                padding: 8px 16px;
                border-radius: 6px;
                border: none;
            }
            QPushButton#VerifyBtn:hover {
                background-color: #26af5f;
            }
            QPushButton#EmergencyBtn {
                background-color: #ff4757;
                color: #ffffff;
                font-weight: bold;
                font-size: 13px;
                padding: 8px 16px;
                border-radius: 6px;
                border: none;
            }
            QPushButton#EmergencyBtn:hover {
                background-color: #e84118;
            }
            QPushButton#CancelBtn {
                background-color: #3d3d5c;
                color: #e2e8f0;
                font-size: 13px;
                padding: 8px 16px;
                border-radius: 6px;
                border: none;
            }
            QPushButton#CancelBtn:hover {
                background-color: #4b4b6f;
            }
            QLabel#Status {
                font-size: 12px;
                font-weight: bold;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)
        
        # Header
        top_h = QHBoxLayout()
        icon_lbl = QLabel("🛡️")
        icon_lbl.setStyleSheet("font-size: 28px; margin-right: 8px;")
        top_h.addWidget(icon_lbl)
        
        hdr_layout = QVBoxLayout()
        t_lbl = QLabel("Session Identity Verification")
        t_lbl.setObjectName("Title")
        s_lbl = QLabel("Enter Master Recovery Password or 6-digit OTP code to exit Honeypot and restore normal Windows session:")
        s_lbl.setObjectName("Sub")
        s_lbl.setWordWrap(True)
        hdr_layout.addWidget(t_lbl)
        hdr_layout.addWidget(s_lbl)
        top_h.addLayout(hdr_layout)
        layout.addLayout(top_h)
        
        # Password Input
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter recovery password or 6-digit OTP code")
        self.input_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_field.returnPressed.connect(self.verify_code)
        layout.addWidget(self.input_field)
        
        # Status Label
        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("Status")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_lbl)
        
        # Buttons Row
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        
        verify_btn = QPushButton("Verify & Unlock")
        verify_btn.setObjectName("VerifyBtn")
        verify_btn.clicked.connect(self.verify_code)
        btn_layout.addWidget(verify_btn)
        
        emergency_btn = QPushButton("Emergency Exit")
        emergency_btn.setObjectName("EmergencyBtn")
        emergency_btn.clicked.connect(self.emergency_exit)
        btn_layout.addWidget(emergency_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("CancelBtn")
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def verify_code(self):
        entered = self.input_field.text().strip()
        from security.drift_detector import ThreatEvaluator
        evaluator = ThreatEvaluator()
        evaluator.is_breached = True
        
        ok = evaluator.verify_otp_and_reset(entered)
        if ok:
            self.status_lbl.setStyleSheet("color: #2ed573;")
            self.status_lbl.setText("Identity Verified! Opening Forensics Dashboard...")
            QApplication.processEvents()
            time.sleep(0.8)
            self.accept()
            self.desktop._can_close = True
            self.desktop.close()
            
            # Open Forensics Recovery Dashboard
            from dashboard.forensic_dashboard import ForensicDashboard
            global _active_forensics_window
            _active_forensics_window = ForensicDashboard()
            _active_forensics_window.show()
        else:
            self.failed_attempts += 1
            self.status_lbl.setStyleSheet("color: #ff4757;")
            self.status_lbl.setText(f"Invalid code. Attempts remaining: {max(0, 3 - self.failed_attempts)}")
            self.input_field.clear()

    def emergency_exit(self):
        self.status_lbl.setStyleSheet("color: #00d2d3;")
        self.status_lbl.setText("Emergency exit confirmed. Restoring desktop...")
        QApplication.processEvents()
        time.sleep(0.4)
        self.accept()
        self.desktop._can_close = True
        self.desktop.close()


class VirtualFsDictAdapter(dict):
    """
    Adapter dictionary that mirrors the centralized VirtualFileSystem.
    Provides backwards compatibility for legacy tests and code accessing shell.virtual_fs.
    """
    def __init__(self, vfs: VirtualFileSystem):
        super().__init__()
        self.vfs = vfs

    def get(self, key, default=None):
        if self.vfs.exists(key):
            children = self.vfs.list_dir(key, include_hidden=True)
            return [c.name for c in children]
        return default if default is not None else []

    def __getitem__(self, key):
        if self.vfs.exists(key):
            children = self.vfs.list_dir(key, include_hidden=True)
            return [c.name for c in children]
        raise KeyError(key)

    def __contains__(self, key):
        return self.vfs.exists(key)

    def __setitem__(self, key, value):
        for item in value:
            item_path = PathUtils.join(key, item)
            if "." in item:
                self.vfs.create_file(item_path, content="", overwrite=True)
            else:
                self.vfs.mkdir(item_path)


class HoneyShell(QFrame):
    """
    Authentic Windows Floating Terminal Emulator (Honeypot PowerShell / CMD).
    Backed by the centralized VirtualFileSystem and VirtualCommandEngine.
    Features Up/Down command history, minimize, maximize/restore, closable,
    and safe sandbox payload quarantine.
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
        self.engine = VirtualCommandEngine(self.sandbox_dir, self.log_dir)
        self.drag_position = QPoint()
        self.is_maximized = False
        self.normal_geom = None
        
        # Command History Navigation
        self.history = []
        self.history_index = -1
        
        # Virtual mock filesystem adapter
        self.virtual_fs = VirtualFsDictAdapter(self.engine.vfs)
        
        self.init_ui()

    @property
    def current_dir(self) -> str:
        return self.engine.current_dir

    @current_dir.setter
    def current_dir(self, val: str):
        self.engine.current_dir = PathUtils.normalize(val)

    def init_ui(self):
        self.setFixedSize(QSize(840, 520))
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
        min_btn.clicked.connect(self.minimize_shell)
        tb_layout.addWidget(min_btn)
        
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("TitleBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        tb_layout.addWidget(self.max_btn)
        
        close_btn = QPushButton("✕")
        close_btn.setObjectName("TitleBtn")
        close_btn.setProperty("class", "CloseBtn")
        close_btn.clicked.connect(self.close_shell)
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
        
        # Windows PowerShell Banner
        self.console.append("Windows PowerShell")
        self.console.append("Copyright (C) Microsoft Corporation. All rights reserved.\n")
        self.console.append("Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows\n")

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and not self.is_maximized:
            self.drag_position = event.globalPosition().toPoint() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.MouseButton.LeftButton and hasattr(self, 'drag_position') and not self.is_maximized:
            self.move(event.globalPosition().toPoint() - self.drag_position)
            event.accept()

    def toggle_maximize(self):
        if not self.is_maximized:
            self.normal_geom = self.geometry()
            parent_rect = self.parent().rect() if self.parent() else QApplication.primaryScreen().geometry()
            self.setGeometry(0, 0, parent_rect.width(), parent_rect.height() - 48)
            self.max_btn.setText("❐")
            self.is_maximized = True
        else:
            if self.normal_geom:
                self.setGeometry(self.normal_geom)
            else:
                self.setFixedSize(QSize(840, 520))
            self.max_btn.setText("□")
            self.is_maximized = False

    def navigate_history(self, direction):
        if not self.history:
            return
        new_idx = self.history_index + direction
        if 0 <= new_idx < len(self.history):
            self.history_index = new_idx
            self.input_field.setText(self.history[self.history_index])
        elif new_idx >= len(self.history):
            self.history_index = len(self.history)
            self.input_field.clear()

    def minimize_shell(self):
        self.hide()

    def close_shell(self):
        self.hide()

    def log_action(self, cmd_raw):
        self.engine.log_action(cmd_raw)

    def process_command(self):
        cmd_raw = self.input_field.text().strip()
        self.input_field.clear()
        
        if not cmd_raw:
            return
            
        self.history.append(cmd_raw)
        self.history_index = len(self.history)
        
        self.console.append(f"PS {self.current_dir}> {cmd_raw}")
        
        # Execute safely via VirtualCommandEngine
        response, should_exit = self.engine.execute(cmd_raw)
        if should_exit:
            self.close_shell()
            return
            
        if response == "__CLEAR__":
            self.console.clear()
        elif response:
            self.console.append(response + "\n")
            
        self.prompt_lbl.setText(f"PS {self.current_dir}>")
        self.console.ensureCursorVisible()

    # Delegate methods for backward compatibility with existing tests
    def _handle_ping(self, args):
        return self.engine._cmd_ping(args)

    def _handle_arp(self, args):
        return self.engine._cmd_arp(args)

    def _handle_route(self, args):
        return self.engine._cmd_route(args)

    def _handle_curl(self, cmd_raw, args):
        return self.engine._cmd_curl(cmd_raw, args)

    def _handle_ssh(self, args):
        return self.engine._cmd_ssh(args)

    def _handle_nslookup(self, args):
        return self.engine._cmd_nslookup(args)

    def _handle_tracert(self, args):
        return self.engine._cmd_tracert(args)

    def _handle_dir(self, args=None):
        return self.engine._cmd_dir(args or [])

    def _handle_cd(self, args):
        res = self.engine._cmd_cd(args)
        self.prompt_lbl.setText(f"PS {self.current_dir}>")
        return res

    def _handle_type(self, args):
        return self.engine._cmd_type(args)

    def _handle_echo(self, cmd_raw):
        return self.engine._handle_redirection(cmd_raw)

    def _handle_tasklist(self):
        return self.engine._cmd_tasklist()

    def _handle_systeminfo(self):
        return self.engine._cmd_systeminfo()

    def _handle_whoami(self, args):
        return self.engine._cmd_whoami(args)

    def _handle_netstat(self, args):
        return self.engine._cmd_netstat(args)

    def _handle_ipconfig(self, args):
        return self.engine._cmd_ipconfig(args)


class DesktopIconWidget(QWidget):
    """Interactive clickable desktop icon matching Windows 11 style."""
    def __init__(self, icon_text, label_text, click_handler, parent=None):
        super().__init__(parent)
        self.handler = click_handler
        self.setFixedSize(84, 88)
        self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        
        layout = QVBoxLayout()
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.icon_lbl = QLabel(icon_text)
        self.icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.icon_lbl.setStyleSheet("font-size: 34px; background: transparent;")
        layout.addWidget(self.icon_lbl)
        
        self.text_lbl = QLabel(label_text)
        self.text_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.text_lbl.setWordWrap(True)
        self.text_lbl.setStyleSheet("""
            color: #ffffff;
            font-family: 'Segoe UI', sans-serif;
            font-size: 11px;
            font-weight: 500;
            background: transparent;
        """)
        layout.addWidget(self.text_lbl)
        self.setLayout(layout)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.setStyleSheet("background-color: rgba(255, 255, 255, 0.15); border-radius: 6px;")
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self.setStyleSheet("background-color: transparent;")
        if event.button() == Qt.MouseButton.LeftButton:
            get_tracker().record_desktop_icon_click(self.text_lbl.text())
            if callable(self.handler):
                self.handler()
        super().mouseReleaseEvent(event)

    def enterEvent(self, event):
        self.setStyleSheet("background-color: rgba(255, 255, 255, 0.08); border-radius: 6px;")
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet("background-color: transparent;")
        super().leaveEvent(event)


class TaskbarWidget(QFrame):
    """
    Authentic Windows 11 Taskbar.
    Pinned at the bottom of the screen with centered icons, Start menu trigger,
    system tray with live clock, active running app indicators, and emergency recovery button.
    """
    def __init__(self, parent_desktop):
        super().__init__(parent_desktop)
        self.desktop = parent_desktop
        self.setFixedHeight(48)
        self.setObjectName("WindowsTaskbar")
        self.setStyleSheet("""
            QFrame#WindowsTaskbar {
                background-color: rgba(24, 24, 24, 0.94);
                border-top: 1px solid rgba(255, 255, 255, 0.08);
            }
            QPushButton#TaskbarBtn {
                background: transparent;
                border: none;
                border-radius: 5px;
                padding: 6px;
                font-size: 18px;
            }
            QPushButton#TaskbarBtn:hover {
                background-color: rgba(255, 255, 255, 0.08);
            }
            QPushButton#TaskbarBtn:pressed {
                background-color: rgba(255, 255, 255, 0.12);
            }
            QLabel#TrayText {
                color: #e2e8f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                padding: 0 4px;
            }
        """)
        
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(10, 0, 10, 0)
        main_layout.setSpacing(0)
        
        # Left dummy for centering
        self.left_box = QFrame()
        self.left_box.setFixedWidth(160)
        main_layout.addWidget(self.left_box)
        main_layout.addStretch()
        
        # Center pinned icons
        center_box = QHBoxLayout()
        center_box.setSpacing(6)
        
        # Start button
        self.start_btn = QPushButton("❖")
        self.start_btn.setObjectName("TaskbarBtn")
        self.start_btn.setStyleSheet("color: #00d2d3; font-size: 20px; font-weight: bold;")
        self.start_btn.setToolTip("Start")
        self.start_btn.clicked.connect(self.desktop.toggle_start_menu)
        center_box.addWidget(self.start_btn)
        
        # Search pill
        search_pill = QFrame()
        search_pill.setFixedSize(120, 32)
        search_pill.setStyleSheet("background-color: rgba(255, 255, 255, 0.06); border-radius: 16px; border: 1px solid rgba(255,255,255,0.06);")
        search_pill.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        search_pill.mousePressEvent = lambda e: self.desktop.toggle_start_menu()
        sp_layout = QHBoxLayout()
        sp_layout.setContentsMargins(10, 0, 10, 0)
        sp_lbl = QLabel("🔍  Search")
        sp_lbl.setStyleSheet("color: #aaaaaa; font-family: 'Segoe UI', sans-serif; font-size: 11px; background: transparent;")
        sp_layout.addWidget(sp_lbl)
        search_pill.setLayout(sp_layout)
        center_box.addWidget(search_pill)
        
        # File Explorer
        self.exp_btn = QPushButton("📁")
        self.exp_btn.setObjectName("TaskbarBtn")
        self.exp_btn.setToolTip("File Explorer")
        self.exp_btn.clicked.connect(self.desktop.toggle_explorer)
        center_box.addWidget(self.exp_btn)
        
        # Chrome / Browser
        self.chrome_btn = QPushButton("🌐")
        self.chrome_btn.setObjectName("TaskbarBtn")
        self.chrome_btn.setToolTip("Google Chrome")
        self.chrome_btn.clicked.connect(self.desktop.toggle_chrome)
        center_box.addWidget(self.chrome_btn)
        
        # PowerShell Terminal
        self.term_btn = QPushButton("💻")
        self.term_btn.setObjectName("TaskbarBtn")
        self.term_btn.setToolTip("Windows PowerShell")
        self.term_btn.clicked.connect(self.desktop.toggle_terminal)
        center_box.addWidget(self.term_btn)
        
        # Notepad
        self.notes_btn = QPushButton("📝")
        self.notes_btn.setObjectName("TaskbarBtn")
        self.notes_btn.setToolTip("Notepad")
        self.notes_btn.clicked.connect(self.desktop.toggle_notepad)
        center_box.addWidget(self.notes_btn)
        
        main_layout.addLayout(center_box)
        main_layout.addStretch()
        
        # Right Tray
        right_tray = QHBoxLayout()
        right_tray.setSpacing(6)
        
        for icon in ["📶", "🔊", "🔋"]:
            lbl = QLabel(icon)
            lbl.setStyleSheet("font-size: 13px; color: #ffffff; padding: 0 2px;")
            right_tray.addWidget(lbl)
            
        lang_lbl = QLabel("ENG\nIN")
        lang_lbl.setObjectName("TrayText")
        lang_lbl.setStyleSheet("font-size: 10px; font-weight: 500; line-height: 10px;")
        right_tray.addWidget(lang_lbl)
        
        self.clock = TaskbarClockOverlay(self)
        right_tray.addWidget(self.clock)
        
        shield_btn = QPushButton("🛡️")
        shield_btn.setObjectName("TaskbarBtn")
        shield_btn.setToolTip("Session Security Recovery")
        shield_btn.setStyleSheet("font-size: 14px; padding: 4px;")
        shield_btn.clicked.connect(self.desktop.show_verification_prompt)
        right_tray.addWidget(shield_btn)
        
        main_layout.addLayout(right_tray)
        self.setLayout(main_layout)

        # Connect to Window Manager for live active app indicators
        wm = get_window_manager()
        wm.window_state_changed.connect(lambda *_: self.update_indicators())
        wm.active_window_changed.connect(lambda *_: self.update_indicators())

    def update_indicators(self):
        wm = get_window_manager()
        active = wm.active_app_id
        
        apps = {
            "explorer": self.exp_btn,
            "chrome": self.chrome_btn,
            "terminal": self.term_btn,
            "notepad": self.notes_btn
        }
        for app_id, btn in apps.items():
            is_open = wm.is_open(app_id)
            is_active = (active == app_id)
            if is_active:
                btn.setStyleSheet("background-color: rgba(255, 255, 255, 0.16); border-bottom: 3px solid #00d2d3; border-radius: 4px; padding: 5px; font-size: 18px;")
            elif is_open:
                btn.setStyleSheet("background-color: rgba(255, 255, 255, 0.08); border-bottom: 2px solid #888888; border-radius: 4px; padding: 5px; font-size: 18px;")
            else:
                btn.setStyleSheet("background: transparent; border: none; border-radius: 5px; padding: 6px; font-size: 18px;")


class HoneypotDesktop(QWidget):
    """
    Full-Screen Windows 11 Honeypot Desktop Environment.
    Renders authentic desktop screenshot / wallpaper, desktop icons with context menu,
    centered Windows 11 taskbar, floating draggable PowerShell terminal,
    interactive File Explorer, Notepad, Decoy Chrome, and Start Menu.
    All applications share the centralized VirtualFileSystem and DecoyWindowManager.
    """
    def __init__(self, snapshot_path=None):
        super().__init__()
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_dir = os.path.join(project_dir, "data", "forensics")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        
        self.tracker = get_tracker()
        self.tracker.start_new_session()
        self.vfs = get_vfs()
        self.window_manager = get_window_manager()
        
        self._can_close = False
        self._last_esc_time = 0.0
        
        screen = QApplication.primaryScreen()
        dpr = screen.devicePixelRatio() if screen else 1.0
        
        self.screenshot = self.load_authentic_desktop(snapshot_path, dpr)
        self.desktop_icon_widgets = []
        
        self.init_ui()
        self.init_hotkey()

    def load_authentic_desktop(self, snapshot_path, dpr):
        """Loads valid desktop snapshot or synthesizes clean desktop from Windows wallpaper."""
        if snapshot_path is None:
            snapshot_path = os.path.join(self.log_dir, "desktop_snapshot.png")
            
        screen = QApplication.primaryScreen()
        geom = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
        target_w = int(geom.width() * dpr)
        target_h = int(geom.height() * dpr)
        
        # 1. Windows Themes wallpaper
        wallpaper_path = os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Themes\TranscodedWallpaper')
        if os.path.exists(wallpaper_path):
            wall = QPixmap(wallpaper_path)
            if not wall.isNull():
                scaled_wall = wall.scaled(target_w, target_h, Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation)
                canvas = QPixmap(target_w, target_h)
                painter = QPainter(canvas)
                ox = max(0, (scaled_wall.width() - target_w) // 2)
                oy = max(0, (scaled_wall.height() - target_h) // 2)
                painter.drawPixmap(0, 0, scaled_wall, ox, oy, target_w, target_h)
                painter.end()
                canvas.setDevicePixelRatio(dpr)
                try:
                    canvas.save(snapshot_path, "PNG")
                except Exception:
                    pass
                return canvas
        
        # 2. Existing valid snapshot
        if os.path.exists(snapshot_path) and os.path.getsize(snapshot_path) > 10000:
            pix = QPixmap(snapshot_path)
            if not pix.isNull():
                pix.setDevicePixelRatio(dpr)
                return pix
                
        # 3. Fallback: modern Windows 11 dark theme background
        canvas = QPixmap(target_w, target_h)
        canvas.fill(QColor("#0d1117"))
        canvas.setDevicePixelRatio(dpr)
        return canvas

    def init_ui(self):
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        screen_geom = QApplication.primaryScreen().geometry()
        self.setGeometry(screen_geom)
        
        # 1. Desktop Icons on left
        self.setup_desktop_icons()
        
        # 2. Windows 11 Taskbar across bottom
        self.taskbar = TaskbarWidget(self)
        self.taskbar.setGeometry(0, screen_geom.height() - 48, screen_geom.width(), 48)
        self.clock_overlay = self.taskbar.clock
        
        # 3. Floating Draggable Honey-Shell Terminal
        self.terminal = HoneyShell(self.sandbox_dir, self.log_dir, parent=self)
        center_x = max(40, (screen_geom.width() - self.terminal.width()) // 2)
        center_y = max(30, (screen_geom.height() - self.terminal.height() - 60) // 2)
        self.terminal.move(center_x, center_y)
        self.window_manager.register_window("terminal", self.terminal, "Windows PowerShell", "💻")
        
        # 4. Decoy Notepad
        self.decoy_notepad = DecoyNotepad(self.sandbox_dir, self.log_dir, parent=self)
        self.decoy_notepad.move(center_x + 60, center_y + 40)
        self.decoy_notepad.hide()
        self.window_manager.register_window("notepad", self.decoy_notepad, "Notepad", "📝")
        
        # 5. Decoy File Explorer
        self.decoy_explorer = DecoyExplorer(self.sandbox_dir, self.log_dir, parent=self)
        self.decoy_explorer.move(max(20, center_x - 60), max(20, center_y - 30))
        self.decoy_explorer.hide()
        self.window_manager.register_window("explorer", self.decoy_explorer, "File Explorer", "📁")
        
        # 6. Decoy Google Chrome Browser
        self.decoy_chrome = DecoyChrome(parent=self)
        self.decoy_chrome.move(max(30, center_x - 30), max(20, center_y - 20))
        self.decoy_chrome.hide()
        self.window_manager.register_window("chrome", self.decoy_chrome, "Google Chrome", "🌐")
        
        # 7. Windows 11 Start Menu
        self.start_menu = Windows11StartMenu(self, parent=self)
        sm_x = max(10, (screen_geom.width() - self.start_menu.width()) // 2)
        sm_y = screen_geom.height() - 48 - self.start_menu.height() - 10
        self.start_menu.move(sm_x, sm_y)
        self.start_menu.hide()

        # Connect Window Manager signals to Forensic Tracker
        self.window_manager.window_state_changed.connect(
            lambda app_id, action: self.tracker.record_window_action(app_id, action=action)
        )
        self.window_manager.active_window_changed.connect(
            lambda app_id: self.tracker.record_window_action(app_id, action="focus") if app_id else None
        )

    def setup_desktop_icons(self):
        """Populates desktop icons dynamically from VirtualFileSystem and standard shortcuts."""
        for w in self.desktop_icon_widgets:
            w.deleteLater()
        self.desktop_icon_widgets.clear()
        
        standard_icons = [
            ("🌐", "Google Chrome", self.open_chrome),
            ("💻", "This PC", self.open_explorer),
            ("🗑️", "Recycle Bin", lambda: self.open_explorer(folder_path="C:\\$Recycle.Bin")),
            ("📁", "clg", lambda: self.open_explorer(folder_path="C:\\Users\\Dell\\Desktop\\clg")),
            ("📄", "tester.txt", lambda: self.open_notepad(file_path="C:\\Users\\Dell\\Desktop\\tester.txt")),
            ("📂", "My Documents", lambda: self.open_explorer(folder_path="C:\\Users\\Dell\\Documents")),
            ("🔒", "passwords.txt", lambda: self.open_notepad(file_path="C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\passwords.txt")),
            ("⚡", "PowerShell", self.open_terminal)
        ]
        
        # Also query user's Desktop directory in VFS for newly created files/folders
        desktop_nodes = self.vfs.list_dir("C:\\Users\\Dell\\Desktop", include_hidden=False)
        added_names = {item[1] for item in standard_icons}
        
        for node in desktop_nodes:
            if node.name not in added_names:
                if node.is_dir:
                    handler = lambda p=node.path: self.open_explorer(folder_path=p)
                else:
                    handler = lambda p=node.path: self.open_notepad(file_path=p)
                standard_icons.append((node.icon, node.name, handler))
                added_names.add(node.name)

        start_y = 20
        start_x = 20
        spacing_y = 86
        col_width = 96
        max_per_col = max(1, (self.height() - 80) // spacing_y)
        
        for idx, (icon_char, label_text, handler) in enumerate(standard_icons):
            col = idx // max_per_col
            row = idx % max_per_col
            icon_widget = DesktopIconWidget(icon_char, label_text, handler, parent=self)
            icon_widget.move(start_x + (col * col_width), start_y + (row * spacing_y))
            icon_widget.show()
            self.desktop_icon_widgets.append(icon_widget)

    def contextMenuEvent(self, event):
        """Windows 11 Right-Click Desktop Context Menu."""
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #252526;
                color: #e0e0e0;
                border: 1px solid #3c3c3c;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                padding: 4px;
            }
            QMenu::item {
                padding: 6px 20px;
                border-radius: 4px;
            }
            QMenu::item:selected {
                background-color: #094771;
                color: #ffffff;
            }
            QMenu::separator {
                height: 1px;
                background-color: #383838;
                margin: 4px 6px;
            }
        """)
        
        view_menu = menu.addMenu("View")
        view_menu.addAction("Large icons")
        view_menu.addAction("Medium icons")
        view_menu.addAction("Small icons")
        
        sort_menu = menu.addMenu("Sort by")
        sort_menu.addAction("Name")
        sort_menu.addAction("Size")
        sort_menu.addAction("Item type")
        sort_menu.addAction("Date modified")
        
        ref_act = menu.addAction("Refresh")
        ref_act.triggered.connect(self.setup_desktop_icons)
        
        menu.addSeparator()
        new_menu = menu.addMenu("New")
        new_fld = new_menu.addAction("Folder")
        new_fld.triggered.connect(self.create_desktop_folder)
        new_doc = new_menu.addAction("Text Document")
        new_doc.triggered.connect(self.create_desktop_document)
        
        menu.addSeparator()
        disp_act = menu.addAction("Display settings")
        disp_act.triggered.connect(self.show_verification_prompt)
        
        menu.exec(event.globalPos())

    def create_desktop_folder(self):
        desktop_dir = "C:\\Users\\Dell\\Desktop"
        base = "New folder"
        p = PathUtils.join(desktop_dir, base)
        idx = 2
        while self.vfs.exists(p):
            p = PathUtils.join(desktop_dir, f"{base} ({idx})")
            idx += 1
        self.vfs.mkdir(p)
        get_tracker().record_file_access(p, action="CREATE_FOLDER")
        self.setup_desktop_icons()

    def create_desktop_document(self):
        desktop_dir = "C:\\Users\\Dell\\Desktop"
        base = "New Text Document.txt"
        p = PathUtils.join(desktop_dir, base)
        idx = 2
        while self.vfs.exists(p):
            p = PathUtils.join(desktop_dir, f"New Text Document ({idx}).txt")
            idx += 1
        self.vfs.create_file(p, content="")
        get_tracker().record_file_access(p, action="CREATE_FILE")
        self.setup_desktop_icons()

    def toggle_start_menu(self):
        if self.start_menu.isVisible():
            self.start_menu.hide()
        else:
            self.start_menu.show()
            self.start_menu.raise_()

    def open_terminal(self):
        get_tracker().record_app_launch("Windows PowerShell")
        self.window_manager.bring_to_front("terminal")
        self.terminal.input_field.setFocus()

    def toggle_terminal(self):
        self.window_manager.toggle_window("terminal")

    def open_chrome(self, url=None):
        get_tracker().record_app_launch("Google Chrome")
        if url:
            self.decoy_chrome.omnibox.setText(url)
            self.decoy_chrome.on_omnibox_enter()
        self.window_manager.bring_to_front("chrome")

    def toggle_chrome(self):
        self.window_manager.toggle_window("chrome")

    def open_notepad(self, file_path=None):
        get_tracker().record_app_launch("Notepad")
        if file_path:
            self.decoy_notepad.open_virtual_file(file_path)
        self.window_manager.bring_to_front("notepad")

    def toggle_notepad(self):
        self.window_manager.toggle_window("notepad")

    def open_explorer(self, folder_path=None):
        get_tracker().record_app_launch("File Explorer")
        if folder_path:
            self.decoy_explorer.navigate_to(folder_path, navigation_method="LAUNCH_OPEN")
        else:
            self.decoy_explorer.navigate_to(self.decoy_explorer.current_path, navigation_method="LAUNCH_VIEW")
        self.window_manager.bring_to_front("explorer")

    def toggle_explorer(self):
        self.window_manager.toggle_window("explorer")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        if hasattr(self, 'screenshot') and not self.screenshot.isNull():
            painter.drawPixmap(self.rect(), self.screenshot)
        else:
            painter.fillRect(self.rect(), QColor("#1e1e1e"))
        super().paintEvent(event)

    def mousePressEvent(self, event):
        if hasattr(self, 'start_menu') and self.start_menu.isVisible():
            if event.pos() not in self.start_menu.geometry() and event.pos() not in self.taskbar.start_btn.geometry():
                self.start_menu.hide()
        super().mousePressEvent(event)

    def init_hotkey(self):
        self.signals = HotkeySignals()
        self.signals.trigger_lock.connect(self.show_verification_prompt)
        
        def run_listener(sig):
            def on_activate():
                sig.trigger_lock.emit()
            
            try:
                with keyboard.GlobalHotKeys({'<ctrl>+<alt>+<shift>+u': on_activate}) as h:
                    h.join()
            except Exception:
                pass
                
        t = threading.Thread(target=run_listener, args=(self.signals,), daemon=True)
        t.start()

    def show_verification_prompt(self):
        print("[DECEPTION] Spawning Verification & Recovery Dialog.", flush=True)
        dlg = HoneypotVerificationDialog(self)
        dlg.exec()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            if hasattr(self, 'start_menu') and self.start_menu.isVisible():
                self.start_menu.hide()
                event.accept()
                return
                
            # Double-Escape within 1.5s emergency exit
            now = time.time()
            if hasattr(self, '_last_esc_time') and (now - self._last_esc_time < 1.5):
                print("[DECEPTION] Double-Escape emergency exit triggered. Restoring session.", flush=True)
                self._can_close = True
                self.close()
                event.accept()
                return
            self._last_esc_time = now
            
            self.show_verification_prompt()
            event.accept()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        if getattr(self, '_can_close', False):
            event.accept()
        else:
            self.show_verification_prompt()
            if getattr(self, '_can_close', False):
                event.accept()
            else:
                event.ignore()


_active_forensics_window = None
_standalone_honey_desktop = None

def launch_honey_desktop(snapshot_path=None):
    """Entrypoint function to run the PyQt6 Honey-Desktop application loop."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
        
    app.setQuitOnLastWindowClosed(False)
    global _standalone_honey_desktop
    _standalone_honey_desktop = HoneypotDesktop(snapshot_path=snapshot_path)
    _standalone_honey_desktop.showFullScreen()
    
    app.exec()


if __name__ == "__main__":
    launch_honey_desktop()
