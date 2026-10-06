import sys
import os
import time
import threading
import psutil

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QFrame, QDialog, QGridLayout,
    QScrollArea
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

class DecoyNotepad(QFrame):
    """
    Authentic Windows Notepad decoy window displaying sensitive honey-token credentials.
    Fully minimizable, draggable, maximizable, and closable.
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
        self.is_maximized = False
        self.normal_geom = None
        self.drag_position = QPoint()
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(QSize(680, 420))
        self.setStyleSheet("""
            QFrame#NotepadContainer {
                background-color: #202020;
                border: 1px solid #3c3c3c;
                border-radius: 8px;
            }
            QFrame#NotepadTitleBar {
                background-color: #1f1f1f;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 1px solid #2d2d2d;
            }
            QLabel#NotepadTitle {
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton#NBtn {
                background: transparent;
                color: #a0a0a0;
                border: none;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
                width: 34px;
                height: 26px;
            }
            QPushButton#NBtn:hover {
                background-color: #333333;
                color: #ffffff;
            }
            QPushButton#NCloseBtn:hover {
                background-color: #e81123;
                color: #ffffff;
                border-top-right-radius: 8px;
            }
            QFrame#MenuBar {
                background-color: #202020;
                border-bottom: 1px solid #2d2d2d;
            }
            QLabel#MenuLabel {
                color: #cccccc;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                padding: 4px 8px;
            }
            QLabel#MenuLabel:hover {
                background-color: #2d2d2d;
                border-radius: 3px;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: #e0e0e0;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }
        """)
        self.setObjectName("NotepadContainer")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Title bar
        self.title_bar = QFrame()
        self.title_bar.setObjectName("NotepadTitleBar")
        self.title_bar.setFixedHeight(30)
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(10, 0, 0, 0)
        tb_layout.setSpacing(2)
        
        icon_lbl = QLabel("📄")
        icon_lbl.setStyleSheet("font-size: 12px; margin-right: 4px;")
        tb_layout.addWidget(icon_lbl)
        
        title_lbl = QLabel("passwords.txt - Notepad")
        title_lbl.setObjectName("NotepadTitle")
        tb_layout.addWidget(title_lbl)
        tb_layout.addStretch()
        
        min_btn = QPushButton("─")
        min_btn.setObjectName("NBtn")
        min_btn.clicked.connect(self.hide)
        tb_layout.addWidget(min_btn)
        
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("NBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        tb_layout.addWidget(self.max_btn)
        
        close_btn = QPushButton("✕")
        close_btn.setObjectName("NCloseBtn")
        close_btn.setProperty("class", "NCloseBtn")
        close_btn.setStyleSheet("background: transparent; color: #a0a0a0; border: none; font-size: 11px; width: 34px; height: 26px;")
        close_btn.clicked.connect(self.hide)
        tb_layout.addWidget(close_btn)
        
        self.title_bar.setLayout(tb_layout)
        layout.addWidget(self.title_bar)
        
        # Menu bar
        menu_bar = QFrame()
        menu_bar.setObjectName("MenuBar")
        menu_bar.setFixedHeight(26)
        mb_layout = QHBoxLayout()
        mb_layout.setContentsMargins(6, 0, 0, 0)
        mb_layout.setSpacing(6)
        for m in ["File", "Edit", "View"]:
            lbl = QLabel(m)
            lbl.setObjectName("MenuLabel")
            mb_layout.addWidget(lbl)
        mb_layout.addStretch()
        menu_bar.setLayout(mb_layout)
        layout.addWidget(menu_bar)
        
        # Content
        self.editor = QTextEdit()
        decoy_content = (
            "=== CONFIDENTIAL SYSTEM VAULT & INFRASTRUCTURE KEYS ===\n\n"
            "[Production Database]\n"
            "Host:     prod-cluster-db.internal.corp (PostgreSQL 15)\n"
            "User:     sec_admin\n"
            "Password: P@ssw0rd_Production_2026!#\n\n"
            "[AWS Cloud Infrastructure]\n"
            "AWS_ACCESS_KEY_ID     = AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "S3_BACKUP_BUCKET      = s3://corp-behavioral-snapshots-secure/\n\n"
            "[Domain Controller]\n"
            "Domain:   CORP-LOCAL\n"
            "Admin:    administrator\n"
            "NTLM:     8846f7eaee8fb117ad06bdd830b7586c\n"
        )
        self.editor.setText(decoy_content)
        self.editor.textChanged.connect(self.on_content_changed)
        layout.addWidget(self.editor)
        
        self.setLayout(layout)

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
                self.setFixedSize(QSize(680, 420))
            self.max_btn.setText("□")
            self.is_maximized = False

    def on_content_changed(self):
        try:
            content = self.editor.toPlainText()
            sandbox_file = os.path.join(self.sandbox_dir, "passwords.txt")
            with open(sandbox_file, "w", encoding="utf-8") as f:
                f.write(content)
            self.tracker.record_file_access("passwords.txt", action="MODIFY")
            self.tracker.record_sandbox_write("passwords.txt", len(content.encode("utf-8")))
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [NOTEPAD_EDIT] passwords.txt modified in sandbox\n")
        except Exception:
            pass

class DecoyExplorer(QFrame):
    """
    Authentic Windows File Explorer decoy window displaying user's folder contents.
    Fully interactive:
    - Clickable folders that navigate deeper into directory structures
    - Up arrow (↑) and Back arrow (←) navigation
    - Dynamic breadcrumbs in the address bar
    - Clickable files that trigger DecoyNotepad or document preview dialogs
    - Real-time search filter
    - Every folder change, file open, and search is logged to ForensicTracker!
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.tracker = get_tracker()
        self.is_maximized = False
        self.normal_geom = None
        self.drag_position = QPoint()
        
        self.current_path = "C:\\Users\\Dell\\Desktop\\clg"
        self.path_history = [self.current_path]
        
        # Virtual filesystem map with rich, realistic project and sensitive honey files
        self.fs_map = {
            "C:\\Users\\Dell": [
                ("📁", "Desktop", True),
                ("📁", "Documents", True),
                ("📁", "Downloads", True),
                ("📁", "Pictures", True),
                ("📄", "user_profile.ini", False)
            ],
            "C:\\Users\\Dell\\Desktop": [
                ("📁", "clg", True),
                ("📁", "Personal_Vault", True),
                ("📁", "Financial_Records_2026", True),
                ("📄", "root_credentials.txt", False),
                ("📄", "crypto_wallets.txt", False)
            ],
            "C:\\Users\\Dell\\Desktop\\clg": [
                ("📁", "Behavioral-Drift-Security", True),
                ("📁", "documents", True),
                ("📄", "project_analysis_and_plan.pdf", False),
                ("📄", "thesis_final_draft.docx", False),
                ("📊", "system_evaluation_metrics.xlsx", False),
                ("🎥", "major_project_demo.mp4", False),
                ("📝", "tester.txt", False)
            ],
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security": [
                ("📁", "data", True),
                ("📁", "ml_engine", True),
                ("📁", "security", True),
                ("📁", "deception", True),
                ("📁", "dashboard", True),
                ("📁", "models", True),
                ("📁", "scripts", True),
                ("📄", "passwords.txt", False),
                ("📄", ".env", False),
                ("📄", "README.md", False)
            ],
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data": [
                ("📁", "forensics", True),
                ("📁", "raw", True),
                ("📁", "sandbox", True),
                ("📁", "sessions", True),
                ("📊", "telemetry_data.jsonl", False),
                ("📄", "app_profiles.json", False)
            ],
            "C:\\Users\\Dell\\Desktop\\clg\\documents": [
                ("📊", "ISE_MAJORPROJECTPPT.pptx", False),
                ("📄", "Literature_Review_id_30.pdf", False),
                ("📄", "Major_Project Synopsis_30.pdf", False),
                ("📄", "confidential_admin_keys.pdf", False)
            ],
            "C:\\Users\\Dell\\Desktop\\Personal_Vault": [
                ("📄", "master_passwords_vault.txt", False),
                ("🔑", "aws_secret_credentials.json", False),
                ("📄", "private_ssh_id_rsa", False)
            ],
            "C:\\Users\\Dell\\Desktop\\Financial_Records_2026": [
                ("📊", "bank_account_tax_filings.xlsx", False),
                ("📄", "direct_deposit_routing_numbers.pdf", False),
                ("📄", "investment_portfolio.csv", False)
            ],
            "C:\\Users\\Dell\\Documents": [
                ("📁", "Projects", True),
                ("📄", "backup_recovery_keys.txt", False),
                ("📄", "academic_transcripts.pdf", False)
            ]
        }
        
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(QSize(780, 480))
        self.setStyleSheet("""
            QFrame#ExplorerContainer {
                background-color: #202020;
                border: 1px solid #3c3c3c;
                border-radius: 8px;
            }
            QFrame#ExplorerTitleBar {
                background-color: #1f1f1f;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                border-bottom: 1px solid #2d2d2d;
            }
            QLabel#ExplorerTitle {
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton#EBtn {
                background: transparent;
                color: #a0a0a0;
                border: none;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                font-weight: bold;
                width: 34px;
                height: 26px;
            }
            QPushButton#EBtn:hover {
                background-color: #333333;
                color: #ffffff;
            }
            QPushButton#ECloseBtn:hover {
                background-color: #e81123;
                color: #ffffff;
                border-top-right-radius: 8px;
            }
            QFrame#AddressBar {
                background-color: #262626;
                border: 1px solid #383838;
                border-radius: 4px;
                padding: 2px 8px;
            }
            QLabel#AddressText {
                color: #cccccc;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
            }
            QFrame#FolderArea {
                background-color: #191919;
                border: none;
            }
            QLabel#ItemLabel {
                color: #e2e8f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                padding: 2px;
            }
            QPushButton#NavArrowBtn {
                background: transparent;
                color: #9aa0a6;
                border: none;
                font-size: 14px;
                width: 24px;
                height: 24px;
                border-radius: 12px;
            }
            QPushButton#NavArrowBtn:hover {
                background-color: #333333;
                color: #ffffff;
            }
            QLineEdit#SearchField {
                background-color: #262626;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                border: 1px solid #383838;
                border-radius: 4px;
                padding: 2px 6px;
            }
        """)
        self.setObjectName("ExplorerContainer")
        
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Title bar
        title_bar = QFrame()
        title_bar.setObjectName("ExplorerTitleBar")
        title_bar.setFixedHeight(30)
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(10, 0, 0, 0)
        tb_layout.setSpacing(2)
        
        icon_lbl = QLabel("📁")
        icon_lbl.setStyleSheet("font-size: 12px; margin-right: 4px;")
        tb_layout.addWidget(icon_lbl)
        
        self.title_lbl = QLabel("clg - File Explorer")
        self.title_lbl.setObjectName("ExplorerTitle")
        tb_layout.addWidget(self.title_lbl)
        tb_layout.addStretch()
        
        min_btn = QPushButton("─")
        min_btn.setObjectName("EBtn")
        min_btn.clicked.connect(self.hide)
        tb_layout.addWidget(min_btn)
        
        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("EBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        tb_layout.addWidget(self.max_btn)
        
        close_btn = QPushButton("✕")
        close_btn.setObjectName("ECloseBtn")
        close_btn.setStyleSheet("background: transparent; color: #a0a0a0; border: none; font-size: 11px; width: 34px; height: 26px;")
        close_btn.clicked.connect(self.hide)
        tb_layout.addWidget(close_btn)
        
        title_bar.setLayout(tb_layout)
        layout.addWidget(title_bar)
        
        # Navigation & Address Bar row
        nav_row = QFrame()
        nav_row.setFixedHeight(38)
        nav_row.setStyleSheet("background-color: #1f1f1f; border-bottom: 1px solid #2d2d2d; padding: 2px 8px;")
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(6, 2, 6, 2)
        nav_layout.setSpacing(6)
        
        back_btn = QPushButton("←")
        back_btn.setObjectName("NavArrowBtn")
        back_btn.clicked.connect(self.navigate_back)
        nav_layout.addWidget(back_btn)

        up_btn = QPushButton("↑")
        up_btn.setObjectName("NavArrowBtn")
        up_btn.clicked.connect(self.navigate_up)
        nav_layout.addWidget(up_btn)
        
        addr_box = QFrame()
        addr_box.setObjectName("AddressBar")
        addr_box_layout = QHBoxLayout()
        addr_box_layout.setContentsMargins(6, 0, 6, 0)
        self.addr_lbl = QLabel(f"📁 This PC > {self.current_path.replace(':', '').replace('\\', ' > ')}")
        self.addr_lbl.setObjectName("AddressText")
        addr_box_layout.addWidget(self.addr_lbl)
        addr_box.setLayout(addr_box_layout)
        nav_layout.addWidget(addr_box, 1)
        
        self.search_box = QLineEdit()
        self.search_box.setObjectName("SearchField")
        self.search_box.setPlaceholderText("🔍 Search folder")
        self.search_box.setFixedWidth(160)
        self.search_box.textChanged.connect(self.on_search_changed)
        nav_layout.addWidget(self.search_box)
        
        nav_row.setLayout(nav_layout)
        layout.addWidget(nav_row)
        
        # Folder grid content inside scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: #191919; border: none;")

        self.folder_area = QFrame()
        self.folder_area.setObjectName("FolderArea")
        self.f_layout = QGridLayout()
        self.f_layout.setContentsMargins(20, 20, 20, 20)
        self.f_layout.setHorizontalSpacing(24)
        self.f_layout.setVerticalSpacing(16)
        self.f_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.folder_area.setLayout(self.f_layout)
        scroll.setWidget(self.folder_area)

        layout.addWidget(scroll, 1)
        self.setLayout(layout)

        self.render_items()

    def render_items(self, filter_query=""):
        # Clear existing grid widgets
        while self.f_layout.count():
            item = self.f_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        items = self.fs_map.get(self.current_path, [])
        if filter_query:
            items = [it for it in items if filter_query.lower() in it[1].lower()]

        for idx, (icon, name, is_dir) in enumerate(items):
            row = idx // 4
            col = idx % 4
            
            box = QFrame()
            box.setFixedSize(140, 84)
            box.setStyleSheet("QFrame { background-color: transparent; border-radius: 6px; } QFrame:hover { background-color: #2d3748; }")
            box.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            b_layout = QVBoxLayout()
            b_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b_layout.setSpacing(4)
            
            i_lbl = QLabel(icon)
            i_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            i_lbl.setStyleSheet("font-size: 28px; background: transparent;")
            b_layout.addWidget(i_lbl)
            
            t_lbl = QLabel(name)
            t_lbl.setObjectName("ItemLabel")
            t_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            t_lbl.setWordWrap(True)
            t_lbl.setStyleSheet("color: #e2e8f0; font-size: 11px; background: transparent;")
            b_layout.addWidget(t_lbl)
            
            box.setLayout(b_layout)
            
            # Interactive click handler
            if is_dir:
                box.mousePressEvent = lambda e, n=name: self.on_folder_clicked(n)
            else:
                box.mousePressEvent = lambda e, n=name: self.on_file_clicked(n)
                
            self.f_layout.addWidget(box, row, col)

    def on_folder_clicked(self, folder_name):
        new_path = f"{self.current_path}\\{folder_name}"
        if new_path not in self.fs_map:
            # Generate dynamic fallback empty directory
            self.fs_map[new_path] = [("📄", "desktop.ini", False)]
            
        print(f"[DECEPTION EXPLORER] Intruder navigated into directory: '{new_path}'", flush=True)
        self.tracker.record_folder_navigation(new_path, source_path=self.current_path)
        self.current_path = new_path
        self.path_history.append(new_path)
        
        self.title_lbl.setText(f"{folder_name} - File Explorer")
        self.addr_lbl.setText(f"📁 This PC > {self.current_path.replace(':', '').replace('\\', ' > ')}")
        self.search_box.clear()
        self.render_items()

    def on_file_clicked(self, file_name):
        full_file_path = f"{self.current_path}\\{file_name}"
        print(f"[DECEPTION EXPLORER] Intruder clicked file: '{full_file_path}'", flush=True)
        self.tracker.record_file_access(full_file_path, action="OPEN")
        
        if "password" in file_name.lower() or file_name.endswith(".txt") or file_name.endswith(".env") or file_name.endswith(".ini") or file_name.endswith(".json"):
            # Open decoy notepad
            parent = self.parent()
            if parent and hasattr(parent, 'open_notepad'):
                parent.open_notepad()
        else:
            # Show simulated Windows document viewer dialog
            dlg = QDialog(self)
            dlg.setWindowTitle(f"{file_name} - Protected Document Preview")
            dlg.setFixedSize(520, 260)
            dlg.setStyleSheet("background-color: #1e1e24; color: #ffffff;")
            d_lay = QVBoxLayout()
            d_lay.setContentsMargins(20, 20, 20, 20)
            
            lbl_title = QLabel(f"<b>{file_name}</b>")
            lbl_title.setStyleSheet("font-size: 15px; color: #00d2d3;")
            d_lay.addWidget(lbl_title)
            
            lbl_desc = QLabel("Corporate Security Notice: This file is restricted under corporate policy.\nContents are decrypted in sandboxed memory container.")
            lbl_desc.setStyleSheet("color: #a4b0be; font-size: 12px;")
            d_lay.addWidget(lbl_desc)
            
            content_preview = QTextEdit()
            content_preview.setReadOnly(True)
            content_preview.setStyleSheet("background-color: #121217; color: #00ff00; font-family: 'Consolas'; font-size: 11px;")
            content_preview.setText(f"--- DUMP OF {file_name} ---\nDocument Classification: STRICTLY CONFIDENTIAL\nOwner: NMAMIT Dept of ISE\nProject ID: 30\nStatus: Archived in Honeypot Sandbox\nChecksum Verified: OK")
            d_lay.addWidget(content_preview)
            
            btn_close = QPushButton("Close")
            btn_close.setStyleSheet("background-color: #2ed573; color: #ffffff; padding: 6px; border-radius: 4px;")
            btn_close.clicked.connect(dlg.accept)
            d_lay.addWidget(btn_close)
            
            dlg.setLayout(d_lay)
            dlg.exec()

    def navigate_up(self):
        if "\\" in self.current_path:
            parts = self.current_path.split("\\")
            if len(parts) > 1:
                parent_path = "\\".join(parts[:-1])
                if parent_path in self.fs_map:
                    self.tracker.record_folder_navigation(parent_path, source_path=self.current_path)
                    self.current_path = parent_path
                    self.path_history.append(parent_path)
                    folder_name = parts[-2]
                    self.title_lbl.setText(f"{folder_name} - File Explorer")
                    self.addr_lbl.setText(f"📁 This PC > {self.current_path.replace(':', '').replace('\\', ' > ')}")
                    self.search_box.clear()
                    self.render_items()

    def navigate_back(self):
        if len(self.path_history) > 1:
            self.path_history.pop()
            prev_path = self.path_history[-1]
            self.tracker.record_folder_navigation(prev_path, source_path=self.current_path)
            self.current_path = prev_path
            folder_name = self.current_path.split("\\")[-1]
            self.title_lbl.setText(f"{folder_name} - File Explorer")
            self.addr_lbl.setText(f"📁 This PC > {self.current_path.replace(':', '').replace('\\', ' > ')}")
            self.search_box.clear()
            self.render_items()

    def on_search_changed(self, text):
        if len(text.strip()) > 1:
            self.tracker.record_event("EXPLORER_SEARCH", text.strip(), {"path": self.current_path})
        self.render_items(filter_query=text.strip())

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
                self.setFixedSize(QSize(780, 480))
            self.max_btn.setText("□")
            self.is_maximized = False


class Windows11StartMenu(QFrame):
    """
    Authentic Windows 11 Centered Start Menu popup.
    Features pinned applications and power/lock options allowing clean exit.
    """
    def __init__(self, parent_desktop, parent=None):
        super().__init__(parent)
        self.desktop = parent_desktop
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(480, 450)
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
        layout.setSpacing(14)
        
        # Search bar
        search = QLineEdit()
        search.setObjectName("SearchField")
        search.setPlaceholderText("🔍 Type here to search")
        layout.addWidget(search)
        
        # Header
        hdr = QLabel("Pinned")
        hdr.setObjectName("SectionHeader")
        layout.addWidget(hdr)
        
        # Grid of apps
        grid = QGridLayout()
        grid.setSpacing(10)
        
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
            grid.addWidget(btn, r, c)
            
        layout.addLayout(grid)
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
    Allows authentic session unlock via Master Bypass Password ('admin') or OTP PIN,
    and provides an Emergency Exit option so users never get trapped.
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
        s_lbl = QLabel("Enter Master Bypass ('admin') or 6-digit OTP code to exit Honeypot and restore normal Windows session:")
        s_lbl.setObjectName("Sub")
        s_lbl.setWordWrap(True)
        hdr_layout.addWidget(t_lbl)
        hdr_layout.addWidget(s_lbl)
        top_h.addLayout(hdr_layout)
        layout.addLayout(top_h)
        
        # Password Input
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter admin or 6-digit OTP code")
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

class HoneyShell(QFrame):
    """
    Authentic Windows Floating Terminal Emulator (Honeypot PowerShell / CMD).
    Draggable anywhere on top of the replicated desktop.
    Features Up/Down command history, minimize, maximize/restore, closable,
    authentic systeminfo, whoami, tasklist (real processes), and diverted file sandbox writes.
    """
    def __init__(self, sandbox_dir, log_dir, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
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
                self.setFixedSize(QSize(840, 520))
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

    def minimize_shell(self):
        """Minimizes terminal cleanly to the taskbar."""
        self.hide()

    def close_shell(self):
        """Closes terminal cleanly."""
        self.hide()

    def hide_fake(self):
        self.minimize_shell()

    def close_fake(self):
        self.close_shell()

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
        self.tracker.record_shell_command(cmd_raw, self.current_dir)
        
        parts = cmd_raw.split()
        base_cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        response = ""
        
        if base_cmd in ["exit", "quit"]:
            self.close_shell()
            return
        elif base_cmd in ["clear", "cls"]:
            self.console.clear()
            return
        elif base_cmd in ["dir", "ls", "get-childitem"]:
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
        elif base_cmd in ["ping", "ping.exe"]:
            response = self._handle_ping(args)
        elif base_cmd in ["arp", "arp.exe"]:
            response = self._handle_arp(args)
        elif base_cmd in ["route", "route.exe"]:
            response = self._handle_route(args)
        elif base_cmd in ["curl", "curl.exe", "wget", "wget.exe", "iwr", "invoke-webrequest"]:
            response = self._handle_curl(cmd_raw, args)
        elif base_cmd in ["ssh", "ssh.exe"]:
            response = self._handle_ssh(args)
        elif base_cmd in ["nslookup", "nslookup.exe"]:
            response = self._handle_nslookup(args)
        elif base_cmd in ["tracert", "tracert.exe", "traceroute"]:
            response = self._handle_tracert(args)
        elif base_cmd in ["nmap", "nmap.exe"]:
            response = self._handle_nmap(args)
        elif base_cmd in ["whoami"]:
            response = self._handle_whoami(args)
        elif base_cmd in ["hostname"]:
            response = "DESKTOP-SEC-WIN11"
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
            response = "Supported Diagnostic Commands: tasklist, Get-Process, systeminfo, netstat, ipconfig, ping, arp, route, curl, wget, ssh, nslookup, tracert, nmap, cd, dir, ls, type, cat, echo, whoami, hostname, net user, cls, clear, exit"
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
        """Generates realistic process output using system processes."""
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
        self.tracker.record_file_access(target, action="SHELL_CAT")
        
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
                    with open(chk, "r", encoding="utf-8") as f:
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
                
            self.tracker.record_sandbox_write(filename, len(text.encode("utf-8")))
            
            items = self.virtual_fs.get(self.current_dir, [])
            if filename not in items:
                items.append(filename)
                self.virtual_fs[self.current_dir] = items
                
            print(f"[DECEPTION] Intercepted payload write. Diverted to sandbox '{sandbox_path}'", flush=True)
            return ""
        except Exception as e:
            return f"Error writing file: {e}"

    def _handle_ping(self, args):
        if not args:
            return "Usage: ping [-t] [-a] [-n count] [-l size] target_name"
        target = args[0] if not args[0].startswith("-") else (args[-1] if len(args) > 1 else "127.0.0.1")
        ip = "192.168.1.1" if ("gateway" in target or "192" in target) else ("8.8.8.8" if ("google" in target or "8.8" in target) else "10.0.1.55")
        
        self.tracker.record_network_recon(f"ping {' '.join(args)}", target, recon_type="ICMP_PING")
        print(f"[HONEYPOT DECEPTION] Intruder executed ping network probe against '{target}' ({ip})", flush=True)

        return (
            f"\nPinging {target} [{ip}] with 32 bytes of data:\n"
            f"Reply from {ip}: bytes=32 time=4ms TTL=64\n"
            f"Reply from {ip}: bytes=32 time=3ms TTL=64\n"
            f"Reply from {ip}: bytes=32 time=5ms TTL=64\n"
            f"Reply from {ip}: bytes=32 time=3ms TTL=64\n\n"
            f"Ping statistics for {ip}:\n"
            f"    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),\n"
            f"Approximate round trip times in milli-seconds:\n"
            f"    Minimum = 3ms, Maximum = 5ms, Average = 3ms"
        )

    def _handle_arp(self, args):
        cmd_str = f"arp {' '.join(args)}" if args else "arp -a"
        self.tracker.record_network_recon(cmd_str, "192.168.1.0/24", recon_type="ARP_CACHE_ENUM")
        print("[HONEYPOT DECEPTION] Intruder enumerated local ARP neighbor cache table", flush=True)

        return (
            "\nInterface: 192.168.1.142 --- 0xa\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           f4-f5-e8-11-22-33     dynamic\n"
            "  192.168.1.10          00-15-5d-01-22-34     dynamic\n"
            "  192.168.1.25          3c-52-82-41-bb-aa     dynamic\n"
            "  192.168.1.55          a0-36-bc-99-14-11     dynamic\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.22            01-00-5e-00-00-16     static\n"
            "  224.0.0.251           01-00-5e-00-00-fb     static\n"
            "  239.255.255.250       01-00-5e-7f-ff-fa     static"
        )

    def _handle_route(self, args):
        cmd_str = f"route {' '.join(args)}" if args else "route print"
        self.tracker.record_network_recon(cmd_str, "192.168.1.1", recon_type="ROUTING_TABLE_ENUM")
        print("[HONEYPOT DECEPTION] Intruder printed IP routing table", flush=True)

        return (
            "===========================================================================\n"
            "Interface List\n"
            " 10 ...00 15 5d 82 4a 1b ...... Intel(R) Ethernet Connection (14) I219-LM\n"
            "  1 ........................... Software Loopback Interface 1\n"
            "===========================================================================\n\n"
            "IPv4 Route Table\n"
            "===========================================================================\n"
            "Active Routes:\n"
            "Network Destination        Netmask          Gateway       Interface  Metric\n"
            "          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.142      25\n"
            "        127.0.0.0        255.0.0.0        On-link         127.0.0.1     331\n"
            "      192.168.1.0    255.255.255.0        On-link     192.168.1.142     281\n"
            "    192.168.1.142  255.255.255.255        On-link     192.168.1.142     281\n"
            "    192.168.1.255  255.255.255.255        On-link     192.168.1.142     281\n"
            "        224.0.0.0        240.0.0.0        On-link         127.0.0.1     331\n"
            "  255.255.255.255  255.255.255.255        On-link         127.0.0.1     331\n"
            "===========================================================================\n"
            "Persistent Routes:\n"
            "  None"
        )

    def _handle_curl(self, cmd_raw, args):
        """
        Emulates curl, wget, and Invoke-WebRequest.
        Intercepts remote attacker payload downloads, diverts the dropped executable
        safely into data/sandbox/, and logs C2 server infrastructure to ForensicTracker.
        """
        if not args:
            return "curl: try 'curl --help' for more information"

        # Identify URL
        url = None
        for a in args:
            if a.startswith("http://") or a.startswith("https://") or "://" in a or ("." in a and not a.startswith("-") and not a.startswith("/")):
                url = a
                break

        if not url:
            url = args[-1]

        # Extract C2 Host
        c2_host = "194.26.29.112"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url if "://" in url else f"http://{url}")
            c2_host = parsed.netloc or parsed.path.split("/")[0] or "attacker.c2.net"
        except Exception:
            c2_host = "attacker.c2.net"

        # Check for destination filename (-o filename, -OutFile filename, or URL basename)
        out_filename = None
        for i, a in enumerate(args):
            if a in ["-o", "-O", "--output", "-OutFile", "-outfile"] and i + 1 < len(args):
                out_filename = args[i + 1]
                break

        if not out_filename:
            # Check URL path
            parts = url.rstrip("/").split("/")
            if len(parts) > 1 and ("." in parts[-1]):
                out_filename = parts[-1]
            elif any(ext in url.lower() for ext in [".exe", ".ps1", ".bat", ".dll", ".sh", ".vbs", ".zip"]):
                for ext in [".exe", ".ps1", ".bat", ".dll", ".sh", ".vbs", ".zip"]:
                    if ext in url.lower():
                        idx = url.lower().find(ext) + len(ext)
                        sub = url[:idx]
                        out_filename = sub.split("/")[-1]
                        break

        # Check if this is a payload download
        is_download = bool(out_filename) or any(ext in url.lower() for ext in [".exe", ".ps1", ".bat", ".dll", ".sh", ".vbs", ".zip", ".tar.gz", "payload", "malware", "shell", "dropper"])

        if is_download:
            if not out_filename:
                out_filename = "malware.exe" if ".exe" in url else "payload.bin"

            # Divert and isolate into sandbox
            sandbox_path = os.path.join(self.sandbox_dir, out_filename)
            os.makedirs(self.sandbox_dir, exist_ok=True)
            quarantine_content = (
                f"# ============================================================\n"
                f"# [QUARANTINED BY HONEYPOT DECEPTION ENGINE]\n"
                f"# Captured Threat Vector: Remote C2 Payload Download\n"
                f"# Target URL            : {url}\n"
                f"# Identified C2 Host    : {c2_host}\n"
                f"# Capture Timestamp     : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# Action Taken          : File Isolated in data/sandbox/\n"
                f"# ============================================================\n"
            )
            try:
                with open(sandbox_path, "w", encoding="utf-8") as f:
                    f.write(quarantine_content)
                file_size = os.path.getsize(sandbox_path)
            except Exception:
                file_size = 256

            # Add to virtual filesystem so 'dir' shows the file
            items = self.virtual_fs.get(self.current_dir, [])
            if out_filename not in items:
                items.append(out_filename)
                self.virtual_fs[self.current_dir] = items

            # Log to forensics
            self.tracker.record_c2_download(url, c2_host, out_filename, file_size)
            self.tracker.record_sandbox_write(out_filename, file_size)
            print(f"[HONEYPOT DECEPTION] Intercepted payload download from C2 server '{c2_host}'. Diverted to sandbox '{sandbox_path}'!", flush=True)

            return (
                f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                f"100  256k  100  256k    0     0   428k      0 --:--:-- --:--:-- --:--:--  430k"
            )
        else:
            # Simple probe (e.g., curl ifconfig.me)
            self.tracker.record_network_recon(cmd_raw, url, recon_type="EXTERNAL_IP_PROBE")
            if any(w in url.lower() for w in ["ifconfig", "ipinfo", "icanhazip", "api.ipify", "ip"]):
                return "203.0.113.42"
            else:
                return (
                    f"<!DOCTYPE html><html><head><title>200 OK</title></head>\n"
                    f"<body><h1>Connected to Gateway Proxy</h1><p>Request routed through isolated container.</p></body></html>"
                )

    def _handle_ssh(self, args):
        if not args:
            return "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] destination [command]"
        target = args[-1]
        host = target.split("@")[-1] if "@" in target else target
        self.tracker.record_network_recon(f"ssh {' '.join(args)}", host, recon_type="LATERAL_MOVEMENT_SSH")
        print(f"[HONEYPOT DECEPTION] Intruder attempted lateral movement via SSH to '{target}'", flush=True)

        return (
            f"The authenticity of host '{host} ({host})' can't be established.\n"
            f"ED25519 key fingerprint is SHA256:4X7mXn82j19slmKq01pOpLm83kALsdjk1290.\n"
            f"This host key is known by the following other names/addresses:\n"
            f"ssh: connect to host {host} port 22: Connection timed out"
        )

    def _handle_nslookup(self, args):
        if not args:
            return "Default Server:  dc01.corp.internal\nAddress:  192.168.1.1\n"
        target = args[0]
        ip = "10.0.1.20" if ("corp" in target or "internal" in target) else "142.250.190.46"
        self.tracker.record_network_recon(f"nslookup {target}", target, recon_type="DNS_QUERY")
        return (
            f"Server:  dc01.corp.internal\n"
            f"Address:  192.168.1.1\n\n"
            f"Non-authoritative answer:\n"
            f"Name:    {target}\n"
            f"Address:  {ip}"
        )

    def _handle_tracert(self, args):
        target = args[0] if args else "8.8.8.8"
        self.tracker.record_network_recon(f"tracert {target}", target, recon_type="ROUTE_TRACE")
        return (
            f"\nTracing route to {target} over a maximum of 30 hops:\n\n"
            f"  1     2 ms     2 ms     2 ms  192.168.1.1\n"
            f"  2    12 ms    11 ms    14 ms  10.24.0.1\n"
            f"  3    18 ms    17 ms    19 ms  172.16.100.1\n"
            f"  4    24 ms    23 ms    25 ms  {target}\n\n"
            f"Trace complete."
        )

    def _handle_nmap(self, args):
        target = args[-1] if args else "192.168.1.1"
        self.tracker.record_network_recon(f"nmap {' '.join(args)}", target, recon_type="PORT_SCAN")
        return (
            f"\nStarting Nmap 7.94 ( https://nmap.org ) at {time.strftime('%Y-%m-%d %H:%M')}\n"
            f"Nmap scan report for {target}\n"
            f"Host is up (0.0024s latency).\n"
            f"Not shown: 996 closed tcp ports\n"
            f"PORT     STATE SERVICE\n"
            f"53/tcp   open  domain\n"
            f"80/tcp   open  http\n"
            f"443/tcp  open  https\n"
            f"8080/tcp open  http-proxy\n\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds"
        )


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
    and system tray with live ticking clock and emergency recovery button.
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
        sp_layout = QHBoxLayout()
        sp_layout.setContentsMargins(10, 0, 10, 0)
        sp_lbl = QLabel("🔍  Search")
        sp_lbl.setStyleSheet("color: #aaaaaa; font-family: 'Segoe UI', sans-serif; font-size: 11px; background: transparent;")
        sp_layout.addWidget(sp_lbl)
        search_pill.setLayout(sp_layout)
        center_box.addWidget(search_pill)
        
        # File Explorer
        exp_btn = QPushButton("📁")
        exp_btn.setObjectName("TaskbarBtn")
        exp_btn.setToolTip("File Explorer")
        exp_btn.clicked.connect(self.desktop.toggle_explorer)
        center_box.addWidget(exp_btn)
        
        # Chrome / Browser
        chrome_btn = QPushButton("🌐")
        chrome_btn.setObjectName("TaskbarBtn")
        chrome_btn.setToolTip("Google Chrome")
        chrome_btn.clicked.connect(self.desktop.toggle_chrome)
        center_box.addWidget(chrome_btn)
        
        # PowerShell Terminal
        term_btn = QPushButton("💻")
        term_btn.setObjectName("TaskbarBtn")
        term_btn.setToolTip("Windows PowerShell")
        term_btn.clicked.connect(self.desktop.toggle_terminal)
        center_box.addWidget(term_btn)
        
        # Notepad
        notes_btn = QPushButton("📝")
        notes_btn.setObjectName("TaskbarBtn")
        notes_btn.setToolTip("Notepad")
        notes_btn.clicked.connect(self.desktop.toggle_notepad)
        center_box.addWidget(notes_btn)
        
        main_layout.addLayout(center_box)
        main_layout.addStretch()
        
        # Right Tray
        right_tray = QHBoxLayout()
        right_tray.setSpacing(6)
        
        # Tray icons
        for icon in ["📶", "🔊", "🔋"]:
            lbl = QLabel(icon)
            lbl.setStyleSheet("font-size: 13px; color: #ffffff; padding: 0 2px;")
            right_tray.addWidget(lbl)
            
        lang_lbl = QLabel("ENG\nIN")
        lang_lbl.setObjectName("TrayText")
        lang_lbl.setStyleSheet("font-size: 10px; font-weight: 500; line-height: 10px;")
        right_tray.addWidget(lang_lbl)
        
        # Live clock overlay
        self.clock = TaskbarClockOverlay(self)
        right_tray.addWidget(self.clock)
        
        # Discreet session recovery shield
        shield_btn = QPushButton("🛡️")
        shield_btn.setObjectName("TaskbarBtn")
        shield_btn.setToolTip("Session Security Recovery")
        shield_btn.setStyleSheet("font-size: 14px; padding: 4px;")
        shield_btn.clicked.connect(self.desktop.show_verification_prompt)
        right_tray.addWidget(shield_btn)
        
        main_layout.addLayout(right_tray)
        self.setLayout(main_layout)


class HoneypotDesktop(QWidget):
    """
    Full-Screen Deception Overlay replicating the user's authentic active Windows 11 desktop.
    Renders the exact pre-breach screenshot or authentic user wallpaper,
    incorporating sub-pixel DPR sharpness, Windows 11 taskbar with live ticking clock,
    desktop icons, an authentic PowerShell terminal (closable and minimizable),
    decoy Notepad credentials, decoy File Explorer, and a Windows Start Menu.
    
    Escape key or Ctrl+Alt+Shift+U triggers Session Identity Verification to return to normal.
    """
    def __init__(self, snapshot_path=None):
        super().__init__()
        self.sandbox_dir = os.path.join(project_dir, "data", "sandbox")
        self.log_dir = os.path.join(project_dir, "data", "forensics")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        self._can_close = False
        self._last_esc_time = 0.0
        
        screen = QApplication.primaryScreen()
        dpr = screen.devicePixelRatio() if screen else 1.0
        
        # Load or synthesize authentic clean desktop screenshot
        self.screenshot = self.load_authentic_desktop(snapshot_path, dpr)
        
        self.init_ui()
        self.init_hotkey()

    def load_authentic_desktop(self, snapshot_path, dpr):
        """Loads valid desktop snapshot, or synthesizes authentic desktop from Windows wallpaper."""
        if snapshot_path is None:
            snapshot_path = os.path.join(self.log_dir, "desktop_snapshot.png")
            
        screen = QApplication.primaryScreen()
        geom = screen.geometry() if screen else QRect(0, 0, 1920, 1080)
        target_w = int(geom.width() * dpr)
        target_h = int(geom.height() * dpr)
        
        # 1. Prioritize authentic user wallpaper from Windows Themes so console/attack windows are never captured in background
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
                print(f"[DECEPTION] Replicating active user desktop from authentic Windows wallpaper (DPR: {dpr})", flush=True)
                return canvas
        
        # 2. Check if clean pre-existing snapshot on disk is valid and NOT black/corrupted
        if os.path.exists(snapshot_path) and os.path.getsize(snapshot_path) > 10000:
            pix = QPixmap(snapshot_path)
            if not pix.isNull():
                img = pix.toImage()
                is_black = True
                for sx in [pix.width() // 4, pix.width() // 2, 3 * pix.width() // 4]:
                    for sy in [pix.height() // 4, pix.height() // 2, 3 * pix.height() // 4]:
                        if img.pixelColor(sx, sy).value() > 15:
                            is_black = False
                            break
                    if not is_black:
                        break
                if not is_black:
                    pix.setDevicePixelRatio(dpr)
                    print(f"[DECEPTION] Replicating active desktop from snapshot '{snapshot_path}' (DPR: {dpr})", flush=True)
                    return pix
                
        # 3. Fallback: clean modern Windows dark background
        canvas = QPixmap(target_w, target_h)
        canvas.fill(QColor("#0d1117"))
        canvas.setDevicePixelRatio(dpr)
        return canvas

    def init_ui(self):
        # Frameless, topmost overlay covering the primary display (no SubWindow flag to ensure full OS integration)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)
        screen_geom = QApplication.primaryScreen().geometry()
        self.setGeometry(screen_geom)
        
        # 1. Desktop Icons on the left side
        self.setup_desktop_icons()
        
        # 2. Windows 11 Taskbar across bottom
        self.taskbar = TaskbarWidget(self)
        self.taskbar.setGeometry(0, screen_geom.height() - 48, screen_geom.width(), 48)
        
        # 3. Live Taskbar Clock Overlay reference (for backward compatibility)
        self.clock_overlay = self.taskbar.clock
        
        # 4. Floating Draggable Honey-Shell Terminal
        self.terminal = HoneyShell(self.sandbox_dir, self.log_dir, parent=self)
        center_x = max(40, (screen_geom.width() - self.terminal.width()) // 2)
        center_y = max(30, (screen_geom.height() - self.terminal.height() - 60) // 2)
        self.terminal.move(center_x, center_y)
        
        # 5. Decoy Windows (Notepad and File Explorer)
        self.decoy_notepad = DecoyNotepad(self.sandbox_dir, self.log_dir, parent=self)
        self.decoy_notepad.move(center_x + 60, center_y + 40)
        self.decoy_notepad.hide()
        
        # Open decoy File Explorer behind terminal or accessible via icons
        self.decoy_explorer = DecoyExplorer(self.sandbox_dir, self.log_dir, parent=self)
        self.decoy_explorer.move(max(20, center_x - 60), max(20, center_y - 30))
        self.decoy_explorer.hide()
        
        # High-Fidelity Decoy Google Chrome Browser
        self.decoy_chrome = DecoyChrome(parent=self)
        self.decoy_chrome.move(max(30, center_x - 30), max(20, center_y - 20))
        self.decoy_chrome.hide()
        
        # 6. Windows 11 Start Menu
        self.start_menu = Windows11StartMenu(self, parent=self)
        sm_x = max(10, (screen_geom.width() - self.start_menu.width()) // 2)
        sm_y = screen_geom.height() - 48 - self.start_menu.height() - 10
        self.start_menu.move(sm_x, sm_y)
        self.start_menu.hide()

    def setup_desktop_icons(self):
        """Creates authentic desktop icons matching user's real desktop."""
        icons = [
            ("🌐", "Google Chrome", self.open_chrome),
            ("💻", "This PC", self.open_explorer),
            ("🗑️", "Recycle Bin", self.open_explorer),
            ("📁", "clg", self.open_explorer),
            ("📄", "tester.txt", self.open_notepad),
            ("📂", "My Documents", self.open_explorer),
            ("🔒", "passwords.txt", self.open_notepad),
            ("⚡", "PowerShell", self.open_terminal)
        ]
        
        start_y = 20
        start_x = 20
        spacing_y = 86
        
        for idx, (icon_char, label_text, handler) in enumerate(icons):
            icon_widget = DesktopIconWidget(icon_char, label_text, handler, parent=self)
            icon_widget.move(start_x, start_y + (idx * spacing_y))

    def toggle_start_menu(self):
        if self.start_menu.isVisible():
            self.start_menu.hide()
        else:
            self.start_menu.show()
            self.start_menu.raise_()

    def open_terminal(self):
        get_tracker().record_app_launch("Windows PowerShell")
        self.terminal.show()
        self.terminal.raise_()
        self.terminal.input_field.setFocus()

    def toggle_terminal(self):
        if self.terminal.isVisible():
            self.terminal.hide()
        else:
            self.open_terminal()

    def open_chrome(self):
        get_tracker().record_app_launch("Google Chrome")
        self.decoy_chrome.show()
        self.decoy_chrome.raise_()

    def toggle_chrome(self):
        if self.decoy_chrome.isVisible():
            self.decoy_chrome.hide()
        else:
            self.open_chrome()

    def open_notepad(self):
        get_tracker().record_app_launch("Notepad")
        self.decoy_notepad.show()
        self.decoy_notepad.raise_()

    def toggle_notepad(self):
        if self.decoy_notepad.isVisible():
            self.decoy_notepad.hide()
        else:
            self.open_notepad()

    def open_explorer(self):
        get_tracker().record_app_launch("File Explorer")
        self.decoy_explorer.show()
        self.decoy_explorer.raise_()

    def toggle_explorer(self):
        if self.decoy_explorer.isVisible():
            self.decoy_explorer.hide()
        else:
            self.open_explorer()

    def paintEvent(self, event):
        """Paints the replicated screenshot/wallpaper of the user's actual desktop with 100% pixel fidelity."""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        if hasattr(self, 'screenshot') and not self.screenshot.isNull():
            painter.drawPixmap(self.rect(), self.screenshot)
        else:
            painter.fillRect(self.rect(), QColor("#1e1e1e"))
        super().paintEvent(event)

    def mousePressEvent(self, event):
        """Close start menu if clicking outside."""
        if hasattr(self, 'start_menu') and self.start_menu.isVisible():
            if event.pos() not in self.start_menu.geometry() and event.pos() not in self.taskbar.start_btn.geometry():
                self.start_menu.hide()
        super().mousePressEvent(event)

    def init_hotkey(self):
        """Starts background pynput listener watching for Ctrl+Alt+Shift+U."""
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
        """Spawns the identity verification prompt allowing clean session restore or emergency exit."""
        print("[DECEPTION] Spawning Verification & Recovery Dialog.", flush=True)
        dlg = HoneypotVerificationDialog(self)
        dlg.exec()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            if hasattr(self, 'start_menu') and self.start_menu.isVisible():
                self.start_menu.hide()
                event.accept()
                return
                
            # Double-Esc detection (within 1.5s) for instant emergency exit
            now = time.time()
            if hasattr(self, '_last_esc_time') and (now - self._last_esc_time < 1.5):
                print("[DECEPTION] Double-Escape emergency exit triggered. Restoring session.", flush=True)
                self._can_close = True
                self.close()
                event.accept()
                return
            self._last_esc_time = now
            
            # Show verification dialog
            self.show_verification_prompt()
            event.accept()
        else:
            super().keyPressEvent(event)

    def closeEvent(self, event):
        if getattr(self, '_can_close', False):
            event.accept()
        else:
            # Show verification dialog when user attempts to close
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
