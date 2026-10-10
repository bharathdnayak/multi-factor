import os
import sys
import time
from typing import Optional

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QLineEdit, QDialog, QFileDialog, QMessageBox, QFontDialog, QStatusBar
)
from PyQt6.QtCore import Qt, QSize, QPoint, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QCursor, QTextCursor

from deception.virtual_fs import get_vfs, PathUtils
from deception.forensic_tracker import get_tracker

class FindReplaceDialog(QDialog):
    """Windows Notepad Find and Replace Dialog."""
    def __init__(self, editor: QTextEdit, parent=None):
        super().__init__(parent)
        self.editor = editor
        self.setWindowTitle("Find and Replace")
        self.setFixedSize(380, 180)
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
            }
            QLabel {
                color: #e0e0e0;
                font-size: 12px;
            }
            QLineEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #444444;
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
            }
            QPushButton {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(10)

        # Find row
        h1 = QHBoxLayout()
        h1.addWidget(QLabel("Find what:"))
        self.find_input = QLineEdit()
        h1.addWidget(self.find_input)
        layout.addLayout(h1)

        # Replace row
        h2 = QHBoxLayout()
        h2.addWidget(QLabel("Replace with:"))
        self.replace_input = QLineEdit()
        h2.addWidget(self.replace_input)
        layout.addLayout(h2)

        # Buttons
        btn_box = QHBoxLayout()
        btn_box.addStretch()

        find_next_btn = QPushButton("Find Next")
        find_next_btn.clicked.connect(self.find_next)
        btn_box.addWidget(find_next_btn)

        replace_btn = QPushButton("Replace")
        replace_btn.clicked.connect(self.replace_one)
        btn_box.addWidget(replace_btn)

        replace_all_btn = QPushButton("Replace All")
        replace_all_btn.clicked.connect(self.replace_all)
        btn_box.addWidget(replace_all_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        btn_box.addWidget(close_btn)

        layout.addLayout(btn_box)
        self.setLayout(layout)

    def find_next(self) -> bool:
        target = self.find_input.text()
        if not target:
            return False
        found = self.editor.find(target)
        if not found:
            # Wrap around to beginning
            cursor = self.editor.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.editor.setTextCursor(cursor)
            found = self.editor.find(target)
        return found

    def replace_one(self):
        target = self.find_input.text()
        replacement = self.replace_input.text()
        cursor = self.editor.textCursor()
        if cursor.hasSelection() and cursor.selectedText() == target:
            cursor.insertText(replacement)
        self.find_next()

    def replace_all(self):
        target = self.find_input.text()
        replacement = self.replace_input.text()
        if not target:
            return
        cursor = self.editor.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editor.setTextCursor(cursor)
        count = 0
        while self.editor.find(target):
            c = self.editor.textCursor()
            c.insertText(replacement)
            count += 1


class DecoyNotepad(QFrame):
    """
    High-Fidelity Windows 11 Decoy Notepad.
    Fully integrated with the centralized VirtualFileSystem:
    - New, Open, Save, Save As
    - Unsaved changes confirmation dialog
    - Status bar (Ln, Col, Char Count, Windows CRLF, UTF-8)
    - Find & Replace dialog
    - Word wrap & Font settings
    - Undo / Redo
    - Forensic telemetry recording
    """
    def __init__(self, sandbox_dir: str, log_dir: str, parent=None, initial_file: Optional[str] = None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
        self.vfs = get_vfs()

        self.is_maximized = False
        self.normal_geom = None
        self.drag_position = QPoint()

        # Document state
        self.current_vfs_path: Optional[str] = initial_file or "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\passwords.txt"
        self.is_dirty: bool = False
        self.word_wrap_enabled: bool = True

        self.init_ui()
        self.load_initial_file()

    def init_ui(self):
        self.setFixedSize(QSize(720, 460))
        self.setObjectName("NotepadContainer")
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
            QPushButton#MenuBtn {
                background-color: transparent;
                color: #cccccc;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                border: none;
                border-radius: 3px;
                padding: 4px 8px;
            }
            QPushButton#MenuBtn:hover {
                background-color: #2d2d2d;
                color: #ffffff;
            }
            QTextEdit {
                background-color: #1a1a1a;
                color: #e0e0e0;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                border: none;
                padding: 10px;
            }
            QFrame#StatusBar {
                background-color: #1f1f1f;
                border-top: 1px solid #2d2d2d;
                border-bottom-left-radius: 8px;
                border-bottom-right-radius: 8px;
            }
            QLabel#StatusLabel {
                color: #999999;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                padding: 2px 8px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 1. Title bar
        self.title_bar = QFrame()
        self.title_bar.setObjectName("NotepadTitleBar")
        self.title_bar.setFixedHeight(30)
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(10, 0, 0, 0)
        tb_layout.setSpacing(2)

        icon_lbl = QLabel("📄")
        icon_lbl.setStyleSheet("font-size: 12px; margin-right: 4px;")
        tb_layout.addWidget(icon_lbl)

        self.title_lbl = QLabel("passwords.txt - Notepad")
        self.title_lbl.setObjectName("NotepadTitle")
        tb_layout.addWidget(self.title_lbl)
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
        close_btn.setStyleSheet("background: transparent; color: #a0a0a0; border: none; font-size: 11px; width: 34px; height: 26px;")
        close_btn.clicked.connect(self.handle_close_attempt)
        tb_layout.addWidget(close_btn)

        self.title_bar.setLayout(tb_layout)
        layout.addWidget(self.title_bar)

        # 2. Interactive Menu Bar
        menu_bar = QFrame()
        menu_bar.setObjectName("MenuBar")
        menu_bar.setFixedHeight(28)
        mb_layout = QHBoxLayout()
        mb_layout.setContentsMargins(6, 0, 0, 0)
        mb_layout.setSpacing(4)

        # File actions
        new_btn = QPushButton("New")
        new_btn.setObjectName("MenuBtn")
        new_btn.clicked.connect(self.new_file)
        mb_layout.addWidget(new_btn)

        open_btn = QPushButton("Open...")
        open_btn.setObjectName("MenuBtn")
        open_btn.clicked.connect(self.prompt_open_file)
        mb_layout.addWidget(open_btn)

        save_btn = QPushButton("Save")
        save_btn.setObjectName("MenuBtn")
        save_btn.clicked.connect(self.save_file)
        mb_layout.addWidget(save_btn)

        save_as_btn = QPushButton("Save As...")
        save_as_btn.setObjectName("MenuBtn")
        save_as_btn.clicked.connect(self.prompt_save_as)
        mb_layout.addWidget(save_as_btn)

        # Edit actions
        find_btn = QPushButton("Find/Replace")
        find_btn.setObjectName("MenuBtn")
        find_btn.clicked.connect(self.open_find_replace)
        mb_layout.addWidget(find_btn)

        # View actions
        self.wrap_btn = QPushButton("Word Wrap: ON")
        self.wrap_btn.setObjectName("MenuBtn")
        self.wrap_btn.clicked.connect(self.toggle_word_wrap)
        mb_layout.addWidget(self.wrap_btn)

        mb_layout.addStretch()
        menu_bar.setLayout(mb_layout)
        layout.addWidget(menu_bar)

        # 3. Main Text Editor
        self.editor = QTextEdit()
        self.editor.cursorPositionChanged.connect(self.update_status_bar)
        self.editor.textChanged.connect(self.on_content_changed)
        layout.addWidget(self.editor, 1)

        # 4. Status Bar
        self.status_bar = QFrame()
        self.status_bar.setObjectName("StatusBar")
        self.status_bar.setFixedHeight(24)
        sb_layout = QHBoxLayout()
        sb_layout.setContentsMargins(8, 0, 8, 0)
        sb_layout.setSpacing(16)

        self.status_pos_lbl = QLabel("Ln 1, Col 1")
        self.status_pos_lbl.setObjectName("StatusLabel")
        sb_layout.addWidget(self.status_pos_lbl)

        self.status_chars_lbl = QLabel("0 characters")
        self.status_chars_lbl.setObjectName("StatusLabel")
        sb_layout.addWidget(self.status_chars_lbl)

        sb_layout.addStretch()

        encoding_lbl = QLabel("UTF-8")
        encoding_lbl.setObjectName("StatusLabel")
        sb_layout.addWidget(encoding_lbl)

        crlf_lbl = QLabel("Windows (CRLF)")
        crlf_lbl.setObjectName("StatusLabel")
        sb_layout.addWidget(crlf_lbl)

        self.status_bar.setLayout(sb_layout)
        layout.addWidget(self.status_bar)

        self.setLayout(layout)

    def load_initial_file(self):
        if self.current_vfs_path and self.vfs.exists(self.current_vfs_path):
            self.open_virtual_file(self.current_vfs_path)
        else:
            # Check passwords.txt
            pwd_path = "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\passwords.txt"
            if self.vfs.exists(pwd_path):
                self.open_virtual_file(pwd_path)
            else:
                self.editor.setPlainText("")
                self.current_vfs_path = None
                self.update_title()

    def update_title(self):
        name = PathUtils.split_path(self.current_vfs_path)[1] if self.current_vfs_path else "Untitled"
        dirty_flag = "*" if self.is_dirty else ""
        self.title_lbl.setText(f"{dirty_flag}{name} - Notepad")

    def update_status_bar(self):
        cursor = self.editor.textCursor()
        line = cursor.blockNumber() + 1
        col = cursor.columnNumber() + 1
        chars = len(self.editor.toPlainText())
        self.status_pos_lbl.setText(f"Ln {line}, Col {col}")
        self.status_chars_lbl.setText(f"{chars:,} characters")

    def open_virtual_file(self, vfs_path: str):
        """Opens a file from the centralized VirtualFileSystem."""
        norm = PathUtils.normalize(vfs_path)
        try:
            content = self.vfs.read_file(norm)
            self.current_vfs_path = norm
            self.editor.blockSignals(True)
            self.editor.setPlainText(content)
            self.editor.blockSignals(False)
            self.is_dirty = False
            self.update_title()
            self.update_status_bar()
            self.tracker.record_file_access(norm, action="VIEW")
        except Exception as e:
            QMessageBox.warning(self, "Notepad", f"Cannot open file '{vfs_path}': {e}")

    def on_content_changed(self):
        was_clean = not self.is_dirty
        self.is_dirty = True
        self.update_title()
        self.update_status_bar()

        # Update sandbox replica for immediate backward compatibility with tests
        try:
            content = self.editor.toPlainText()
            filename = PathUtils.split_path(self.current_vfs_path)[1] if self.current_vfs_path else "passwords.txt"
            sandbox_file = os.path.join(self.sandbox_dir, filename)
            with open(sandbox_file, "w", encoding="utf-8") as f:
                f.write(content)
            if was_clean:
                self.tracker.record_file_access(filename, action="MODIFY", application="NOTEPAD")
                self.tracker.record_sandbox_write(filename, len(content.encode("utf-8")))
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] [NOTEPAD_EDIT] {filename} modified\n")
        except Exception:
            pass

    def save_file(self) -> bool:
        """Saves current content back into the VirtualFileSystem."""
        if not self.current_vfs_path:
            return self.prompt_save_as()

        content = self.editor.toPlainText()
        try:
            self.vfs.write_file(self.current_vfs_path, content, append=False)
            self.is_dirty = False
            self.update_title()
            self.tracker.record_file_access(self.current_vfs_path, action="SAVE")
            return True
        except Exception as e:
            QMessageBox.warning(self, "Notepad", f"Cannot save file: {e}")
            return False

    def prompt_save_as(self) -> bool:
        # Windows-like virtual Save As dialog
        dlg = QDialog(self)
        dlg.setWindowTitle("Save As")
        dlg.setFixedSize(400, 150)
        dlg.setStyleSheet("background-color: #252526; color: #ffffff;")
        d_lay = QVBoxLayout()
        d_lay.addWidget(QLabel("Save to virtual path:"))
        path_input = QLineEdit(self.current_vfs_path or "C:\\Users\\Dell\\Desktop\\new_document.txt")
        path_input.setStyleSheet("background-color: #1e1e1e; color: #ffffff; padding: 4px;")
        d_lay.addWidget(path_input)

        btn_row = QHBoxLayout()
        btn_save = QPushButton("Save")
        btn_save.clicked.connect(dlg.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)
        btn_row.addWidget(btn_save)
        btn_row.addWidget(btn_cancel)
        d_lay.addLayout(btn_row)
        dlg.setLayout(d_lay)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_path = path_input.text().strip()
            if new_path:
                self.current_vfs_path = PathUtils.normalize(new_path)
                return self.save_file()
        return False

    def prompt_open_file(self):
        if not self.check_unsaved_changes():
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Open Virtual File")
        dlg.setFixedSize(400, 150)
        dlg.setStyleSheet("background-color: #252526; color: #ffffff;")
        d_lay = QVBoxLayout()
        d_lay.addWidget(QLabel("Virtual file path to open:"))
        path_input = QLineEdit("C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\passwords.txt")
        path_input.setStyleSheet("background-color: #1e1e1e; color: #ffffff; padding: 4px;")
        d_lay.addWidget(path_input)

        btn_row = QHBoxLayout()
        btn_open = QPushButton("Open")
        btn_open.clicked.connect(dlg.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)
        btn_row.addWidget(btn_open)
        btn_row.addWidget(btn_cancel)
        d_lay.addLayout(btn_row)
        dlg.setLayout(d_lay)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            target = path_input.text().strip()
            if self.vfs.exists(target):
                self.open_virtual_file(target)
            else:
                QMessageBox.warning(self, "Notepad", f"File '{target}' does not exist.")

    def new_file(self):
        if not self.check_unsaved_changes():
            return
        self.editor.clear()
        self.current_vfs_path = None
        self.is_dirty = False
        self.update_title()
        self.update_status_bar()

    def check_unsaved_changes(self) -> bool:
        """Returns True if safe to proceed, False if user cancelled."""
        if not self.is_dirty:
            return True

        filename = PathUtils.split_path(self.current_vfs_path)[1] if self.current_vfs_path else "Untitled"
        res = QMessageBox.question(
            self,
            "Notepad",
            f"Do you want to save changes to {filename}?",
            QMessageBox.StandardButton.Save | QMessageBox.StandardButton.Discard | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save
        )

        if res == QMessageBox.StandardButton.Save:
            return self.save_file()
        elif res == QMessageBox.StandardButton.Discard:
            self.is_dirty = False
            return True
        else:
            return False

    def handle_close_attempt(self):
        if self.check_unsaved_changes():
            self.hide()

    def open_find_replace(self):
        dlg = FindReplaceDialog(self.editor, self)
        dlg.show()

    def toggle_word_wrap(self):
        self.word_wrap_enabled = not self.word_wrap_enabled
        if self.word_wrap_enabled:
            self.editor.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
            self.wrap_btn.setText("Word Wrap: ON")
        else:
            self.editor.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
            self.wrap_btn.setText("Word Wrap: OFF")

    # Drag and Window Controls
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
            parent_rect = self.parent().rect() if self.parent() else self.screen().geometry()
            self.setGeometry(0, 0, parent_rect.width(), parent_rect.height() - 48)
            self.max_btn.setText("❐")
            self.is_maximized = True
        else:
            if self.normal_geom:
                self.setGeometry(self.normal_geom)
            else:
                self.setFixedSize(QSize(720, 460))
            self.max_btn.setText("□")
            self.is_maximized = False
