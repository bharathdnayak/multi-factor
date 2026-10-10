import os
import sys
import time
from typing import Optional, List, Tuple

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QScrollArea, QGridLayout, QTableWidget, QTableWidgetItem, QHeaderView,
    QMenu, QDialog, QMessageBox, QSplitter, QTreeWidget, QTreeWidgetItem,
    QAbstractItemView
)
from PyQt6.QtCore import Qt, QSize, QPoint, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QCursor, QIcon, QAction

from deception.virtual_fs import get_vfs, PathUtils, VirtualNode
from deception.forensic_tracker import get_tracker


class ItemPropertiesDialog(QDialog):
    """Windows File / Folder Properties Dialog."""
    def __init__(self, node: VirtualNode, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{node.name} Properties")
        self.setFixedSize(360, 340)
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
            QLabel#PropVal {
                color: #ffffff;
                font-weight: 500;
            }
            QPushButton {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 6px 16px;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
            }
            QFrame#Divider {
                border-top: 1px solid #3d3d3d;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(10)

        # Header with icon and name
        hdr = QHBoxLayout()
        icon_lbl = QLabel(node.icon)
        icon_lbl.setStyleSheet("font-size: 32px;")
        hdr.addWidget(icon_lbl)

        name_lbl = QLabel(f"<b>{node.name}</b>")
        name_lbl.setStyleSheet("font-size: 14px; color: #00d2d3;")
        hdr.addWidget(name_lbl)
        hdr.addStretch()
        layout.addLayout(hdr)

        div1 = QFrame()
        div1.setObjectName("Divider")
        layout.addWidget(div1)

        # Properties table
        props = [
            ("Type of file:", node.type_description),
            ("Location:", PathUtils.split_path(node.path)[0]),
            ("Size:", node.format_size() if not node.is_dir else "4,096 bytes (Virtual Directory)"),
            ("Created:", time.strftime("%d-%m-%Y %I:%M %p", time.localtime(node.created_time))),
            ("Modified:", node.format_modified_time()),
            ("Attributes:", f"Read-only: {node.attributes.get('readonly', False)}, Hidden: {node.attributes.get('hidden', False)}")
        ]

        for label, val in props:
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(110)
            row.addWidget(lbl)
            val_lbl = QLabel(str(val))
            val_lbl.setObjectName("PropVal")
            val_lbl.setWordWrap(True)
            row.addWidget(val_lbl)
            layout.addLayout(row)

        div2 = QFrame()
        div2.setObjectName("Divider")
        layout.addWidget(div2)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        btn_row.addWidget(ok_btn)
        layout.addLayout(btn_row)

        self.setLayout(layout)


class DecoyExplorer(QFrame):
    """
    High-Fidelity Windows 11 File Explorer Decoy Window.
    Backed by the centralized VirtualFileSystem:
    - Back, Forward, Up, Refresh navigation history
    - Clickable breadcrumbs and editable address bar with direct path entry
    - Expandable navigation tree (Quick Access & This PC drives)
    - View modes: Details View (table with columns) and Icon/Tile View
    - Sorting by Name, Date modified, Type, Size
    - Virtual clipboard: Copy, Cut, Paste
    - Virtual operations: New Folder, New Document, Rename, Delete (Recycle Bin), Restore
    - Search field querying the virtual filesystem
    - Real-time synchronization with PowerShell and Notepad via change listeners
    """
    def __init__(self, sandbox_dir: str, log_dir: str, parent=None):
        super().__init__(parent)
        self.sandbox_dir = sandbox_dir
        self.log_dir = log_dir
        self.tracker = get_tracker()
        self.vfs = get_vfs()

        self.is_maximized = False
        self.normal_geom = None
        self.drag_position = QPoint()

        # Navigation State
        self.current_path = "C:\\Users\\Dell\\Desktop\\clg"
        self.path_history: List[str] = [self.current_path]
        self.history_index: int = 0
        self.view_mode: str = "details"  # "details" or "icons"
        self.is_editing_address: bool = False

        self.init_ui()
        self.vfs.register_change_listener(self.on_vfs_changed)
        self.navigate_to(self.current_path, record_history=False)

    def init_ui(self):
        self.setFixedSize(QSize(860, 520))
        self.setObjectName("ExplorerContainer")
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
            QFrame#NavRow {
                background-color: #1f1f1f;
                border-bottom: 1px solid #2d2d2d;
            }
            QPushButton#NavArrowBtn {
                background-color: transparent;
                color: #cccccc;
                border: none;
                border-radius: 4px;
                font-size: 14px;
                font-weight: bold;
                width: 28px;
                height: 26px;
            }
            QPushButton#NavArrowBtn:hover {
                background-color: #333333;
                color: #ffffff;
            }
            QPushButton#NavArrowBtn:disabled {
                color: #555555;
            }
            QFrame#BreadcrumbBar {
                background-color: #262626;
                border: 1px solid #383838;
                border-radius: 4px;
                padding: 1px 4px;
            }
            QPushButton#BreadcrumbPill {
                background-color: transparent;
                color: #e0e0e0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                border: none;
                border-radius: 3px;
                padding: 2px 4px;
            }
            QPushButton#BreadcrumbPill:hover {
                background-color: #3a3a3a;
                color: #ffffff;
            }
            QLineEdit#AddressInput {
                background-color: #262626;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                border: 1px solid #00d2d3;
                border-radius: 4px;
                padding: 2px 6px;
            }
            QLineEdit#SearchField {
                background-color: #262626;
                color: #ffffff;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                border: 1px solid #383838;
                border-radius: 4px;
                padding: 2px 8px;
            }
            QTreeWidget#SidebarTree {
                background-color: #181818;
                color: #cccccc;
                border: none;
                border-right: 1px solid #2d2d2d;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                padding: 4px;
            }
            QTreeWidget#SidebarTree::item {
                padding: 4px 2px;
                border-radius: 4px;
            }
            QTreeWidget#SidebarTree::item:hover {
                background-color: #282828;
                color: #ffffff;
            }
            QTreeWidget#SidebarTree::item:selected {
                background-color: #333333;
                color: #00d2d3;
            }
            QTableWidget#DetailsTable {
                background-color: #191919;
                color: #e0e0e0;
                border: none;
                font-family: 'Segoe UI', sans-serif;
                font-size: 12px;
                gridline-color: transparent;
            }
            QTableWidget#DetailsTable::item {
                padding: 4px 6px;
                border-bottom: 1px solid #222222;
            }
            QTableWidget#DetailsTable::item:selected {
                background-color: #2a374a;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #1f1f1f;
                color: #999999;
                border: none;
                border-right: 1px solid #2d2d2d;
                padding: 4px 8px;
                font-size: 11px;
                font-weight: 600;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # 1. Window Title Bar
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

        # 2. Navigation & Breadcrumb Row
        nav_row = QFrame()
        nav_row.setObjectName("NavRow")
        nav_row.setFixedHeight(38)
        nav_layout = QHBoxLayout()
        nav_layout.setContentsMargins(8, 2, 8, 2)
        nav_layout.setSpacing(6)

        self.back_btn = QPushButton("←")
        self.back_btn.setObjectName("NavArrowBtn")
        self.back_btn.setToolTip("Back")
        self.back_btn.clicked.connect(self.navigate_back)
        nav_layout.addWidget(self.back_btn)

        self.forward_btn = QPushButton("→")
        self.forward_btn.setObjectName("NavArrowBtn")
        self.forward_btn.setToolTip("Forward")
        self.forward_btn.clicked.connect(self.navigate_forward)
        nav_layout.addWidget(self.forward_btn)

        self.up_btn = QPushButton("↑")
        self.up_btn.setObjectName("NavArrowBtn")
        self.up_btn.setToolTip("Up to parent folder")
        self.up_btn.clicked.connect(self.navigate_up)
        nav_layout.addWidget(self.up_btn)

        self.refresh_btn = QPushButton("↻")
        self.refresh_btn.setObjectName("NavArrowBtn")
        self.refresh_btn.setToolTip("Refresh (F5)")
        self.refresh_btn.clicked.connect(self.refresh_current_folder)
        nav_layout.addWidget(self.refresh_btn)

        # Breadcrumbs bar and address edit container
        self.addr_container = QFrame()
        self.addr_container.setObjectName("BreadcrumbBar")
        self.addr_container_layout = QHBoxLayout()
        self.addr_container_layout.setContentsMargins(4, 0, 4, 0)
        self.addr_container_layout.setSpacing(2)

        # Dynamic breadcrumbs container
        self.breadcrumbs_widget = QFrame()
        self.breadcrumbs_layout = QHBoxLayout()
        self.breadcrumbs_layout.setContentsMargins(0, 0, 0, 0)
        self.breadcrumbs_layout.setSpacing(2)
        self.breadcrumbs_widget.setLayout(self.breadcrumbs_layout)
        self.addr_container_layout.addWidget(self.breadcrumbs_widget, 1)

        # Editable address entry (toggled on click)
        self.address_input = QLineEdit()
        self.address_input.setObjectName("AddressInput")
        self.address_input.returnPressed.connect(self.on_address_entered)
        self.address_input.hide()
        self.addr_container_layout.addWidget(self.address_input, 1)

        # Edit toggle button
        edit_addr_btn = QPushButton("✏️")
        edit_addr_btn.setStyleSheet("background: transparent; border: none; font-size: 11px; padding: 2px;")
        edit_addr_btn.clicked.connect(self.toggle_address_editor)
        self.addr_container_layout.addWidget(edit_addr_btn)

        self.addr_container.setLayout(self.addr_container_layout)
        nav_layout.addWidget(self.addr_container, 1)

        # Address label reference for backward compatibility with existing tests
        self.addr_lbl = QLabel()

        # View mode toggle
        view_toggle_btn = QPushButton("🗂️ View")
        view_toggle_btn.setObjectName("NavArrowBtn")
        view_toggle_btn.setFixedWidth(64)
        view_toggle_btn.clicked.connect(self.toggle_view_mode)
        nav_layout.addWidget(view_toggle_btn)

        # Search field
        self.search_box = QLineEdit()
        self.search_box.setObjectName("SearchField")
        self.search_box.setPlaceholderText("🔍 Search")
        self.search_box.setFixedWidth(160)
        self.search_box.textChanged.connect(self.on_search_changed)
        nav_layout.addWidget(self.search_box)

        nav_row.setLayout(nav_layout)
        layout.addWidget(nav_row)

        # 3. Main Content Splitter (Sidebar Tree + File Area)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: #2d2d2d; width: 1px; }")

        # Left Navigation Sidebar
        self.sidebar_tree = QTreeWidget()
        self.sidebar_tree.setObjectName("SidebarTree")
        self.sidebar_tree.setHeaderHidden(True)
        self.sidebar_tree.setFixedWidth(190)
        self.populate_sidebar_tree()
        self.sidebar_tree.itemClicked.connect(self.on_sidebar_item_clicked)
        splitter.addWidget(self.sidebar_tree)

        # Right File Area (Table and Icon Grid container)
        self.right_container = QFrame()
        r_layout = QVBoxLayout()
        r_layout.setContentsMargins(0, 0, 0, 0)
        r_layout.setSpacing(0)

        # 3a. Details Table View
        self.details_table = QTableWidget()
        self.details_table.setObjectName("DetailsTable")
        self.details_table.setColumnCount(4)
        self.details_table.setHorizontalHeaderLabels(["Name", "Date modified", "Type", "Size"])
        self.details_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.details_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.details_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.details_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self.details_table.verticalHeader().setVisible(False)
        self.details_table.setShowGrid(False)
        self.details_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.details_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.details_table.customContextMenuRequested.connect(self.show_context_menu)
        self.details_table.itemDoubleClicked.connect(self.on_table_item_double_clicked)

        # Keyboard Navigation for Table (Enter, Backspace, Delete)
        orig_key_press = self.details_table.keyPressEvent
        def on_table_key(event):
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                curr = self.details_table.currentRow()
                if curr >= 0:
                    node_item = self.details_table.item(curr, 0)
                    node = node_item.data(Qt.ItemDataRole.UserRole) if node_item else None
                    if node:
                        if node.is_dir:
                            self.navigate_to(node.path, navigation_method="KEYBOARD_ENTER")
                        else:
                            self.on_file_clicked(node.name)
                        return
            elif event.key() == Qt.Key.Key_Backspace:
                self.navigate_up()
                return
            elif event.key() == Qt.Key.Key_Delete:
                curr = self.details_table.currentRow()
                if curr >= 0:
                    node_item = self.details_table.item(curr, 0)
                    node = node_item.data(Qt.ItemDataRole.UserRole) if node_item else None
                    if node:
                        self.delete_node(node)
                        return
            orig_key_press(event)
        self.details_table.keyPressEvent = on_table_key

        r_layout.addWidget(self.details_table)

        # 3b. Icons Grid View (inside scroll area)
        self.icons_scroll = QScrollArea()
        self.icons_scroll.setWidgetResizable(True)
        self.icons_scroll.setStyleSheet("background-color: #191919; border: none;")
        self.icons_area = QFrame()
        self.f_layout = QGridLayout()
        self.f_layout.setContentsMargins(18, 18, 18, 18)
        self.f_layout.setHorizontalSpacing(20)
        self.f_layout.setVerticalSpacing(16)
        self.f_layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        self.icons_area.setLayout(self.f_layout)
        self.icons_area.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.icons_area.customContextMenuRequested.connect(self.show_context_menu)
        self.icons_scroll.setWidget(self.icons_area)
        self.icons_scroll.hide()
        r_layout.addWidget(self.icons_scroll)

        # Empty folder notice
        self.empty_lbl = QLabel("This folder is empty.")
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl.setStyleSheet("color: #777777; font-family: 'Segoe UI', sans-serif; font-size: 13px; padding: 40px;")
        self.empty_lbl.hide()
        r_layout.addWidget(self.empty_lbl)

        self.right_container.setLayout(r_layout)
        splitter.addWidget(self.right_container)

        splitter.setSizes([190, 670])
        layout.addWidget(splitter, 1)

        self.setLayout(layout)

    def populate_sidebar_tree(self):
        self.sidebar_tree.clear()

        # Quick access group
        qa_root = QTreeWidgetItem(self.sidebar_tree, ["⭐ Quick access"])
        qa_root.setExpanded(True)

        qa_items = [
            ("🖥️ Desktop", "C:\\Users\\Dell\\Desktop"),
            ("📁 clg", "C:\\Users\\Dell\\Desktop\\clg"),
            ("📄 Documents", "C:\\Users\\Dell\\Documents"),
            ("📥 Downloads", "C:\\Users\\Dell\\Downloads"),
            ("🖼️ Pictures", "C:\\Users\\Dell\\Pictures")
        ]
        for label, path in qa_items:
            child = QTreeWidgetItem(qa_root, [label])
            child.setData(0, Qt.ItemDataRole.UserRole, path)

        # This PC group
        this_pc = QTreeWidgetItem(self.sidebar_tree, ["💻 This PC"])
        this_pc.setExpanded(True)

        c_drive = QTreeWidgetItem(this_pc, ["💾 Local Disk (C:)"])
        c_drive.setData(0, Qt.ItemDataRole.UserRole, "C:\\")
        c_drive.setExpanded(True)

        # Subfolders of C:\
        for d in ["Program Files", "Users", "Windows"]:
            sub = QTreeWidgetItem(c_drive, [f"📁 {d}"])
            sub.setData(0, Qt.ItemDataRole.UserRole, f"C:\\{d}")

        # Recycle Bin
        rb_item = QTreeWidgetItem(self.sidebar_tree, ["🗑️ Recycle Bin"])
        rb_item.setData(0, Qt.ItemDataRole.UserRole, "C:\\$Recycle.Bin")

    def on_sidebar_item_clicked(self, item: QTreeWidgetItem, column: int):
        target_path = item.data(0, Qt.ItemDataRole.UserRole)
        if target_path:
            self.navigate_to(target_path)

    def on_vfs_changed(self, action: str, path: str):
        """Callback invoked whenever the VirtualFileSystem is modified."""
        # Refresh current view if the affected path is in or child of current directory
        self.render_current_folder()

    def navigate_to(self, new_path: str, record_history: bool = True, navigation_method: str = "DOUBLE_CLICK"):
        norm = PathUtils.normalize(new_path)
        if not self.vfs.exists(norm):
            self.tracker.record_failed_access(norm, reason="Path not found in virtual filesystem")
            if os.environ.get("HEADLESS_TEST") != "1" and self.isVisible():
                try:
                    QMessageBox.warning(self, "File Explorer", f"Windows cannot find '{new_path}'. Check the spelling and try again.")
                except Exception:
                    pass
            return

        node = self.vfs.get_node(norm)
        if not node.is_dir:
            self.on_file_clicked(node.name)
            return

        old_path = self.current_path
        if record_history and (not self.path_history or self.path_history[self.history_index] != norm):
            self.path_history = self.path_history[:self.history_index + 1]
            self.path_history.append(norm)
            self.history_index = len(self.path_history) - 1

        self.current_path = norm
        self.tracker.record_folder_navigation(norm, source_path=old_path, method=navigation_method)

        folder_name = PathUtils.split_path(norm)[1] or "Local Disk (C:)"
        self.title_lbl.setText(f"{folder_name} - File Explorer")
        self.addr_lbl.setText(f"📁 This PC > {self.current_path.replace(':', '').replace('\\', ' > ')}")
        self.address_input.setText(self.current_path)

        self.update_breadcrumbs()
        self.update_nav_buttons()
        self.search_box.clear()
        self.render_current_folder()

    def update_nav_buttons(self):
        self.back_btn.setEnabled(self.history_index > 0)
        self.forward_btn.setEnabled(self.history_index < len(self.path_history) - 1)
        self.up_btn.setEnabled(not PathUtils.path_equal(self.current_path, "C:\\"))

    def navigate_back(self):
        if self.history_index > 0:
            self.history_index -= 1
            target = self.path_history[self.history_index]
            self.navigate_to(target, record_history=False, navigation_method="HISTORY_BACK")

    def navigate_forward(self):
        if self.history_index < len(self.path_history) - 1:
            self.history_index += 1
            target = self.path_history[self.history_index]
            self.navigate_to(target, record_history=False, navigation_method="HISTORY_FORWARD")

    def navigate_up(self):
        if not PathUtils.path_equal(self.current_path, "C:\\"):
            parent, _ = PathUtils.split_path(self.current_path)
            self.navigate_to(parent, navigation_method="NAVIGATE_UP")

    def refresh_current_folder(self):
        self.render_current_folder()

    def toggle_address_editor(self):
        self.is_editing_address = not self.is_editing_address
        if self.is_editing_address:
            self.breadcrumbs_widget.hide()
            self.address_input.setText(self.current_path)
            self.address_input.show()
            self.address_input.setFocus()
            self.address_input.selectAll()
        else:
            self.address_input.hide()
            self.breadcrumbs_widget.show()

    def on_address_entered(self):
        entered = self.address_input.text().strip()
        self.toggle_address_editor()
        if entered:
            resolved = self.vfs.resolve_path(self.current_path, entered)
            self.navigate_to(resolved, navigation_method="ADDRESS_BAR")

    def update_breadcrumbs(self):
        # Clear existing breadcrumb buttons
        while self.breadcrumbs_layout.count():
            item = self.breadcrumbs_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Build path segments
        segments = []
        cur = self.current_path
        while True:
            parent, name = PathUtils.split_path(cur)
            segments.append((name or "Local Disk (C:)", cur))
            if PathUtils.path_equal(cur, "C:\\") or not name:
                break
            cur = parent

        segments.reverse()

        for idx, (seg_name, seg_path) in enumerate(segments):
            if idx > 0:
                sep = QLabel("›")
                sep.setStyleSheet("color: #777777; font-size: 11px;")
                self.breadcrumbs_layout.addWidget(sep)

            pill = QPushButton(seg_name)
            pill.setObjectName("BreadcrumbPill")
            pill.clicked.connect(lambda _, p=seg_path: self.navigate_to(p, navigation_method="BREADCRUMB"))
            self.breadcrumbs_layout.addWidget(pill)

        self.breadcrumbs_layout.addStretch()

    def toggle_view_mode(self):
        if self.view_mode == "details":
            self.view_mode = "icons"
            self.details_table.hide()
            self.icons_scroll.show()
        else:
            self.view_mode = "details"
            self.icons_scroll.hide()
            self.details_table.show()
        self.render_current_folder()

    def on_search_changed(self, query: str):
        q = query.strip()
        if not q:
            self.render_current_folder()
            return

        # Search recursively within current path
        results = self.vfs.search(q, root_path=self.current_path, recursive=True)
        self.render_items_list(results)

    def render_current_folder(self):
        items = self.vfs.list_dir(self.current_path, include_hidden=False)
        self.render_items_list(items)

    def render_items_list(self, items: List[VirtualNode]):
        if not items:
            self.empty_lbl.show()
            self.details_table.setRowCount(0)
            while self.f_layout.count():
                it = self.f_layout.takeAt(0)
                if it.widget():
                    it.widget().deleteLater()
            return

        self.empty_lbl.hide()

        if self.view_mode == "details":
            self.render_details_view(items)
        else:
            self.render_icons_view(items)

    def render_details_view(self, items: List[VirtualNode]):
        self.details_table.setRowCount(len(items))
        for row, node in enumerate(items):
            # Column 0: Icon + Name
            name_item = QTableWidgetItem(f"{node.icon}  {node.name}")
            name_item.setData(Qt.ItemDataRole.UserRole, node)
            self.details_table.setItem(row, 0, name_item)

            # Column 1: Date modified
            date_item = QTableWidgetItem(node.format_modified_time())
            self.details_table.setItem(row, 1, date_item)

            # Column 2: Type
            type_item = QTableWidgetItem(node.type_description)
            self.details_table.setItem(row, 2, type_item)

            # Column 3: Size
            size_item = QTableWidgetItem(node.format_size())
            size_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self.details_table.setItem(row, 3, size_item)

    def render_icons_view(self, items: List[VirtualNode]):
        while self.f_layout.count():
            it = self.f_layout.takeAt(0)
            if it.widget():
                it.widget().deleteLater()

        for idx, node in enumerate(items):
            r = idx // 4
            c = idx % 4

            box = QFrame()
            box.setFixedSize(140, 84)
            box.setStyleSheet("QFrame { background-color: transparent; border-radius: 6px; } QFrame:hover { background-color: #2d3748; }")
            box.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            b_layout = QVBoxLayout()
            b_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b_layout.setSpacing(4)

            i_lbl = QLabel(node.icon)
            i_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            i_lbl.setStyleSheet("font-size: 28px; background: transparent;")
            b_layout.addWidget(i_lbl)

            t_lbl = QLabel(node.name)
            t_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            t_lbl.setWordWrap(True)
            t_lbl.setStyleSheet("color: #e2e8f0; font-size: 11px; background: transparent;")
            b_layout.addWidget(t_lbl)

            box.setLayout(b_layout)

            if node.is_dir:
                box.mousePressEvent = lambda e, n=node.name: self.on_folder_clicked(n)
            else:
                box.mousePressEvent = lambda e, n=node.name: self.on_file_clicked(n)

            self.f_layout.addWidget(box, r, c)

    def on_table_item_double_clicked(self, item: QTableWidgetItem):
        row = item.row()
        node_item = self.details_table.item(row, 0)
        node = node_item.data(Qt.ItemDataRole.UserRole) if node_item else None
        if node:
            if node.is_dir:
                self.navigate_to(node.path)
            else:
                self.on_file_clicked(node.name)

    def on_folder_clicked(self, folder_name: str):
        """Backward compatible folder click handler tested by tests."""
        new_path = PathUtils.join(self.current_path, folder_name)
        if not self.vfs.exists(new_path):
            self.vfs.mkdir(new_path)
        self.navigate_to(new_path)

    def on_file_clicked(self, file_name: str):
        """Backward compatible file click handler."""
        full_path = PathUtils.join(self.current_path, file_name)
        self.tracker.record_file_access(full_path, action="OPEN")

        text_exts = [".txt", ".env", ".ini", ".json", ".log", ".py", ".md", ".sql", ".csv"]
        if any(file_name.lower().endswith(ext) for ext in text_exts) or "password" in file_name.lower():
            # Open via DecoyNotepad
            parent = self.parent()
            if parent and hasattr(parent, 'open_notepad'):
                parent.open_notepad(file_path=full_path)
            elif parent and hasattr(parent, 'decoy_notepad'):
                parent.decoy_notepad.open_virtual_file(full_path)
                parent.decoy_notepad.show()
                parent.decoy_notepad.raise_()
        else:
            # Show simulated Windows document viewer dialog
            self.show_document_viewer(file_name, full_path)

    def show_document_viewer(self, file_name: str, file_path: str):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"{file_name} - Protected Document Preview")
        dlg.setFixedSize(540, 280)
        dlg.setStyleSheet("background-color: #1e1e24; color: #ffffff;")
        d_lay = QVBoxLayout()
        d_lay.setContentsMargins(20, 20, 20, 20)

        lbl_title = QLabel(f"<b>{file_name}</b>")
        lbl_title.setStyleSheet("font-size: 15px; color: #00d2d3;")
        d_lay.addWidget(lbl_title)

        lbl_desc = QLabel("Corporate Security Notice: This file is restricted under corporate policy.\nContents are decrypted in sandboxed memory container.")
        lbl_desc.setStyleSheet("color: #a4b0be; font-size: 12px;")
        d_lay.addWidget(lbl_desc)

        content_preview = QLineEdit() if file_name.endswith(".url") else QLabel()
        from PyQt6.QtWidgets import QTextEdit
        te = QTextEdit()
        te.setReadOnly(True)
        te.setStyleSheet("background-color: #121217; color: #00ff00; font-family: 'Consolas'; font-size: 11px;")
        te.setText(f"--- DUMP OF {file_name} ---\nDocument Classification: STRICTLY CONFIDENTIAL\nVirtual Path: {file_path}\nOwner: NMAMIT Dept of ISE\nProject ID: 30\nStatus: Archived in Honeypot Sandbox\nChecksum Verified: OK")
        d_lay.addWidget(te)

        btn_close = QPushButton("Close")
        btn_close.setStyleSheet("background-color: #2ed573; color: #ffffff; padding: 6px; border-radius: 4px;")
        btn_close.clicked.connect(dlg.accept)
        d_lay.addWidget(btn_close)

        dlg.setLayout(d_lay)
        dlg.exec()

    # Context Menu Actions
    def show_context_menu(self, pos: QPoint):
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

        selected_item = self.details_table.itemAt(pos) if self.view_mode == "details" else None
        node: Optional[VirtualNode] = None
        if selected_item:
            row = selected_item.row()
            node = self.details_table.item(row, 0).data(Qt.ItemDataRole.UserRole)

        if node:
            # Context menu for clicked item
            open_act = menu.addAction(f"Open")
            open_act.triggered.connect(lambda: self.on_folder_clicked(node.name) if node.is_dir else self.on_file_clicked(node.name))

            menu.addSeparator()
            cut_act = menu.addAction("Cut")
            cut_act.triggered.connect(lambda: self._action_cut(node))

            copy_act = menu.addAction("Copy")
            copy_act.triggered.connect(lambda: self._action_copy(node))

            rename_act = menu.addAction("Rename (F2)")
            rename_act.triggered.connect(lambda: self.prompt_rename(node))

            del_act = menu.addAction("Delete")
            del_act.triggered.connect(lambda: self.delete_node(node))

            menu.addSeparator()
            prop_act = menu.addAction("Properties")
            prop_act.triggered.connect(lambda: self.show_properties(node))
        else:
            # Context menu for empty space
            view_menu = menu.addMenu("View")
            det_act = view_menu.addAction("Details")
            det_act.triggered.connect(lambda: self.set_view_mode("details"))
            icon_act = view_menu.addAction("Icons")
            icon_act.triggered.connect(lambda: self.set_view_mode("icons"))

            ref_act = menu.addAction("Refresh")
            ref_act.triggered.connect(self.refresh_current_folder)

            menu.addSeparator()
            paste_act = menu.addAction("Paste")
            paste_act.setEnabled(self.vfs.clipboard.has_items())
            paste_act.triggered.connect(self.paste_from_clipboard)

            menu.addSeparator()
            new_menu = menu.addMenu("New")
            new_fld = new_menu.addAction("Folder")
            new_fld.triggered.connect(self.prompt_new_folder)
            new_doc = new_menu.addAction("Text Document")
            new_doc.triggered.connect(self.prompt_new_document)

            menu.addSeparator()
            curr_node = self.vfs.get_node(self.current_path)
            if curr_node:
                prop_act = menu.addAction("Properties")
                prop_act.triggered.connect(lambda: self.show_properties(curr_node))

        widget = self.details_table if self.view_mode == "details" else self.icons_area
        menu.exec(widget.mapToGlobal(pos))

    def set_view_mode(self, mode: str):
        if self.view_mode != mode:
            self.toggle_view_mode()

    def prompt_new_folder(self):
        base_name = "New folder"
        target_path = PathUtils.join(self.current_path, base_name)
        idx = 2
        while self.vfs.exists(target_path):
            target_path = PathUtils.join(self.current_path, f"{base_name} ({idx})")
            idx += 1
        self.vfs.mkdir(target_path)
        self.tracker.record_file_access(target_path, action="CREATE_FOLDER")

    def prompt_new_document(self):
        base_name = "New Text Document.txt"
        target_path = PathUtils.join(self.current_path, base_name)
        idx = 2
        while self.vfs.exists(target_path):
            target_path = PathUtils.join(self.current_path, f"New Text Document ({idx}).txt")
            idx += 1
        self.vfs.create_file(target_path, content="")
        self.tracker.record_file_access(target_path, action="CREATE_FILE")

    def prompt_rename(self, node: VirtualNode):
        dlg = QDialog(self)
        dlg.setWindowTitle("Rename Item")
        dlg.setFixedSize(360, 130)
        dlg.setStyleSheet("background-color: #252526; color: #ffffff;")
        d_lay = QVBoxLayout()
        d_lay.addWidget(QLabel(f"Enter new name for '{node.name}':"))
        name_input = QLineEdit(node.name)
        name_input.setStyleSheet("background-color: #1e1e1e; color: #ffffff; padding: 4px;")
        d_lay.addWidget(name_input)

        btn_row = QHBoxLayout()
        btn_ok = QPushButton("OK")
        btn_ok.clicked.connect(dlg.accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(dlg.reject)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        d_lay.addLayout(btn_row)
        dlg.setLayout(d_lay)

        if dlg.exec() == QDialog.DialogCode.Accepted:
            new_name = name_input.text().strip()
            if new_name and new_name != node.name:
                try:
                    self.vfs.rename(node.path, new_name)
                    self.tracker.record_file_access(node.path, action="RENAME")
                except Exception as e:
                    QMessageBox.warning(self, "Rename", f"Cannot rename item: {e}")

    def delete_node(self, node: VirtualNode):
        try:
            self.vfs.delete(node.path, to_recycle_bin=True)
            self.tracker.record_file_access(node.path, action="DELETE")
        except Exception as e:
            QMessageBox.warning(self, "Delete", f"Cannot delete item: {e}")

    def paste_from_clipboard(self):
        mode, paths = self.vfs.clipboard.get_items()
        if not mode or not paths:
            return

        for p in paths:
            try:
                if mode == "cut":
                    self.vfs.move(p, self.current_path)
                    self.tracker.record_file_access(p, action="MOVE")
                else:
                    self.vfs.copy(p, self.current_path)
                    self.tracker.record_file_access(p, action="COPY")
            except Exception as e:
                QMessageBox.warning(self, "Paste", f"Cannot paste item '{p}': {e}")

        if mode == "cut":
            self.vfs.clipboard.clear()

    def _action_copy(self, node: VirtualNode):
        self.vfs.clipboard.copy([node.path])
        self.tracker.record_clipboard_action(action="COPY", paths=[node.path])

    def _action_cut(self, node: VirtualNode):
        self.vfs.clipboard.cut([node.path])
        self.tracker.record_clipboard_action(action="CUT", paths=[node.path])

    def show_properties(self, node: VirtualNode):
        self.tracker.record_properties_view(node.path, is_dir=node.is_dir)
        dlg = ItemPropertiesDialog(node, self)
        dlg.exec()

    # Window Controls & Dragging
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
                self.setFixedSize(QSize(860, 520))
            self.max_btn.setText("□")
            self.is_maximized = False
