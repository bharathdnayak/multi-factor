import sys
import os
import time

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QTextEdit, QFrame, QScrollArea, QStackedWidget,
    QTextBrowser
)
from PyQt6.QtCore import Qt, QSize, QPoint, QUrl
from PyQt6.QtGui import QFont, QColor, QCursor

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deception.forensic_tracker import get_tracker


class DecoyChrome(QFrame):
    """
    High-Fidelity Google Chrome Decoy Window with Honey-Token Web Portals.
    Provides a hyper-realistic browser environment to trap and record the intruder's web activity.
    Features:
    - Authentic Chrome Tab Bar & Bookmarks Bar with multi-tab support
    - Chrome Omnibox / URL address bar with dynamic routing
    - Interactive Google Search engine that logs queries and displays results
    - Decoy Corporate NetBanking Portal (credential harvesting trap)
    - Decoy AWS Management Console (honey-token access keys and S3 buckets)
    - Decoy Internal GitHub Enterprise (fake repositories with .env secrets)
    - Decoy Corporate Webmail with honey-token emails
    - Decoy Cloud Vault / Internal Infrastructure
    - Optional Isolated Real Internet Browsing with download sandbox interception
    - All actions recorded directly to ForensicTracker for offline Ollama threat intelligence.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tracker = get_tracker()
        self.is_maximized = False
        self.normal_geom = None
        self.drag_position = QPoint()
        self.current_url = "https://www.google.com"
        self.history = ["https://www.google.com"]
        self.history_idx = 0
        
        # Real internet access configuration (Disabled by default for strict isolation)
        self.internet_enabled = os.environ.get("DECOY_BROWSER_INTERNET_ENABLED", "false").lower() in ("true", "1", "yes")
        self.sandbox_dir = os.path.join(PROJECT_ROOT, "data", "sandbox")
        os.makedirs(self.sandbox_dir, exist_ok=True)
        
        # Tabs model
        self.tabs = [
            {"id": 0, "title": "Google", "url": "https://www.google.com", "stack_idx": 0}
        ]
        self.active_tab_idx = 0
        
        self.init_ui()

    def init_ui(self):
        self.setFixedSize(QSize(960, 600))
        self.setObjectName("ChromeContainer")
        self.setStyleSheet("""
            QFrame#ChromeContainer {
                background-color: #202124;
                border: 1px solid #3c4043;
                border-radius: 8px;
            }
            QFrame#TabBar {
                background-color: #1f1f1f;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
            }
            QFrame#ActiveTab {
                background-color: #35363a;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 4px 10px;
            }
            QLabel#TabTitle {
                color: #e8eaed;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 11px;
                font-weight: 500;
            }
            QFrame#NavRow {
                background-color: #35363a;
                border-bottom: 1px solid #28292c;
                padding: 4px 8px;
            }
            QPushButton#NavBtn {
                background-color: transparent;
                color: #9aa0a6;
                border: none;
                border-radius: 14px;
                font-size: 14px;
                width: 28px;
                height: 28px;
            }
            QPushButton#NavBtn:hover {
                background-color: #434448;
                color: #e8eaed;
            }
            QLineEdit#Omnibox {
                background-color: #202124;
                color: #e8eaed;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
                border: 1px solid #5f6368;
                border-radius: 14px;
                padding: 4px 14px;
            }
            QLineEdit#Omnibox:focus {
                border-color: #8ab4f8;
            }
            QFrame#BookmarksBar {
                background-color: #28292c;
                border-bottom: 1px solid #3c4043;
                padding: 2px 8px;
            }
            QPushButton#BookmarkBtn {
                background-color: transparent;
                color: #bdc1c6;
                border: none;
                border-radius: 4px;
                font-size: 11px;
                padding: 3px 8px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton#BookmarkBtn:hover {
                background-color: #3c4043;
                color: #ffffff;
            }
            QPushButton#WindowControlBtn {
                background: transparent;
                color: #9aa0a6;
                border: none;
                font-family: 'Segoe UI', sans-serif;
                font-size: 11px;
                width: 32px;
                height: 26px;
            }
            QPushButton#WindowControlBtn:hover {
                background-color: #434448;
                color: #ffffff;
            }
            QPushButton#CloseBtn:hover {
                background-color: #e81123;
                color: #ffffff;
                border-top-right-radius: 8px;
            }
            QFrame#PageArea {
                background-color: #202124;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ---------------- 1. Chrome Tab Bar & Window Controls ----------------
        tab_bar = QFrame()
        tab_bar.setObjectName("TabBar")
        tab_bar.setFixedHeight(34)
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(8, 6, 0, 0)
        tb_layout.setSpacing(4)

        # Tab 1: Active Tab (Google)
        self.active_tab = QFrame()
        self.active_tab.setObjectName("ActiveTab")
        self.active_tab.setFixedWidth(160)
        at_layout = QHBoxLayout()
        at_layout.setContentsMargins(8, 2, 8, 2)
        at_layout.setSpacing(6)
        
        tab_icon = QLabel("🌐")
        tab_icon.setStyleSheet("font-size: 12px; background: transparent;")
        at_layout.addWidget(tab_icon)
        
        self.tab_title = QLabel("Google")
        self.tab_title.setObjectName("TabTitle")
        at_layout.addWidget(self.tab_title)
        at_layout.addStretch()
        
        self.active_tab.setLayout(at_layout)
        self.active_tab.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        self.active_tab.mousePressEvent = lambda e: self.navigate_to_google()
        tb_layout.addWidget(self.active_tab)

        # Tab 2: Corporate Webmail
        self.mail_tab = QFrame()
        self.mail_tab.setStyleSheet("background-color: #28292c; border-top-left-radius: 8px; border-top-right-radius: 8px; padding: 4px 10px;")
        self.mail_tab.setFixedWidth(150)
        self.mail_tab.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        mt_layout = QHBoxLayout()
        mt_layout.setContentsMargins(8, 2, 8, 2)
        mt_layout.setSpacing(6)
        m_icon = QLabel("📧")
        m_icon.setStyleSheet("font-size: 12px; background: transparent;")
        mt_layout.addWidget(m_icon)
        m_title = QLabel("Corp Webmail (3)")
        m_title.setStyleSheet("color: #9aa0a6; font-size: 11px;")
        mt_layout.addWidget(m_title)
        mt_layout.addStretch()
        self.mail_tab.setLayout(mt_layout)
        self.mail_tab.mousePressEvent = lambda e: self.navigate_to_mail()
        tb_layout.addWidget(self.mail_tab)

        # Tab 3: Internal Cloud Drive
        self.drive_tab = QFrame()
        self.drive_tab.setStyleSheet("background-color: #28292c; border-top-left-radius: 8px; border-top-right-radius: 8px; padding: 4px 10px;")
        self.drive_tab.setFixedWidth(140)
        self.drive_tab.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
        dt_layout = QHBoxLayout()
        dt_layout.setContentsMargins(8, 2, 8, 2)
        dt_layout.setSpacing(6)
        d_icon = QLabel("📁")
        d_icon.setStyleSheet("font-size: 12px; background: transparent;")
        dt_layout.addWidget(d_icon)
        d_title = QLabel("Cloud Vault")
        d_title.setStyleSheet("color: #9aa0a6; font-size: 11px;")
        dt_layout.addWidget(d_title)
        dt_layout.addStretch()
        self.drive_tab.setLayout(dt_layout)
        self.drive_tab.mousePressEvent = lambda e: self.navigate_to_drive()
        tb_layout.addWidget(self.drive_tab)

        # Add Tab button (+)
        self.new_tab_btn = QPushButton("+")
        self.new_tab_btn.setObjectName("NewTabBtn")
        self.new_tab_btn.setToolTip("New tab")
        self.new_tab_btn.setStyleSheet("background: transparent; color: #9aa0a6; border: none; font-size: 16px; font-weight: bold; width: 26px; height: 26px; border-radius: 13px;")
        self.new_tab_btn.clicked.connect(self.on_new_tab_clicked)
        tb_layout.addWidget(self.new_tab_btn)

        tb_layout.addStretch()

        # Window Controls (Min, Max, Close)
        min_btn = QPushButton("─")
        min_btn.setObjectName("WindowControlBtn")
        min_btn.clicked.connect(self.hide)
        tb_layout.addWidget(min_btn)

        self.max_btn = QPushButton("□")
        self.max_btn.setObjectName("WindowControlBtn")
        self.max_btn.clicked.connect(self.toggle_maximize)
        tb_layout.addWidget(self.max_btn)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("CloseBtn")
        close_btn.setStyleSheet("background: transparent; color: #9aa0a6; border: none; font-size: 11px; width: 34px; height: 26px;")
        close_btn.clicked.connect(self.hide)
        tb_layout.addWidget(close_btn)

        tab_bar.setLayout(tb_layout)
        layout.addWidget(tab_bar)

        # ---------------- 2. Navigation Row & Omnibox ----------------
        nav_row = QFrame()
        nav_row.setObjectName("NavRow")
        nav_row.setFixedHeight(42)
        nr_layout = QHBoxLayout()
        nr_layout.setContentsMargins(8, 5, 8, 5)
        nr_layout.setSpacing(6)

        back_btn = QPushButton("←")
        back_btn.setObjectName("NavBtn")
        back_btn.clicked.connect(self.go_back)
        nr_layout.addWidget(back_btn)

        fwd_btn = QPushButton("→")
        fwd_btn.setObjectName("NavBtn")
        fwd_btn.clicked.connect(self.go_forward)
        nr_layout.addWidget(fwd_btn)

        refresh_btn = QPushButton("⟳")
        refresh_btn.setObjectName("NavBtn")
        refresh_btn.clicked.connect(self.reload_page)
        nr_layout.addWidget(refresh_btn)

        # Omnibox
        self.omnibox = QLineEdit()
        self.omnibox.setObjectName("Omnibox")
        self.omnibox.setText("https://www.google.com")
        self.omnibox.returnPressed.connect(self.on_omnibox_enter)
        nr_layout.addWidget(self.omnibox, 1)

        # Internet mode indicator badge
        self.internet_badge = QPushButton("🌐 Real Web: ON" if self.internet_enabled else "🛡️ Isolated Mode")
        self.internet_badge.setObjectName("InternetBadge")
        badge_bg = "#2ed573" if self.internet_enabled else "#383838"
        self.internet_badge.setStyleSheet(f"background-color: {badge_bg}; color: #ffffff; border-radius: 12px; font-size: 10px; font-weight: 600; padding: 4px 8px; border: none;")
        self.internet_badge.setToolTip("Click to toggle Decoy Browser internet connectivity mode")
        self.internet_badge.clicked.connect(self.toggle_internet_mode)
        nr_layout.addWidget(self.internet_badge)

        avatar_lbl = QLabel("👤")
        avatar_lbl.setStyleSheet("font-size: 14px; padding: 0 4px;")
        nr_layout.addWidget(avatar_lbl)

        menu_lbl = QLabel("⋮")
        menu_lbl.setStyleSheet("color: #9aa0a6; font-size: 18px; font-weight: bold; padding: 0 4px;")
        nr_layout.addWidget(menu_lbl)

        nav_row.setLayout(nr_layout)
        layout.addWidget(nav_row)

        # ---------------- 3. Chrome Bookmarks Bar (TASK-6) ----------------
        bookmarks_bar = QFrame()
        bookmarks_bar.setObjectName("BookmarksBar")
        bookmarks_bar.setFixedHeight(28)
        bm_layout = QHBoxLayout()
        bm_layout.setContentsMargins(8, 0, 8, 0)
        bm_layout.setSpacing(4)

        # Bookmarks links
        bm_bank = QPushButton("🏦 Corporate NetBanking")
        bm_bank.setObjectName("BookmarkBtn")
        bm_bank.clicked.connect(self.navigate_to_banking)
        bm_layout.addWidget(bm_bank)

        bm_aws = QPushButton("☁️ AWS Console")
        bm_aws.setObjectName("BookmarkBtn")
        bm_aws.clicked.connect(self.navigate_to_aws)
        bm_layout.addWidget(bm_aws)

        bm_git = QPushButton("🐙 GitHub Enterprise")
        bm_git.setObjectName("BookmarkBtn")
        bm_git.clicked.connect(self.navigate_to_github)
        bm_layout.addWidget(bm_git)

        bm_mail = QPushButton("📧 Webmail")
        bm_mail.setObjectName("BookmarkBtn")
        bm_mail.clicked.connect(self.navigate_to_mail)
        bm_layout.addWidget(bm_mail)

        bm_vault = QPushButton("📁 Cloud Vault")
        bm_vault.setObjectName("BookmarkBtn")
        bm_vault.clicked.connect(self.navigate_to_drive)
        bm_layout.addWidget(bm_vault)

        bm_layout.addStretch()
        bookmarks_bar.setLayout(bm_layout)
        layout.addWidget(bookmarks_bar)

        # ---------------- 4. Stacked Web Pages Area ----------------
        self.pages_stack = QStackedWidget()
        self.pages_stack.setObjectName("PageArea")

        # Page 0: Google Search Homepage
        self.google_page = self.create_google_page()
        self.pages_stack.addWidget(self.google_page)

        # Page 1: Google Search Results Page
        self.results_page = self.create_results_page()
        self.pages_stack.addWidget(self.results_page)

        # Page 2: Corporate Webmail
        self.mail_page = self.create_mail_page()
        self.pages_stack.addWidget(self.mail_page)

        # Page 3: Corporate Cloud Drive
        self.drive_page = self.create_drive_page()
        self.pages_stack.addWidget(self.drive_page)

        # Page 4: Generic Sandbox URL Gateway
        self.generic_page = self.create_generic_page()
        self.pages_stack.addWidget(self.generic_page)

        # Page 5: Corporate NetBanking Portal (TASK-6)
        self.banking_page = self.create_banking_page()
        self.pages_stack.addWidget(self.banking_page)

        # Page 6: AWS Management Console (TASK-6)
        self.aws_page = self.create_aws_page()
        self.pages_stack.addWidget(self.aws_page)

        # Page 7: Internal GitHub Enterprise (TASK-6)
        self.github_page = self.create_github_page()
        self.pages_stack.addWidget(self.github_page)

        # Page 8: Isolated Real Internet Browser
        self.real_browser_page = self.create_real_browser_page()
        self.pages_stack.addWidget(self.real_browser_page)

        layout.addWidget(self.pages_stack, 1)
        self.setLayout(layout)

    # ---------------- PAGE BUILDERS ----------------

    def create_google_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #202124;")
        p_layout = QVBoxLayout()
        p_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        p_layout.setSpacing(20)

        logo = QLabel("<span style='color:#4285f4'>G</span><span style='color:#ea4335'>o</span><span style='color:#fbbc05'>o</span><span style='color:#4285f4'>g</span><span style='color:#34a853'>l</span><span style='color:#ea4335'>e</span>")
        logo.setStyleSheet("font-size: 56px; font-weight: bold; font-family: 'Product Sans', Arial, sans-serif;")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        p_layout.addWidget(logo)

        search_box = QFrame()
        search_box.setFixedSize(540, 44)
        search_box.setStyleSheet("background-color: #303134; border: 1px solid #5f6368; border-radius: 22px; padding: 2px 14px;")
        sb_layout = QHBoxLayout()
        sb_layout.setContentsMargins(8, 0, 8, 0)

        s_icon = QLabel("🔍")
        s_icon.setStyleSheet("color: #9aa0a6; font-size: 13px; background: transparent;")
        sb_layout.addWidget(s_icon)

        self.google_search_input = QLineEdit()
        self.google_search_input.setStyleSheet("background: transparent; border: none; color: #ffffff; font-size: 13px;")
        self.google_search_input.setPlaceholderText("Search Google or type a URL")
        self.google_search_input.returnPressed.connect(self.execute_google_search)
        sb_layout.addWidget(self.google_search_input, 1)

        mic_icon = QLabel("🎤")
        mic_icon.setStyleSheet("font-size: 14px; background: transparent;")
        sb_layout.addWidget(mic_icon)

        search_box.setLayout(sb_layout)
        p_layout.addWidget(search_box, alignment=Qt.AlignmentFlag.AlignCenter)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)

        gs_btn = QPushButton("Google Search")
        gs_btn.setStyleSheet("background-color: #303134; color: #e8eaed; border: none; border-radius: 4px; padding: 8px 16px; font-size: 12px;")
        gs_btn.clicked.connect(self.execute_google_search)
        btn_row.addWidget(gs_btn)

        lucky_btn = QPushButton("I'm Feeling Lucky")
        lucky_btn.setStyleSheet("background-color: #303134; color: #e8eaed; border: none; border-radius: 4px; padding: 8px 16px; font-size: 12px;")
        lucky_btn.clicked.connect(self.execute_google_search)
        btn_row.addWidget(lucky_btn)

        p_layout.addLayout(btn_row)
        page.setLayout(p_layout)
        return page

    def create_results_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #202124;")
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 20, 30, 20)
        layout.setSpacing(14)

        self.results_header = QLabel("Results for: ...")
        self.results_header.setStyleSheet("color: #9aa0a6; font-size: 12px;")
        layout.addWidget(self.results_header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")

        self.results_container = QWidget()
        self.results_layout = QVBoxLayout()
        self.results_layout.setSpacing(18)
        self.results_container.setLayout(self.results_layout)
        scroll.setWidget(self.results_container)

        layout.addWidget(scroll, 1)
        page.setLayout(layout)
        return page

    def create_banking_page(self):
        """Page 5: Decoy Corporate NetBanking Portal (TASK-6 Credential Trap)"""
        page = QFrame()
        page.setStyleSheet("background-color: #0b1329;")
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setContentsMargins(40, 20, 40, 20)

        # Bank Card Container
        bank_card = QFrame()
        bank_card.setFixedSize(480, 400)
        bank_card.setStyleSheet("""
            QFrame {
                background-color: #111e38;
                border: 1px solid #1e3a8a;
                border-radius: 12px;
                padding: 24px;
            }
        """)
        c_layout = QVBoxLayout(bank_card)
        c_layout.setSpacing(12)

        # Branding
        hdr_layout = QHBoxLayout()
        bank_logo = QLabel("🏦")
        bank_logo.setStyleSheet("font-size: 30px; border: none;")
        hdr_layout.addWidget(bank_logo)

        brand_text = QVBoxLayout()
        b_title = QLabel("CORPSEC COMMERCIAL BANKING")
        b_title.setStyleSheet("color: #60a5fa; font-weight: bold; font-size: 15px; border: none;")
        b_sub = QLabel("Treasury Disbursement & Corporate Wire Gateway")
        b_sub.setStyleSheet("color: #94a3b8; font-size: 10px; border: none;")
        brand_text.addWidget(b_title)
        brand_text.addWidget(b_sub)
        hdr_layout.addLayout(brand_text)
        hdr_layout.addStretch()
        c_layout.addLayout(hdr_layout)

        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("color: #1e3a8a;")
        c_layout.addWidget(div)

        # Form Inputs
        u_lbl = QLabel("Corporate Customer ID / Username:")
        u_lbl.setStyleSheet("color: #cbd5e1; font-size: 11px; border: none;")
        c_layout.addWidget(u_lbl)

        self.bank_user_input = QLineEdit()
        self.bank_user_input.setPlaceholderText("e.g. CORP_TREASURY_ADMIN")
        self.bank_user_input.setText("CORP_TREASURY_ADMIN")
        self.bank_user_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        c_layout.addWidget(self.bank_user_input)

        p_lbl = QLabel("Master Security Password:")
        p_lbl.setStyleSheet("color: #cbd5e1; font-size: 11px; border: none;")
        c_layout.addWidget(p_lbl)

        self.bank_pass_input = QLineEdit()
        self.bank_pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.bank_pass_input.setPlaceholderText("Enter confidential password")
        self.bank_pass_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        c_layout.addWidget(self.bank_pass_input)

        t_lbl = QLabel("Hardware RSA Token / 2FA Code:")
        t_lbl.setStyleSheet("color: #cbd5e1; font-size: 11px; border: none;")
        c_layout.addWidget(t_lbl)

        self.bank_token_input = QLineEdit()
        self.bank_token_input.setPlaceholderText("6-digit authenticator code")
        self.bank_token_input.setStyleSheet("""
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12px;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        c_layout.addWidget(self.bank_token_input)

        # Submit button
        sign_in_btn = QPushButton("Authorize Secure Sign In")
        sign_in_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #2563eb, #1d4ed8);
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 6px;
                padding: 10px;
                font-size: 12px;
                margin-top: 6px;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        sign_in_btn.clicked.connect(self.on_bank_login_submitted)
        c_layout.addWidget(sign_in_btn)

        self.bank_status_lbl = QLabel("")
        self.bank_status_lbl.setStyleSheet("color: #ef4444; font-size: 10px; border: none;")
        self.bank_status_lbl.setWordWrap(True)
        c_layout.addWidget(self.bank_status_lbl)

        layout.addWidget(bank_card)
        page.setLayout(layout)
        return page

    def create_aws_page(self):
        """Page 6: Decoy AWS Management Console (TASK-6 Honey-Tokens)"""
        page = QFrame()
        page.setStyleSheet("background-color: #0f172a;")
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(12)

        # AWS Top Banner
        aws_top = QFrame()
        aws_top.setStyleSheet("background-color: #1e293b; border-radius: 6px; padding: 10px 16px;")
        at_layout = QHBoxLayout(aws_top)
        at_layout.setContentsMargins(0, 0, 0, 0)
        
        aws_logo = QLabel("☁️ <b>AWS Management Console</b>")
        aws_logo.setStyleSheet("color: #f97316; font-size: 14px;")
        at_layout.addWidget(aws_logo)

        region_lbl = QLabel("us-east-1 (N. Virginia) | Account: <b>Root Admin (4892-0194-8831)</b>")
        region_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        at_layout.addStretch()
        at_layout.addWidget(region_lbl)
        layout.addWidget(aws_top)

        # Main AWS Grid
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")

        aws_content = QWidget()
        ac_layout = QVBoxLayout(aws_content)
        ac_layout.setSpacing(14)

        # Honey-Token Card: IAM Root Access Keys
        key_card = QFrame()
        key_card.setStyleSheet("background-color: #1e293b; border: 1px solid #dc2626; border-radius: 8px; padding: 14px;")
        kc_layout = QVBoxLayout(key_card)
        kc_layout.setSpacing(6)

        k_title = QLabel("🚨 <b>Active IAM Root Access Credentials</b> (Decoy Honey-Token)")
        k_title.setStyleSheet("color: #ef4444; font-size: 13px;")
        kc_layout.addWidget(k_title)

        k_desc = QLabel("Root API access keys have full unrestricted administrative privileges across all infrastructure:")
        k_desc.setStyleSheet("color: #cbd5e1; font-size: 11px;")
        kc_layout.addWidget(k_desc)

        keys_box = QFrame()
        keys_box.setStyleSheet("background-color: #090d16; border-radius: 4px; padding: 8px 12px;")
        kb_layout = QVBoxLayout(keys_box)
        kb_layout.setSpacing(4)
        
        self.aws_access_key = QLabel("AWS_ACCESS_KEY_ID: <b style='color:#38bdf8;'>AKIA5HONEYPOT7X92Q0</b>")
        self.aws_access_key.setStyleSheet("font-family: 'Consolas', monospace; font-size: 11px; color: #f1f5f9;")
        kb_layout.addWidget(self.aws_access_key)

        self.aws_secret_key = QLabel("AWS_SECRET_ACCESS_KEY: <b style='color:#38bdf8;'>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</b>")
        self.aws_secret_key.setStyleSheet("font-family: 'Consolas', monospace; font-size: 11px; color: #f1f5f9;")
        kb_layout.addWidget(self.aws_secret_key)
        kc_layout.addWidget(keys_box)

        copy_btn = QPushButton("📋 Extract & Copy AWS Root Credentials")
        copy_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc2626;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 11px;
                align-self: flex-start;
            }
            QPushButton:hover { background-color: #b91c1c; }
        """)
        copy_btn.clicked.connect(self.on_aws_keys_extracted)
        kc_layout.addWidget(copy_btn)
        ac_layout.addWidget(key_card)

        # S3 Buckets Table
        s3_card = QFrame()
        s3_card.setStyleSheet("background-color: #1e293b; border-radius: 8px; padding: 14px;")
        s3_layout = QVBoxLayout(s3_card)
        s3_layout.setSpacing(8)

        s3_title = QLabel("🪣 <b>Amazon S3 Cloud Storage Buckets (3)</b>")
        s3_title.setStyleSheet("color: #f1f5f9; font-size: 13px;")
        s3_layout.addWidget(s3_title)

        buckets = [
            ("🪣 corp-finance-q3-payroll-backups", "2.4 GB", "US East (us-east-1)", "Modified 4 hours ago"),
            ("🪣 prod-db-credentials-vault", "140 MB", "US East (us-east-1)", "Modified Yesterday"),
            ("🪣 customer-kyc-pii-documents", "850 MB", "US West (us-west-2)", "Modified Oct 2026")
        ]

        for b_name, b_sz, b_reg, b_mod in buckets:
            b_row = QFrame()
            b_row.setStyleSheet("background-color: #0f172a; border-radius: 4px; padding: 8px 10px;")
            b_layout = QHBoxLayout(b_row)
            b_layout.setContentsMargins(4, 4, 4, 4)

            lbl = QLabel(b_name)
            lbl.setStyleSheet("color: #38bdf8; font-size: 12px; font-weight: 500;")
            b_layout.addWidget(lbl, 1)

            sz_lbl = QLabel(b_sz)
            sz_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
            b_layout.addWidget(sz_lbl)

            reg_lbl = QLabel(b_reg)
            reg_lbl.setStyleSheet("color: #64748b; font-size: 11px;")
            b_layout.addWidget(reg_lbl)

            b_row.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            b_row.mousePressEvent = lambda e, name=b_name: self.on_s3_bucket_clicked(name)
            s3_layout.addWidget(b_row)

        ac_layout.addWidget(s3_card)
        scroll.setWidget(aws_content)
        layout.addWidget(scroll, 1)

        page.setLayout(layout)
        return page

    def create_github_page(self):
        """Page 7: Decoy Internal GitHub Enterprise Portal (TASK-6 Honey-Tokens)"""
        page = QFrame()
        page.setStyleSheet("background-color: #0d1117;")
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(12)

        # GitHub Header
        gh_top = QFrame()
        gh_top.setStyleSheet("background-color: #161b22; border-bottom: 1px solid #30363d; padding: 8px 14px;")
        gt_layout = QHBoxLayout(gh_top)
        gt_layout.setContentsMargins(0, 0, 0, 0)
        
        gh_logo = QLabel("🐙 <b>GitHub Enterprise</b> | internal-engineering")
        gh_logo.setStyleSheet("color: #f0f6fc; font-size: 13px;")
        gt_layout.addWidget(gh_logo)
        gt_layout.addStretch()

        user_badge = QLabel("Signed in as <b>lead-developer</b>")
        user_badge.setStyleSheet("color: #8b949e; font-size: 11px;")
        gt_layout.addWidget(user_badge)
        layout.addWidget(gh_top)

        # Repositories & Honey-Token File Viewer
        gh_split = QHBoxLayout()
        gh_split.setSpacing(12)

        # Left: Repo list
        repo_panel = QFrame()
        repo_panel.setFixedWidth(280)
        repo_panel.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 10px;")
        rp_layout = QVBoxLayout(repo_panel)
        rp_layout.setSpacing(8)

        rp_title = QLabel("Repositories (3)")
        rp_title.setStyleSheet("color: #f0f6fc; font-weight: bold; font-size: 12px;")
        rp_layout.addWidget(rp_title)

        repos = [
            ("🔒 prod-infrastructure-secrets", "Terraform & AWS Vault credentials"),
            ("🔒 payment-gateway-service", "Stripe API & banking webhooks"),
            ("🔒 database-migration-scripts", "Postgres admin migrations")
        ]

        for r_name, r_desc in repos:
            r_card = QFrame()
            r_card.setStyleSheet("background-color: #21262d; border-radius: 4px; padding: 8px;")
            rc_layout = QVBoxLayout(r_card)
            rc_layout.setSpacing(2)

            rl = QLabel(r_name)
            rl.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 11px;")
            rc_layout.addWidget(rl)

            rd = QLabel(r_desc)
            rd.setStyleSheet("color: #8b949e; font-size: 10px;")
            rc_layout.addWidget(rd)

            r_card.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            r_card.mousePressEvent = lambda e, rn=r_name: self.on_repo_clicked(rn)
            rp_layout.addWidget(r_card)

        rp_layout.addStretch()
        gh_split.addWidget(repo_panel)

        # Right: Repository File Inspector & Honey-Token display
        self.file_inspector = QFrame()
        self.file_inspector.setStyleSheet("background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px;")
        fi_layout = QVBoxLayout(self.file_inspector)
        fi_layout.setSpacing(8)

        self.gh_repo_header = QLabel("📁 <b>prod-infrastructure-secrets / .env.production</b>")
        self.gh_repo_header.setStyleSheet("color: #f0f6fc; font-size: 13px;")
        fi_layout.addWidget(self.gh_repo_header)

        self.gh_code_view = QTextEdit()
        self.gh_code_view.setReadOnly(True)
        self.gh_code_view.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                color: #79c0ff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 11px;
                border: 1px solid #30363d;
                border-radius: 4px;
                padding: 10px;
            }
        """)
        self.gh_code_view.setText(
            "# ============================================================\n"
            "# HIGH-CONFIDENTIALITY PRODUCTION ENVIRONMENT SECRETS\n"
            "# DO NOT COMMIT TO PUBLIC REPOSITORIES\n"
            "# ============================================================\n\n"
            "ENVIRONMENT=production\n"
            "DATABASE_URL=postgres://dba_master:P@ssw0rd_Vault_2026@10.0.1.55:5432/corp_prod\n"
            "DB_ENCRYPTION_KEY=aes256_kdf_993821049281038291048291\n\n"
            "# CLUSTER IAM INTEGRATION\n"
            "AWS_ACCESS_KEY_ID=AKIA_HONEY_PROD_9921\n"
            "AWS_SECRET_ACCESS_KEY=c3VwZXJfc2VjcmV0X2tleV9jb3JwX2ludGVybmFs\n"
            "AWS_S3_BUCKET=corp-finance-q3-payroll-backups\n\n"
            "# THIRD-PARTY PAYMENT API KEYS\n"
            "STRIPE_LIVE_SECRET_KEY=sk_live_51HoneyPotTrappedKey884\n"
            "JWT_SIGNING_SECRET=corp_internal_jwt_secret_token_prod\n"
        )
        fi_layout.addWidget(self.gh_code_view, 1)

        copy_env_btn = QPushButton("📋 Copy Production Environment Secrets")
        copy_env_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 4px;
                padding: 6px 14px;
                font-size: 11px;
                align-self: flex-start;
            }
            QPushButton:hover { background-color: #2ea043; }
        """)
        copy_env_btn.clicked.connect(self.on_github_secrets_extracted)
        fi_layout.addWidget(copy_env_btn)

        gh_split.addWidget(self.file_inspector, 1)
        layout.addLayout(gh_split, 1)

        page.setLayout(layout)
        return page

    def create_mail_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #1a1a1a;")
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        hdr = QLabel("📧 Corporate Webmail - User: administrator@internal.corp")
        hdr.setStyleSheet("color: #8ab4f8; font-size: 14px; font-weight: bold; border-bottom: 1px solid #333333; padding-bottom: 8px;")
        layout.addWidget(hdr)

        emails = [
            ("🔐 [CONFIDENTIAL] IT Security - Root DB & SSH Credentials Updated", "From: sec-ops@internal.corp", "Attached are the temporary credentials for production cluster. Password format: P@ssw0rd_2026_Secure. Please store in KeePass."),
            ("💼 [FINANCE] Q3 Employee Salary & Bonus Disbursement Ledger", "From: payroll@internal.corp", "Dear Admin, review the linked spreadsheet containing direct bank routing and tax account identifiers for all staff."),
            ("☁️ [INFRASTRUCTURE] AWS Secret Access Keys Migration Notice", "From: cloud-eng@internal.corp", "Migration completed. Secret keys for S3 backups and production IAM roles have been stored in /root/.aws/credentials.")
        ]

        for subj, sender, preview in emails:
            card = QFrame()
            card.setStyleSheet("background-color: #242424; border: 1px solid #383838; border-radius: 6px; padding: 10px;")
            c_layout = QVBoxLayout()
            c_layout.setSpacing(4)
            
            s_lbl = QLabel(subj)
            s_lbl.setStyleSheet("color: #e8eaed; font-size: 12px; font-weight: bold;")
            c_layout.addWidget(s_lbl)
            
            f_lbl = QLabel(sender)
            f_lbl.setStyleSheet("color: #9aa0a6; font-size: 11px;")
            c_layout.addWidget(f_lbl)
            
            p_lbl = QLabel(preview)
            p_lbl.setStyleSheet("color: #cccccc; font-size: 11px;")
            p_lbl.setWordWrap(True)
            c_layout.addWidget(p_lbl)
            
            card.setLayout(c_layout)
            card.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            card.mousePressEvent = lambda e, s=subj: self.on_email_clicked(s)
            layout.addWidget(card)

        layout.addStretch()
        page.setLayout(layout)
        return page

    def create_drive_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #1f1f1f;")
        layout = QVBoxLayout()
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(12)

        hdr = QLabel("📁 Corporate Cloud Vault & Sensitive Storage")
        hdr.setStyleSheet("color: #34a853; font-size: 14px; font-weight: bold; border-bottom: 1px solid #333333; padding-bottom: 8px;")
        layout.addWidget(hdr)

        files = [
            ("📄", "corporate_vpn_credentials.ovpn", "14 KB", "Modified 2 hours ago"),
            ("📊", "employee_ssn_and_bank_details.xlsx", "1.4 MB", "Modified Yesterday"),
            ("🔑", "id_rsa_production_gateway", "3 KB", "Modified Oct 2026"),
            ("💾", "database_dump_users_hashes.sql", "48 MB", "Modified Last Week")
        ]

        for icon, name, sz, mod in files:
            row = QFrame()
            row.setStyleSheet("background-color: #282828; border-radius: 5px; padding: 8px 12px;")
            r_layout = QHBoxLayout()
            r_layout.setSpacing(12)
            
            i_lbl = QLabel(icon)
            i_lbl.setStyleSheet("font-size: 20px;")
            r_layout.addWidget(i_lbl)
            
            n_lbl = QLabel(name)
            n_lbl.setStyleSheet("color: #e8eaed; font-size: 12px; font-weight: 500;")
            r_layout.addWidget(n_lbl, 1)
            
            s_lbl = QLabel(sz)
            s_lbl.setStyleSheet("color: #9aa0a6; font-size: 11px;")
            r_layout.addWidget(s_lbl)
            
            m_lbl = QLabel(mod)
            m_lbl.setStyleSheet("color: #888888; font-size: 11px;")
            r_layout.addWidget(m_lbl)
            
            row.setLayout(r_layout)
            row.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            row.mousePressEvent = lambda e, fn=name: self.on_drive_file_clicked(fn)
            layout.addWidget(row)

        layout.addStretch()
        page.setLayout(layout)
        return page

    def create_generic_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #202124;")
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(14)

        icon = QLabel("🔒")
        icon.setStyleSheet("font-size: 42px;")
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon)

        self.gen_url_lbl = QLabel("Secure Gateway: ...")
        self.gen_url_lbl.setStyleSheet("color: #8ab4f8; font-size: 15px; font-weight: bold;")
        self.gen_url_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.gen_url_lbl)

        desc = QLabel("Internal Sandbox Proxy Connected.<br>Direct internet outbound requests are safely isolated in the honeypot network container.")
        desc.setStyleSheet("color: #9aa0a6; font-size: 12px; text-align: center;")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)

        page.setLayout(layout)
        return page

    def create_real_browser_page(self):
        page = QFrame()
        page.setStyleSheet("background-color: #202124;")
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Status header for real web
        self.real_web_status = QLabel("Isolated Web Engine Active | Sandboxed Profile")
        self.real_web_status.setFixedHeight(22)
        self.real_web_status.setStyleSheet("background-color: #2b2b2b; color: #00d2d3; font-size: 11px; padding-left: 10px; border-bottom: 1px solid #3c3c3c;")
        layout.addWidget(self.real_web_status)

        # HTML / Web renderer
        self.real_web_browser = QTextBrowser()
        self.real_web_browser.setOpenExternalLinks(False)
        self.real_web_browser.anchorClicked.connect(self.on_real_browser_anchor_clicked)
        self.real_web_browser.setStyleSheet("""
            QTextBrowser {
                background-color: #ffffff;
                color: #202124;
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 13px;
                border: none;
                padding: 16px;
            }
        """)
        layout.addWidget(self.real_web_browser, 1)

        page.setLayout(layout)
        return page

    # ---------------- INTERACTION LOGIC & FORENSIC HOOKS ----------------

    def execute_google_search(self):
        query = self.google_search_input.text().strip()
        if not query:
            return
            
        print(f"[DECEPTION CHROME] Intruder executed search query: '{query}'", flush=True)
        self.tracker.record_browser_search(query)

        self.omnibox.setText(f"https://www.google.com/search?q={query.replace(' ', '+')}")
        self.tab_title.setText(f"{query} - Google Search")
        self.results_header.setText(f"About 4,210,000 results for '{query}' (0.34 seconds)")

        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        mock_results = self.generate_mock_search_results(query)
        for title, link, snippet in mock_results:
            card = QFrame()
            card.setStyleSheet("background-color: #28292a; border-radius: 6px; padding: 10px;")
            c_layout = QVBoxLayout()
            c_layout.setSpacing(4)
            
            l_lbl = QLabel(link)
            l_lbl.setStyleSheet("color: #9aa0a6; font-size: 10px;")
            c_layout.addWidget(l_lbl)
            
            t_lbl = QLabel(f"<b>{title}</b>")
            t_lbl.setStyleSheet("color: #8ab4f8; font-size: 13px;")
            c_layout.addWidget(t_lbl)
            
            s_lbl = QLabel(snippet)
            s_lbl.setStyleSheet("color: #bdc1c6; font-size: 11px;")
            s_lbl.setWordWrap(True)
            c_layout.addWidget(s_lbl)
            
            card.setLayout(c_layout)
            card.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
            card.mousePressEvent = lambda e, t=title, l=link: self.on_search_result_clicked(t, l)
            self.results_layout.addWidget(card)

        self.pages_stack.setCurrentIndex(1)

    def generate_mock_search_results(self, query):
        q_lower = query.lower()
        if any(w in q_lower for w in ["password", "credential", "login", "key"]):
            return [
                ("Internal Corporate Password Vault - 1Password Enterprise", "https://vault.internal.corp/login", "Centralized credentials directory for engineering, infrastructure root accounts, and databases."),
                ("Default Passwords for Local Workstations and Routers", "https://github.corp.internal/internal-ops/sec-notes", "Standard baseline passwords used during initial provisioning of Windows systems."),
                ("How to Extract Saved Passwords from Windows Vault", "https://superuser.com/questions/18294", "Step by step command prompt guide using vaultcmd and mimikatz on administrative sessions.")
            ]
        elif any(w in q_lower for w in ["bank", "transfer", "finance", "crypto", "money"]):
            return [
                ("Corporate NetBanking - Commercial Treasury Login", "https://bank.corp.internal/login", "Authorized corporate disbursement portal. Dual authentication required."),
                ("Wire Transfer Authorization Form & Account Numbers", "https://finance.internal.corp/wire-transfers.pdf", "Internal account routing numbers and approval matrix for wire transfers."),
                ("Ledger / Metamask Seed Backup Verification", "https://vault.internal.corp/crypto/seeds", "Encrypted paper backups for operational crypto treasury accounts.")
            ]
        elif any(w in q_lower for w in ["aws", "cloud", "amazon", "s3", "ec2"]):
            return [
                ("AWS Management Console - Sign In", "https://aws.amazon.com/console/signin", "Access S3 storage buckets, EC2 clusters, and IAM production roles."),
                ("AWS Root Access Key Rotation Guide", "https://aws.internal.corp/key-rotation", "Active credentials and root secrets documentation.")
            ]
        else:
            return [
                (f"Guide: How to find {query} on Windows 11", f"https://docs.microsoft.com/en-us/windows/{query}", f"Official documentation and common command line usage patterns for {query}."),
                (f"Internal Documentation - Search Results for '{query}'", "https://confluence.internal.corp/search", f"Found 14 corporate documents and project source files referencing '{query}'."),
                (f"GitHub Repository - Utilities and Tools for {query}", "https://github.corp.internal/corp-tools/repo", f"Public scripts, automation scripts, and utilities matching search term '{query}'.")
            ]

    def on_search_result_clicked(self, title, link):
        self.tracker.record_file_access(f"SearchResult: {title} ({link})", action="CLICK")
        if "bank" in link.lower():
            self.navigate_to_banking()
        elif "aws" in link.lower():
            self.navigate_to_aws()
        elif "github" in link.lower() or "git" in link.lower():
            self.navigate_to_github()
        else:
            self.omnibox.setText(link)
            self.tab_title.setText(title[:20])
            self.gen_url_lbl.setText(f"🔒 Decoy Destination: {title}")
            self.pages_stack.setCurrentIndex(4)

    def on_bank_login_submitted(self):
        """Captures entered credentials in the NetBanking honey-pot form."""
        user = self.bank_user_input.text().strip()
        pwd = self.bank_pass_input.text().strip()
        token = self.bank_token_input.text().strip()

        print(f"[HONEYPOT DECEPTION] Trapped banking login credentials for user '{user}' (Password length: {len(pwd)})", flush=True)
        self.tracker.record_credential_trap(
            service="Corporate NetBanking",
            username=user,
            password_length=len(pwd),
            notes=f"2FA Token submitted: {token[:3]}***" if token else "No token provided"
        )
        self.bank_status_lbl.setText("⚠️ [ERR_AUTH_TIMEOUT] Hardware security token synchronization timeout. An alert has been dispatched to Corporate SecOps.")

    def on_aws_keys_extracted(self):
        """Logs when the intruder attempts to extract or copy the fake AWS root keys."""
        print("[HONEYPOT DECEPTION] Intruder clicked to extract AWS Root Access Keys (Honey-Token AKIA5HONEYPOT7X92Q0)!", flush=True)
        self.tracker.record_file_access(
            "AWS_HONEY_TOKEN: AKIA5HONEYPOT7X92Q0",
            action="CREDENTIAL_EXFILTRATION_ATTEMPT"
        )
        # Copy to clipboard if available
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText("AWS_ACCESS_KEY_ID=AKIA5HONEYPOT7X92Q0\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")

    def on_s3_bucket_clicked(self, bucket_name):
        print(f"[HONEYPOT DECEPTION] Intruder browsed S3 bucket: '{bucket_name}'", flush=True)
        self.tracker.record_file_access(f"AWS S3 Bucket: {bucket_name}", action="S3_BUCKET_ENUMERATE")

    def on_repo_clicked(self, repo_name):
        print(f"[HONEYPOT DECEPTION] Intruder inspected GitHub repository: '{repo_name}'", flush=True)
        self.tracker.record_file_access(f"GitHub: {repo_name}", action="REPO_BROWSE")
        self.gh_repo_header.setText(f"📁 <b>{repo_name} / .env.production</b>")

    def on_github_secrets_extracted(self):
        print("[HONEYPOT DECEPTION] Intruder copied production secrets from GitHub repository .env.production!", flush=True)
        self.tracker.record_file_access(
            "GitHub: prod-infrastructure-secrets/.env.production",
            action="SECRETS_EXFILTRATION_ATTEMPT"
        )
        clipboard = QApplication.clipboard()
        if clipboard:
            clipboard.setText(self.gh_code_view.toPlainText())

    def on_email_clicked(self, subject):
        self.tracker.record_file_access(f"Email: {subject}", action="VIEW")
        print(f"[DECEPTION CHROME] Intruder opened confidential email: '{subject}'", flush=True)

    def on_drive_file_clicked(self, filename):
        self.tracker.record_file_access(f"CloudDrive: {filename}", action="DOWNLOAD_ATTEMPT")
        print(f"[DECEPTION CHROME] Intruder clicked sensitive cloud file: '{filename}'", flush=True)

    def on_omnibox_enter(self):
        raw_url = self.omnibox.text().strip()
        url = raw_url.lower()
        self.tracker.record_url_visit(raw_url)
        print(f"[DECEPTION CHROME] Intruder entered URL: '{raw_url}'", flush=True)
        
        if "bank" in url or "finance" in url:
            self.navigate_to_banking()
        elif "aws" in url or "amazon" in url:
            self.navigate_to_aws()
        elif "github" in url or "git" in url:
            self.navigate_to_github()
        elif "mail" in url:
            self.navigate_to_mail()
        elif "drive" in url or "vault" in url or "cloud" in url:
            self.navigate_to_drive()
        elif "google" in url and "search" not in url:
            self.navigate_to_google()
        else:
            if self.internet_enabled:
                self.navigate_to_real_web(raw_url)
            else:
                self.gen_url_lbl.setText(f"Secure Gateway: {raw_url}")
                self.tab_title.setText(raw_url[:20])
                self.pages_stack.setCurrentIndex(4)
                self.record_history_entry(raw_url, 4)

    def navigate_to_real_web(self, target_url: str):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        self.omnibox.setText(target_url)
        self.tracker.record_event(
            "BROWSER_NAVIGATE_START",
            target_url,
            {"source": "omnibox", "internet_enabled": self.internet_enabled},
            severity="INFO"
        )

        # Check for remote executable / binary payload download attempt
        lower_url = target_url.lower()
        is_payload = any(lower_url.endswith(ext) or ext + "?" in lower_url for ext in [".exe", ".bat", ".dll", ".ps1", ".vbs", ".zip", ".bin"])
        if is_payload:
            # Block execution and safely isolate into data/sandbox/
            parts = target_url.rstrip("/").split("/")
            filename = parts[-1].split("?")[0] if parts else "quarantined_payload.exe"
            if not filename or "." not in filename:
                filename = "quarantined_payload.exe"

            sandbox_path = os.path.join(self.sandbox_dir, filename)
            quarantine_content = (
                f"# ============================================================\n"
                f"# [QUARANTINED BY HONEYPOT DECEPTION BROWSER]\n"
                f"# Captured Threat Vector: Browser Executable Download Attempt\n"
                f"# Source URL            : {target_url}\n"
                f"# Timestamp             : {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"# Action Taken          : File Quarantined in data/sandbox/\n"
                f"# ============================================================\n"
            )
            try:
                with open(sandbox_path, "w", encoding="utf-8") as f:
                    f.write(quarantine_content)
            except Exception:
                pass

            netloc = "c2-server.net"
            try:
                from urllib.parse import urlparse
                netloc = urlparse(target_url).netloc or "c2-server.net"
            except Exception:
                pass

            self.tracker.record_c2_download(target_url, netloc, filename, len(quarantine_content.encode("utf-8")))
            self.real_web_browser.setHtml(
                f"<div style='font-family: Segoe UI, sans-serif; padding: 24px; color: #ffffff; background-color: #1e1e1e;'>"
                f"<h2 style='color: #ff4757;'>⚠️ Download Intercepted & Quarantined</h2>"
                f"<p>The browser intercepted an executable payload download: <b>{filename}</b></p>"
                f"<p style='color: #00d2d3;'>File safely isolated to: <code>data/sandbox/{filename}</code></p>"
                f"<p style='color: #aaaaaa;'>Execution against the host operating system was prevented by honeypot policy.</p>"
                f"</div>"
            )
            self.tab_title.setText(f"Blocked: {filename}")
            self.pages_stack.setCurrentIndex(8)
            self.record_history_entry(target_url, 8)
            return

        # Attempt safe real HTTP fetch
        try:
            import urllib.request
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            )
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                code = resp.getcode()
                content_bytes = resp.read(500000)  # Max 500KB
                encoding = resp.headers.get_content_charset() or "utf-8"
                html_text = content_bytes.decode(encoding, errors="replace")

            title = "Web Page"
            if "<title>" in html_text.lower() and "</title>" in html_text.lower():
                s = html_text.lower().find("<title>") + 7
                e = html_text.lower().find("</title>", s)
                title = html_text[s:e].strip()

            self.real_web_browser.setHtml(html_text)
            self.tab_title.setText(title[:25])
            self.real_web_status.setText(f"Connected: {target_url} (HTTP {code})")
            self.pages_stack.setCurrentIndex(8)
            self.record_history_entry(target_url, 8)
            self.tracker.record_event(
                "BROWSER_NAVIGATE_SUCCESS",
                target_url,
                {"title": title, "status": code},
                severity="INFO"
            )
        except Exception as e:
            from urllib.parse import urlparse
            host_str = urlparse(target_url).netloc or target_url
            error_html = (
                f"<div style='font-family: Segoe UI, sans-serif; padding: 40px; color: #ffffff; background-color: #202124; text-align: center;'>"
                f"<div style='font-size: 54px; margin-bottom: 12px;'>🌐</div>"
                f"<h2 style='color: #e8eaed;'>This site can’t be reached</h2>"
                f"<p style='color: #9aa0a6;'>Check if there is a typo in {host_str}.</p>"
                f"<p style='color: #5f6368; font-size: 11px;'>DNS_PROBE_FINISHED_NXDOMAIN / ERR_NAME_NOT_RESOLVED</p>"
                f"</div>"
            )
            self.real_web_browser.setHtml(error_html)
            self.tab_title.setText(target_url[:20])
            self.real_web_status.setText(f"Navigation Failed: {e}")
            self.pages_stack.setCurrentIndex(8)
            self.record_history_entry(target_url, 8)
            self.tracker.record_event(
                "BROWSER_NAVIGATE_ERROR",
                target_url,
                {"error": str(e)},
                severity="INFO"
            )

    def on_real_browser_anchor_clicked(self, qurl: QUrl):
        link = qurl.toString()
        if link:
            self.omnibox.setText(link)
            self.on_omnibox_enter()

    def record_history_entry(self, url: str, stack_idx: int):
        if not self.history or self.history[self.history_idx] != url:
            self.history = self.history[:self.history_idx + 1]
            self.history.append(url)
            self.history_idx = len(self.history) - 1

    def navigate_to_google(self):
        self.omnibox.setText("https://www.google.com")
        self.tab_title.setText("Google")
        self.pages_stack.setCurrentIndex(0)
        self.record_history_entry("https://www.google.com", 0)

    def navigate_to_banking(self):
        self.tracker.record_url_visit("https://bank.corp.internal/login")
        self.omnibox.setText("https://bank.corp.internal/login")
        self.tab_title.setText("Corporate NetBanking")
        self.pages_stack.setCurrentIndex(5)
        self.record_history_entry("https://bank.corp.internal/login", 5)

    def navigate_to_aws(self):
        self.tracker.record_url_visit("https://aws.amazon.com/console/signin")
        self.omnibox.setText("https://aws.amazon.com/console/signin")
        self.tab_title.setText("AWS Management Console")
        self.pages_stack.setCurrentIndex(6)
        self.record_history_entry("https://aws.amazon.com/console/signin", 6)

    def navigate_to_github(self):
        self.tracker.record_url_visit("https://github.corp.internal")
        self.omnibox.setText("https://github.corp.internal")
        self.tab_title.setText("GitHub Enterprise")
        self.pages_stack.setCurrentIndex(7)
        self.record_history_entry("https://github.corp.internal", 7)

    def navigate_to_mail(self):
        self.tracker.record_url_visit("https://mail.internal.corp")
        self.omnibox.setText("https://mail.internal.corp/inbox")
        self.tab_title.setText("Corp Webmail (3)")
        self.pages_stack.setCurrentIndex(2)
        self.record_history_entry("https://mail.internal.corp/inbox", 2)

    def navigate_to_drive(self):
        self.tracker.record_url_visit("https://vault.internal.corp/drive")
        self.omnibox.setText("https://vault.internal.corp/drive")
        self.tab_title.setText("Cloud Vault")
        self.pages_stack.setCurrentIndex(3)
        self.record_history_entry("https://vault.internal.corp/drive", 3)

    def go_back(self):
        if self.history_idx > 0:
            self.history_idx -= 1
            prev_url = self.history[self.history_idx]
            self.omnibox.setText(prev_url)
            self.on_omnibox_enter()
        else:
            self.navigate_to_google()

    def go_forward(self):
        if self.history_idx < len(self.history) - 1:
            self.history_idx += 1
            next_url = self.history[self.history_idx]
            self.omnibox.setText(next_url)
            self.on_omnibox_enter()

    def reload_page(self):
        cur = self.omnibox.text().strip()
        if cur:
            self.on_omnibox_enter()

    def toggle_internet_mode(self):
        self.internet_enabled = not self.internet_enabled
        badge_bg = "#2ed573" if self.internet_enabled else "#383838"
        self.internet_badge.setText("🌐 Real Web: ON" if self.internet_enabled else "🛡️ Isolated Mode")
        self.internet_badge.setStyleSheet(f"background-color: {badge_bg}; color: #ffffff; border-radius: 12px; font-size: 10px; font-weight: 600; padding: 4px 8px; border: none;")

    def on_new_tab_clicked(self):
        self.navigate_to_google()

    # ---------------- WINDOW DRAGGING & SIZING ----------------

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
                self.setFixedSize(QSize(960, 600))
            self.max_btn.setText("□")
            self.is_maximized = False


if __name__ == "__main__":
    app = QApplication(sys.argv)
    chrome = DecoyChrome()
    chrome.show()
    sys.exit(app.exec())
