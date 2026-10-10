import os
import sys
import time
import copy
import threading
from typing import Optional, List, Dict, Tuple, Any, Callable

class PathUtils:
    """Windows-specific path manipulation and normalization utilities."""

    CANONICAL_SEGMENTS = {
        "users": "Users",
        "dell": "Dell",
        "desktop": "Desktop",
        "documents": "Documents",
        "downloads": "Downloads",
        "pictures": "Pictures",
        "videos": "Videos",
        "music": "Music",
        "appdata": "AppData",
        "roaming": "Roaming",
        "local": "Local",
        "locallow": "LocalLow",
        "windows": "Windows",
        "system32": "System32",
        "syswow64": "SysWOW64",
        "drivers": "drivers",
        "etc": "etc",
        "program files": "Program Files",
        "program files (x86)": "Program Files (x86)",
        "programdata": "ProgramData",
        "public": "Public",
        "temp": "Temp",
        "$recycle.bin": "$Recycle.Bin",
        "clg": "clg",
        "behavioral-drift-security": "Behavioral-Drift-Security",
    }

    @staticmethod
    def normalize(path: str) -> str:
        r"""
        Normalizes a path into standard Windows format:
        - Converts forward slashes to backslashes
        - Resolves relative components (. and ..)
        - Normalizes drive letters to uppercase (e.g. C:\)
        - Canonicalizes casing of well-known Windows directory names
        - Strips trailing backslashes except for drive root (e.g. C:\)
        - Handles relative paths assuming root if not rooted
        """
        if not path:
            return "C:\\"

        # Replace forward slashes with backslashes
        p = str(path).strip().replace("/", "\\")

        # Handle drive letter
        drive = "C:"
        rest = p
        if len(p) >= 2 and p[1] == ":":
            drive = p[:2].upper()
            rest = p[2:]
        elif p.startswith("\\"):
            drive = "C:"
            rest = p
        else:
            drive = "C:"
            rest = "\\" + p

        # Split segments and resolve . and ..
        raw_segments = rest.split("\\")
        resolved = []
        for seg in raw_segments:
            seg = seg.strip()
            if not seg or seg == ".":
                continue
            if seg == "..":
                if resolved:
                    resolved.pop()
            else:
                canon = PathUtils.CANONICAL_SEGMENTS.get(seg.lower(), seg)
                resolved.append(canon)

        if not resolved:
            return f"{drive}\\"
        return f"{drive}\\" + "\\".join(resolved)

    @staticmethod
    def path_equal(p1: str, p2: str) -> bool:
        """Case-insensitive Windows path comparison."""
        return PathUtils.normalize(p1).lower() == PathUtils.normalize(p2).lower()

    @staticmethod
    def split_path(path: str) -> Tuple[str, str]:
        """
        Splits a normalized path into (parent_directory, entry_name).
        For drive root 'C:\\', returns ('C:\\', '').
        """
        norm = PathUtils.normalize(path)
        if len(norm) <= 3 and norm.endswith(":\\"):
            return norm, ""
        
        parts = norm.split("\\")
        name = parts[-1]
        parent = "\\".join(parts[:-1])
        if len(parent) == 2 and parent.endswith(":"):
            parent += "\\"
        return parent, name

    @staticmethod
    def join(base: str, *parts: str) -> str:
        """Joins segments onto a base path and normalizes."""
        cur = base
        for p in parts:
            if not p:
                continue
            p_clean = str(p).replace("/", "\\")
            if len(p_clean) >= 2 and p_clean[1] == ":":
                cur = p_clean
            elif p_clean.startswith("\\"):
                drive = cur[:2] if len(cur) >= 2 and cur[1] == ":" else "C:"
                cur = f"{drive}{p_clean}"
            else:
                if not cur.endswith("\\"):
                    cur += "\\"
                cur += p_clean
        return PathUtils.normalize(cur)

    @staticmethod
    def is_descendant(parent: str, child: str) -> bool:
        """Returns True if child path is logically inside parent directory."""
        norm_parent = PathUtils.normalize(parent).lower()
        norm_child = PathUtils.normalize(child).lower()
        if not norm_parent.endswith("\\"):
            norm_parent += "\\"
        return norm_child.startswith(norm_parent) and norm_child != norm_parent


class VirtualNode:
    """Base class for virtual filesystem nodes (files and directories)."""
    def __init__(
        self,
        name: str,
        path: str,
        is_dir: bool = False,
        size: int = 0,
        attributes: Optional[Dict[str, bool]] = None,
        created_time: Optional[float] = None,
        modified_time: Optional[float] = None,
        icon: str = "📄"
    ):
        self.name = name
        self.path = PathUtils.normalize(path)
        self.is_dir = is_dir
        self.size = size
        self.attributes = attributes or {"hidden": False, "readonly": False, "system": False}
        now = time.time()
        self.created_time = created_time if created_time is not None else now
        self.modified_time = modified_time if modified_time is not None else now
        self.icon = icon

    @property
    def extension(self) -> str:
        if self.is_dir or "." not in self.name:
            return ""
        return "." + self.name.split(".")[-1].lower()

    @property
    def type_description(self) -> str:
        if self.is_dir:
            return "File folder"
        ext = self.extension
        type_map = {
            ".txt": "Text Document",
            ".log": "Text Document",
            ".ini": "Configuration Settings",
            ".json": "JSON File",
            ".py": "Python Source File",
            ".exe": "Application",
            ".bat": "Windows Batch File",
            ".ps1": "Windows PowerShell Script",
            ".pdf": "PDF Document",
            ".docx": "Microsoft Word Document",
            ".xlsx": "Microsoft Excel Worksheet",
            ".pptx": "Microsoft PowerPoint Presentation",
            ".csv": "Microsoft Excel Comma Separated Values File",
            ".mp4": "MP4 Video",
            ".png": "PNG Image",
            ".jpg": "JPEG Image",
            ".zip": "Compressed (zipped) Folder",
            ".sql": "SQL Script",
            ".env": "Environment File",
        }
        return type_map.get(ext, f"{ext[1:].upper()} File" if ext else "File")

    def format_modified_time(self) -> str:
        return time.strftime("%d-%m-%Y %I:%M %p", time.localtime(self.modified_time))

    def format_size(self) -> str:
        if self.is_dir:
            return ""
        if self.size < 1024:
            return f"{self.size} B"
        elif self.size < 1024 * 1024:
            return f"{max(1, self.size // 1024)} KB"
        else:
            return f"{round(self.size / (1024 * 1024), 1)} MB"


class VirtualFile(VirtualNode):
    """Virtual file containing synthetic text, code, or binary payload content."""
    def __init__(
        self,
        name: str,
        path: str,
        content: str = "",
        size: Optional[int] = None,
        attributes: Optional[Dict[str, bool]] = None,
        created_time: Optional[float] = None,
        modified_time: Optional[float] = None,
        icon: str = "📄"
    ):
        super().__init__(
            name=name,
            path=path,
            is_dir=False,
            size=size if size is not None else len(content.encode("utf-8")),
            attributes=attributes,
            created_time=created_time,
            modified_time=modified_time,
            icon=icon
        )
        self.content = content
        self.encoding = "utf-8"

    def set_content(self, content: str):
        self.content = content
        self.size = len(content.encode(self.encoding, errors="replace"))
        self.modified_time = time.time()


class VirtualDirectory(VirtualNode):
    """Virtual directory containing child files and subdirectories."""
    def __init__(
        self,
        name: str,
        path: str,
        attributes: Optional[Dict[str, bool]] = None,
        created_time: Optional[float] = None,
        modified_time: Optional[float] = None,
        icon: str = "📁"
    ):
        super().__init__(
            name=name,
            path=path,
            is_dir=True,
            size=0,
            attributes=attributes,
            created_time=created_time,
            modified_time=modified_time,
            icon=icon
        )
        # Mapping lowercase child name -> VirtualNode
        self.children: Dict[str, VirtualNode] = {}

    def add_child(self, node: VirtualNode):
        self.children[node.name.lower()] = node
        self.modified_time = time.time()

    def remove_child(self, name: str) -> Optional[VirtualNode]:
        node = self.children.pop(name.lower(), None)
        if node:
            self.modified_time = time.time()
        return node

    def get_child(self, name: str) -> Optional[VirtualNode]:
        return self.children.get(name.lower())

    def list_children(self, include_hidden: bool = True) -> List[VirtualNode]:
        nodes = list(self.children.values())
        if not include_hidden:
            nodes = [n for n in nodes if not n.attributes.get("hidden", False)]
        # Sort directories first, then alphabetically
        nodes.sort(key=lambda n: (not n.is_dir, n.name.lower()))
        return nodes


class VirtualRecycleBinEntry:
    """Represents a deleted item preserved in the virtual recycle bin."""
    def __init__(self, original_path: str, node: VirtualNode):
        self.entry_id = f"DEL_{int(time.time() * 1000)}_{node.name}"
        self.original_path = PathUtils.normalize(original_path)
        self.deleted_time = time.time()
        self.node = node


class VirtualClipboard:
    """Virtual clipboard for decoy file copying, cutting, and pasting."""
    def __init__(self):
        self.mode: Optional[str] = None  # 'copy' or 'cut'
        self.paths: List[str] = []

    def copy(self, paths: List[str]):
        self.mode = "copy"
        self.paths = [PathUtils.normalize(p) for p in paths]

    def cut(self, paths: List[str]):
        self.mode = "cut"
        self.paths = [PathUtils.normalize(p) for p in paths]

    def has_items(self) -> bool:
        return bool(self.mode and self.paths)

    def get_items(self) -> Tuple[Optional[str], List[str]]:
        return self.mode, list(self.paths)

    def clear(self):
        self.mode = None
        self.paths = []


class VirtualFileSystem:
    """
    Centralized, Thread-Safe Virtual Windows Filesystem.
    All decoy applications (DecoyExplorer, HoneyShell, DecoyNotepad, Desktop)
    interact with this single consistent state.
    """
    _instance = None
    _lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> "VirtualFileSystem":
        with cls._lock:
            if cls._instance is None:
                cls._instance = VirtualFileSystem()
            return cls._instance

    def __init__(self):
        self._lock = threading.RLock()
        self.clipboard = VirtualClipboard()
        self.recycle_bin: Dict[str, VirtualRecycleBinEntry] = {}
        self.listeners: List[Callable[[str, str], None]] = []

        # Root directory
        self.root = VirtualDirectory(name="C:", path="C:\\", icon="💾")
        self._seed_filesystem()

    def register_change_listener(self, callback: Callable[[str, str], None]):
        """Registers a callback(action, path) invoked whenever VFS changes."""
        with self._lock:
            if callback not in self.listeners:
                self.listeners.append(callback)

    def unregister_change_listener(self, callback: Callable[[str, str], None]):
        with self._lock:
            if callback in self.listeners:
                self.listeners.remove(callback)

    def _notify_change(self, action: str, path: str):
        for listener in list(self.listeners):
            try:
                listener(action, path)
            except Exception:
                pass

    def _seed_filesystem(self):
        """Populates authentic Windows 11 directory hierarchy and realistic honeytokens."""
        # Standard system & user folders
        standard_dirs = [
            "C:\\Windows",
            "C:\\Windows\\System32",
            "C:\\Windows\\System32\\drivers",
            "C:\\Windows\\System32\\config",
            "C:\\Program Files",
            "C:\\Program Files\\Google",
            "C:\\Program Files\\Google\\Chrome",
            "C:\\Program Files\\PowerShell",
            "C:\\Program Files (x86)",
            "C:\\ProgramData",
            "C:\\Users",
            "C:\\Users\\Public",
            "C:\\Users\\Administrator",
            "C:\\Users\\Dell",
            "C:\\Users\\Dell\\Desktop",
            "C:\\Users\\Dell\\Documents",
            "C:\\Users\\Dell\\Downloads",
            "C:\\Users\\Dell\\Pictures",
            "C:\\Users\\Dell\\Videos",
            "C:\\Users\\Dell\\Music",
            "C:\\Users\\Dell\\AppData",
            "C:\\Users\\Dell\\AppData\\Local",
            "C:\\Users\\Dell\\AppData\\Roaming",
            "C:\\Users\\Dell\\Desktop\\clg",
            "C:\\Users\\Dell\\Desktop\\clg\\documents",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data\\forensics",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data\\raw",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data\\sandbox",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\data\\sessions",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\dashboard",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\deception",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\ml_engine",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\models",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\scripts",
            "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\security",
            "C:\\Users\\Dell\\Desktop\\Personal_Vault",
            "C:\\Users\\Dell\\Desktop\\Financial_Records_2026",
            "C:\\$Recycle.Bin",
        ]

        for d in standard_dirs:
            self._mkdir_internal(d)

        # Mark hidden folders
        appdata_node = self.get_node("C:\\Users\\Dell\\AppData")
        if appdata_node:
            appdata_node.attributes["hidden"] = True

        recycle_node = self.get_node("C:\\$Recycle.Bin")
        if recycle_node:
            recycle_node.attributes["hidden"] = True
            recycle_node.attributes["system"] = True
            recycle_node.icon = "🗑️"

        # Realistic Windows system files
        sys_files = [
            ("C:\\Windows\\System32\\cmd.exe", "# Windows Command Processor binary stub", 312320, "⚡"),
            ("C:\\Windows\\System32\\powershell.exe", "# Windows PowerShell executable binary stub", 450560, "⚡"),
            ("C:\\Windows\\System32\\taskmgr.exe", "# Task Manager binary stub", 225280, "📊"),
            ("C:\\Windows\\System32\\netstat.exe", "# TCP/IP Network Diagnostic Utility", 81920, "⚡"),
            ("C:\\Windows\\System32\\ipconfig.exe", "# IP Configuration Utility", 94208, "⚡"),
            ("C:\\Windows\\System32\\whoami.exe", "# Windows User Identity Utility", 65536, "⚡"),
        ]
        for path, content, size, icon in sys_files:
            self._create_file_internal(path, content=content, size=size, icon=icon)

        # Realistic project and honey files
        honey_files = [
            (
                "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\passwords.txt",
                (
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
                ),
                None, "🔒"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\.env",
                (
                    "DATABASE_URL=postgresql://sec_admin:P%40ssw0rd2026@prod-cluster-db.internal.corp:5432/behavioral_sec\n"
                    "JWT_SECRET=super_secret_jwt_signing_key_honeypot_2026\n"
                    "TELEGRAM_BOT_TOKEN=718291029:AAFk92Lkas0182Kals-example_token\n"
                    "ADMIN_API_KEY=adm_live_9201839281923847\n"
                    "HONEYPOT_MODE=strict\n"
                ),
                None, "🔑"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\README.md",
                (
                    "# Behavioral Drift Continuous Security\n\n"
                    "Multi-Factor Continuous Behavioral Biometric Authentication & Honeypot Forensics.\n"
                    "Department of Information Science & Engineering | Major Project\n"
                ),
                None, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Personal_Vault\\master_passwords_vault.txt",
                (
                    "=== PERSONAL PASSWORDS VAULT ===\n"
                    "Personal Gmail:       chirag.ise@nmamit.in / MyCollegePass@2026!\n"
                    "GitHub Personal:      chirag-dev / ghp_Z58d83Ka92Lq93Kasl38Adk2JqpO11283\n"
                    "Crypto Wallet Seed:   witch collapse practice feed shame open despair creek road again ice cheese\n"
                    "Bank Account NetPin:  491024 (HDFC Corp Banking)\n"
                ),
                None, "🔒"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Personal_Vault\\aws_secret_credentials.json",
                (
                    '{\n'
                    '  "default": {\n'
                    '    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",\n'
                    '    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",\n'
                    '    "region": "ap-south-1"\n'
                    '  }\n'
                    '}'
                ),
                None, "🔑"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Personal_Vault\\private_ssh_id_rsa",
                (
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
                    "NhAAAAAwEAAQAAAYEAv7Yn5V2+mX7zK84j...[HONEYTOKEN PRIVATE KEY DUMP]...\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                ),
                None, "🔒"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\root_credentials.txt",
                "Root administrator password: DellLatitude@Workstation2026!",
                None, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\crypto_wallets.txt",
                "BTC Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\nETH: 0x71C836e4B38A2d3F3D8C86940845BEE10313554b",
                None, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\tester.txt",
                "Workstation health check: nominal. Behavioral evaluation sensors running.",
                None, "📝"
            ),
            (
                "C:\\Users\\Dell\\Documents\\backup_recovery_keys.txt",
                "BitLocker Recovery Key: 421092-192840-592810-384910-294019-482910-582910-192840",
                None, "📄"
            ),
            (
                "C:\\Users\\Dell\\Documents\\academic_transcripts.pdf",
                "%PDF-1.5 simulated academic transcript document",
                124500, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\project_analysis_and_plan.pdf",
                "%PDF-1.5 Major Project System Architecture & Implementation Plan",
                450200, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\thesis_final_draft.docx",
                "DOCX monolithic academic thesis draft",
                284000, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\system_evaluation_metrics.xlsx",
                "XLSX evaluation metrics: AUC=0.984, EER=0.021, Latency=41ms",
                95000, "📊"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\major_project_demo.mp4",
                "MP4 video demonstration recording",
                14200000, "🎥"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\documents\\ISE_MAJORPROJECTPPT.pptx",
                "PPTX Final Viva Presentation Slide Deck",
                3200000, "📊"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\documents\\Literature_Review_id_30.pdf",
                "%PDF-1.5 Literature Review: Continuous Authentication",
                310000, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\documents\\Major_Project Synopsis_30.pdf",
                "%PDF-1.5 Project Synopsis Team 30",
                180000, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\clg\\documents\\confidential_admin_keys.pdf",
                "%PDF-1.5 Confidential Department Infrastructure Keys",
                240000, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Financial_Records_2026\\bank_account_tax_filings.xlsx",
                "XLSX Confidential Tax Filings FY 2025-2026",
                112000, "📊"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Financial_Records_2026\\direct_deposit_routing_numbers.pdf",
                "%PDF-1.5 Direct Deposit Routing and Account Numbers",
                156000, "📄"
            ),
            (
                "C:\\Users\\Dell\\Desktop\\Financial_Records_2026\\investment_portfolio.csv",
                "Symbol,Quantity,Price,Value\nBTC,0.85,64000,54400\nETH,12.4,3200,39680\nNVDA,150,120,18000",
                None, "📊"
            ),
            (
                "C:\\Users\\Dell\\user_profile.ini",
                "[User]\nUsername=Dell\nRole=Administrator\nTheme=Dark\nDomain=WORKGROUP\n",
                None, "📄"
            )
        ]

        for path, content, size, icon in honey_files:
            self._create_file_internal(path, content=content, size=size, icon=icon)

        # Mark .env as hidden
        env_node = self.get_node("C:\\Users\\Dell\\Desktop\\clg\\Behavioral-Drift-Security\\.env")
        if env_node:
            env_node.attributes["hidden"] = True

    def _get_or_create_dir(self, norm_path: str) -> VirtualDirectory:
        """Traverses from root down to norm_path, creating missing directories."""
        if PathUtils.path_equal(norm_path, "C:\\"):
            return self.root

        parent_path, dir_name = PathUtils.split_path(norm_path)
        parent_dir = self._get_or_create_dir(parent_path)

        existing = parent_dir.get_child(dir_name)
        if existing and existing.is_dir:
            return existing

        new_dir = VirtualDirectory(name=dir_name, path=norm_path)
        parent_dir.add_child(new_dir)
        return new_dir

    def _mkdir_internal(self, path: str) -> VirtualDirectory:
        norm = PathUtils.normalize(path)
        return self._get_or_create_dir(norm)

    def _create_file_internal(
        self,
        path: str,
        content: str = "",
        size: Optional[int] = None,
        icon: str = "📄"
    ) -> VirtualFile:
        norm = PathUtils.normalize(path)
        parent_path, file_name = PathUtils.split_path(norm)
        parent_dir = self._get_or_create_dir(parent_path)

        f = VirtualFile(
            name=file_name,
            path=norm,
            content=content,
            size=size,
            icon=icon
        )
        parent_dir.add_child(f)
        return f

    # --------------------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------------------

    def exists(self, path: str) -> bool:
        return self.get_node(path) is not None

    def is_dir(self, path: str) -> bool:
        node = self.get_node(path)
        return node.is_dir if node else False

    def is_file(self, path: str) -> bool:
        node = self.get_node(path)
        return (not node.is_dir) if node else False

    def get_node(self, path: str) -> Optional[VirtualNode]:
        """Looks up any node by virtual path in case-insensitive manner."""
        with self._lock:
            norm = PathUtils.normalize(path)
            if PathUtils.path_equal(norm, "C:\\"):
                return self.root

            parts = norm[3:].split("\\") if norm.startswith("C:\\") else norm.split("\\")
            curr: VirtualNode = self.root

            for part in parts:
                if not part:
                    continue
                if not curr.is_dir:
                    return None
                curr = curr.get_child(part)
                if curr is None:
                    return None
            return curr

    def list_dir(self, path: str, include_hidden: bool = True) -> List[VirtualNode]:
        with self._lock:
            node = self.get_node(path)
            if not node or not node.is_dir:
                return []
            return node.list_children(include_hidden=include_hidden)

    def mkdir(self, path: str, parents: bool = True, notify: bool = True) -> VirtualDirectory:
        """Creates a virtual directory."""
        with self._lock:
            norm = PathUtils.normalize(path)
            if self.exists(norm):
                node = self.get_node(norm)
                if node.is_dir:
                    return node
                raise FileExistsError(f"A file with name '{norm}' already exists.")

            parent_path, name = PathUtils.split_path(norm)
            parent_node = self.get_node(parent_path)

            if not parent_node:
                if parents:
                    parent_node = self._mkdir_internal(parent_path)
                else:
                    raise FileNotFoundError(f"Cannot find parent path '{parent_path}'.")

            if not parent_node.is_dir:
                raise NotADirectoryError(f"'{parent_path}' is not a directory.")

            new_dir = VirtualDirectory(name=name, path=norm)
            parent_node.add_child(new_dir)
            if notify:
                self._notify_change("mkdir", norm)
            return new_dir

    def create_file(
        self,
        path: str,
        content: str = "",
        overwrite: bool = False,
        icon: str = "📄",
        notify: bool = True
    ) -> VirtualFile:
        """Creates a new virtual file."""
        with self._lock:
            norm = PathUtils.normalize(path)
            existing = self.get_node(norm)

            if existing:
                if existing.is_dir:
                    raise IsADirectoryError(f"'{norm}' is an existing directory.")
                if not overwrite:
                    raise FileExistsError(f"File '{norm}' already exists.")
                existing.set_content(content)
                if notify:
                    self._notify_change("modify", norm)
                return existing

            parent_path, name = PathUtils.split_path(norm)
            parent_node = self.get_node(parent_path)
            if not parent_node:
                parent_node = self._mkdir_internal(parent_path)

            new_file = VirtualFile(name=name, path=norm, content=content, icon=icon)
            parent_node.add_child(new_file)
            if notify:
                self._notify_change("create", norm)
            return new_file

    def read_file(self, path: str) -> str:
        with self._lock:
            node = self.get_node(path)
            if not node:
                raise FileNotFoundError(f"Cannot find path '{path}'.")
            if node.is_dir:
                raise IsADirectoryError(f"'{path}' is a directory.")
            return node.content

    def write_file(
        self,
        path: str,
        content: str,
        append: bool = False,
        notify: bool = True
    ) -> VirtualFile:
        with self._lock:
            norm = PathUtils.normalize(path)
            node = self.get_node(norm)
            if node:
                if node.is_dir:
                    raise IsADirectoryError(f"'{norm}' is a directory.")
                new_text = (node.content + content) if append else content
                node.set_content(new_text)
                if notify:
                    self._notify_change("modify", norm)
                return node
            return self.create_file(norm, content=content, notify=notify)

    def rename(self, old_path: str, new_name_or_path: str, notify: bool = True) -> VirtualNode:
        """Renames a file or directory."""
        with self._lock:
            norm_old = PathUtils.normalize(old_path)
            node = self.get_node(norm_old)
            if not node:
                raise FileNotFoundError(f"Cannot find path '{old_path}'.")

            if PathUtils.path_equal(norm_old, "C:\\"):
                raise PermissionError("Cannot rename root directory 'C:\\'.")

            old_parent_path, _ = PathUtils.split_path(norm_old)
            old_parent = self.get_node(old_parent_path)

            # Determine new path
            if "\\" in new_name_or_path or "/" in new_name_or_path:
                norm_new = PathUtils.normalize(new_name_or_path)
                new_parent_path, new_name = PathUtils.split_path(norm_new)
            else:
                new_name = new_name_or_path.strip()
                norm_new = PathUtils.join(old_parent_path, new_name)
                new_parent_path = old_parent_path

            if self.exists(norm_new) and not PathUtils.path_equal(norm_old, norm_new):
                raise FileExistsError(f"An item with name '{norm_new}' already exists.")

            new_parent = self.get_node(new_parent_path)
            if not new_parent or not new_parent.is_dir:
                raise NotADirectoryError(f"Destination '{new_parent_path}' is not a valid directory.")

            # Remove from old parent
            old_parent.remove_child(node.name)

            # Update node properties and recursive paths if directory
            node.name = new_name
            node.path = norm_new
            node.modified_time = time.time()

            if node.is_dir:
                self._update_subtree_paths(node)

            new_parent.add_child(node)

            if notify:
                self._notify_change("rename", f"{norm_old}->{norm_new}")
            return node

    def _update_subtree_paths(self, dir_node: VirtualDirectory):
        """Recursively updates path attributes of child nodes when a directory moves/renames."""
        for child in dir_node.children.values():
            child.path = PathUtils.join(dir_node.path, child.name)
            if child.is_dir:
                self._update_subtree_paths(child)

    def delete(self, path: str, to_recycle_bin: bool = True, notify: bool = True) -> bool:
        """Deletes a node, optionally moving to virtual recycle bin."""
        with self._lock:
            norm = PathUtils.normalize(path)
            if PathUtils.path_equal(norm, "C:\\"):
                raise PermissionError("Cannot delete root directory 'C:\\'.")

            node = self.get_node(norm)
            if not node:
                raise FileNotFoundError(f"Cannot find path '{path}'.")

            parent_path, _ = PathUtils.split_path(norm)
            parent = self.get_node(parent_path)
            if not parent or not parent.is_dir:
                return False

            removed = parent.remove_child(node.name)
            if removed and to_recycle_bin:
                entry = VirtualRecycleBinEntry(norm, removed)
                self.recycle_bin[entry.entry_id] = entry

            if notify:
                self._notify_change("delete", norm)
            return True

    def restore_from_recycle_bin(self, entry_id_or_path: str, notify: bool = True) -> Optional[VirtualNode]:
        """Restores a deleted item from the virtual recycle bin to its original location."""
        with self._lock:
            entry: Optional[VirtualRecycleBinEntry] = None
            if entry_id_or_path in self.recycle_bin:
                entry = self.recycle_bin.pop(entry_id_or_path)
            else:
                for k, v in list(self.recycle_bin.items()):
                    if PathUtils.path_equal(v.original_path, entry_id_or_path) or v.node.name.lower() == entry_id_or_path.lower():
                        entry = self.recycle_bin.pop(k)
                        break

            if not entry:
                return None

            parent_path, name = PathUtils.split_path(entry.original_path)
            parent = self.get_node(parent_path)
            if not parent:
                parent = self._mkdir_internal(parent_path)

            entry.node.path = entry.original_path
            parent.add_child(entry.node)
            if notify:
                self._notify_change("restore", entry.original_path)
            return entry.node

    def get_recycle_bin_items(self) -> List[VirtualRecycleBinEntry]:
        with self._lock:
            return list(self.recycle_bin.values())

    def empty_recycle_bin(self, notify: bool = True):
        with self._lock:
            self.recycle_bin.clear()
            if notify:
                self._notify_change("empty_recycle_bin", "C:\\$Recycle.Bin")

    def copy(self, src_path: str, dst_dir_or_path: str, notify: bool = True) -> VirtualNode:
        """Deep copies a file or directory into a destination directory or path."""
        with self._lock:
            norm_src = PathUtils.normalize(src_path)
            node = self.get_node(norm_src)
            if not node:
                raise FileNotFoundError(f"Source '{src_path}' not found.")

            norm_dst = PathUtils.normalize(dst_dir_or_path)
            dst_node = self.get_node(norm_dst)

            if dst_node and dst_node.is_dir:
                target_path = PathUtils.join(norm_dst, node.name)
            else:
                target_path = norm_dst

            parent_path, new_name = PathUtils.split_path(target_path)
            parent_dir = self.get_node(parent_path)
            if not parent_dir:
                parent_dir = self._mkdir_internal(parent_path)

            copied_node = self._clone_node(node, target_path)
            copied_node.name = new_name
            parent_dir.add_child(copied_node)

            if notify:
                self._notify_change("copy", f"{norm_src}->{target_path}")
            return copied_node

    def _clone_node(self, node: VirtualNode, new_path: str) -> VirtualNode:
        now = time.time()
        if node.is_dir:
            dir_node = VirtualDirectory(
                name=node.name,
                path=new_path,
                attributes=copy.deepcopy(node.attributes),
                created_time=now,
                modified_time=now,
                icon=node.icon
            )
            for child in node.list_children(include_hidden=True):
                child_new_path = PathUtils.join(new_path, child.name)
                cloned_child = self._clone_node(child, child_new_path)
                dir_node.add_child(cloned_child)
            return dir_node
        else:
            return VirtualFile(
                name=node.name,
                path=new_path,
                content=node.content,
                size=node.size,
                attributes=copy.deepcopy(node.attributes),
                created_time=now,
                modified_time=now,
                icon=node.icon
            )

    def move(self, src_path: str, dst_dir_or_path: str, notify: bool = True) -> VirtualNode:
        """Moves a file or directory to another directory or new path."""
        with self._lock:
            norm_src = PathUtils.normalize(src_path)
            norm_dst = PathUtils.normalize(dst_dir_or_path)

            dst_node = self.get_node(norm_dst)
            if dst_node and dst_node.is_dir:
                target_path = PathUtils.join(norm_dst, PathUtils.split_path(norm_src)[1])
            else:
                target_path = norm_dst

            return self.rename(norm_src, target_path, notify=notify)

    def search(self, query: str, root_path: str = "C:\\", recursive: bool = True) -> List[VirtualNode]:
        """Searches files and folders matching query substring."""
        with self._lock:
            q = query.strip().lower()
            if not q:
                return []

            start_node = self.get_node(root_path)
            if not start_node or not start_node.is_dir:
                return []

            results: List[VirtualNode] = []
            queue = [start_node]

            while queue:
                curr = queue.pop(0)
                children = curr.list_children(include_hidden=True)
                for child in children:
                    if q in child.name.lower():
                        results.append(child)
                    if child.is_dir and recursive:
                        queue.append(child)

            return results

    def resolve_path(self, current_dir: str, target_path: str) -> str:
        """Resolves relative or absolute path against a current directory."""
        if not target_path:
            return PathUtils.normalize(current_dir)
        t = target_path.strip().replace("/", "\\")
        if len(t) >= 2 and t[1] == ":":
            return PathUtils.normalize(t)
        if t.startswith("\\"):
            drive = current_dir[:2] if len(current_dir) >= 2 and current_dir[1] == ":" else "C:"
            return PathUtils.normalize(f"{drive}{t}")
        return PathUtils.join(current_dir, t)


# Helper accessor
def get_vfs() -> VirtualFileSystem:
    return VirtualFileSystem.get_instance()
