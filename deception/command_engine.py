import os
import sys
import time
import psutil
from typing import Tuple, List, Optional
from urllib.parse import urlparse

from deception.virtual_fs import get_vfs, PathUtils, VirtualNode
from deception.forensic_tracker import get_tracker

class VirtualCommandEngine:
    """
    Safe, Controlled Virtual Command Execution Engine.
    Executes PowerShell / Command Prompt cmdlets against the centralized VirtualFileSystem.
    SECURITY BOUNDARY: Never executes arbitrary attacker shell commands against the host OS!
    All state modifications occur strictly within the honeypot's virtual environment.
    """
    def __init__(self, sandbox_dir: str, log_dir: str):
        self.sandbox_dir = sandbox_dir
        self.log_dir = log_dir
        self.log_path = os.path.join(log_dir, "honeypot_commands.log")
        self.tracker = get_tracker()
        self.vfs = get_vfs()
        self.current_dir = "C:\\Windows\\system32"
        self.history: List[str] = []

    def log_action(self, cmd_raw: str):
        """Appends command execution to the audit log."""
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {cmd_raw}\n")
        except Exception:
            pass

    def execute(self, cmd_raw: str) -> Tuple[str, bool]:
        """
        Processes a command string.
        Returns (response_text, should_exit).
        """
        raw = cmd_raw.strip()
        if not raw:
            return "", False

        self.history.append(raw)
        self.log_action(raw)
        self.tracker.record_shell_command(raw, self.current_dir)

        # Handle redirection (e.g. echo ... > file.txt)
        if ">" in raw and not raw.startswith("route"):
            return self._handle_redirection(raw), False

        parts = raw.split()
        base_cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []

        # Command Dispatcher
        if base_cmd in ["exit", "quit"]:
            return "", True
        elif base_cmd in ["clear", "cls", "clear-host"]:
            return "__CLEAR__", False
        elif base_cmd in ["pwd", "get-location"]:
            return f"\nPath\n----\n{self.current_dir}", False
        elif base_cmd in ["cd", "chdir", "set-location"]:
            return self._cmd_cd(args), False
        elif base_cmd in ["dir", "ls", "get-childitem", "gci"]:
            return self._cmd_dir(args), False
        elif base_cmd in ["type", "cat", "get-content", "gc"]:
            return self._cmd_type(args), False
        elif base_cmd in ["mkdir", "md"]:
            return self._cmd_mkdir(args), False
        elif base_cmd in ["new-item", "ni"]:
            return self._cmd_new_item(raw, args), False
        elif base_cmd in ["copy-item", "copy", "cp", "cpi"]:
            return self._cmd_copy(args), False
        elif base_cmd in ["move-item", "move", "mv", "mi"]:
            return self._cmd_move(args), False
        elif base_cmd in ["rename-item", "ren", "rename", "rni"]:
            return self._cmd_rename(args), False
        elif base_cmd in ["remove-item", "del", "rm", "erase", "ri"]:
            return self._cmd_remove(args), False
        elif base_cmd in ["get-item", "gi"]:
            return self._cmd_get_item(args), False
        elif base_cmd in ["get-itemproperty", "gp"]:
            return self._cmd_get_item_property(args), False
        elif base_cmd in ["echo", "write-output"]:
            return self._cmd_echo(args), False
        elif base_cmd in ["tasklist", "ps", "get-process", "gps"]:
            return self._cmd_tasklist(), False
        elif base_cmd in ["systeminfo"]:
            return self._cmd_systeminfo(), False
        elif base_cmd in ["whoami"]:
            return self._cmd_whoami(args), False
        elif base_cmd in ["hostname"]:
            return "DESKTOP-SEC-WIN11", False
        elif base_cmd in ["ipconfig", "ipconfig.exe"]:
            return self._cmd_ipconfig(args), False
        elif base_cmd in ["netstat", "netstat.exe"]:
            return self._cmd_netstat(args), False
        elif base_cmd in ["ping", "ping.exe"]:
            return self._cmd_ping(args), False
        elif base_cmd in ["arp", "arp.exe"]:
            return self._cmd_arp(args), False
        elif base_cmd in ["route", "route.exe"]:
            return self._cmd_route(args), False
        elif base_cmd in ["curl", "curl.exe", "wget", "wget.exe", "iwr", "invoke-webrequest"]:
            return self._cmd_curl(raw, args), False
        elif base_cmd in ["ssh", "ssh.exe"]:
            return self._cmd_ssh(args), False
        elif base_cmd in ["nslookup", "nslookup.exe"]:
            return self._cmd_nslookup(args), False
        elif base_cmd in ["tracert", "tracert.exe", "traceroute"]:
            return self._cmd_tracert(args), False
        elif base_cmd in ["nmap", "nmap.exe"]:
            return self._cmd_nmap(args), False
        elif base_cmd in ["net", "net.exe"]:
            return self._cmd_net(args), False
        elif base_cmd in ["get-history", "history", "h"]:
            return self._cmd_get_history(), False
        elif base_cmd in ["help", "get-help"]:
            return (
                "Supported Diagnostic Cmdlets & Commands:\n"
                "  pwd, cd, dir, ls, Get-ChildItem, cat, type, Get-Content, mkdir, New-Item,\n"
                "  Copy-Item, Move-Item, Rename-Item, Remove-Item, Get-Item, Get-Process, tasklist,\n"
                "  whoami, hostname, ipconfig, ping, arp, route, netstat, curl, wget, ssh,\n"
                "  nslookup, tracert, nmap, net user, net localgroup, systeminfo, Get-History, cls, exit"
            ), False
        else:
            return (
                f"{base_cmd} : The term '{base_cmd}' is not recognized as the name of a cmdlet, "
                f"function, script file, or operable program.\n"
                f"Check the spelling of the name, or if a path was included, verify that the path is correct and try again."
            ), False

    # --------------------------------------------------------------------------
    # Filesystem Cmdlets
    # --------------------------------------------------------------------------

    def _cmd_cd(self, args: List[str]) -> str:
        if not args:
            return self.current_dir

        target = args[0].strip().strip('"').strip("'")
        if target == "..":
            parent, _ = PathUtils.split_path(self.current_dir)
            self.current_dir = parent
            return ""

        if target == "\\":
            self.current_dir = "C:\\"
            return ""

        resolved = self.vfs.resolve_path(self.current_dir, target)
        node = self.vfs.get_node(resolved)
        if node and node.is_dir:
            self.current_dir = node.path
            return ""

        return f"Cannot find path '{target}' because it does not exist."

    def _cmd_dir(self, args: List[str]) -> str:
        target_path = self.current_dir
        if args and not args[0].startswith("-"):
            target_path = self.vfs.resolve_path(self.current_dir, args[0].strip('"').strip("'"))

        node = self.vfs.get_node(target_path)
        if not node:
            return f"Cannot find path '{target_path}' because it does not exist."

        if not node.is_dir:
            # Single file display
            res = (
                f"\n    Directory: {PathUtils.split_path(node.path)[0]}\n\n"
                f"Mode                 LastWriteTime         Length Name\n"
                f"----                 -------------         ------ ----\n"
                f"-a---          {node.format_modified_time()}           {node.size} {node.name}\n"
            )
            return res

        items = self.vfs.list_dir(node.path, include_hidden=True)
        res = (
            f"\n    Directory: {node.path}\n\n"
            f"Mode                 LastWriteTime         Length Name\n"
            f"----                 -------------         ------ ----\n"
        )
        for item in items:
            mode = "d----" if item.is_dir else "-a---"
            length_str = "" if item.is_dir else str(item.size).rjust(14)
            if item.is_dir:
                length_str = "              "
            res += f"{mode:<5}          {item.format_modified_time()} {length_str} {item.name}\n"
        return res

    def _cmd_type(self, args: List[str]) -> str:
        if not args:
            return "Cannot bind argument to parameter 'Path' because it is null."

        target = args[0].strip().strip('"').strip("'")
        resolved = self.vfs.resolve_path(self.current_dir, target)
        self.tracker.record_file_access(resolved, action="SHELL_CAT")

        try:
            content = self.vfs.read_file(resolved)
            return content
        except FileNotFoundError:
            # Check sandbox fallback
            chk = os.path.join(self.sandbox_dir, target)
            if os.path.exists(chk):
                try:
                    with open(chk, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass
            return f"Cannot find path '{target}' because it does not exist."
        except IsADirectoryError:
            return f"Cannot read directory '{target}' as text."
        except Exception as e:
            return f"Error reading file: {e}"

    def _cmd_mkdir(self, args: List[str]) -> str:
        if not args:
            return "mkdir : Cannot bind argument to parameter 'Path' because it is null."

        dir_name = args[0].strip().strip('"').strip("'")
        resolved = self.vfs.resolve_path(self.current_dir, dir_name)
        try:
            new_dir = self.vfs.mkdir(resolved, parents=True)
            self.tracker.record_file_access(resolved, action="CREATE_DIR")
            return (
                f"\n    Directory: {PathUtils.split_path(new_dir.path)[0]}\n\n"
                f"Mode                 LastWriteTime         Length Name\n"
                f"----                 -------------         ------ ----\n"
                f"d----          {new_dir.format_modified_time()}                {new_dir.name}\n"
            )
        except Exception as e:
            return f"mkdir : {e}"

    def _cmd_new_item(self, raw_cmd: str, args: List[str]) -> str:
        item_type = "file"
        name = None
        for i, a in enumerate(args):
            al = a.lower()
            if al in ["-type", "-itemtype"] and i + 1 < len(args):
                item_type = args[i + 1].lower()
            elif al in ["-name", "-path"] and i + 1 < len(args):
                name = args[i + 1].strip('"').strip("'")
            elif not a.startswith("-") and not name:
                name = a.strip('"').strip("'")

        if not name:
            return "New-Item : Parameter 'Name' or 'Path' is required."

        resolved = self.vfs.resolve_path(self.current_dir, name)
        try:
            if "dir" in item_type:
                node = self.vfs.mkdir(resolved, parents=True)
                mode = "d----"
            else:
                node = self.vfs.create_file(resolved, content="", overwrite=True)
                mode = "-a---"

            self.tracker.record_file_access(resolved, action="CREATE")
            return (
                f"\n    Directory: {PathUtils.split_path(node.path)[0]}\n\n"
                f"Mode                 LastWriteTime         Length Name\n"
                f"----                 -------------         ------ ----\n"
                f"{mode}          {node.format_modified_time()}           {node.size if not node.is_dir else ''} {node.name}\n"
            )
        except Exception as e:
            return f"New-Item : {e}"

    def _cmd_copy(self, args: List[str]) -> str:
        if len(args) < 2:
            return "Copy-Item : Requires source and destination path parameters."
        src = self.vfs.resolve_path(self.current_dir, args[0].strip('"').strip("'"))
        dst = self.vfs.resolve_path(self.current_dir, args[1].strip('"').strip("'"))
        try:
            self.vfs.copy(src, dst)
            self.tracker.record_file_access(src, action="COPY")
            return ""
        except Exception as e:
            return f"Copy-Item : {e}"

    def _cmd_move(self, args: List[str]) -> str:
        if len(args) < 2:
            return "Move-Item : Requires source and destination path parameters."
        src = self.vfs.resolve_path(self.current_dir, args[0].strip('"').strip("'"))
        dst = self.vfs.resolve_path(self.current_dir, args[1].strip('"').strip("'"))
        try:
            self.vfs.move(src, dst)
            self.tracker.record_file_access(src, action="MOVE")
            return ""
        except Exception as e:
            return f"Move-Item : {e}"

    def _cmd_rename(self, args: List[str]) -> str:
        if len(args) < 2:
            return "Rename-Item : Requires path and new name parameters."
        src = self.vfs.resolve_path(self.current_dir, args[0].strip('"').strip("'"))
        new_name = args[1].strip('"').strip("'")
        try:
            self.vfs.rename(src, new_name)
            self.tracker.record_file_access(src, action="RENAME")
            return ""
        except Exception as e:
            return f"Rename-Item : {e}"

    def _cmd_remove(self, args: List[str]) -> str:
        if not args:
            return "Remove-Item : Parameter 'Path' is required."
        target = args[0].strip('"').strip("'")
        resolved = self.vfs.resolve_path(self.current_dir, target)
        try:
            self.vfs.delete(resolved, to_recycle_bin=True)
            self.tracker.record_file_access(resolved, action="DELETE")
            return ""
        except Exception as e:
            return f"Remove-Item : {e}"

    def _cmd_get_item(self, args: List[str]) -> str:
        target = args[0].strip('"').strip("'") if args else self.current_dir
        resolved = self.vfs.resolve_path(self.current_dir, target)
        node = self.vfs.get_node(resolved)
        if not node:
            return f"Cannot find path '{target}' because it does not exist."
        mode = "d----" if node.is_dir else "-a---"
        return (
            f"\n    Directory: {PathUtils.split_path(node.path)[0]}\n\n"
            f"Mode                 LastWriteTime         Length Name\n"
            f"----                 -------------         ------ ----\n"
            f"{mode}          {node.format_modified_time()}           {node.size if not node.is_dir else ''} {node.name}\n"
        )

    def _cmd_get_item_property(self, args: List[str]) -> str:
        target = args[0].strip('"').strip("'") if args else self.current_dir
        resolved = self.vfs.resolve_path(self.current_dir, target)
        node = self.vfs.get_node(resolved)
        if not node:
            return f"Cannot find path '{target}' because it does not exist."
        return (
            f"\nPSPath            : Microsoft.PowerShell.Core\\FileSystem::{node.path}\n"
            f"PSParentPath      : Microsoft.PowerShell.Core\\FileSystem::{PathUtils.split_path(node.path)[0]}\n"
            f"PSChildName       : {node.name}\n"
            f"PSIsContainer     : {node.is_dir}\n"
            f"Length            : {node.size if not node.is_dir else 0}\n"
            f"CreationTime      : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(node.created_time))}\n"
            f"LastWriteTime     : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(node.modified_time))}\n"
            f"Attributes        : {'Directory' if node.is_dir else 'Archive'}"
        )

    def _cmd_echo(self, args: List[str]) -> str:
        return " ".join(args)

    def _handle_redirection(self, raw_cmd: str) -> str:
        append = ">>" in raw_cmd
        delimiter = ">>" if append else ">"
        cmd_part, file_part = raw_cmd.split(delimiter, 1)

        text = cmd_part.strip()
        for prefix in ["echo", "write-output", "set-content", "add-content"]:
            if text.lower().startswith(prefix):
                text = text[len(prefix):].strip()
                break

        if (text.startswith("'") and text.endswith("'")) or (text.startswith('"') and text.endswith('"')):
            text = text[1:-1]

        filename = file_part.strip().strip('"').strip("'")
        resolved = self.vfs.resolve_path(self.current_dir, filename)

        # Write into VFS
        try:
            self.vfs.write_file(resolved, text + "\n", append=append)
        except Exception as e:
            return f"Error writing to virtual file: {e}"

        # Divert suspicious attacker file payload safely to isolated Sandbox directory
        sandbox_path = os.path.join(self.sandbox_dir, PathUtils.split_path(resolved)[1])
        os.makedirs(self.sandbox_dir, exist_ok=True)
        try:
            mode = "a" if append else "w"
            with open(sandbox_path, mode, encoding="utf-8") as f:
                f.write(text + "\n")
        except Exception:
            pass

        self.tracker.record_sandbox_write(PathUtils.split_path(resolved)[1], len(text.encode("utf-8")))
        return ""

    # --------------------------------------------------------------------------
    # System & Network Diagnostics
    # --------------------------------------------------------------------------

    def _cmd_tasklist(self) -> str:
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

    def _cmd_systeminfo(self) -> str:
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

    def _cmd_whoami(self, args: List[str]) -> str:
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

    def _cmd_ipconfig(self, args: List[str]) -> str:
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

    def _cmd_netstat(self, args: List[str]) -> str:
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

    def _cmd_ping(self, args: List[str]) -> str:
        if not args:
            return "Usage: ping [-t] [-a] [-n count] [-l size] target_name"
        target = args[0] if not args[0].startswith("-") else (args[-1] if len(args) > 1 else "127.0.0.1")
        ip = "192.168.1.1" if ("gateway" in target or "192" in target) else ("8.8.8.8" if ("google" in target or "8.8" in target) else "10.0.1.55")

        self.tracker.record_network_recon(f"ping {' '.join(args)}", target, recon_type="ICMP_PING")

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

    def _cmd_arp(self, args: List[str]) -> str:
        cmd_str = f"arp {' '.join(args)}" if args else "arp -a"
        self.tracker.record_network_recon(cmd_str, "192.168.1.0/24", recon_type="ARP_CACHE_ENUM")

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

    def _cmd_route(self, args: List[str]) -> str:
        cmd_str = f"route {' '.join(args)}" if args else "route print"
        self.tracker.record_network_recon(cmd_str, "192.168.1.1", recon_type="ROUTING_TABLE_ENUM")

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

    def _cmd_curl(self, cmd_raw: str, args: List[str]) -> str:
        """
        Interprets curl/wget/Invoke-WebRequest safely without real execution.
        Intercepts remote attacker payloads, diverts them safely into data/sandbox/,
        updates the VirtualFileSystem so 'dir' shows the file, and logs to ForensicTracker.
        """
        if not args:
            return "curl: try 'curl --help' for more information"

        url = None
        for a in args:
            if a.startswith("http://") or a.startswith("https://") or "://" in a or ("." in a and not a.startswith("-") and not a.startswith("/")):
                url = a
                break
        if not url:
            url = args[-1]

        c2_host = "194.26.29.112"
        try:
            parsed = urlparse(url if "://" in url else f"http://{url}")
            c2_host = parsed.netloc or parsed.path.split("/")[0] or "attacker.c2.net"
        except Exception:
            c2_host = "attacker.c2.net"

        out_filename = None
        for i, a in enumerate(args):
            if a in ["-o", "-O", "--output", "-OutFile", "-outfile"] and i + 1 < len(args):
                out_filename = args[i + 1].strip('"').strip("'")
                break

        if not out_filename:
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

        if not out_filename:
            out_filename = "c2_dropper.exe" if "c2" in url.lower() or ".exe" in url.lower() else "downloaded_file.bin"

        # Quarantined payload content
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

        # 1. Isolate in sandbox
        sandbox_path = os.path.join(self.sandbox_dir, out_filename)
        os.makedirs(self.sandbox_dir, exist_ok=True)
        try:
            with open(sandbox_path, "w", encoding="utf-8") as f:
                f.write(quarantine_content)
        except Exception:
            pass

        # 2. Add to VirtualFileSystem at current directory so 'dir' immediately reflects it
        vfs_path = self.vfs.resolve_path(self.current_dir, out_filename)
        self.vfs.create_file(vfs_path, content=quarantine_content, overwrite=True)

        # 3. Log to forensic tracker
        self.tracker.record_c2_download(
            url=url,
            c2_host=c2_host,
            filename=out_filename,
            file_size=len(quarantine_content.encode("utf-8"))
        )

        return (
            f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
            f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
            f"100  1024  100  1024    0     0   4100      0 --:--:-- --:--:-- --:--:--  4112\n"
            f"Downloaded '{out_filename}' from {c2_host}."
        )

    def _cmd_ssh(self, args: List[str]) -> str:
        target = args[0] if args else "10.0.1.55"
        host = target.split("@")[-1] if "@" in target else target
        self.tracker.record_network_recon(f"ssh {' '.join(args)}", target, recon_type="LATERAL_MOVEMENT_SSH")
        return (
            f"The authenticity of host '{host}' can't be established.\n"
            f"ED25519 key fingerprint is SHA256:4kR210kLa92Kas0182a.\n"
            f"ssh: connect to host {host} port 22: Connection timed out"
        )

    def _cmd_nslookup(self, args: List[str]) -> str:
        target = args[0] if args else "internal.corp"
        self.tracker.record_network_recon(f"nslookup {' '.join(args)}", target, recon_type="DNS_QUERY")
        return (
            f"Server:  dns.google\n"
            f"Address:  8.8.8.8\n\n"
            f"Non-authoritative answer:\n"
            f"Name:    {target}\n"
            f"Addresses:  10.0.4.52\n"
            f"          10.0.4.53"
        )

    def _cmd_tracert(self, args: List[str]) -> str:
        target = args[0] if args else "8.8.8.8"
        self.tracker.record_network_recon(f"tracert {' '.join(args)}", target, recon_type="ROUTE_TRACE")
        return (
            f"\nTracing route to {target} over a maximum of 30 hops:\n\n"
            f"  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
            f"  2     3 ms     3 ms     2 ms  10.0.1.254\n"
            f"  3    12 ms    11 ms    12 ms  172.16.0.1\n"
            f"  4    15 ms    14 ms    15 ms  {target}\n\n"
            f"Trace complete."
        )

    def _cmd_nmap(self, args: List[str]) -> str:
        target = args[0] if args else "192.168.1.1"
        self.tracker.record_network_recon(f"nmap {' '.join(args)}", target, recon_type="PORT_SCAN_RECON")
        return (
            f"\nStarting Nmap 7.94 ( https://nmap.org ) at {time.strftime('%Y-%m-%d %H:%M')}\n"
            f"Nmap scan report for {target}\n"
            f"Host is up (0.0032s latency).\n"
            f"Not shown: 996 closed tcp ports (reset)\n"
            f"PORT     STATE SERVICE\n"
            f"22/tcp   open  ssh\n"
            f"80/tcp   open  http\n"
            f"443/tcp  open  https\n"
            f"8080/tcp open  http-proxy\n\n"
            f"Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds"
        )

    def _cmd_net(self, args: List[str]) -> str:
        if args and args[0].lower() == "user":
            return (
                "\nUser accounts for \\\\DESKTOP-SEC-WIN11\n\n"
                "-------------------------------------------------------------------------------\n"
                "Administrator            DefaultAccount           Guest\n"
                "Dell                     WDAGUtilityAccount\n"
                "The command completed successfully."
            )
        elif args and args[0].lower() == "localgroup":
            return (
                "\nMembers of local group Administrators:\n\n"
                "-------------------------------------------------------------------------------\n"
                "Administrator\n"
                "Dell\n"
                "The command completed successfully."
            )
        return "The syntax of this command is: NET [ ACCOUNTS | COMPUTER | CONFIG | GROUP | USER ]"

    def _cmd_get_history(self) -> str:
        if not self.history:
            return ""
        lines = ["  Id CommandLine", "  -- -----------"]
        for idx, cmd in enumerate(self.history, start=1):
            lines.append(f"  {idx:<2} {cmd}")
        return "\n".join(lines)
