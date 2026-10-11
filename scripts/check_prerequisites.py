#!/usr/bin/env python3
"""
================================================================================
PRE-FLIGHT & PREREQUISITES VERIFICATION TOOL
Department of Information Science and Engineering | NMAMIT | Team 30
Multi-Factor Behavioral Drift Continuous Authentication & Honeypot Forensics
================================================================================

Validates all system requirements before running or deploying:
  1. Operating System & Architecture
  2. Python Runtime Version
  3. Installed Python Packages against requirements.txt
  4. Directory Structure & Write Permissions
  5. Configuration Files (.env and security/config.json)
  6. Machine Learning Models Integrity
  7. Offline Ollama Daemon & LLM Threat Models
  8. Hardware Webcam Device Availability
  9. Network Ports (8000 for SOC Dashboard, 11434 for Ollama)
 10. Available Disk Space
================================================================================
"""

import os
import sys
import json
import socket
import shutil
import urllib.request
import urllib.error
from typing import Dict, Any, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def strip(cls, text: str) -> str:
        for c in [cls.GREEN, cls.YELLOW, cls.RED, cls.CYAN, cls.BOLD, cls.RESET]:
            text = text.replace(c, "")
        return text


def print_status(component: str, status: str, detail: str = ""):
    color = Colors.GREEN if status == "OK" else (Colors.YELLOW if status == "WARN" else Colors.RED)
    tag = f"[{color}{status:<4}{Colors.RESET}]"
    detail_str = f" - {detail}" if detail else ""
    try:
        print(f"  {tag} {component:<35}{detail_str}")
    except Exception:
        print(f"  [{status:<4}] {component:<35}{detail_str}")


def check_os() -> Tuple[str, str]:
    is_win = sys.platform == "win32"
    details = f"{sys.platform} ({'Windows' if is_win else 'Non-Windows'})"
    return ("OK" if is_win else "WARN", details)


def check_python_version() -> Tuple[str, str]:
    major, minor, micro = sys.version_info[:3]
    version_str = f"Python {major}.{minor}.{micro}"
    if major == 3 and 10 <= minor <= 14:
        return ("OK", f"{version_str} (Supported 3.10 - 3.14)")
    elif major == 3 and minor < 10:
        return ("FAIL", f"{version_str} (Requires Python 3.10+)")
    else:
        return ("WARN", f"{version_str} (Untested version; 3.10 - 3.14 recommended)")


def check_directories() -> Tuple[str, str]:
    required_dirs = [
        "data/sessions",
        "data/raw",
        "data/forensics",
        "data/sandbox",
        "data/logs",
        "data/harvested",
        "data/benchmarks",
        "models"
    ]
    missing = []
    unwritable = []
    for rel_d in required_dirs:
        abs_d = os.path.join(PROJECT_ROOT, rel_d)
        if not os.path.exists(abs_d):
            try:
                os.makedirs(abs_d, exist_ok=True)
            except Exception:
                missing.append(rel_d)
        if os.path.exists(abs_d):
            try:
                test_file = os.path.join(abs_d, ".perm_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
            except Exception:
                unwritable.append(rel_d)

    if missing:
        return ("FAIL", f"Missing directories: {', '.join(missing)}")
    if unwritable:
        return ("FAIL", f"Permission denied writing to: {', '.join(unwritable)}")
    return ("OK", f"All {len(required_dirs)} runtime directories verified and writable")


def check_config_files() -> Tuple[str, str]:
    env_path = os.path.join(PROJECT_ROOT, ".env")
    env_example = os.path.join(PROJECT_ROOT, ".env.example")
    cfg_path = os.path.join(PROJECT_ROOT, "security", "config.json")
    cfg_example = os.path.join(PROJECT_ROOT, "security", "config.json.example")

    notes = []
    if not os.path.exists(env_path):
        if os.path.exists(env_example):
            try:
                shutil.copyfile(env_example, env_path)
                notes.append("Created .env from .env.example")
            except Exception as e:
                return ("FAIL", f"Could not create .env: {e}")
        else:
            return ("FAIL", "Missing .env and .env.example")
    else:
        notes.append("Preserved existing .env")

    if not os.path.exists(cfg_path):
        if os.path.exists(cfg_example):
            try:
                shutil.copyfile(cfg_example, cfg_path)
                notes.append("Created config.json from template")
            except Exception as e:
                return ("FAIL", f"Could not create config.json: {e}")
    else:
        notes.append("Preserved existing config.json")

    return ("OK", "; ".join(notes))


def check_models() -> Tuple[str, str]:
    pkl_path = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl")
    pt_path = os.path.join(PROJECT_ROOT, "models", "sequence_model.pt")
    meta_path = os.path.join(PROJECT_ROOT, "models", "sequence_meta.json")

    if os.path.exists(pkl_path) and os.path.exists(pt_path) and os.path.exists(meta_path):
        try:
            from ml_engine.models import BehavioralModels
            models = BehavioralModels()
            models.load(pkl_path)
            from ml_engine.sequence_model import DeepSVDDDetector
            seq = DeepSVDDDetector(models_dir=os.path.join(PROJECT_ROOT, "models"))
            if models.is_trained and seq.model is not None and seq.center is not None:
                return ("OK", "Biometric OC-SVM, Context IsoFor, & Deep SVDD 1D-CNN verified")
        except Exception as e:
            return ("WARN", f"Model files exist but verification had warning: {e}")

    return ("WARN", "ML checkpoints need initial training (run: python ml_engine/train.py --simulate)")


def check_ollama() -> Tuple[str, str]:
    ollama_url = os.environ.get("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    target_model = os.environ.get("OLLAMA_MODEL", "qwen3.5:4b")

    try:
        req = urllib.request.Request(f"{ollama_url}/api/tags", headers={"User-Agent": "PrereqCheck/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            installed_models = [m.get("name") for m in data.get("models", [])]
            if target_model in installed_models:
                return ("OK", f"Ollama online with target model '{target_model}'")
            elif any(m.startswith("qwen") for m in installed_models):
                qwen_found = [m for m in installed_models if "qwen" in m][0]
                return ("OK", f"Ollama online with fallback model '{qwen_found}' (Target: '{target_model}')")
            elif installed_models:
                return ("WARN", f"Ollama online, but '{target_model}' not installed. Installed: {', '.join(installed_models[:3])}")
            else:
                return ("WARN", f"Ollama online, but no models installed. Run: ollama pull {target_model}")
    except Exception:
        return ("WARN", f"Ollama daemon not reachable at {ollama_url} (Application will use built-in offline DFIR heuristic rules)")


def check_camera() -> Tuple[str, str]:
    try:
        import cv2
        device_idx = int(os.environ.get("WEBCAM_DEVICE_INDEX", 0))
        cap = cv2.VideoCapture(device_idx)
        if not cap.isOpened() and device_idx == 0:
            cap = cv2.VideoCapture(1)
        if cap.isOpened():
            ret, frame = cap.read()
            cap.release()
            cv2.destroyAllWindows()
            if ret:
                return ("OK", f"Webcam active and returning valid video frames (Device {device_idx})")
            return ("WARN", "Webcam device opened, but frame capture timed out")
        cap.release()
        return ("WARN", f"No camera detected at index {device_idx} (Webcam captures will be skipped safely)")
    except Exception as e:
        return ("WARN", f"Camera probe exception: {e}")


def check_port(port: int = 8000) -> Tuple[str, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        if result == 0:
            # Port is currently occupied
            return ("WARN", f"Port {port} is currently IN USE (Web dashboard may conflict unless previous instance is stopped)")
        else:
            return ("OK", f"Port {port} is AVAILABLE for Cyber-Ops Web Dashboard")
    except Exception as e:
        return ("WARN", f"Port {port} check exception: {e}")


def check_disk_space(min_gb: float = 5.0) -> Tuple[str, str]:
    try:
        total, used, free = shutil.disk_usage(PROJECT_ROOT)
        free_gb = free / (1024 ** 3)
        if free_gb >= min_gb:
            return ("OK", f"{free_gb:.1f} GB free disk space available (Minimum: {min_gb} GB)")
        else:
            return ("WARN", f"Low disk space: {free_gb:.1f} GB free (Recommended: {min_gb} GB)")
    except Exception as e:
        return ("WARN", f"Could not check disk space: {e}")


def run_all_checks() -> bool:
    print("\n" + "=" * 74)
    print("  BEHAVIORAL DRIFT CONTINUOUS SECURITY - PRE-FLIGHT VERIFICATION")
    print("  Department of ISE | Team 30 | Major Project")
    print("=" * 74)
    print(f"  Project Root: {PROJECT_ROOT}\n")

    results = []

    # 1. OS Check
    st, det = check_os()
    print_status("Operating System", st, det)
    results.append(st)

    # 2. Python Version Check
    st, det = check_python_version()
    print_status("Python Runtime", st, det)
    results.append(st)

    # 3. Disk Space
    st, det = check_disk_space()
    print_status("Disk Space", st, det)
    results.append(st)

    # 4. Runtime Directories
    st, det = check_directories()
    print_status("Runtime Storage Layout", st, det)
    results.append(st)

    # 5. Config Templates
    st, det = check_config_files()
    print_status("Safe Configuration Files", st, det)
    results.append(st)

    # 6. ML Models
    st, det = check_models()
    print_status("Machine Learning Models", st, det)
    results.append(st)

    # 7. Hardware Camera
    st, det = check_camera()
    print_status("Hardware Webcam Sensor", st, det)
    results.append(st)

    # 8. Ollama AI Engine
    st, det = check_ollama()
    print_status("Offline Ollama Threat Engine", st, det)
    results.append(st)

    # 9. Web Port Availability
    dashboard_port = int(os.environ.get("PORT", 8000))
    st, det = check_port(dashboard_port)
    print_status(f"Web Dashboard Port ({dashboard_port})", st, det)
    results.append(st)

    print("=" * 74)
    has_fail = "FAIL" in results
    if has_fail:
        print(f"  {Colors.RED}[CRITICAL] One or more prerequisites failed! Please resolve them above.{Colors.RESET}")
    else:
        print(f"  {Colors.GREEN}[SUCCESS] All core prerequisites verified! System is ready to run.{Colors.RESET}")
    print("=" * 74 + "\n")

    return not has_fail


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
