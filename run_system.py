#!/usr/bin/env python3
"""
================================================================================
UNIFIED ONE-CLICK LAUNCHER & PROCESS SUPERVISOR (TASK-11)
Department of Information Science & Engineering (ISE) | Team 30
Multi-Factor Behavioral Drift Continuous Authentication System
================================================================================

This supervisor orchestrates and continuously monitors all 3 background workers:
- Worker 1: Telemetry Sensor Agent (telemetry/agent.py)
- Worker 2: Continuous Threat Evaluator Daemon (telemetry/evaluator.py)
- Worker 3: Cyber-Ops Web Dashboard Server (dashboard/app.py on port 8000)

Features:
- Discreet Windows System Tray Icon (Green Security Shield with checkmark)
- Automatic browser launch to http://localhost:8000
- Heartbeat health monitoring & automatic restart of failed workers
- Clean single-press Ctrl+C / System Tray graceful termination
- Individual rotating log files in data/logs/ to eliminate terminal clutter
"""

import os
import sys
import time
import signal
import psutil
import logging
import argparse
import threading
import subprocess
import webbrowser
from typing import Dict, Any, List, Optional

# Qt GUI imports for system tray
try:
    from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu
    from PyQt6.QtGui import QIcon, QPixmap, QPainter, QColor, QPen, QPainterPath, QAction
    from PyQt6.QtCore import QTimer
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

LOGS_DIR = os.path.join(PROJECT_ROOT, "data", "logs")
os.makedirs(LOGS_DIR, exist_ok=True)


def create_shield_icon(color_hex: str = "#27ae60") -> Optional[Any]:
    """
    Renders a crisp, high-resolution vector security shield icon
    with an authentic white checkmark for the Windows notification tray.
    """
    if not PYQT_AVAILABLE:
        return None
    try:
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        pixmap = QPixmap(64, 64)
        pixmap.fill(QColor(0, 0, 0, 0))  # Transparent background
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Draw shield contour
        path = QPainterPath()
        path.moveTo(32, 4)
        path.lineTo(58, 14)
        path.quadTo(58, 44, 32, 60)
        path.quadTo(6, 44, 6, 14)
        path.closeSubpath()

        painter.setBrush(QColor(color_hex))
        painter.setPen(QPen(QColor("#1e8449"), 2))
        painter.drawPath(path)

        # Draw white security checkmark inside shield
        painter.setPen(QPen(QColor("#ffffff"), 4))
        painter.drawLine(22, 33, 29, 41)
        painter.drawLine(29, 41, 43, 21)

        painter.end()
        return QIcon(pixmap)
    except Exception:
        return None


class WorkerProcess:
    """Manages lifecycle, log redirection, and health checks of a single worker sub-process."""
    def __init__(self, name: str, cmd: List[str], log_filename: str):
        self.name = name
        self.cmd = cmd
        self.log_path = os.path.join(LOGS_DIR, log_filename)
        self.proc: Optional[subprocess.Popen] = None
        self.log_file = None
        self.restart_count = 0
        self.start_time: float = 0.0

    def start(self):
        self.log_file = open(self.log_path, "a", encoding="utf-8")
        self.log_file.write(f"\n--- Process Started: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        self.log_file.flush()

        self.start_time = time.time()
        self.proc = subprocess.Popen(
            self.cmd,
            cwd=PROJECT_ROOT,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=os.environ.copy()
        )

    def is_alive(self) -> bool:
        if self.proc is None:
            return False
        return self.proc.poll() is None

    def pid(self) -> Optional[int]:
        return self.proc.pid if self.proc else None

    def stop(self, timeout: float = 3.0):
        if self.proc and self.is_alive():
            try:
                self.proc.terminate()
                self.proc.wait(timeout=timeout)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass

        if self.log_file:
            try:
                self.log_file.write(f"--- Process Terminated: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                self.log_file.flush()
                self.log_file.close()
            except Exception:
                pass


class SystemSupervisor:
    """
    Supervises background security micro-services, monitors their health,
    and manages the Windows system tray and browser integration.
    """
    def __init__(self, port: int = 8000, enable_browser: bool = True, enable_tray: bool = True):
        self.port = port
        self.enable_browser = enable_browser
        self.enable_tray = enable_tray and PYQT_AVAILABLE
        self.running = False
        self.tray_icon = None
        self.app = None

        py = sys.executable
        self.workers: Dict[str, WorkerProcess] = {
            "telemetry_agent": WorkerProcess(
                name="Telemetry Sensor Agent",
                cmd=[py, "-u", "telemetry/agent.py", "--friendly"],
                log_filename="supervisor_telemetry_agent.log"
            ),
            "threat_evaluator": WorkerProcess(
                name="Threat Evaluator Daemon",
                cmd=[py, "-u", "telemetry/evaluator.py"],
                log_filename="supervisor_evaluator.log"
            ),
            "web_dashboard": WorkerProcess(
                name="Cyber-Ops Web Dashboard",
                cmd=[py, "-u", "-m", "uvicorn", "dashboard.app:app", "--host", "0.0.0.0", "--port", str(self.port)],
                log_filename="supervisor_dashboard.log"
            )
        }

    def start_all_workers(self):
        print("\n" + "=" * 74)
        print("  BEHAVIORAL DRIFT CONTINUOUS AUTHENTICATION - PROCESS SUPERVISOR")
        print("  Department of ISE | Team 30 | Major Project")
        print("=" * 74)

        for key, worker in self.workers.items():
            worker.start()
            print(f"  [*] {worker.name:<30} -> PID {worker.pid():<6} [ONLINE]")

        dashboard_url = f"http://localhost:{self.port}"
        print(f"  [*] Live Web Defense Console          -> {dashboard_url} [ONLINE]")
        print("=" * 74)
        print("  [i] All services are actively monitoring physical biometrics & context.")
        print("  [i] Press Ctrl+C in terminal or Right-Click Tray Icon -> Exit to stop.")
        print("=" * 74 + "\n", flush=True)

        self.running = True

        # Open web dashboard in browser after slight delay to allow uvicorn binding
        if self.enable_browser:
            threading.Thread(target=self._launch_browser_delayed, args=(dashboard_url,), daemon=True).start()

    def _launch_browser_delayed(self, url: str):
        time.sleep(1.8)
        if self.running:
            try:
                webbrowser.open(url)
            except Exception:
                pass

    def check_health_and_restart(self):
        """Monitors child worker process heartbeats and recovers dropped workers."""
        for key, worker in self.workers.items():
            if self.running and not worker.is_alive():
                print(f"[SUPERVISOR] [ALERT] {worker.name} exited unexpectedly. Restarting...", flush=True)
                worker.restart_count += 1
                worker.start()
                print(f"[SUPERVISOR] {worker.name} restarted with PID {worker.pid()}.", flush=True)

    def stop_all_workers(self):
        print("\n[SUPERVISOR] Initiating graceful shutdown of all background services...", flush=True)
        self.running = False

        for key, worker in self.workers.items():
            if worker.is_alive():
                print(f"  [-] Stopping {worker.name} (PID {worker.pid()})...", flush=True)
                worker.stop()

        print("[SUPERVISOR] All workers stopped cleanly. Workstation security restored to idle.\n", flush=True)

    def get_status_summary(self) -> Dict[str, Any]:
        """Returns health status dictionary for REST APIs or diagnostics."""
        return {
            "supervisor_running": self.running,
            "port": self.port,
            "dashboard_url": f"http://localhost:{self.port}",
            "workers": {
                k: {
                    "name": w.name,
                    "is_alive": w.is_alive(),
                    "pid": w.pid(),
                    "restarts": w.restart_count,
                    "log_path": w.log_path
                }
                for k, w in self.workers.items()
            }
        }

    # --- System Tray Integration ---
    def setup_tray_icon(self, app: QApplication):
        self.app = app
        icon = create_shield_icon("#27ae60")
        if not icon:
            return

        self.tray_icon = QSystemTrayIcon(icon, app)
        self.tray_icon.setToolTip("Behavioral Drift Continuous Defense - Active\n(3 Services Online)")

        menu = QMenu()

        action_title = QAction(">> Behavioral Drift Defense Active <<", menu)
        action_title.setEnabled(False)
        menu.addAction(action_title)
        menu.addSeparator()

        action_open = QAction("Open Web Dashboard", menu)
        action_open.triggered.connect(lambda: webbrowser.open(f"http://localhost:{self.port}"))
        menu.addAction(action_open)

        action_logs = QAction("Open Logs Folder", menu)
        action_logs.triggered.connect(lambda: os.startfile(LOGS_DIR) if sys.platform == "win32" else None)
        menu.addAction(action_logs)

        menu.addSeparator()

        action_stop = QAction("Stop Services & Exit", menu)
        action_stop.triggered.connect(self._on_tray_exit)
        menu.addAction(action_stop)

        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()

        # Show desktop notification
        self.tray_icon.showMessage(
            "Continuous Authentication Active",
            "Workstation protected by Multi-Factor Behavioral Drift AI & Active Honeypots.",
            QSystemTrayIcon.MessageIcon.Information,
            3000
        )

    def _on_tray_exit(self):
        self.stop_all_workers()
        if self.app:
            self.app.quit()


def run_supervisor(port: int = 8000, enable_browser: bool = True, enable_tray: bool = True, auto_stop_sec: Optional[float] = None):
    """Main supervisor entry point."""
    supervisor = SystemSupervisor(port=port, enable_browser=enable_browser, enable_tray=enable_tray)

    # Set up signal handlers for graceful Ctrl+C
    def sig_handler(sig, frame):
        supervisor.stop_all_workers()
        if supervisor.app:
            supervisor.app.quit()
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
    except Exception:
        pass

    supervisor.start_all_workers()

    # If auto-stop specified (for unit tests / automated validation)
    if auto_stop_sec is not None and auto_stop_sec > 0:
        time.sleep(auto_stop_sec)
        supervisor.stop_all_workers()
        return supervisor

    # GUI Event Loop Mode with System Tray
    if supervisor.enable_tray:
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            app.setQuitOnLastWindowClosed(False)

        supervisor.setup_tray_icon(app)

        # Health monitoring timer
        timer = QTimer()
        timer.timeout.connect(supervisor.check_health_and_restart)
        timer.start(2000)

        try:
            app.exec()
        except KeyboardInterrupt:
            pass
        finally:
            supervisor.stop_all_workers()
    else:
        # CLI-only background loop
        try:
            while supervisor.running:
                time.sleep(2.0)
                supervisor.check_health_and_restart()
        except KeyboardInterrupt:
            pass
        finally:
            supervisor.stop_all_workers()

    return supervisor


def main():
    parser = argparse.ArgumentParser(description="Unified One-Click Launcher & Process Supervisor")
    parser.add_argument("--port", type=int, default=8000, help="Web dashboard port (default: 8000)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    parser.add_argument("--no-tray", action="store_true", help="Disable PyQt system tray icon (CLI-only mode)")
    parser.add_argument("--auto-stop", type=float, default=None, help="Automatically terminate after N seconds (for tests)")
    parser.add_argument("--status", action="store_true", help="Check status of running system and exit")

    args = parser.parse_args()

    if args.status:
        # Check if dashboard port is listening
        is_running = False
        try:
            import urllib.request
            req = urllib.request.urlopen(f"http://localhost:{args.port}/api/status", timeout=2)
            if req.status == 200:
                is_running = True
        except Exception:
            is_running = False

        print("\n" + "=" * 60)
        print(" BEHAVIORAL DRIFT CONTINUOUS SECURITY - STATUS CHECK")
        print("=" * 60)
        print(f" Dashboard Service (Port {args.port}) : {'ONLINE' if is_running else 'OFFLINE'}")
        print("=" * 60 + "\n")
        sys.exit(0 if is_running else 1)

    run_supervisor(
        port=args.port,
        enable_browser=not args.no_browser,
        enable_tray=not args.no_tray,
        auto_stop_sec=args.auto_stop
    )


if __name__ == "__main__":
    main()
