import os
import sys
import time
import json
import glob
import asyncio
import logging
import subprocess
from typing import List, Optional
from contextlib import asynccontextmanager
from collections import deque

import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _load_local_env_defaults():
    """Populate unset environment variables from .env without overriding process env."""
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#") and "=" in s:
                    k, v = s.split("=", 1)
                    key = k.strip()
                    val = v.strip().strip('"').strip("'")
                    if key and val and not os.environ.get(key):
                        os.environ[key] = val
    except Exception:
        pass


_load_local_env_defaults()

def _is_worker_supervisor_active() -> bool:
    """Returns True when Process Supervisor Worker 2 owns desktop breach alerts."""
    lock_path = os.path.join(PROJECT_ROOT, "data", "logs", "supervisor.lock")
    if not os.path.exists(lock_path):
        return False
    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            info = json.load(f)
        pid = int(info.get("pid", -1))
        if pid > 0 and psutil.pid_exists(pid):
            proc = psutil.Process(pid)
            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                return "run_system.py" in " ".join(proc.cmdline()).lower()
    except Exception:
        pass
    return False


active_breach_is_simulated = False

# Windows active window helper
try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None

from telemetry.evaluator import ThreatEvaluator
from deception.forensic_tracker import get_tracker
from deception.ai_intent_analyzer import IntruderIntentAnalyzer
from dashboard.pdf_generator import ForensicReportGenerator

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dashboard_app")

# ---------------------------------------------------------
# Global State & Singletons
# ---------------------------------------------------------
evaluator = ThreatEvaluator()
tracker = get_tracker()
report_generator = ForensicReportGenerator()
ai_analyzer = IntruderIntentAnalyzer()

# Rolling telemetry buffer (stores last 120 seconds of telemetry records)
telemetry_history: deque = deque(maxlen=120)
incident_log: deque = deque(maxlen=60)
server_start_time = time.time()

# Default initial state (truthful idle baseline; updated only by real or explicitly simulated events)
current_telemetry_state = {
    "timestamp": time.time(),
    "instant_risk": 0.0,
    "smoothed_risk": 0.0,
    "threshold": 0.55,
    "status": "NORMAL",  # NORMAL | WARNING | BREACHED
    "data_state": "IDLE",  # IDLE | LIVE | STALE | SIMULATED
    "is_simulated": False,
    "append_chart": False,
    "telemetry_age_seconds": None,
    "active_app": "None",
    "active_window": "Waiting for telemetry window",
    "interaction_mode": "idle",
    "dwell_mean": 0.0,
    "flight_mean": 0.0,
    "keystroke_count": 0,
    "mouse_velocity": 0.0,
    "mouse_events": 0,
    "cpu_usage": 0.0,
    "ram_usage_mb": 0.0,
    "is_breached": False,
    "otp_issued": False,
    "svdd_confidence": 1.0,
    "event_count": 0
}

# Cached AI analysis keyed by (session_id, timeline_length)
_cached_ai_key = None
_cached_ai_report = None


def _get_cached_ai_analysis(timeline, stats):
    """Returns real IntruderIntentAnalyzer output cached per forensic timeline state."""
    global _cached_ai_key, _cached_ai_report
    session_id = stats.get("session_id", "") if isinstance(stats, dict) else ""
    cache_key = (session_id, len(timeline))
    if _cached_ai_key == cache_key and _cached_ai_report is not None:
        return _cached_ai_report

    if not timeline:
        report = ai_analyzer._build_empty_session_report()
        report["attacker_persona"] = "Awaiting Intruder Event"
        report["primary_intent"] = "System monitoring baseline owner behavior. Honeypot armed."
        report["source"] = "Baseline Monitor"
    else:
        try:
            report = ai_analyzer.analyze_session(timeline=timeline, stats=stats)
        except Exception:
            report = ai_analyzer._heuristic_expert_analysis(
                timeline, stats, ai_analyzer.evaluate_deterministic_threat(timeline, stats)
            )
    _cached_ai_key = cache_key
    _cached_ai_report = report
    return report

# ---------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------
def get_foreground_window_info():
    """Retrieves active window title and process name on Windows."""
    if win32gui is None:
        return "System.exe", "Active Desktop Session"
    try:
        hwnd = win32gui.GetForegroundWindow()
        if not hwnd:
            return "explorer.exe", "Desktop"
        title = win32gui.GetWindowText(hwnd) or "Active Window"
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        try:
            proc = psutil.Process(pid)
            app_name = proc.name()
        except Exception:
            app_name = "explorer.exe"
        return app_name, title
    except Exception:
        return "Code.exe", "Major Project Workspace"


def scan_latest_forensic_files():
    """Scans data/forensics for the newest PDF report, intruder photo, and session actions."""
    forensics_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
    latest_pdf = None
    latest_intruder = None
    desktop_snapshot = os.path.join(forensics_dir, "desktop_snapshot.png")

    if os.path.exists(forensics_dir):
        # Latest PDF
        pdfs = glob.glob(os.path.join(forensics_dir, "*.pdf"))
        if pdfs:
            pdfs.sort(key=os.path.getmtime, reverse=True)
            latest_pdf = {
                "filename": os.path.basename(pdfs[0]),
                "filepath": pdfs[0],
                "size_kb": round(os.path.getsize(pdfs[0]) / 1024, 1),
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(pdfs[0])))
            }

        # Latest Intruder photo
        intruders = glob.glob(os.path.join(forensics_dir, "intruder_*.jpg"))
        if intruders:
            intruders.sort(key=os.path.getmtime, reverse=True)
            latest_intruder = {
                "filename": os.path.basename(intruders[0]),
                "filepath": intruders[0],
                "size_kb": round(os.path.getsize(intruders[0]) / 1024, 1),
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getmtime(intruders[0])))
            }

    return latest_pdf, latest_intruder, os.path.exists(desktop_snapshot)


# ---------------------------------------------------------
# WebSocket Connection Manager
# ---------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        dead_connections = []
        async with self._lock:
            connections = list(self.active_connections)

        for ws in connections:
            try:
                await ws.send_json(message)
            except Exception:
                dead_connections.append(ws)

        if dead_connections:
            async with self._lock:
                for ws in dead_connections:
                    if ws in self.active_connections:
                        self.active_connections.remove(ws)


ws_manager = ConnectionManager()


# ---------------------------------------------------------
# Background Telemetry Engine & WebSocket Emitter
# ---------------------------------------------------------
class TelemetryStreamer:
    def __init__(self):
        self.running = False
        self.task: Optional[asyncio.Task] = None
        self.last_file_pos = 0
        self._last_file_head = ""
        self.last_real_telemetry_ts: Optional[float] = None
        self.telemetry_file = os.environ.get(
            "TELEMETRY_LOG_PATH",
            os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
        )

    async def start(self):
        self.running = True
        self.task = asyncio.create_task(self._stream_loop())
        logger.info("TelemetryStreamer background loop launched.")

    async def stop(self):
        self.running = False
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        logger.info("TelemetryStreamer background loop stopped.")

    async def _stream_loop(self):
        # Seek cleanly to EOF so we never parse partial JSON lines or replay old sessions
        if os.path.exists(self.telemetry_file):
            try:
                self.last_file_pos = os.path.getsize(self.telemetry_file)
            except Exception:
                self.last_file_pos = 0

        while self.running:
            global active_breach_is_simulated
            try:
                sync_event = evaluator.sync_cross_process_state()
                if sync_event == "RESET":
                    active_breach_is_simulated = False
                if sync_event == "RESET" and current_telemetry_state.get("is_breached"):
                    current_telemetry_state.update({
                        "instant_risk": 0.0,
                        "smoothed_risk": 0.0,
                        "status": "NORMAL",
                        "data_state": "IDLE",
                        "is_simulated": False,
                        "is_breached": False,
                        "otp_issued": False,
                        "append_chart": False,
                    })

                new_row = self._read_next_telemetry_line()
                now = time.time()
                otp_issued = bool(evaluator.active_otp or evaluator._load_active_otp())

                if new_row:
                    # Score telemetry line without duplicating Worker 2 desktop alerts when supervisor is active
                    emit_alerts = not _is_worker_supervisor_active()
                    fused_risk, smoothed_risk, triggered = evaluator.evaluate_row(new_row, emit_alerts=emit_alerts)
                    svdd_conf = round(float(getattr(evaluator, "last_svdd_conf", 0.98)), 3)
                    app_name = new_row.get("active_app", "unknown")
                    win_title = new_row.get("active_window", "Active Desktop")
                    mode = new_row.get("interaction_mode", "general_productivity")
                    dwell = float(new_row.get("dwell_mean", 0.0))
                    flight = float(new_row.get("flight_mean", 0.0))
                    k_count = int(new_row.get("keystroke_count", 0))
                    m_vel = float(new_row.get("mouse_velocity_mean", 0.0))
                    m_events = int(new_row.get("mouse_events", 0))
                    cpu = float(new_row.get("cpu_usage", 0.0))
                    ram = float(new_row.get("ram_usage_mb", 0.0))
                    is_sim = bool(new_row.get("is_simulated", False))

                    self.last_real_telemetry_ts = now
                    data_state = "SIMULATED" if is_sim else ("IDLE" if (k_count == 0 and m_events < 5) else "LIVE")
                    status = "BREACHED" if (evaluator.is_breached or fused_risk >= 0.78) else (
                        "WARNING" if (fused_risk >= 0.40 or smoothed_risk >= 0.40) else "NORMAL"
                    )

                    if triggered:
                        incident_log.appendleft({
                            "time": time.strftime("%H:%M:%S"),
                            "level": "CRITICAL",
                            "message": f"Behavioral Drift Breach Triggered! Risk: {fused_risk:.2f} (Threshold: 0.55). Honeypot Activated."
                        })

                    current_telemetry_state.update({
                        "timestamp": now,
                        "instant_risk": round(fused_risk, 3),
                        "smoothed_risk": round(smoothed_risk, 3),
                        "threshold": 0.55,
                        "status": status,
                        "data_state": data_state,
                        "is_simulated": is_sim,
                        "append_chart": True,
                        "telemetry_age_seconds": 0.0,
                        "active_app": app_name,
                        "active_window": win_title,
                        "interaction_mode": mode,
                        "dwell_mean": round(dwell, 4),
                        "flight_mean": round(flight, 4),
                        "keystroke_count": k_count,
                        "mouse_velocity": round(m_vel, 1),
                        "mouse_events": m_events,
                        "cpu_usage": round(cpu, 1),
                        "ram_usage_mb": round(ram, 1),
                        "is_breached": evaluator.is_breached,
                        "otp_issued": bool(evaluator.active_otp or evaluator._load_active_otp()),
                        "svdd_confidence": svdd_conf,
                        "event_count": current_telemetry_state.get("event_count", 0) + 1
                    })
                    telemetry_history.append(dict(current_telemetry_state))
                else:
                    # Truthful heartbeat when no new telemetry window has arrived (never fake metrics)
                    app_name, win_title = get_foreground_window_info()
                    cpu = psutil.cpu_percent(interval=None)
                    ram = psutil.virtual_memory().used / (1024 * 1024)
                    age = round(now - self.last_real_telemetry_ts, 1) if self.last_real_telemetry_ts is not None else None

                    if current_telemetry_state.get("is_simulated") and evaluator.is_breached:
                        data_state = "SIMULATED"
                    elif age is not None and age > 25.0:
                        data_state = "STALE"
                    else:
                        data_state = "IDLE"

                    status = "BREACHED" if evaluator.is_breached else (
                        "WARNING" if current_telemetry_state.get("smoothed_risk", 0.0) >= 0.40 else "NORMAL"
                    )

                    current_telemetry_state.update({
                        "timestamp": now,
                        "status": status,
                        "data_state": data_state,
                        "append_chart": False,
                        "telemetry_age_seconds": age,
                        "active_app": app_name if current_telemetry_state.get("event_count", 0) == 0 else current_telemetry_state["active_app"],
                        "active_window": win_title if current_telemetry_state.get("event_count", 0) == 0 else current_telemetry_state["active_window"],
                        "cpu_usage": round(cpu, 1),
                        "ram_usage_mb": round(ram, 1),
                        "is_breached": evaluator.is_breached,
                        "otp_issued": otp_issued,
                    })

                payload = {
                    "type": "TELEMETRY_UPDATE",
                    "data": current_telemetry_state,
                    "latest_alert": incident_log[0] if incident_log else None
                }
                await ws_manager.broadcast(payload)

            except Exception as e:
                logger.error(f"Error in telemetry stream loop: {e}")

            await asyncio.sleep(1.0)

    def _read_next_telemetry_line(self):
        """Tails telemetry_data.jsonl safely, handling truncation/rotation and partial writes."""
        if not os.path.exists(self.telemetry_file):
            self.last_file_pos = 0
            self._last_file_head = ""
            return None
        try:
            file_size = os.path.getsize(self.telemetry_file)
            with open(self.telemetry_file, "r", encoding="utf-8", errors="replace") as f:
                head_sample = f.read(128)
                rewritten = bool(
                    self._last_file_head
                    and not (
                        head_sample.startswith(self._last_file_head)
                        or self._last_file_head.startswith(head_sample)
                    )
                )
                if file_size < self.last_file_pos or rewritten:
                    self.last_file_pos = 0
                self._last_file_head = head_sample

                f.seek(self.last_file_pos)
                while True:
                    line = f.readline()
                    if not line:
                        self.last_file_pos = f.tell()
                        break
                    if not line.endswith("\n"):
                        # Partial write in progress; wait for newline
                        break
                    self.last_file_pos = f.tell()
                    stripped = line.strip()
                    if stripped:
                        return json.loads(stripped)
        except Exception:
            pass
        return None


streamer = TelemetryStreamer()


# ---------------------------------------------------------
# FastAPI App Setup & Lifespan
# ---------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Starting Continuous Authentication SOC Web Server...")
    incident_log.appendleft({
        "time": time.strftime("%H:%M:%S"),
        "level": "INFO",
        "message": "Continuous Authentication SOC Daemon initialized. Quad-Factor ML Engine Online."
    })
    await streamer.start()
    yield
    # Shutdown
    logger.info("Stopping Continuous Authentication SOC Web Server...")
    await streamer.stop()


app = FastAPI(
    title="Behavioral Drift Continuous Authentication SOC",
    description="Real-Time Desktop Security, Behavioral Drift Monitoring, Honeypot Deception & AI Forensics",
    version="2.0.0",
    lifespan=lifespan
)

# Enable CORS strictly for configured/local origins (wildcard credentials disabled)
_default_port = os.environ.get("PORT", "8000").strip() or "8000"
_cors_env = os.environ.get(
    "CORS_ORIGINS",
    f"http://localhost:{_default_port},http://127.0.0.1:{_default_port},http://localhost:8000,http://127.0.0.1:8000",
)
_allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static and Templates Mounts
static_dir = os.path.join(PROJECT_ROOT, "dashboard", "static")
templates_dir = os.path.join(PROJECT_ROOT, "dashboard", "templates")
app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)


# ---------------------------------------------------------
# Pydantic Request Models
# ---------------------------------------------------------
class SimulateAnomalyRequest(BaseModel):
    anomaly_type: str = "acute_spike"  # acute_spike | sluggish_typing | frantic_erratic | sustained_drift
    severity: float = 0.88


class ResetSecurityRequest(BaseModel):
    bypass_key: str = ""


# ---------------------------------------------------------
# Web Page Route
# ---------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
async def serve_dashboard(request: Request):
    """Renders the master cyber-defense monitoring interface."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "title": "Continuous Authentication SOC",
            "team_id": "Team 30 | ISE Dept | NMAMIT"
        }
    )


# ---------------------------------------------------------
# WebSocket Endpoint
# ---------------------------------------------------------
@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket):
    """Real-time bi-directional telemetry streaming over WebSocket."""
    await ws_manager.connect(websocket)
    try:
        # Send initial snapshot immediately upon connection
        await websocket.send_json({
            "type": "INITIAL_SNAPSHOT",
            "data": current_telemetry_state,
            "history": list(telemetry_history),
            "incidents": list(incident_log)
        })
        while True:
            # Handle incoming client messages (e.g., ping or client actions)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                cmd = msg.get("command")
                if cmd == "ping":
                    await websocket.send_json({"type": "PONG", "time": time.time()})
                elif cmd == "simulate_anomaly":
                    await handle_simulate_anomaly(msg.get("anomaly_type", "acute_spike"), msg.get("severity", 0.88))
                elif cmd == "reset":
                    res = await handle_security_reset(msg.get("bypass_key", ""))
                    if isinstance(res, JSONResponse):
                        await websocket.send_json({
                            "type": "RESET_DENIED",
                            "message": "Invalid verification credential. Provide the valid 6-digit OTP or Recovery Key."
                        })
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket)


# ---------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------
@app.get("/api/status")
async def get_system_status():
    """Returns overall health, models, and breach status."""
    evaluator.sync_cross_process_state()
    latest_pdf, latest_intruder, has_desktop = scan_latest_forensic_files()
    return {
        "status": "ONLINE",
        "evaluator_models_loaded": evaluator.models_loaded,
        "deep_svdd_active": evaluator.sequence_detector.model is not None,
        "is_breached": evaluator.is_breached,
        "otp_issued": bool(evaluator.active_otp or evaluator._load_active_otp()),
        "data_state": current_telemetry_state.get("data_state", "IDLE"),
        "is_simulated": current_telemetry_state.get("is_simulated", False),
        "current_instant_risk": current_telemetry_state["instant_risk"],
        "current_smoothed_risk": current_telemetry_state["smoothed_risk"],
        "threshold": 0.55,
        "active_ws_clients": len(ws_manager.active_connections),
        "uptime_seconds": round(time.time() - server_start_time, 1),
        "latest_forensic_pdf": latest_pdf["filename"] if latest_pdf else None,
        "latest_intruder_photo": latest_intruder["filename"] if latest_intruder else None,
        "honeypot_actions_recorded": len(tracker.events)
    }


@app.get("/api/telemetry/recent")
async def get_recent_telemetry(limit: int = Query(60, ge=5, le=120)):
    """Returns the rolling history of recent telemetry frames for charting."""
    data = list(telemetry_history)[-limit:]
    return {
        "count": len(data),
        "history": data,
        "current": current_telemetry_state
    }


@app.get("/api/forensics/latest")
async def get_latest_forensics():
    """Returns metadata and grounded AI/heuristic threat assessment for latest forensic captures."""
    latest_pdf, latest_intruder, has_desktop = scan_latest_forensic_files()
    timeline = tracker.get_timeline()
    stats = tracker.get_summary_stats()
    ai_report = await asyncio.to_thread(_get_cached_ai_analysis, timeline, stats)

    return {
        "has_forensics": latest_pdf is not None or latest_intruder is not None,
        "latest_pdf": latest_pdf,
        "latest_intruder": latest_intruder,
        "has_desktop_snapshot": has_desktop,
        "stats": stats,
        "timeline_events_count": len(timeline),
        "recent_timeline": timeline[-10:] if timeline else [],
        "ai_analysis": {
            "threat_level": ai_report.get("threat_level", "LOW"),
            "threat_score": ai_report.get("threat_score", 0.05),
            "attacker_persona": ai_report.get("attacker_persona", "Awaiting Intruder Event"),
            "primary_intent": ai_report.get("primary_intent", "System monitoring baseline owner behavior."),
            "mitre_tactics": ai_report.get("mitre_tactics", []),
            "model_name": ai_report.get("model_name", "None"),
            "source": ai_report.get("source", "Baseline Monitor"),
            "observed_facts": ai_report.get("observed_facts", []),
        }
    }


@app.get("/api/forensics/download_pdf")
async def download_forensic_pdf(name: Optional[str] = None):
    """Downloads the latest or specified forensic PDF report."""
    forensics_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
    
    if name:
        target_path = os.path.join(forensics_dir, os.path.basename(name))
        if os.path.exists(target_path):
            return FileResponse(target_path, media_type="application/pdf", filename=os.path.basename(target_path), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

    # Pick latest PDF
    pdfs = glob.glob(os.path.join(forensics_dir, "*.pdf"))
    if pdfs:
        pdfs.sort(key=os.path.getmtime, reverse=True)
        latest = pdfs[0]
        return FileResponse(latest, media_type="application/pdf", filename=os.path.basename(latest), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

    # If no PDF exists, generate one dynamically!
    try:
        new_pdf = report_generator.generate_report()
        return FileResponse(new_pdf, media_type="application/pdf", filename=os.path.basename(new_pdf), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate forensic PDF: {str(e)}")


@app.post("/api/forensics/generate_pdf")
async def trigger_generate_pdf():
    """Generates a fresh multi-page Forensic PDF Report immediately on demand."""
    try:
        pdf_path = report_generator.generate_report()
        filename = os.path.basename(pdf_path)
        incident_log.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "level": "INFO",
            "message": f"Generated Forensic PDF Report '{filename}' with SHA-256 seal."
        })
        return {
            "success": True,
            "filename": filename,
            "path": pdf_path,
            "download_url": f"/api/forensics/download_pdf?name={filename}"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation failed: {str(e)}")


@app.get("/api/forensics/intruder_photo")
async def get_intruder_photo(name: Optional[str] = None):
    """Serves the latest or requested intruder webcam snapshot."""
    forensics_dir = os.path.join(PROJECT_ROOT, "data", "forensics")
    if name:
        target = os.path.join(forensics_dir, os.path.basename(name))
        if os.path.exists(target):
            return FileResponse(target, media_type="image/jpeg")

    intruders = glob.glob(os.path.join(forensics_dir, "intruder_*.jpg"))
    if intruders:
        intruders.sort(key=os.path.getmtime, reverse=True)
        return FileResponse(intruders[0], media_type="image/jpeg")

    # Fallback to desktop snapshot if intruder photo not yet captured
    desktop = os.path.join(forensics_dir, "desktop_snapshot.png")
    if os.path.exists(desktop):
        return FileResponse(desktop, media_type="image/png")

    raise HTTPException(status_code=404, detail="No intruder photo available yet.")


@app.get("/api/forensics/desktop_snapshot")
async def get_desktop_snapshot():
    """Serves the preserved authentic Windows desktop wallpaper snapshot."""
    snapshot_path = os.path.join(PROJECT_ROOT, "data", "forensics", "desktop_snapshot.png")
    if os.path.exists(snapshot_path):
        return FileResponse(snapshot_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Desktop snapshot not found.")


@app.post("/api/security/simulate_anomaly")
async def simulate_anomaly_endpoint(req: SimulateAnomalyRequest):
    """
    Simulates an imposter behavioral anomaly for professor / evaluator demonstrations.
    Directly injects anomalous biometric features, triggers threat escalation,
    and broadcasts live across WebSockets.
    """
    result = await handle_simulate_anomaly(req.anomaly_type, req.severity)
    return result


async def handle_simulate_anomaly(anomaly_type: str, severity: float):
    now = time.time()
    
    if anomaly_type == "acute_spike":
        # Frantic / erratic keystroke and mouse behavior
        simulated_row = {
            "timestamp": now,
            "hour_of_day": int(time.strftime("%H")),
            "keystroke_count": 8,
            "dwell_mean": 0.28,
            "dwell_std": 0.18,
            "flight_mean": 0.52,
            "flight_std": 0.35,
            "app_dwell_mean": 0.28,
            "app_flight_mean": 0.52,
            "app_backspace_ratio": 0.25,
            "app_special_ratio": 0.0,
            "app_click_count": 2,
            "app_scroll_count": 0,
            "app_pause_ratio": 0.40,
            "avg_thinking_pause_sec": 4.5,
            "interaction_mode": "unauthorized_recon",
            "micro_session_id": "sim_anomaly_acute",
            "mouse_events": 450,
            "mouse_velocity_mean": 1250.0,
            "mouse_acceleration_mean": 4500.0,
            "mouse_jerk_mean": -6500000.0,
            "mouse_straightness_mean": 0.55,
            "active_app": "powershell.exe",
            "active_window": "Windows PowerShell - Administrative Recon",
            "cpu_usage": 78.5,
            "ram_usage_mb": 420.0
        }
        reason = "ACUTE INTRUSION ATTACK (Sluggish Hunt-and-Peck + PowerShell Recon)"
    elif anomaly_type == "sluggish_typing":
        # Slow, uncertain imposter typing
        simulated_row = {
            "timestamp": now,
            "hour_of_day": int(time.strftime("%H")),
            "keystroke_count": 5,
            "dwell_mean": 0.34,
            "dwell_std": 0.12,
            "flight_mean": 0.68,
            "flight_std": 0.42,
            "app_dwell_mean": 0.34,
            "app_flight_mean": 0.68,
            "app_backspace_ratio": 0.40,
            "app_special_ratio": 0.0,
            "app_click_count": 0,
            "app_scroll_count": 1,
            "app_pause_ratio": 0.60,
            "avg_thinking_pause_sec": 6.2,
            "interaction_mode": "unauthorized_access",
            "micro_session_id": "sim_anomaly_sluggish",
            "mouse_events": 80,
            "mouse_velocity_mean": 140.0,
            "mouse_acceleration_mean": 600.0,
            "mouse_jerk_mean": -200000.0,
            "mouse_straightness_mean": 0.45,
            "active_app": "cmd.exe",
            "active_window": "Command Prompt - whoami /priv",
            "cpu_usage": 45.0,
            "ram_usage_mb": 210.0
        }
        reason = "SLUGGISH IMPOSTER TYPING (High Dwell & Extreme Inter-Key Delays)"
    elif anomaly_type == "frantic_erratic":
        # Rapid, frantic keystrokes and erratic mouse movement
        simulated_row = {
            "timestamp": now,
            "hour_of_day": int(time.strftime("%H")),
            "keystroke_count": 28,
            "dwell_mean": 0.035,
            "dwell_std": 0.015,
            "flight_mean": 0.055,
            "flight_std": 0.020,
            "app_dwell_mean": 0.035,
            "app_flight_mean": 0.055,
            "app_backspace_ratio": 0.0,
            "app_special_ratio": 0.60,
            "app_click_count": 15,
            "app_scroll_count": 25,
            "app_pause_ratio": 0.0,
            "avg_thinking_pause_sec": 0.0,
            "interaction_mode": "rapid_automation",
            "micro_session_id": "sim_anomaly_frantic",
            "mouse_events": 950,
            "mouse_velocity_mean": 1850.0,
            "mouse_acceleration_mean": 6200.0,
            "mouse_jerk_mean": -9500000.0,
            "mouse_straightness_mean": 0.35,
            "active_app": "mimikatz.exe",
            "active_window": "mimikatz # sekurlsa::logonpasswords",
            "cpu_usage": 88.0,
            "ram_usage_mb": 512.0
        }
        reason = "FRANTIC AUTOMATION / ERRATIC SCRIPT ANOMALY"
    else:  # sustained_drift
        simulated_row = {
            "timestamp": now,
            "hour_of_day": int(time.strftime("%H")),
            "keystroke_count": 12,
            "dwell_mean": 0.22,
            "dwell_std": 0.08,
            "flight_mean": 0.38,
            "flight_std": 0.15,
            "app_dwell_mean": 0.22,
            "app_flight_mean": 0.38,
            "app_backspace_ratio": 0.15,
            "app_special_ratio": 0.10,
            "app_click_count": 4,
            "app_scroll_count": 5,
            "app_pause_ratio": 0.30,
            "avg_thinking_pause_sec": 3.0,
            "interaction_mode": "suspicious_drift",
            "micro_session_id": "sim_anomaly_drift",
            "mouse_events": 300,
            "mouse_velocity_mean": 680.0,
            "mouse_acceleration_mean": 1800.0,
            "mouse_jerk_mean": -1200000.0,
            "mouse_straightness_mean": 0.60,
            "active_app": "chrome.exe",
            "active_window": "Honeypot Bank Portal Recon",
            "cpu_usage": 55.0,
            "ram_usage_mb": 310.0
        }
        reason = "SUSTAINED MULTI-WINDOW BEHAVIORAL DRIFT"

    # Tag row clearly as simulated
    simulated_row["is_simulated"] = True

    global active_breach_is_simulated
    existing_real_breach = bool(
        evaluator.is_breached
        and not active_breach_is_simulated
        and (evaluator.active_otp or evaluator._load_active_otp())
    )

    # Evaluate the simulated row (suppress side-effectful alerts when a real breach is already active)
    fused_risk, smoothed_risk, triggered = evaluator.evaluate_row(simulated_row, emit_alerts=not existing_real_breach)
    svdd_conf = round(float(getattr(evaluator, "last_svdd_conf", max(0.0, 1.0 - fused_risk))), 3)

    # Force elevate if severity specified
    forced_risk = max(fused_risk, severity)
    evaluator.is_breached = True
    exposed_sim_otp = None
    if not existing_real_breach:
        active_breach_is_simulated = True
        if not evaluator.active_otp:
            from security.otp_service import generate_otp
            evaluator.active_otp = generate_otp()
        evaluator._save_active_otp(evaluator.active_otp, is_breach=True)
        exposed_sim_otp = evaluator.active_otp

    # Record in tracker
    tracker.record_shell_command(
        command=f"[ANOMALY SIMULATION] {reason}",
        current_dir="C:\\Security\\Simulation"
    )

    incident_log.appendleft({
        "time": time.strftime("%H:%M:%S"),
        "level": "CRITICAL",
        "message": f"[SIMULATED BREACH] {reason} | Risk: {forced_risk:.2f} (Threshold: 0.55)"
    })

    current_telemetry_state.update({
        "timestamp": now,
        "instant_risk": round(forced_risk, 3),
        "smoothed_risk": round(forced_risk * 0.92, 3),
        "status": "BREACHED",
        "data_state": "SIMULATED",
        "is_simulated": True,
        "append_chart": True,
        "telemetry_age_seconds": 0.0,
        "active_app": simulated_row["active_app"],
        "active_window": simulated_row["active_window"],
        "interaction_mode": simulated_row["interaction_mode"],
        "dwell_mean": simulated_row["dwell_mean"],
        "flight_mean": simulated_row["flight_mean"],
        "keystroke_count": simulated_row["keystroke_count"],
        "mouse_velocity": simulated_row["mouse_velocity_mean"],
        "mouse_events": simulated_row["mouse_events"],
        "cpu_usage": simulated_row["cpu_usage"],
        "ram_usage_mb": simulated_row["ram_usage_mb"],
        "is_breached": True,
        "otp_issued": True,
        "svdd_confidence": svdd_conf,
        "event_count": current_telemetry_state.get("event_count", 0) + 1
    })

    telemetry_history.append(dict(current_telemetry_state))

    # Persist simulated row to telemetry stream for daemon IPC synchronization (unless disabled for isolated tests)
    if os.environ.get("DISABLE_SIM_TELEMETRY_WRITE") != "1":
        try:
            telemetry_file = streamer.telemetry_file
            os.makedirs(os.path.dirname(os.path.abspath(telemetry_file)), exist_ok=True)
            with open(telemetry_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(simulated_row) + "\n")
                f.flush()
        except Exception as e:
            logger.warning(f"Could not append simulated anomaly to telemetry log: {e}")

    # Broadcast breach immediately without exposing raw OTP
    await ws_manager.broadcast({
        "type": "BREACH_ALERT",
        "data": current_telemetry_state,
        "latest_alert": incident_log[0]
    })

    return {
        "status": "success",
        "anomaly_type": anomaly_type,
        "reason": reason,
        "instant_risk": forced_risk,
        "smoothed_risk": current_telemetry_state["smoothed_risk"],
        "is_breached": True,
        "is_simulated": True,
        "otp_issued": True,
        "otp_redacted": existing_real_breach,
        "simulated_otp": exposed_sim_otp,
    }


@app.post("/api/security/reset")
async def reset_security_endpoint(req: Optional[ResetSecurityRequest] = None):
    """
    Verifies OTP / configured Emergency Recovery Key and resets the security breach state.
    Rejects unauthenticated or trivial credentials with HTTP 403.
    """
    bypass = req.bypass_key if req else ""
    result = await handle_security_reset(bypass)
    return result


async def handle_security_reset(bypass_key: str = ""):
    verified = evaluator.verify_otp_and_reset(bypass_key)
    if not verified:
        incident_log.appendleft({
            "time": time.strftime("%H:%M:%S"),
            "level": "WARNING",
            "message": "SECURITY RESET DENIED: Invalid 6-digit OTP or Recovery Key."
        })
        await ws_manager.broadcast({
            "type": "RESET_DENIED",
            "latest_alert": incident_log[0]
        })
        return JSONResponse(
            status_code=403,
            content={
                "status": "denied",
                "message": "Verification failed. Enter the active 6-digit OTP or configured Emergency Recovery Key.",
                "is_breached": evaluator.is_breached
            }
        )

    global active_breach_is_simulated
    active_breach_is_simulated = False

    incident_log.appendleft({
        "time": time.strftime("%H:%M:%S"),
        "level": "SUCCESS",
        "message": "Security State Normalized. Identity Verified. Quad-Factor Engine adapted to baseline."
    })

    current_telemetry_state.update({
        "instant_risk": 0.0,
        "smoothed_risk": 0.0,
        "status": "NORMAL",
        "data_state": "IDLE",
        "is_simulated": False,
        "append_chart": True,
        "is_breached": False,
        "otp_issued": False,
        "svdd_confidence": 1.0
    })
    telemetry_history.append(dict(current_telemetry_state))

    await ws_manager.broadcast({
        "type": "SYSTEM_RESET",
        "data": current_telemetry_state,
        "latest_alert": incident_log[0]
    })

    return {
        "status": "success",
        "message": "Security breach reset. Continuous monitoring resumed.",
        "is_breached": False
    }


@app.get("/api/incidents")
async def get_incident_feed():
    """Returns recent security incident log entries."""
    return {
        "count": len(incident_log),
        "incidents": list(incident_log)
    }


class StepUpVerifyRequest(BaseModel):
    entered_code: str = ""


@app.get("/api/security/tier_status")
async def get_security_tier_status():
    """Returns current 3-tier risk orchestration status and recent transitions."""
    if evaluator.orchestrator:
        return evaluator.orchestrator.get_status()
    return {
        "current_tier": "TIER_1_LOW",
        "thresholds": {"low": 0.40, "high": 0.75},
        "active_step_up_challenge": False,
        "step_up_failures": 0,
        "total_evaluations": 0,
        "recent_transitions": []
    }


@app.post("/api/security/step_up_verify")
async def verify_step_up_endpoint(req: StepUpVerifyRequest):
    """Verifies a non-blocking Tier 2 step-up MFA challenge."""
    if evaluator.orchestrator:
        active_code = evaluator.active_otp or evaluator._load_active_otp()
        success, msg = evaluator.orchestrator.verify_step_up(req.entered_code, active_code)
        if success:
            current_telemetry_state["status"] = "NORMAL"
            current_telemetry_state["instant_risk"] = 0.08
            incident_log.appendleft({
                "time": time.strftime("%H:%M:%S"),
                "level": "SUCCESS",
                "message": f"Tier 2 Step-Up Challenge Verified. Restored Tier 1 baseline."
            })
        else:
            incident_log.appendleft({
                "time": time.strftime("%H:%M:%S"),
                "level": "WARNING",
                "message": f"Tier 2 Step-Up Failed ({evaluator.orchestrator.step_up_failures}/3): {msg}"
            })
        return {
            "success": success,
            "message": msg,
            "tier": evaluator.orchestrator.current_tier.value,
            "step_up_failures": evaluator.orchestrator.step_up_failures
        }
    return {"success": True, "message": "Identity verified.", "tier": "TIER_1_LOW", "step_up_failures": 0}


# ---------------------------------------------------------
# Desktop Application Integration & Explorer Endpoints
# ---------------------------------------------------------
@app.post("/api/system/launch_forensics_gui")
async def launch_forensics_gui_endpoint():
    """Spawns the native PyQt6 Forensic Analyst Workbench desktop application."""
    try:
        forensic_script = os.path.join(PROJECT_ROOT, "dashboard", "forensic_dashboard.py")
        if not os.path.exists(forensic_script):
            raise HTTPException(status_code=404, detail="Forensic dashboard script not found.")
        subprocess.Popen([sys.executable, forensic_script], cwd=PROJECT_ROOT)
        return {"status": "success", "message": "Forensic Desktop Dashboard launched."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to launch forensics GUI: {str(e)}")


@app.post("/api/system/launch_honeypot_gui")
async def launch_honeypot_gui_endpoint():
    """Spawns the native PyQt6 isolated Sandboxed Windows 11 Honeypot Desktop."""
    try:
        honeypot_script = os.path.join(PROJECT_ROOT, "deception", "honey_desktop.py")
        if not os.path.exists(honeypot_script):
            raise HTTPException(status_code=404, detail="Honeypot desktop script not found.")
        subprocess.Popen([sys.executable, honeypot_script], cwd=PROJECT_ROOT)
        return {"status": "success", "message": "Sandboxed Honeypot Desktop launched."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to launch honeypot GUI: {str(e)}")


@app.post("/api/system/open_folder")
async def open_folder_endpoint(folder: str = "logs"):
    """Opens a system directory (logs, sandbox, forensics) in Windows Explorer."""
    allowed_folders = {
        "logs": os.path.join(PROJECT_ROOT, "data", "logs"),
        "sandbox": os.path.join(PROJECT_ROOT, "data", "sandbox"),
        "forensics": os.path.join(PROJECT_ROOT, "data", "forensics"),
    }
    target_dir = allowed_folders.get(folder.lower())
    if not target_dir or not os.path.exists(target_dir):
        raise HTTPException(status_code=400, detail="Invalid or non-existent folder specified.")
    
    try:
        if sys.platform == "win32":
            os.startfile(target_dir)
        return {"status": "success", "message": f"Opened {folder} folder in File Explorer."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to open folder: {str(e)}")


# ---------------------------------------------------------
# Standalone Runner
# ---------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    _bind_host = os.environ.get("HOST", "127.0.0.1")
    _bind_port = int(os.environ.get("PORT", 8000))
    print("\n" + "=" * 70)
    print("CONTINUOUS AUTHENTICATION & HONEYPOT FORENSICS WEB DASHBOARD")
    print("Department of ISE | Team 30 | Major Project")
    print(f"Serving live monitoring console at: http://{_bind_host}:{_bind_port}")
    print("=" * 70 + "\n")
    uvicorn.run("dashboard.app:app", host=_bind_host, port=_bind_port, reload=False)
