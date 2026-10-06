import time
import os
import sys
import json
import hashlib
import threading
import math
import argparse
import numpy as np
import psutil

# Windows-specific imports for window tracking
if sys.platform == "win32":
    import win32gui
    import win32process
    import win32api
    import win32con
else:
    win32gui = None
    win32process = None

from pynput import keyboard, mouse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.controller import classify_activity_context, CODE_SYMBOLS, BehavioralAIController
from telemetry.environmental_sensor import get_environmental_sensor

class MicroSessionTracker:
    """
    Tracks and maintains fine-grained micro-sessions per application and cognitive sub-task.
    Specifically captures:
    - Inter-keystroke thinking/reading pauses (1.5s - 30s)
    - Typing burst lengths and rhythm (characters typed between pauses)
    - Code syntax symbol density ({}[]();:=+-*/<>)
    - Error revision rate (Backspaces/Deletes)
    - Mouse reading scroll intervals
    - Flushes completed sessions to data/sessions/session_history.jsonl
    - Updates running Gaussian baselines in data/sessions/app_baselines.json
    - Continuously writes live active session to data/sessions/active_session.json
    """
    def __init__(self, sessions_dir=None):
        if sessions_dir is None:
            self.sessions_dir = os.path.join(PROJECT_ROOT, "data", "sessions")
        else:
            self.sessions_dir = sessions_dir
            
        os.makedirs(self.sessions_dir, exist_ok=True)
        self.history_file = os.path.join(self.sessions_dir, "session_history.jsonl")
        self.active_file = os.path.join(self.sessions_dir, "active_session.json")
        self.controller = BehavioralAIController()
        self.lock = threading.Lock()
        
        self.current_app = "unknown"
        self.current_title = "unknown"
        self.current_context = "general_productivity"
        self.session_id = None
        self.start_time = time.time()
        self.last_event_time = time.time()
        
        # Micro-session metrics
        self.keystrokes = 0
        self.code_symbol_count = 0
        self.backspace_count = 0
        self.thinking_pauses = []
        self.typing_bursts = []
        self.current_burst_chars = 0
        self.dwell_times = []
        self.flight_times = []
        
        self.mouse_moves = 0
        self.mouse_clicks = 0
        self.mouse_scrolls = 0
        
        self._init_session("unknown", "unknown")

    def _init_session(self, app_name, window_title):
        self.session_id = f"sess_{time.strftime('%Y%m%d_%H%M%S')}_{os.path.splitext(app_name)[0]}"
        self.current_app = app_name
        self.current_title = window_title
        self.current_context = classify_activity_context(app_name, window_title)
        self.start_time = time.time()
        self.last_event_time = self.start_time
        
        self.keystrokes = 0
        self.code_symbol_count = 0
        self.backspace_count = 0
        self.thinking_pauses = []
        self.typing_bursts = []
        self.current_burst_chars = 0
        self.dwell_times = []
        self.flight_times = []
        
        self.mouse_moves = 0
        self.mouse_clicks = 0
        self.mouse_scrolls = 0

    def record_key_press(self, key_char, is_backspace=False, is_symbol=False):
        now = time.time()
        with self.lock:
            self.keystrokes += 1
            if is_backspace:
                self.backspace_count += 1
            if is_symbol:
                self.code_symbol_count += 1
                
            gap = now - self.last_event_time
            if 1.5 <= gap <= 30.0:
                # Thinking pause registered!
                self.thinking_pauses.append(gap)
                if self.current_burst_chars > 0:
                    self.typing_bursts.append(self.current_burst_chars)
                    self.current_burst_chars = 0
                    
            self.current_burst_chars += 1
            self.last_event_time = now

    def record_key_release(self, dwell, flight):
        with self.lock:
            if dwell is not None and dwell <= 2.0:
                self.dwell_times.append(dwell)
            if flight is not None and flight <= 5.0:
                self.flight_times.append(flight)

    def record_mouse_event(self, event_type, delta=1):
        with self.lock:
            if event_type == "move":
                self.mouse_moves += 1
            elif event_type == "click":
                self.mouse_clicks += delta
            elif event_type == "scroll":
                self.mouse_scrolls += delta
            self.last_event_time = time.time()

    def heartbeat(self, app_name, window_title):
        """Called periodically by telemetry agent to detect context switches or finalize idle sessions."""
        now = time.time()
        with self.lock:
            new_context = classify_activity_context(app_name, window_title)
            idle_time = now - self.last_event_time
            app_changed = (app_name != self.current_app and app_name != "unknown")
            context_changed = (new_context != self.current_context)
            title_changed = (
                window_title and 
                window_title != self.current_title and 
                window_title != "unknown" and 
                self.current_title != "unknown" and 
                (self.keystrokes >= 5 or (now - self.start_time) >= 20.0)
            )
            is_idle_timeout = (idle_time > 60.0 and self.keystrokes > 0)
            
            if app_changed or context_changed or title_changed or is_idle_timeout:
                # Finalize prior session if it had meaningful activity
                if self.keystrokes >= 3 or (now - self.start_time) >= 10.0:
                    self._finalize_and_save_session()
                # Start new micro-session
                self._init_session(app_name, window_title)
            else:
                if window_title and window_title != "unknown":
                    self.current_title = window_title
                    self.current_context = new_context
                    
            self._write_active_session_snapshot()

    def _finalize_and_save_session(self):
        """Calculates final metrics for the micro-session and persists it."""
        now = time.time()
        elapsed = max(0.1, now - self.start_time)
        
        if self.current_burst_chars > 0:
            self.typing_bursts.append(self.current_burst_chars)
            self.current_burst_chars = 0
            
        total_keys = max(1, self.keystrokes)
        avg_pause = float(np.mean(self.thinking_pauses)) if self.thinking_pauses else 0.0
        max_pause = float(np.max(self.thinking_pauses)) if self.thinking_pauses else 0.0
        pause_ratio = float(min(1.0, sum(self.thinking_pauses) / elapsed)) if elapsed > 0 else 0.0
        avg_burst = float(np.mean(self.typing_bursts)) if self.typing_bursts else float(self.keystrokes)
        symbol_ratio = float(round(self.code_symbol_count / total_keys, 4))
        backspace_ratio = float(round(self.backspace_count / total_keys, 4))
        dwell_m = float(np.mean(self.dwell_times)) if self.dwell_times else 0.09
        flight_m = float(np.mean(self.flight_times)) if self.flight_times else 0.14
        scroll_ratio = float(round(self.mouse_scrolls / max(1, self.mouse_moves + self.mouse_scrolls), 4))
        
        session_summary = {
            "session_id": self.session_id,
            "app_name": self.current_app,
            "window_title": self.current_title,
            "context_mode": self.current_context,
            "start_time": self.start_time,
            "end_time": now,
            "elapsed_seconds": round(elapsed, 2),
            "keystrokes": self.keystrokes,
            "thinking_pause_count": len(self.thinking_pauses),
            "avg_thinking_pause_sec": round(avg_pause, 3),
            "max_thinking_pause_sec": round(max_pause, 3),
            "thinking_pause_ratio": round(pause_ratio, 4),
            "typing_burst_count": len(self.typing_bursts),
            "avg_burst_length": round(avg_burst, 2),
            "code_symbol_count": self.code_symbol_count,
            "code_symbol_ratio": symbol_ratio,
            "backspace_count": self.backspace_count,
            "backspace_ratio": backspace_ratio,
            "dwell_mean": round(dwell_m, 4),
            "flight_mean": round(flight_m, 4),
            "mouse_moves": self.mouse_moves,
            "mouse_clicks": self.mouse_clicks,
            "mouse_scrolls": self.mouse_scrolls,
            "reading_scroll_ratio": scroll_ratio,
            "status": "completed",
            "recorded_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Append to historical sessions
        try:
            with open(self.history_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(session_summary) + "\n")
        except Exception as e:
            print(f"[SESSION_TRACKER] [ERROR] Failed to save session history: {e}", file=sys.stderr)
            
        # Update baseline model automatically
        try:
            self.controller.learn_from_session(session_summary, verified=True)
        except Exception:
            pass

    def _write_active_session_snapshot(self):
        """Writes real-time active session to disk for instant external querying."""
        now = time.time()
        elapsed = max(0.1, now - self.start_time)
        total_keys = max(1, self.keystrokes)
        
        snapshot = {
            "session_id": self.session_id,
            "app_name": self.current_app,
            "window_title": self.current_title,
            "context_mode": self.current_context,
            "start_time": self.start_time,
            "elapsed_seconds": round(elapsed, 1),
            "keystrokes": self.keystrokes,
            "thinking_pause_count": len(self.thinking_pauses),
            "avg_thinking_pause_sec": round(float(np.mean(self.thinking_pauses)), 3) if self.thinking_pauses else 0.0,
            "typing_burst_count": len(self.typing_bursts),
            "avg_burst_length": round(float(np.mean(self.typing_bursts)), 1) if self.typing_bursts else float(self.current_burst_chars),
            "code_symbol_count": self.code_symbol_count,
            "code_symbol_ratio": round(self.code_symbol_count / total_keys, 4),
            "backspace_count": self.backspace_count,
            "backspace_ratio": round(self.backspace_count / total_keys, 4),
            "mouse_clicks": self.mouse_clicks,
            "mouse_scrolls": self.mouse_scrolls,
            "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "active"
        }
        
        try:
            with open(self.active_file, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except Exception:
            pass

    def close(self):
        with self.lock:
            if self.keystrokes >= 2 or (time.time() - self.start_time) >= 5.0:
                self._finalize_and_save_session()


class AppBehaviorProfiler:
    """
    Maintains backward compatibility with earlier telemetry tests while
    syncing into the modern behavioral baseline structure.
    """
    def __init__(self, profiles_path=None):
        if profiles_path is None:
            self.profiles_path = os.path.join(PROJECT_ROOT, "data", "app_profiles.json")
        else:
            self.profiles_path = profiles_path
        self.lock = threading.Lock()
        self.profiles = self._load_profiles()

    def _load_profiles(self):
        if os.path.exists(self.profiles_path):
            try:
                with open(self.profiles_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def save_profiles(self):
        os.makedirs(os.path.dirname(self.profiles_path), exist_ok=True)
        try:
            with open(self.profiles_path, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2)
        except Exception:
            pass

    def update_profile(self, app_name, dwell, flight, backspace_ratio, special_ratio, scroll_count, pause_ratio):
        if not app_name or app_name == "unknown":
            return
            
        with self.lock:
            if app_name not in self.profiles:
                self.profiles[app_name] = {
                    "observations": 0,
                    "avg_dwell": float(dwell),
                    "avg_flight": float(flight),
                    "avg_backspace_ratio": float(backspace_ratio),
                    "avg_special_ratio": float(special_ratio),
                    "avg_scroll_count": int(scroll_count),
                    "avg_pause_ratio": float(pause_ratio),
                    "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
                }
            
            p = self.profiles[app_name]
            n = p["observations"]
            alpha = 1.0 / (n + 1) if n < 50 else 0.05
            p["avg_dwell"] = round((1 - alpha) * p["avg_dwell"] + alpha * dwell, 4)
            p["avg_flight"] = round((1 - alpha) * p["avg_flight"] + alpha * flight, 4)
            p["avg_backspace_ratio"] = round((1 - alpha) * p["avg_backspace_ratio"] + alpha * backspace_ratio, 4)
            p["avg_special_ratio"] = round((1 - alpha) * p["avg_special_ratio"] + alpha * special_ratio, 4)
            p["avg_scroll_count"] = round((1 - alpha) * p["avg_scroll_count"] + alpha * scroll_count, 1)
            p["avg_pause_ratio"] = round((1 - alpha) * p["avg_pause_ratio"] + alpha * pause_ratio, 4)
            p["observations"] += 1
            p["last_updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            
            if p["observations"] % 5 == 0:
                self.save_profiles()


class TelemetryAgent:
    def __init__(self, output_file=None, window_size_seconds=10, silent=False, friendly=False):
        if output_file is None:
            self.output_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
        elif not os.path.isabs(output_file):
            self.output_file = os.path.join(PROJECT_ROOT, output_file)
        else:
            self.output_file = output_file
            
        self.window_size_seconds = window_size_seconds
        self.silent = silent
        self.friendly = friendly
        self.profiler = AppBehaviorProfiler()
        self.session_tracker = MicroSessionTracker()
        self.env_sensor = get_environmental_sensor()
        
        # Keyboard telemetry storage
        self.active_presses = {}  # key_hash -> press_timestamp
        self.last_release_time = None
        self.dwell_times = []
        self.flight_times = []
        self.key_count = 0
        
        # In-App Specific Metrics
        self.backspace_count = 0
        self.special_count = 0
        self.pause_durations = []

        # Mouse telemetry storage
        self.current_stroke = []  # List of (x, y, timestamp)
        self.stroke_lock = threading.Lock()
        self.stroke_idle_threshold = 0.1  # 100ms of inactivity ends a stroke
        
        # Processed mouse metrics for the current window
        self.velocities = []
        self.accelerations = []
        self.jerks = []
        self.straightness_scores = []
        self.mouse_event_count = 0
        self.mouse_clicks = 0
        self.mouse_scrolls = 0

        # Control flags
        self.running = False
        self.aggregation_thread = None
        self.mouse_listener = None
        self.keyboard_listener = None

    def _hash_key(self, key):
        """Converts key input into a privacy-safe SHA-256 hash."""
        try:
            key_str = str(key)
            if hasattr(key, 'char') and key.char is not None:
                key_str = key.char
            elif hasattr(key, 'name') and key.name is not None:
                key_str = key.name
        except Exception:
            key_str = "unknown"
            
        return hashlib.sha256(key_str.encode('utf-8')).hexdigest()

    def _get_active_window_context(self):
        """Retrieves active window title, process name, CPU & memory usage."""
        app_name = "unknown"
        window_title = "unknown"
        cpu_usage = 0.0
        ram_usage = 0.0
        
        if sys.platform != "win32" or win32gui is None:
            return app_name, window_title, cpu_usage, ram_usage

        try:
            hwnd = win32gui.GetForegroundWindow()
            if hwnd:
                title = win32gui.GetWindowText(hwnd)
                if title:
                    window_title = title
                
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid:
                    proc = psutil.Process(pid)
                    app_name = proc.name()
                    ram_usage = proc.memory_info().rss / (1024 * 1024)
                    cpu_usage = proc.cpu_percent()
        except Exception:
            pass

        return app_name, window_title, cpu_usage, ram_usage

    # --- Keyboard Callbacks ---
    def on_press(self, key):
        if not self.running:
            return
        
        self.key_count += 1
        key_hash = self._hash_key(key)
        now = time.time()
        
        # Character inspection for code symbols and error correction
        is_backspace = False
        is_symbol = False
        char_val = None
        
        if key in (keyboard.Key.backspace, keyboard.Key.delete):
            self.backspace_count += 1
            is_backspace = True
        elif key in (keyboard.Key.enter, keyboard.Key.tab, keyboard.Key.shift, keyboard.Key.shift_r, 
                     keyboard.Key.ctrl, keyboard.Key.ctrl_r, keyboard.Key.alt, keyboard.Key.cmd):
            self.special_count += 1
        else:
            if hasattr(key, 'char') and key.char:
                char_val = key.char
                if char_val in CODE_SYMBOLS:
                    self.special_count += 1
                    is_symbol = True

        # Inform MicroSessionTracker
        self.session_tracker.record_key_press(char_val, is_backspace=is_backspace, is_symbol=is_symbol)
            
        # Track inter-keystroke thinking/reading pauses (1.5s to 30.0s)
        if self.last_release_time is not None:
            gap = now - self.last_release_time
            if 1.5 <= gap <= 30.0:
                self.pause_durations.append(gap)
            elif gap < 5.0:
                self.flight_times.append(gap)
            self.last_release_time = None
        
        if key_hash not in self.active_presses:
            self.active_presses[key_hash] = now

    def on_release(self, key):
        if not self.running:
            return
        
        key_hash = self._hash_key(key)
        now = time.time()
        self.last_release_time = now
        
        dwell = None
        if key_hash in self.active_presses:
            press_time = self.active_presses.pop(key_hash)
            dwell = now - press_time
            if dwell <= 2.0:
                self.dwell_times.append(dwell)

        flight = self.flight_times[-1] if self.flight_times else None
        self.session_tracker.record_key_release(dwell, flight)

    # --- Mouse Callbacks & Stroke Analysis ---
    def on_move(self, x, y):
        if not self.running:
            return
            
        now = time.time()
        self.mouse_event_count += 1
        self.session_tracker.record_mouse_event("move")
        
        with self.stroke_lock:
            if self.current_stroke and (now - self.current_stroke[-1][2] > self.stroke_idle_threshold):
                self._process_stroke()
            
            self.current_stroke.append((x, y, now))

    def on_click(self, x, y, button, pressed):
        if self.running and pressed:
            self.mouse_clicks += 1
            self.session_tracker.record_mouse_event("click")

    def on_scroll(self, x, y, dx, dy):
        if self.running:
            delta = abs(dy) if dy != 0 else 1
            self.mouse_scrolls += delta
            self.session_tracker.record_mouse_event("scroll", delta=delta)

    def _process_stroke(self):
        """Analyzes a single mouse movement stroke to extract physics features."""
        stroke = self.current_stroke
        self.current_stroke = []
        
        if len(stroke) < 3:
            return
            
        x_coords = [p[0] for p in stroke]
        y_coords = [p[1] for p in stroke]
        times = [p[2] for p in stroke]
        
        dx = x_coords[-1] - x_coords[0]
        dy = y_coords[-1] - y_coords[0]
        straight_dist = math.sqrt(dx**2 + dy**2)
        
        path_len = 0.0
        segment_velocities = []
        
        for i in range(len(stroke) - 1):
            seg_dx = x_coords[i+1] - x_coords[i]
            seg_dy = y_coords[i+1] - y_coords[i]
            seg_dt = times[i+1] - times[i]
            
            dist = math.sqrt(seg_dx**2 + seg_dy**2)
            path_len += dist
            
            if seg_dt > 0:
                segment_velocities.append(dist / seg_dt)
                
        if path_len > 0:
            straightness = straight_dist / path_len
            self.straightness_scores.append(min(straightness, 1.0))
            
        if len(segment_velocities) >= 1:
            self.velocities.extend(segment_velocities)
            
            segment_accelerations = []
            for i in range(len(segment_velocities) - 1):
                dv = segment_velocities[i+1] - segment_velocities[i]
                dt = (times[i+2] - times[i]) / 2.0
                if dt > 0:
                    segment_accelerations.append(dv / dt)
            
            if segment_accelerations:
                self.accelerations.extend(segment_accelerations)
                
                segment_jerks = []
                for i in range(len(segment_accelerations) - 1):
                    da = segment_accelerations[i+1] - segment_accelerations[i]
                    dt = (times[i+3] - times[i+1]) / 2.0
                    if dt > 0:
                        segment_jerks.append(da / dt)
                
                if segment_jerks:
                    self.jerks.extend(segment_jerks)

    def _aggregate_and_output(self):
        """Averages features collected in the current window and saves/outputs JSON."""
        while self.running:
            time.sleep(self.window_size_seconds)
            
            with self.stroke_lock:
                if self.current_stroke:
                    self._process_stroke()

            app_name, win_title, cpu, ram = self._get_active_window_context()
            
            # Send heartbeat to MicroSessionTracker
            self.session_tracker.heartbeat(app_name, win_title)
            
            # Aggregate Keystroke features
            avg_dwell = np.mean(self.dwell_times) if self.dwell_times else 0.0
            std_dwell = np.std(self.dwell_times) if self.dwell_times else 0.0
            avg_flight = np.mean(self.flight_times) if self.flight_times else 0.0
            std_flight = np.std(self.flight_times) if self.flight_times else 0.0
            
            # Aggregate Mouse features
            avg_vel = np.mean(self.velocities) if self.velocities else 0.0
            avg_acc = np.mean(self.accelerations) if self.accelerations else 0.0
            avg_jerk = np.mean(self.jerks) if self.jerks else 0.0
            avg_straight = np.mean(self.straightness_scores) if self.straightness_scores else 1.0

            # Calculate Intra-Application Behavioral Ratios
            total_keys = max(1, self.key_count)
            backspace_ratio = self.backspace_count / total_keys
            special_ratio = self.special_count / total_keys
            pause_ratio = min(1.0, (sum(self.pause_durations) / self.window_size_seconds)) if self.pause_durations else 0.0
            avg_pause_sec = float(np.mean(self.pause_durations)) if self.pause_durations else 0.0

            # Granular Task Classification
            interaction_mode = classify_activity_context(app_name, win_title)

            # Update Persistent Per-Application Profiler
            if avg_dwell > 0.0 or self.key_count > 0:
                self.profiler.update_profile(
                    app_name, avg_dwell, avg_flight, backspace_ratio, 
                    special_ratio, self.mouse_scrolls, pause_ratio
                )

            # Construct the feature JSON
            telemetry_row = {
                "timestamp": time.time(),
                "hour_of_day": time.localtime().tm_hour,
                "keystroke_count": self.key_count,
                "dwell_mean": float(avg_dwell),
                "dwell_std": float(std_dwell),
                "flight_mean": float(avg_flight),
                "flight_std": float(std_flight),
                "app_dwell_mean": float(avg_dwell),
                "app_flight_mean": float(avg_flight),
                "app_backspace_ratio": float(round(backspace_ratio, 4)),
                "app_special_ratio": float(round(special_ratio, 4)),
                "app_click_count": int(self.mouse_clicks),
                "app_scroll_count": int(self.mouse_scrolls),
                "app_pause_ratio": float(round(pause_ratio, 4)),
                "avg_thinking_pause_sec": float(round(avg_pause_sec, 3)),
                "interaction_mode": interaction_mode,
                "micro_session_id": self.session_tracker.session_id,
                "mouse_events": self.mouse_event_count,
                "mouse_velocity_mean": float(avg_vel),
                "mouse_acceleration_mean": float(avg_acc),
                "mouse_jerk_mean": float(avg_jerk),
                "mouse_straightness_mean": float(avg_straight),
                "active_app": app_name,
                "active_window": win_title,
                "cpu_usage": float(cpu),
                "ram_usage_mb": float(ram)
            }
            
            # Merge Passive Environmental Ambient Sensors (TASK-8)
            try:
                env_snapshot = self.env_sensor.get_environmental_snapshot()
                telemetry_row.update(env_snapshot)
            except Exception:
                pass
            
            # Reset window logs
            self.dwell_times = []
            self.flight_times = []
            self.key_count = 0
            self.backspace_count = 0
            self.special_count = 0
            self.pause_durations = []
            
            self.velocities = []
            self.accelerations = []
            self.jerks = []
            self.straightness_scores = []
            self.mouse_event_count = 0
            self.mouse_clicks = 0
            self.mouse_scrolls = 0

            json_str = json.dumps(telemetry_row)
            if self.friendly:
                t_str = time.strftime("%H:%M:%S")
                raw_title = str(win_title)
                short_title = raw_title[:45] + "..." if len(raw_title) > 45 else raw_title
                ctx_display = interaction_mode.replace("_", " ").title()
                pause_info = f"{avg_pause_sec:.1f}s" if avg_pause_sec > 0 else "0s"
                print(f"[{t_str}] App: {app_name} | Task: {ctx_display} | Win: '{short_title}'", flush=True)
                print(f"         -> Keys: {telemetry_row['keystroke_count']} | Symbols: {telemetry_row['app_special_ratio']*100:.0f}% | Thinking: {pause_info} | Backspace: {telemetry_row['app_backspace_ratio']*100:.0f}%", flush=True)
            elif not self.silent:
                print(f"[TELEMETRY] {json_str}", flush=True)
            
            try:
                with open(self.output_file, "a") as f:
                    f.write(json_str + "\n")
            except Exception as e:
                print(f"[ERROR] Failed to write to telemetry log file: {e}", file=sys.stderr)

    def start(self):
        """Starts listeners and the aggregation worker thread."""
        if not self.silent:
            print("[INFO] Starting Telemetry Agent with Micro-Session Tracking...", flush=True)
        self.running = True
        
        # Start mouse hook
        self.mouse_listener = mouse.Listener(
            on_move=self.on_move,
            on_click=self.on_click,
            on_scroll=self.on_scroll
        )
        self.mouse_listener.start()
        
        # Start keyboard hook
        self.keyboard_listener = keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
        self.keyboard_listener.start()
        
        # Start aggregation thread
        self.aggregation_thread = threading.Thread(target=self._aggregate_and_output, daemon=True)
        self.aggregation_thread.start()
        
        if not self.silent:
            print(f"[INFO] Telemetry active. Logging every {self.window_size_seconds}s to '{self.output_file}'", flush=True)

    def stop(self):
        """Stops hooks and aggregation."""
        if not self.silent:
            print("[INFO] Stopping Telemetry Agent...", flush=True)
        self.running = False
        
        if self.mouse_listener:
            self.mouse_listener.stop()
        if self.keyboard_listener:
            self.keyboard_listener.stop()
            
        self.profiler.save_profiles()
        self.session_tracker.close()
        if not self.silent:
            print("[INFO] Telemetry Agent stopped successfully. Micro-sessions saved.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Factor Behavioral Telemetry Hook Agent")
    parser.add_argument("--silent", action="store_true", help="Run silently without printing raw telemetry output")
    parser.add_argument("--friendly", action="store_true", help="Display clean, human-friendly live activity status")
    parser.add_argument("--output", type=str, default=None, help="Path to telemetry output file")
    parser.add_argument("--window", type=int, default=10, help="Window size in seconds (default: 10)")
    args = parser.parse_args()

    agent = TelemetryAgent(output_file=args.output, window_size_seconds=args.window, silent=args.silent, friendly=args.friendly)
    try:
        agent.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
        print("[INFO] Exited cleanly.", flush=True)
