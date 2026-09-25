import time
import os
import sys
import json
import hashlib
import threading
import math
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

class AppBehaviorProfiler:
    """
    Tracks and maintains fine-grained behavioral interaction patterns inside
    specific applications (e.g. Antigravity IDE, browsers, terminals).
    Records typing rhythm, error correction (backspaces), pause cadence (thinking/reading),
    special shortcut usage, and mouse click/scroll dynamics.
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
            
            # Save to disk every 5 observations
            if p["observations"] % 5 == 0:
                self.save_profiles()

class TelemetryAgent:
    def __init__(self, output_file=None, window_size_seconds=10):
        if output_file is None:
            self.output_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
        elif not os.path.isabs(output_file):
            self.output_file = os.path.join(PROJECT_ROOT, output_file)
        else:
            self.output_file = output_file
        self.window_size_seconds = window_size_seconds
        self.profiler = AppBehaviorProfiler()
        
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
        
        # Check for error-correction (Backspace / Delete)
        if key in (keyboard.Key.backspace, keyboard.Key.delete):
            self.backspace_count += 1
        elif key in (keyboard.Key.enter, keyboard.Key.tab, keyboard.Key.shift, keyboard.Key.shift_r, 
                     keyboard.Key.ctrl, keyboard.Key.ctrl_r, keyboard.Key.alt, keyboard.Key.cmd):
            self.special_count += 1
            
        # Track inter-keystroke thinking/reading pauses (1.5s to 12s)
        if self.last_release_time is not None:
            gap = now - self.last_release_time
            if 1.5 <= gap <= 12.0:
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
        
        if key_hash in self.active_presses:
            press_time = self.active_presses.pop(key_hash)
            dwell = now - press_time
            if dwell <= 2.0:
                self.dwell_times.append(dwell)

    # --- Mouse Callbacks & Stroke Analysis ---
    def on_move(self, x, y):
        if not self.running:
            return
            
        now = time.time()
        self.mouse_event_count += 1
        
        with self.stroke_lock:
            if self.current_stroke and (now - self.current_stroke[-1][2] > self.stroke_idle_threshold):
                self._process_stroke()
            
            self.current_stroke.append((x, y, now))

    def on_click(self, x, y, button, pressed):
        if self.running and pressed:
            self.mouse_clicks += 1

    def on_scroll(self, x, y, dx, dy):
        if self.running:
            self.mouse_scrolls += abs(dy) if dy != 0 else 1

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

            # Classify High-Level Intra-App Task Pattern
            app_lower = app_name.lower()
            if any(k in app_lower for k in ["antigravity", "code", "cursor", "pycharm"]):
                if pause_ratio > 0.25 and special_ratio > 0.12:
                    interaction_mode = "ai_chat_or_prompting"
                else:
                    interaction_mode = "rapid_code_editing"
            elif any(k in app_lower for k in ["chrome", "brave", "edge", "firefox"]):
                if self.mouse_scrolls > 8:
                    interaction_mode = "reading_and_browsing"
                else:
                    interaction_mode = "web_interaction"
            elif any(k in app_lower for k in ["powershell", "cmd", "terminal", "bash"]):
                interaction_mode = "command_execution"
            else:
                interaction_mode = "general_productivity"

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
                "interaction_mode": interaction_mode,
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
            print(f"[TELEMETRY] {json_str}", flush=True)
            
            try:
                with open(self.output_file, "a") as f:
                    f.write(json_str + "\n")
            except Exception as e:
                print(f"[ERROR] Failed to write to telemetry log file: {e}", file=sys.stderr)

    def start(self):
        """Starts listeners and the aggregation worker thread."""
        print("[INFO] Starting Telemetry Agent with Intra-App Behavioral Profiling...", flush=True)
        self.running = True
        
        # Start mouse hook with move, click, and scroll listeners
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
        
        print(f"[INFO] Telemetry active. Logging every {self.window_size_seconds}s to '{self.output_file}'", flush=True)

    def stop(self):
        """Stops hooks and aggregation."""
        print("[INFO] Stopping Telemetry Agent...", flush=True)
        self.running = False
        
        if self.mouse_listener:
            self.mouse_listener.stop()
        if self.keyboard_listener:
            self.keyboard_listener.stop()
            
        self.profiler.save_profiles()
        print("[INFO] Telemetry Agent stopped successfully. App profiles saved.", flush=True)

if __name__ == "__main__":
    agent = TelemetryAgent()
    try:
        agent.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
        print("[INFO] Exited cleanly.", flush=True)
