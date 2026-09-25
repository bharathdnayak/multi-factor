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
    # Fallback or placeholder for non-Windows development
    win32gui = None
    win32process = None

from pynput import keyboard, mouse

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class TelemetryAgent:
    def __init__(self, output_file=None, window_size_seconds=10):
        if output_file is None:
            self.output_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
        elif not os.path.isabs(output_file):
            self.output_file = os.path.join(PROJECT_ROOT, output_file)
        else:
            self.output_file = output_file
        self.window_size_seconds = window_size_seconds
        
        # Keyboard telemetry storage
        self.active_presses = {}  # key_hash -> press_timestamp
        self.last_release_time = None
        self.dwell_times = []
        self.flight_times = []
        self.key_count = 0

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
                # Get window title
                title = win32gui.GetWindowText(hwnd)
                if title:
                    window_title = title
                
                # Get process ID
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid:
                    proc = psutil.Process(pid)
                    app_name = proc.name()
                    
                    # Memory info in MB
                    ram_usage = proc.memory_info().rss / (1024 * 1024)
                    
                    # CPU usage (interval=None is non-blocking but gives usage since last call/creation)
                    cpu_usage = proc.cpu_percent()
        except Exception:
            # Silent fallback to protect background thread
            pass

        return app_name, window_title, cpu_usage, ram_usage

    # --- Keyboard Callbacks ---
    def on_press(self, key):
        if not self.running:
            return
        
        self.key_count += 1
        key_hash = self._hash_key(key)
        now = time.time()
        
        # Log press if not already logged (handle key repeat events)
        if key_hash not in self.active_presses:
            self.active_presses[key_hash] = now
            
        # Calculate flight time from the last release
        if self.last_release_time is not None:
            flight = now - self.last_release_time
            # Discard flight times longer than 5 seconds (indicating a long pause, not typing rhythm)
            if flight <= 5.0:
                self.flight_times.append(flight)
            self.last_release_time = None

    def on_release(self, key):
        if not self.running:
            return
        
        key_hash = self._hash_key(key)
        now = time.time()
        self.last_release_time = now
        
        # Calculate dwell time
        if key_hash in self.active_presses:
            press_time = self.active_presses.pop(key_hash)
            dwell = now - press_time
            if dwell <= 2.0:  # Exclude keys held for more than 2 seconds (e.g. game keys)
                self.dwell_times.append(dwell)

    # --- Mouse Callbacks & Stroke Analysis ---
    def on_move(self, x, y):
        if not self.running:
            return
            
        now = time.time()
        self.mouse_event_count += 1
        
        with self.stroke_lock:
            # End current stroke if idle threshold is crossed
            if self.current_stroke and (now - self.current_stroke[-1][2] > self.stroke_idle_threshold):
                self._process_stroke()
            
            self.current_stroke.append((x, y, now))

    def _process_stroke(self):
        """Analyzes a single mouse movement stroke to extract physics features."""
        stroke = self.current_stroke
        self.current_stroke = []  # Clear for the next stroke
        
        if len(stroke) < 3:
            return
            
        # 1. Straightness Curvature
        x_coords = [p[0] for p in stroke]
        y_coords = [p[1] for p in stroke]
        times = [p[2] for p in stroke]
        
        # Straight-line distance between start and end
        dx = x_coords[-1] - x_coords[0]
        dy = y_coords[-1] - y_coords[0]
        straight_dist = math.sqrt(dx**2 + dy**2)
        
        # Cumulative path length
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
            
        # 2. Velocity, Acceleration, Jerk
        if len(segment_velocities) >= 1:
            self.velocities.extend(segment_velocities)
            
            # Accelerations (change in velocity over change in time)
            segment_accelerations = []
            for i in range(len(segment_velocities) - 1):
                dv = segment_velocities[i+1] - segment_velocities[i]
                # dt is the average time between segments
                dt = (times[i+2] - times[i]) / 2.0
                if dt > 0:
                    segment_accelerations.append(dv / dt)
            
            if segment_accelerations:
                self.accelerations.extend(segment_accelerations)
                
                # Jerk (change in acceleration over change in time)
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
            
            # Check if there is an active stroke still open and process it
            with self.stroke_lock:
                if self.current_stroke:
                    self._process_stroke()

            # Retrieve active process context info
            app_name, win_title, cpu, ram = self._get_active_window_context()
            
            # Aggregate Key features
            avg_dwell = np.mean(self.dwell_times) if self.dwell_times else 0.0
            std_dwell = np.std(self.dwell_times) if self.dwell_times else 0.0
            avg_flight = np.mean(self.flight_times) if self.flight_times else 0.0
            std_flight = np.std(self.flight_times) if self.flight_times else 0.0
            
            # Aggregate Mouse features
            avg_vel = np.mean(self.velocities) if self.velocities else 0.0
            avg_acc = np.mean(self.accelerations) if self.accelerations else 0.0
            avg_jerk = np.mean(self.jerks) if self.jerks else 0.0
            avg_straight = np.mean(self.straightness_scores) if self.straightness_scores else 1.0

            # Construct the feature JSON
            telemetry_row = {
                "timestamp": time.time(),
                "hour_of_day": time.localtime().tm_hour,
                "keystroke_count": self.key_count,
                "dwell_mean": float(avg_dwell),
                "dwell_std": float(std_dwell),
                "flight_mean": float(avg_flight),
                "flight_std": float(std_flight),
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
            
            # Reset logs for next window
            self.dwell_times = []
            self.flight_times = []
            self.key_count = 0
            
            self.velocities = []
            self.accelerations = []
            self.jerks = []
            self.straightness_scores = []
            self.mouse_event_count = 0

            # Output to stream (stdout and file append)
            json_str = json.dumps(telemetry_row)
            print(f"[TELEMETRY] {json_str}", flush=True)
            
            try:
                with open(self.output_file, "a") as f:
                    f.write(json_str + "\n")
            except Exception as e:
                print(f"[ERROR] Failed to write to telemetry log file: {e}", file=sys.stderr)

    def start(self):
        """Starts listeners and the aggregation worker thread."""
        print("[INFO] Starting Telemetry Agent...", flush=True)
        self.running = True
        
        # Start mouse hook
        self.mouse_listener = mouse.Listener(on_move=self.on_move)
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
            
        print("[INFO] Telemetry Agent stopped successfully.", flush=True)

if __name__ == "__main__":
    agent = TelemetryAgent()
    try:
        agent.start()
        # Keep main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()
        print("[INFO] Exited cleanly.", flush=True)
