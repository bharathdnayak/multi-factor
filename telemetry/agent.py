import os
import sys
import time
import csv
import queue
import threading
from pynput import keyboard, mouse
import psutil

# Windows-specific import
try:
    import win32gui
    import win32process
except ImportError:
    win32gui = None
    win32process = None

# Queue for thread-safe writing
write_queue = queue.Queue()

# Ensure raw data directories exist
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw")
os.makedirs(DATA_DIR, exist_ok=True)

KEYSTROKES_FILE = os.path.join(DATA_DIR, "keystrokes.csv")
MOUSE_FILE = os.path.join(DATA_DIR, "mouse.csv")
CONTEXT_FILE = os.path.join(DATA_DIR, "context.csv")

# Initialize CSV headers if files do not exist
for filepath, headers in [
    (KEYSTROKES_FILE, ["timestamp", "key", "event_type"]),
    (MOUSE_FILE, ["timestamp", "x", "y", "event_type"]),
    (CONTEXT_FILE, ["timestamp", "active_window", "process_name", "cpu_usage", "memory_usage"])
]:
    if not os.path.exists(filepath):
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

def get_active_window_details():
    if not win32gui or not win32process:
        return "Unknown", "Unknown"
    try:
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            title = win32gui.GetWindowText(hwnd)
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid:
                proc = psutil.Process(pid)
                return title, proc.name()
    except Exception:
        pass
    return "Unknown", "Unknown"

# Keyboard hooks
def on_press(key):
    try:
        key_str = key.char if hasattr(key, 'char') and key.char else str(key)
    except Exception:
        key_str = str(key)
    write_queue.put((KEYSTROKES_FILE, [time.time(), key_str, "press"]))

def on_release(key):
    try:
        key_str = key.char if hasattr(key, 'char') and key.char else str(key)
    except Exception:
        key_str = str(key)
    write_queue.put((KEYSTROKES_FILE, [time.time(), key_str, "release"]))

# Mouse hooks
def on_move(x, y):
    write_queue.put((MOUSE_FILE, [time.time(), x, y, "move"]))

def on_click(x, y, button, pressed):
    event_type = f"click_{button.name}_{'press' if pressed else 'release'}"
    write_queue.put((MOUSE_FILE, [time.time(), x, y, event_type]))

# Background context poller
def context_poller():
    while not stop_event.is_set():
        title, proc_name = get_active_window_details()
        cpu = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory().percent
        write_queue.put((CONTEXT_FILE, [time.time(), title, proc_name, cpu, memory]))
        time.sleep(2.0)

# Thread-safe file writer
def file_writer():
    while not stop_event.is_set() or not write_queue.empty():
        try:
            filepath, row = write_queue.get(timeout=1.0)
            with open(filepath, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(row)
            write_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            print(f"Error writing to file: {e}", file=sys.stderr)

if __name__ == "__main__":
    stop_event = threading.Event()
    
    print("Initializing background listeners...")
    print(f"Logging data to: {DATA_DIR}")
    
    # Start threads
    writer_thread = threading.Thread(target=file_writer, daemon=True)
    writer_thread.start()
    
    poller_thread = threading.Thread(target=context_poller, daemon=True)
    poller_thread.start()
    
    keyboard_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
    mouse_listener = mouse.Listener(on_move=on_move, on_click=on_click)
    
    keyboard_listener.start()
    mouse_listener.start()
    
    print("\n>>> DATA COLLECTION RUNNING.")
    print("Type and move your mouse normally. Switch between different applications.")
    print("Press Ctrl+C to terminate data collection cleanly.")
    
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\nStopping data collection...")
        stop_event.set()
        
        # Stop listeners
        keyboard_listener.stop()
        mouse_listener.stop()
        
        # Wait for threads
        poller_thread.join(timeout=3.0)
        writer_thread.join(timeout=3.0)
        
        print("Data collection stopped successfully. CSV logs are saved.")
