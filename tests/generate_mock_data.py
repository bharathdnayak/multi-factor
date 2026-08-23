import os
import csv
import random
import time

def generate_keystrokes(filepath, duration_seconds, typing_style="normal"):
    """
    Simulates keystroke press and release events spanning a fixed duration.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    keys = ["a8f2b3e4", "b9c1d2e5", "e3f4a5b6", "c7d8e9f0", "f1a2b3c4"]
    
    start_time = 1787477000.0
    current_time = start_time
    end_time = start_time + duration_seconds
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "key", "event_type"])
        
        while current_time < end_time:
            key = random.choice(keys)
            
            # Key Press
            writer.writerow([round(current_time, 4), key, "press"])
            
            # Key Dwell (Hold) duration
            if typing_style == "normal":
                dwell = random.uniform(0.07, 0.14)
            else:
                dwell = random.uniform(0.22, 0.38)
                
            current_time += dwell
            
            # Key Release
            writer.writerow([round(current_time, 4), key, "release"])
            
            # Inter-key Flight duration
            if typing_style == "normal":
                flight = random.uniform(0.1, 0.25)
            else:
                flight = random.uniform(0.35, 0.7)
                
            current_time += flight

def generate_mouse(filepath, duration_seconds, mouse_style="normal"):
    """
    Simulates mouse movements grouped into strokes spanning a fixed duration.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    start_time = 1787477000.0
    current_time = start_time
    end_time = start_time + duration_seconds
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "x", "y", "event_type"])
        
        x, y = 500, 500
        
        while current_time < end_time:
            target_x = x + random.randint(-150, 150)
            target_y = y + random.randint(-150, 150)
            
            steps = random.randint(10, 15)
            
            for step in range(steps):
                t = step / steps
                lx = x + t * (target_x - x)
                ly = y + t * (target_y - y)
                
                if mouse_style == "normal":
                    jitter_x = random.uniform(-1, 1)
                    jitter_y = random.uniform(-1, 1)
                else:
                    jitter_x = random.uniform(-10, 10)
                    jitter_y = random.uniform(-10, 10)
                    
                px = int(lx + jitter_x)
                py = int(ly + jitter_y)
                
                if mouse_style == "normal":
                    dt = random.uniform(0.015, 0.025)
                else:
                    dt = random.uniform(0.005, 0.012)
                    
                current_time += dt
                writer.writerow([round(current_time, 4), px, py, "move"])
                
            if random.random() > 0.6:
                current_time += 0.05
                writer.writerow([round(current_time, 4), target_x, target_y, "click_LEFT_press"])
                current_time += 0.08
                writer.writerow([round(current_time, 4), target_x, target_y, "click_LEFT_release"])
                
            x, y = target_x, target_y
            current_time += random.uniform(0.3, 0.8)

def generate_context(filepath, duration_seconds, context_style="normal"):
    """
    Simulates application and system usage logs spanning a fixed duration.
    """
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    normal_apps = [
        ("Project Plan - Word", "winword.exe"),
        ("Google Chrome - Research", "chrome.exe"),
        ("main.py - VS Code", "code.exe"),
        ("File Explorer", "explorer.exe")
    ]
    
    imposter_apps = [
        ("Administrator: Command Prompt", "cmd.exe"),
        ("Windows PowerShell", "powershell.exe"),
        ("Registry Editor", "regedit.exe"),
        ("Process Hacker", "processhacker.exe")
    ]
    
    start_time = 1787477000.0
    current_time = start_time
    end_time = start_time + duration_seconds
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "active_window", "process_name", "cpu_usage", "memory_usage"])
        
        while current_time < end_time:
            if context_style == "normal":
                title, proc = random.choice(normal_apps)
                cpu = random.uniform(1.0, 15.0)
                mem = random.uniform(40.0, 52.0)
            else:
                title, proc = random.choice(imposter_apps)
                cpu = random.uniform(35.0, 80.0)
                mem = random.uniform(68.0, 82.0)
                
            writer.writerow([round(current_time, 4), title, proc, round(cpu, 1), round(mem, 1)])
            current_time += random.uniform(2.0, 5.0)

def main():
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    print("Generating Owner Baseline Data (Synchronized)...")
    generate_keystrokes(os.path.join(project_dir, "data", "raw", "keystrokes.csv"), 500, "normal")
    generate_mouse(os.path.join(project_dir, "data", "raw", "mouse.csv"), 500, "normal")
    generate_context(os.path.join(project_dir, "data", "raw", "context.csv"), 500, "normal")
    
    print("Generating Imposter Test Data (Synchronized)...")
    generate_keystrokes(os.path.join(project_dir, "data", "raw", "imposter_keystrokes.csv"), 300, "imposter")
    generate_mouse(os.path.join(project_dir, "data", "raw", "imposter_mouse.csv"), 300, "imposter")
    generate_context(os.path.join(project_dir, "data", "raw", "imposter_context.csv"), 300, "imposter")
    
    print("Synchronized mock datasets created successfully!")

if __name__ == "__main__":
    main()
