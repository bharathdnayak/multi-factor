import os
import sys
import json
import argparse
import numpy as np
import joblib
from datetime import datetime

# Append project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml_engine.models import BehavioralModels

try:
    import matplotlib.pyplot as plt
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_real_data(file_path=None):
    """Loads telemetry rows from the JSONL log file, normalizing older formats."""
    if file_path is None:
        file_path = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    elif not os.path.isabs(file_path):
        file_path = os.path.join(PROJECT_ROOT, file_path)

    if not os.path.exists(file_path):
        return []
    
    rows = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    r = json.loads(line)
                    # Normalize intra-app metrics for historic rows
                    if "app_dwell_mean" not in r:
                        r["app_dwell_mean"] = r.get("dwell_mean", 0.09)
                    if "app_flight_mean" not in r:
                        r["app_flight_mean"] = r.get("flight_mean", 0.12)
                    if "app_backspace_ratio" not in r:
                        r["app_backspace_ratio"] = 0.12
                    if "app_special_ratio" not in r:
                        r["app_special_ratio"] = 0.20
                    if "app_pause_ratio" not in r:
                        r["app_pause_ratio"] = 0.38
                    if "app_scroll_count" not in r:
                        r["app_scroll_count"] = 4
                    rows.append(r)
                except Exception:
                    pass
    return rows

def generate_synthetic_data(num_samples=200, is_attacker=False):
    """Generates synthetic telemetry rows for simulation/demo purposes."""
    np.random.seed(42 if not is_attacker else 24)
    data = []
    
    for _ in range(num_samples):
        if not is_attacker:
            # Owner: consistent fast typing, smooth mouse curves, developer apps & AI chat
            app_choice = str(np.random.choice(["Antigravity.exe", "code.exe", "chrome.exe", "brave.exe", "Spotify.exe", "grafana.exe"], p=[0.35, 0.25, 0.20, 0.10, 0.05, 0.05]))
            row = {
                "dwell_mean": float(np.random.normal(0.09, 0.012)),
                "dwell_std": float(np.random.normal(0.015, 0.003)),
                "flight_mean": float(np.random.normal(0.12, 0.015)),
                "flight_std": float(np.random.normal(0.02, 0.004)),
                "app_dwell_mean": float(np.random.normal(0.088, 0.01)),
                "app_flight_mean": float(np.random.normal(0.115, 0.012)),
                "app_backspace_ratio": float(np.clip(np.random.normal(0.12, 0.03), 0.0, 0.5)),
                "app_special_ratio": float(np.clip(np.random.normal(0.20, 0.04), 0.0, 0.6)),
                "app_click_count": int(np.random.poisson(4)),
                "app_scroll_count": int(np.random.poisson(6)),
                "app_pause_ratio": float(np.clip(np.random.normal(0.40, 0.08), 0.0, 1.0)),
                "interaction_mode": "ai_chat_or_prompting",
                "mouse_velocity_mean": float(np.random.normal(250.0, 30.0)),
                "mouse_acceleration_mean": float(np.random.normal(12.0, 2.0)),
                "mouse_jerk_mean": float(np.random.normal(1.1, 0.15)),
                "mouse_straightness_mean": float(np.clip(np.random.normal(0.92, 0.03), 0.0, 1.0)),
                "hour_of_day": 14,
                "cpu_usage": float(np.random.normal(2.5, 0.8)),
                "ram_usage_mb": float(np.random.normal(250.0, 40.0)),
                "active_app": app_choice
            }
        else:
            # Attacker: slow hunt-and-peck typing, erratic jittery mouse, terminal/admin apps
            row = {
                "dwell_mean": float(np.random.normal(0.24, 0.04)),
                "dwell_std": float(np.random.normal(0.045, 0.01)),
                "flight_mean": float(np.random.normal(0.32, 0.06)),
                "flight_std": float(np.random.normal(0.065, 0.015)),
                "app_dwell_mean": float(np.random.normal(0.24, 0.04)),
                "app_flight_mean": float(np.random.normal(0.32, 0.06)),
                "app_backspace_ratio": float(np.clip(np.random.normal(0.02, 0.01), 0.0, 0.2)),
                "app_special_ratio": float(np.clip(np.random.normal(0.03, 0.02), 0.0, 0.2)),
                "app_click_count": int(np.random.poisson(1)),
                "app_scroll_count": 0,
                "app_pause_ratio": float(np.clip(np.random.normal(0.06, 0.03), 0.0, 0.3)),
                "interaction_mode": "command_execution",
                "mouse_velocity_mean": float(np.random.normal(750.0, 120.0)),
                "mouse_acceleration_mean": float(np.random.normal(55.0, 10.0)),
                "mouse_jerk_mean": float(np.random.normal(9.5, 2.0)),
                "mouse_straightness_mean": float(np.clip(np.random.normal(0.55, 0.12), 0.0, 1.0)),
                "hour_of_day": 23,  # unusual hour
                "cpu_usage": float(np.random.normal(18.0, 4.0)),
                "ram_usage_mb": float(np.random.normal(480.0, 50.0)),
                "active_app": "cmd.exe" if np.random.rand() > 0.2 else "powershell.exe"
            }
            
        data.append(row)
        
    return data

def run_simulation():
    """Runs a simulated evaluation of the models, prints stats, and generates performance graphs."""
    print("=== STARTING MODEL PERFORMANCE SIMULATION ===", flush=True)
    
    # 1. Generate data
    train_data = generate_synthetic_data(num_samples=1000, is_attacker=False)
    test_owner = generate_synthetic_data(num_samples=300, is_attacker=False)
    test_attacker = generate_synthetic_data(num_samples=300, is_attacker=True)
    
    # 2. Train models (Auto-Calibration is performed inside models.train())
    models = BehavioralModels()
    models.train(train_data)
    
    # 3. Evaluate Owner (Class 1) and Attacker (Class 0)
    owner_svm_scores = []
    owner_if_scores = []
    owner_fused_scores = []
    
    attacker_svm_scores = []
    attacker_if_scores = []
    attacker_fused_scores = []
    
    # Weights for fusion score: w1*SVM + w2*IF
    w1, w2 = 0.6, 0.4
    
    for row in test_owner:
        svm, iforest = models.score(row)
        owner_svm_scores.append(svm)
        owner_if_scores.append(iforest)
        owner_fused_scores.append(w1 * svm + w2 * iforest)
        
    for row in test_attacker:
        svm, iforest = models.score(row)
        attacker_svm_scores.append(svm)
        attacker_if_scores.append(iforest)
        attacker_fused_scores.append(w1 * svm + w2 * iforest)
        
    # Threat trigger is Risk > 0.80, which corresponds to Fused Score < 0.20
    # Let's set a standard normality/confidence threshold at 0.50
    threshold = 0.50
    
    owner_correct = sum(1 for s in owner_fused_scores if s >= threshold)
    attacker_correct = sum(1 for s in attacker_fused_scores if s < threshold)
    
    tpr = (owner_correct / len(test_owner)) * 100
    tnr = (attacker_correct / len(test_attacker)) * 100
    
    print("\n" + "="*45)
    print("      SIMULATED MODEL EVALUATION REPORT      ")
    print("="*45)
    print(f"Normal User Samples: {len(test_owner)}")
    print(f"Attacker Samples:    {len(test_attacker)}")
    print("-" * 45)
    print(f"Authorized Owner Recognized (TPR): {tpr:.2f}%")
    print(f"Unauthorized Attacker Blocked (TNR): {tnr:.2f}%")
    print(f"False Alarm Rate (False Positives):  {(100 - tpr):.2f}%")
    print("="*45)

    # 4. Generate visual plot
    if PLOT_AVAILABLE:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Plot 1: Keystroke/Mouse Biometrics Anomaly Scores (One-Class SVM)
        ax1.hist(owner_svm_scores, bins=15, alpha=0.6, label="Owner (Normal)", color="g")
        ax1.hist(attacker_svm_scores, bins=15, alpha=0.6, label="Attacker (Anomaly)", color="r")
        ax1.set_title("Biometric Dynamics Confidence (OC-SVM)")
        ax1.set_xlabel("Confidence [0.0 = Anomaly, 1.0 = Normal]")
        ax1.set_ylabel("Frequency")
        ax1.legend()
        ax1.grid(True, linestyle="--", alpha=0.5)

        # Plot 2: Context Anomaly Scores (Isolation Forest)
        ax2.hist(owner_if_scores, bins=15, alpha=0.6, label="Owner (Normal)", color="g")
        ax2.hist(attacker_if_scores, bins=15, alpha=0.6, label="Attacker (Anomaly)", color="r")
        ax2.set_title("Context Activity Confidence (Isolation Forest)")
        ax2.set_xlabel("Confidence [0.0 = Anomaly, 1.0 = Normal]")
        ax2.set_ylabel("Frequency")
        ax2.legend()
        ax2.grid(True, linestyle="--", alpha=0.5)

        plt.suptitle("Continuous Authentication - Model Performance (Auto-Calibrated)")
        plt.tight_layout()
        
        chart_name = os.path.join(PROJECT_ROOT, "model_performance.png")
        plt.savefig(chart_name, dpi=300)
        print(f"\n[SUCCESS] Generated slide-ready performance visualization chart: '{chart_name}'", flush=True)
    else:
        print("\n[NOTE] Matplotlib is not installed. Skipping performance visualization chart export.", flush=True)

    # Save models
    models.save("ml_engine/trained_models.pkl")

def adapt_to_verified_drift(log_file="telemetry_data.jsonl", limit=2000):
    """
    Trims the active rolling history log files to keep baseline statistics fresh,
    then retrains the models on the updated baseline.
    """
    print("\nAdapting to verified behavior drift (retraining)...", flush=True)
    if not os.path.isabs(log_file):
        log_file = os.path.join(PROJECT_ROOT, log_file)
    if os.path.exists(log_file):
        try:
            with open(log_file, "r") as f:
                lines = f.readlines()
            if len(lines) > limit:
                with open(log_file, "w") as f:
                    f.writelines(lines[-limit:])
                print(f"[INFO] Trimmed {log_file} to latest {limit} entries.", flush=True)
        except Exception as e:
            print(f"[WARNING] Failed to trim log file: {e}", file=sys.stderr)
            
    # Retrain
    real_rows = load_real_data(log_file)
    if real_rows:
        models = BehavioralModels()
        models.train(real_rows)
        models.save("ml_engine/trained_models.pkl")

def train_models(file_path="telemetry_data.jsonl", output_model_path=None):
    """Programmatically trains and saves models from a telemetry JSONL file."""
    real_rows = load_real_data(file_path)
    if not real_rows:
        print(f"[WARNING] No data found in '{file_path}'.", file=sys.stderr)
        return False
        
    print(f"[INFO] Loaded {len(real_rows)} records for training.", flush=True)
    models = BehavioralModels()
    models.train(real_rows)
    models.save(output_model_path or "ml_engine/trained_models.pkl")
    return True

def main():
    parser = argparse.ArgumentParser(description="Continuous Authentication - ML Model Training Pipeline")
    parser.add_argument("--simulate", action="store_true", help="Run model simulation with synthetic data and plot metrics")
    args = parser.parse_args()
    
    if args.simulate:
        run_simulation()
        return

    print("=== STARTING MODEL TRAINING PIPELINE ===", flush=True)
    real_rows = load_real_data("telemetry_data.jsonl")
    
    MIN_ROWS = 15
    if len(real_rows) < MIN_ROWS:
        print(f"\n[WARNING] Insufficient data. Found only {len(real_rows)} rows in 'telemetry_data.jsonl'.", file=sys.stderr)
        print(f"Please run the telemetry agent first to capture the owner's baseline patterns:", file=sys.stderr)
        print(f"    python telemetry/agent.py\n", file=sys.stderr)
        sys.exit(1)
        
    train_models("telemetry_data.jsonl")
    
    # Train PyTorch sequence SVDD model if raw keystroke file exists
    ks_path = os.path.join(PROJECT_ROOT, "data", "raw", "keystrokes.csv")
    if os.path.exists(ks_path):
        print("\n[INFO] Found raw keystroke timing file. Training Deep SVDD 1D-CNN...", flush=True)
        try:
            from ml_engine.sequence_model import DeepSVDDDetector
            svdd = DeepSVDDDetector()
            svdd.train(ks_path)
        except Exception as e:
            print(f"[WARNING] PyTorch Sequence training failed: {e}", file=sys.stderr)
            
    print("[SUCCESS] Training pipeline execution finished.", flush=True)

if __name__ == "__main__":
    main()
