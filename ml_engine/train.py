import os
import sys
import json
import argparse
import numpy as np
import pandas as pd
from models import BehavioralModels

# Optional import for plotting
try:
    import matplotlib.pyplot as plt
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False

def load_real_data(file_path="telemetry_data.jsonl"):
    """Loads telemetry rows from the JSONL log file."""
    if not os.path.exists(file_path):
        return []
    
    rows = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    return rows

def generate_synthetic_data(num_samples=200, is_attacker=False):
    """Generates synthetic telemetry rows for simulation/demo purposes."""
    np.random.seed(42 if not is_attacker else 24)
    data = []
    
    for _ in range(num_samples):
        if not is_attacker:
            # Owner: consistent fast typing, smooth mouse curves, developer apps
            row = {
                "dwell_mean": float(np.random.normal(0.09, 0.012)),
                "dwell_std": float(np.random.normal(0.015, 0.003)),
                "flight_mean": float(np.random.normal(0.12, 0.015)),
                "flight_std": float(np.random.normal(0.02, 0.004)),
                "mouse_velocity_mean": float(np.random.normal(250.0, 30.0)),
                "mouse_acceleration_mean": float(np.random.normal(12.0, 2.0)),
                "mouse_jerk_mean": float(np.random.normal(1.1, 0.15)),
                "mouse_straightness_mean": float(np.clip(np.random.normal(0.92, 0.03), 0.0, 1.0)),
                "hour_of_day": 14,
                "cpu_usage": float(np.random.normal(2.5, 0.8)),
                "ram_usage_mb": float(np.random.normal(150.0, 10.0)),
                "active_app": "code.exe" if np.random.rand() > 0.1 else "chrome.exe"
            }
        else:
            # Attacker: slow hunt-and-peck typing, erratic jittery mouse, terminal/admin apps
            row = {
                "dwell_mean": float(np.random.normal(0.24, 0.04)),
                "dwell_std": float(np.random.normal(0.045, 0.01)),
                "flight_mean": float(np.random.normal(0.32, 0.06)),
                "flight_std": float(np.random.normal(0.065, 0.015)),
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
    train_data = generate_synthetic_data(num_samples=4000, is_attacker=False)
    test_owner = generate_synthetic_data(num_samples=1000, is_attacker=False)
    test_attacker = generate_synthetic_data(num_samples=1000, is_attacker=True)
    
    # 2. Train models
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
        
    # Calculate classification metrics
    # Threat trigger is Risk > 0.80, which means Fused Score < 0.20 (since fused score represents confidence/normality)
    threshold = 0.45  # normal confidence threshold
    
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

    # 4. Generate visual plot for presentation slide
    if PLOT_AVAILABLE:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Plot 1: Keystroke/Mouse Biometrics Anomaly Scores (One-Class SVM)
        ax1.hist(owner_svm_scores, bins=15, alpha=0.6, label="Owner (Normal)", color="g")
        ax1.hist(attacker_svm_scores, bins=15, alpha=0.6, label="Attacker (Anomaly)", color="r")
        ax1.set_title("Biometric Dynamics Scores (OC-SVM)")
        ax1.set_xlabel("Normality Score [0.0 = Anomaly, 1.0 = Normal]")
        ax1.set_ylabel("Frequency")
        ax1.legend()
        ax1.grid(True, linestyle="--", alpha=0.5)

        # Plot 2: Context Anomaly Scores (Isolation Forest)
        ax2.hist(owner_if_scores, bins=15, alpha=0.6, label="Owner (Normal)", color="g")
        ax2.hist(attacker_if_scores, bins=15, alpha=0.6, label="Attacker (Anomaly)", color="r")
        ax2.set_title("Context Activity Scores (Isolation Forest)")
        ax2.set_xlabel("Normality Score [0.0 = Anomaly, 1.0 = Normal]")
        ax2.set_ylabel("Frequency")
        ax2.legend()
        ax2.grid(True, linestyle="--", alpha=0.5)

        plt.suptitle("Continuous Authentication - Model Score Separation Profile")
        plt.tight_layout()
        
        chart_name = "model_performance.png"
        plt.savefig(chart_name, dpi=300)
        print(f"\n[SUCCESS] Generated slide-ready performance visualization chart: '{chart_name}'", flush=True)
    else:
        print("\n[NOTE] Matplotlib is not installed. Skipping performance visualization chart export.", flush=True)

    # Save models
    models.save("ml_engine/trained_models.pkl")

def main():
    parser = argparse.ArgumentParser(description="Continuous Authentication - ML Model Training Pipeline")
    parser.add_argument("--simulate", action="store_true", help="Run model simulation with synthetic data and plot metrics")
    args = parser.parse_args()
    
    if args.simulate:
        run_simulation()
        return

    # Real training flow
    print("=== STARTING MODEL TRAINING PIPELINE ===", flush=True)
    real_rows = load_real_data("telemetry_data.jsonl")
    
    # We require at least 15 telemetry rows (approx. 2.5 minutes of active session log)
    MIN_ROWS = 15
    if len(real_rows) < MIN_ROWS:
        print(f"\n[WARNING] Insufficient data. Found only {len(real_rows)} rows in 'telemetry_data.jsonl'.", file=sys.stderr)
        print(f"Please run the telemetry agent first to capture the owner's baseline patterns:", file=sys.stderr)
        print(f"    python telemetry/agent.py\n", file=sys.stderr)
        print(f"Collect at least {MIN_ROWS} data rows (approx. 2.5 minutes of typing/mouse activity) before training.", file=sys.stderr)
        sys.exit(1)
        
    print(f"[INFO] Loaded {len(real_rows)} baseline records from 'telemetry_data.jsonl'.", flush=True)
    
    models = BehavioralModels()
    models.train(real_rows)
    models.save("ml_engine/trained_models.pkl")
    print("[SUCCESS] Training pipeline execution finished.", flush=True)

if __name__ == "__main__":
    main()
