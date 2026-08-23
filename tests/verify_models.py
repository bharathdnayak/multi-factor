import os
import sys
import numpy as np
import pandas as pd

# Append project directory to system path to import modules
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from ml_engine.models import BehavioralModels
from ml_engine.sequence_model import DeepSVDDDetector

def run_verification():
    raw_data_dir = os.path.join(project_dir, "data", "raw")
    
    # 1. Load Trained Models
    print("Loading serialized models...")
    models = BehavioralModels()
    models.load("ml_engine/trained_models.pkl")
    seq_detector = DeepSVDDDetector()
    
    if not models.is_trained or seq_detector.model is None:
        print("FAIL: Model files could not be loaded. Ensure they are trained and saved in models/.", file=sys.stderr)
        sys.exit(1)
        
    print("[OK] Models loaded successfully.\n")

    # Generate synthetic validation row representation
    # Normal user telemetry
    normal_row = {
        "dwell_mean": 0.09,
        "dwell_std": 0.015,
        "flight_mean": 0.12,
        "flight_std": 0.02,
        "mouse_velocity_mean": 250.0,
        "mouse_acceleration_mean": 12.0,
        "mouse_jerk_mean": 1.1,
        "mouse_straightness_mean": 0.92,
        "hour_of_day": 14,
        "cpu_usage": 2.5,
        "ram_usage_mb": 150.0,
        "active_app": "code.exe"
    }
    
    # Imposter/attacker telemetry
    imposter_row = {
        "dwell_mean": 0.24,
        "dwell_std": 0.045,
        "flight_mean": 0.32,
        "flight_std": 0.065,
        "mouse_velocity_mean": 750.0,
        "mouse_acceleration_mean": 55.0,
        "mouse_jerk_mean": 9.5,
        "mouse_straightness_mean": 0.55,
        "hour_of_day": 23,
        "cpu_usage": 18.0,
        "ram_usage_mb": 480.0,
        "active_app": "cmd.exe"
    }

    # Evaluate Biometrics and Context
    print("--- BIOMETRIC Dynamics Verification (One-Class SVM) ---")
    owner_bio_conf, _ = models.score(normal_row)
    imposter_bio_conf, _ = models.score(imposter_row)
    
    # Convert confidence (1=normal, 0=anomaly) to risk (0=normal, 1=anomaly)
    owner_bio_risk = 1.0 - owner_bio_conf
    imposter_bio_risk = 1.0 - imposter_bio_conf
    
    print(f"Owner Biometric Risk: {owner_bio_risk:.4f} (Confidence: {owner_bio_conf:.4f})")
    print(f"Imposter Biometric Risk: {imposter_bio_risk:.4f} (Confidence: {imposter_bio_conf:.4f})")
    
    bio_check = owner_bio_risk < 0.35 and imposter_bio_risk > 0.65
    if bio_check:
        print("[SUCCESS] Biometric model correctly separates Owner and Imposter.")
    else:
        print("[FAIL] Biometric model failed to separate Owner and Imposter!")

    print("\n--- SYSTEM CONTEXT VERIFICATION (Isolation Forest) ---")
    _, owner_ctx_conf = models.score(normal_row)
    _, imposter_ctx_conf = models.score(imposter_row)
    
    owner_ctx_risk = 1.0 - owner_ctx_conf
    imposter_ctx_risk = 1.0 - imposter_ctx_conf
    
    print(f"Owner Context Risk: {owner_ctx_risk:.4f} (Confidence: {owner_ctx_conf:.4f})")
    print(f"Imposter Context Risk: {imposter_ctx_risk:.4f} (Confidence: {imposter_ctx_conf:.4f})")
    
    ctx_check = owner_ctx_risk < 0.35 and imposter_ctx_risk > 0.65
    if ctx_check:
        print("[SUCCESS] Context model correctly separates Owner and Imposter.")
    else:
        print("[FAIL] Context model failed to separate Owner and Imposter!")

    # --- PyTorch Sequence Model Verification (Deep SVDD 1D-CNN) ---
    print("\n--- PYTORCH SEQUENCE BIOMETRIC VERIFICATION (Deep SVDD 1D-CNN) ---")
    normal_ks_path = os.path.join(raw_data_dir, "keystrokes.csv")
    imposter_ks_path = os.path.join(raw_data_dir, "imposter_keystrokes.csv")
    
    normal_seqs = seq_detector.extract_raw_sequences(normal_ks_path)
    imposter_seqs = seq_detector.extract_raw_sequences(imposter_ks_path)
    
    normal_seq_scores = []
    for seq in normal_seqs:
        score = seq_detector.predict_score(seq[0], seq[1])
        normal_seq_scores.append(score)
        
    imposter_seq_scores = []
    for seq in imposter_seqs:
        score = seq_detector.predict_score(seq[0], seq[1])
        imposter_seq_scores.append(score)
        
    mean_normal_seq = np.mean(normal_seq_scores) if normal_seq_scores else 0.0
    mean_imposter_seq = np.mean(imposter_seq_scores) if imposter_seq_scores else 0.0
    
    print(f"Loaded {len(normal_seqs)} normal sequences, {len(imposter_seqs)} imposter sequences.")
    print(f"Mean Owner Sequence Risk Score: {mean_normal_seq:.4f}")
    print(f"Mean Imposter Sequence Risk Score: {mean_imposter_seq:.4f}")
    
    seq_check = mean_normal_seq < 0.35 and mean_imposter_seq > 0.65
    if seq_check:
        print("[SUCCESS] PyTorch 1D-CNN model correctly separates Owner and Imposter.")
    else:
        print("[FAIL] PyTorch 1D-CNN model failed to separate Owner and Imposter!")

    print("\n-------------------------------------------")
    if bio_check and ctx_check and seq_check:
        print("ALL VERIFICATIONS (SVM, Isolation Forest, and PyTorch 1D-CNN) PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("VERIFICATION FAILED ON ONE OR MORE MODELS.")
        sys.exit(1)

if __name__ == "__main__":
    run_verification()
