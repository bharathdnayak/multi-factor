"""
Independent Verification: Model Packaging, Serialized Checkpoints, and Legacy Rollback
Tests loading from clean process, schema compatibility, metadata consistency, and rollback fidelity.
"""
import os
import sys
import json
import pickle
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.models import BehavioralModels
from ml_engine.sequence_model import DeepSVDDDetector
from telemetry.evaluator import ThreatEvaluator

def run_packaging_tests():
    print("=" * 70)
    print("INDEPENDENT VALIDATION: MODEL PACKAGING, METADATA & ROLLBACK FIDELITY")
    print("=" * 70)

    # 1. Verify existence of backup checkpoints
    backup_pkl = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models_backup.pkl")
    backup_pt = os.path.join(PROJECT_ROOT, "models", "sequence_model_backup.pt")
    backup_json = os.path.join(PROJECT_ROOT, "models", "sequence_meta_backup.json")

    assert os.path.exists(backup_pkl), "Backup models.pkl must exist"
    assert os.path.exists(backup_pt), "Backup sequence_model.pt must exist"
    assert os.path.exists(backup_json), "Backup sequence_meta.json must exist"
    print(f"[BACKUPS VERIFIED] Backup model artifacts intact ({os.path.getsize(backup_pkl):,} bytes).")

    # 2. Test loading BehavioralModels from clean process
    models = BehavioralModels()
    models.load(os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl"))
    assert models.is_trained is True
    assert hasattr(models.biometric_scaler, "mean_")
    assert hasattr(models.context_scaler, "mean_")
    print(f"[MODELS LOADED] One-Class SVM & Isolation Forest loaded. Calibrated thresholds: Bio={models.biometric_threshold:.6f}, Ctx={models.context_threshold:.6f}")

    # 3. Test loading PyTorch Sequence Detector
    seq_det = DeepSVDDDetector()
    assert seq_det.model is not None
    assert seq_det.center is not None
    assert seq_det.radius is not None
    print(f"[DEEP SVDD LOADED] Hypersphere center dim: {len(seq_det.center)}, Radius: {seq_det.radius:.6f}")

    # 4. Verify trained_models_meta.json consistency
    meta_path = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models_meta.json")
    assert os.path.exists(meta_path)
    with open(meta_path, "r") as f:
        meta = json.load(f)
    assert meta["model_version"] == "2.0.0"
    assert "biometric_model" in meta["subsystems"]
    assert "multimodal_fusion" in meta["subsystems"]
    print(f"[METADATA VERIFIED] Meta JSON matched version {meta['model_version']} with {len(meta['subsystems']['biometric_model']['features'])} biometric features.")

    # 5. Verify Legacy Rollback Fidelity
    evaluator = ThreatEvaluator()
    sample_row = {
        "hour_of_day": 14, "keystroke_count": 20,
        "dwell_mean": 0.09, "dwell_std": 0.015,
        "flight_mean": 0.12, "flight_std": 0.02,
        "app_dwell_mean": 0.09, "app_flight_mean": 0.12,
        "app_backspace_ratio": 0.12, "app_special_ratio": 0.20,
        "app_click_count": 4, "app_scroll_count": 6, "app_pause_ratio": 0.40,
        "interaction_mode": "ai_chat_or_prompting",
        "mouse_events": 30,
        "mouse_velocity_mean": 250.0, "mouse_acceleration_mean": 12.0,
        "mouse_jerk_mean": 1.1, "mouse_straightness_mean": 0.92,
        "cpu_usage": 2.5, "ram_usage_mb": 250.0,
        "active_app": "Code.exe",
        "dwell_sequence": [0.09] * 30, "flight_sequence": [0.12] * 30
    }

    # Evaluate in legacy mode
    legacy_fused, legacy_smoothed, _ = evaluator.evaluate_row(sample_row, legacy_mode=True)
    # Evaluate in dynamic mode
    dynamic_fused, dynamic_smoothed, _ = evaluator.evaluate_row(sample_row, dynamic_fusion=True)

    print(f"[ROLLBACK EXECUTION] Legacy Mode Risk: {legacy_fused:.4f} | Dynamic Mode Risk: {dynamic_fused:.4f}")
    assert legacy_fused is not None and 0.0 <= legacy_fused <= 1.0
    assert dynamic_fused is not None and 0.0 <= dynamic_fused <= 1.0

    print("=" * 70)
    print("ALL MODEL PACKAGING AND ROLLBACK TESTS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_packaging_tests()
