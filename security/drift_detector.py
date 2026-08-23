import os
import sys
import time
import json
import collections

# Append project root directory to path
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from ml_engine.models import BehavioralModels
from security.webcam import capture_intruder
from security.otp_service import generate_otp, dispatch_otp

class ThreatEvaluator:
    """
    Threat Evaluation and Alert Dispatcher.
    Combines Biometric (OC-SVM) and Context (Isolation Forest) models,
    applies a 30-second moving average, and coordinates alerting.
    """
    def __init__(self, models_path="ml_engine/trained_models.pkl", threshold=0.75, cooldown_seconds=300):
        self.models_path = os.path.join(project_dir, models_path)
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        
        self.models = BehavioralModels()
        self.models_loaded = False
        
        # Sliding queue to hold the last 3 score windows (3 * 10s = 30s)
        self.risk_history = collections.deque(maxlen=3)
        
        # State management
        self.is_breached = False
        self.last_alert_time = 0.0
        self.active_otp = None
        
        self.load_models()

    def load_models(self):
        """Attempts to load the serialized ML models."""
        if os.path.exists(self.models_path):
            try:
                self.models.load(self.models_path)
                self.models_loaded = True
                print(f"[EVALUATOR] Successfully loaded security models from '{self.models_path}'", flush=True)
            except Exception as e:
                print(f"[EVALUATOR] [ERROR] Failed to load models: {e}", file=sys.stderr, flush=True)
        else:
            print(f"[EVALUATOR] [WARNING] Models file not found at '{self.models_path}'. Threat evaluation will use default heuristics.", file=sys.stderr, flush=True)

    def evaluate_row(self, telemetry_row, weights=(0.6, 0.4)):
        """
        Scores a single telemetry JSON row and updates the moving average risk.
        
        Formulation:
            Confidence = w1 * SVM_Score + w2 * IF_Score
            Risk = 1.0 - Confidence
            
        Returns:
            fused_risk: The current raw risk score.
            smoothed_risk: The 30-second moving average risk.
            triggered: Boolean indicating if a breach alert was triggered in this step.
        """
        w1, w2 = weights
        triggered = False
        
        if not self.models_loaded:
            # Fallback heuristic if models are not trained yet
            # Flag high risk if process context CPU is extremely high or app is unknown cmd
            cpu = telemetry_row.get("cpu_usage", 0.0)
            app = str(telemetry_row.get("active_app", "")).lower()
            heur_risk = 0.85 if (cpu > 60.0 or "cmd" in app or "powershell" in app) else 0.10
            self.risk_history.append(heur_risk)
            fused_risk = heur_risk
        else:
            try:
                # 1. Fetch normalized confidence scores [0.0 - 1.0] from classifiers
                svm_conf, if_conf = self.models.score(telemetry_row)
                
                # 2. Score Fusion (Weighted Average of Normality)
                fused_conf = w1 * svm_conf + w2 * if_conf
                fused_risk = 1.0 - fused_conf
                
                # 3. Add to sliding queue for 30s smoothing
                self.risk_history.append(fused_risk)
            except Exception as e:
                print(f"[EVALUATOR] [ERROR] Scoring exception: {e}", file=sys.stderr, flush=True)
                fused_risk = 0.5
                self.risk_history.append(fused_risk)
                
        # 4. Calculate smoothed moving average
        smoothed_risk = sum(self.risk_history) / len(self.risk_history)
        
        # 5. Check Anomaly Breach Conditions
        now = time.time()
        if smoothed_risk >= self.threshold:
            if not self.is_breached and (now - self.last_alert_time > self.cooldown_seconds):
                # Breach declared! Trigger security events
                self.is_breached = True
                self.last_alert_time = now
                self.active_otp = generate_otp()
                triggered = True
                
                print(f"\n[ALERT] BEHAVIORAL DRIFT BREACH DETECTED! Smoothed Risk: {smoothed_risk:.4f}", flush=True)
                
                # Trigger Active Response Actions
                capture_intruder()
                dispatch_otp(self.active_otp)
                
                # Save active OTP code securely to verify identity later
                self._save_active_otp(self.active_otp)
                
        return float(fused_risk), float(smoothed_risk), triggered

    def verify_otp_and_reset(self, entered_otp):
        """
        Verifies the user's OTP code. If correct, resets the breach lock state
        and triggers behavior adaptation (drift training).
        """
        stored_otp = self._load_active_otp()
        if stored_otp and entered_otp.strip() == stored_otp.strip():
            print("\n[SECURITY] OTP Verification Successful! Restoring session...", flush=True)
            self.is_breached = False
            self.active_otp = None
            self._clear_active_otp()
            
            # Retrain models to adapt to behavior drift
            try:
                from ml_engine.train import adapt_to_verified_drift
                adapt_to_verified_drift()
                # Reload models with the newly adapted boundaries
                self.load_models()
            except Exception as e:
                print(f"[EVALUATOR] [WARNING] Adaptation retraining failed: {e}", file=sys.stderr, flush=True)
            return True
            
        print("[SECURITY] Invalid OTP code entered.", flush=True)
        return False

    def _save_active_otp(self, otp):
        otp_file = os.path.join(project_dir, "models", ".active_otp")
        os.makedirs(os.path.dirname(otp_file), exist_ok=True)
        try:
            with open(otp_file, "w") as f:
                f.write(otp)
        except Exception:
            pass

    def _load_active_otp(self):
        otp_file = os.path.join(project_dir, "models", ".active_otp")
        if os.path.exists(otp_file):
            try:
                with open(otp_file, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return self.active_otp

    def _clear_active_otp(self):
        otp_file = os.path.join(project_dir, "models", ".active_otp")
        if os.path.exists(otp_file):
            try:
                os.remove(otp_file)
            except Exception:
                pass

if __name__ == "__main__":
    # Test script running evaluator logic on mock values
    evaluator = ThreatEvaluator()
    dummy_row = {
        "cpu_usage": 80.0,
        "active_app": "cmd.exe",
        "ram_usage_mb": 500.0,
        "hour_of_day": 23
    }
    print("Evaluating high-risk telemetry entry...")
    evaluator.evaluate_row(dummy_row)
