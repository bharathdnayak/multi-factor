import os
import sys
import time
import json
import collections

# Append project root directory to path
project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_dir)

from ml_engine.models import BehavioralModels
from ml_engine.controller import BehavioralAIController
from security.webcam import capture_intruder
from security.otp_service import generate_otp, dispatch_otp

class ThreatEvaluator:
    """
    Threat Evaluation and Alert Dispatcher.
    Combines Biometric (OC-SVM), Context (Isolation Forest), and Cognitive Task (BehavioralAIController)
    models, applies a 30-second moving average, and coordinates alerting.
    """
    def __init__(self, models_path="ml_engine/trained_models.pkl", threshold=0.55, cooldown_seconds=120):
        self.models_path = os.path.join(project_dir, models_path)
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        
        self.models = BehavioralModels()
        self.controller = BehavioralAIController()
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
            cpu = telemetry_row.get("cpu_usage", 0.0)
            app = str(telemetry_row.get("active_app", "")).lower()
            heur_risk = 0.85 if (cpu > 60.0 or "cmd" in app or "powershell" in app) else 0.10
            self.risk_history.append(heur_risk)
            fused_risk = heur_risk
        else:
            try:
                # 1. Fetch normalized confidence scores [0.0 - 1.0] from classifiers
                svm_conf, if_conf = self.models.score(telemetry_row)
                
                # 2. Fetch Cognitive Task confidence from Behavioral AI Controller
                try:
                    ctrl_anomaly, _ = self.controller.evaluate_telemetry_row(telemetry_row)
                    ctrl_conf = 1.0 - ctrl_anomaly
                except Exception:
                    ctrl_conf = svm_conf

                # 3. Tri-Factor Fusion across Biometrics, Context, and Cognitive Profile
                if len(weights) == 3:
                    w_svm, w_if, w_ctrl = weights
                else:
                    w1, w2 = weights
                    w_svm = w1 * 0.70
                    w_ctrl = w1 * 0.30
                    w_if = w2
                
                fused_conf = w_svm * svm_conf + w_if * if_conf + w_ctrl * ctrl_conf
                fused_risk = 1.0 - fused_conf
                
                # 4. Add to sliding queue for 30s smoothing
                self.risk_history.append(fused_risk)
            except Exception as e:
                print(f"[EVALUATOR] [ERROR] Scoring exception: {e}", file=sys.stderr, flush=True)
                fused_risk = 0.5
                self.risk_history.append(fused_risk)
                
        # 4. Calculate smoothed moving average
        smoothed_risk = sum(self.risk_history) / len(self.risk_history)
        
        # 5. Check Anomaly Breach Conditions
        now = time.time()
        keys_in_window = telemetry_row.get("keystroke_count", 0)

        # Multi-Criteria Anomaly Trigger Logic:
        # A) Sustained Behavioral Drift: 30s smoothed risk >= threshold (default 0.55)
        # B) Acute Imposter Spike: instantaneous risk >= 0.78 with active typing (keys >= 2)
        # C) Successive High-Risk Windows: 2 recent windows with risk >= 0.65
        is_sustained = (smoothed_risk >= self.threshold)
        is_acute = (fused_risk >= 0.78 and keys_in_window >= 2)
        is_two_spike = (len(self.risk_history) >= 2 and fused_risk >= 0.65 and list(self.risk_history)[-2] >= 0.60)

        should_trigger = is_sustained or is_acute or is_two_spike

        if should_trigger:
            if not self.is_breached and (now - self.last_alert_time > self.cooldown_seconds):
                # Breach declared! Trigger security events
                self.is_breached = True
                self.last_alert_time = now
                self.active_otp = generate_otp()
                triggered = True
                
                trigger_reason = "ACUTE INTRUDER SPIKE" if is_acute else ("SUCCESSIVE ANOMALY" if is_two_spike else "SUSTAINED BEHAVIORAL DRIFT")
                print(f"\n[ALERT] BEHAVIORAL DRIFT BREACH DETECTED! ({trigger_reason})", flush=True)
                print(f"[ALERT] Instant Risk: {fused_risk:.4f} | Smoothed (30s): {smoothed_risk:.4f} (Threshold: {self.threshold:.2f})", flush=True)
                print(f"[OTP] Generated Session OTP: >>> {self.active_otp} <<< (saved to models/.active_otp)", flush=True)
                print(f"[OTP] Master Bypass Password: >>> admin <<< (or admin123 / 123456)", flush=True)
                
                # Trigger Active Response Actions
                capture_intruder()
                dispatch_otp(self.active_otp)
                
                # Save active OTP code securely to verify identity later
                self._save_active_otp(self.active_otp)
                
        return float(fused_risk), float(smoothed_risk), triggered

    def verify_otp_and_reset(self, entered_otp):
        """
        Verifies the user's OTP code or Master Bypass Password.
        If correct, resets the breach lock state and triggers behavior adaptation (drift training).
        """
        entered = str(entered_otp).strip()
        stored_otp = self._load_active_otp()
        
        # Load configured master bypass password
        configured_bypass = "admin"
        try:
            from security.otp_service import load_or_create_config
            cfg = load_or_create_config()
            configured_bypass = cfg.get("security", {}).get("master_bypass_password", "admin")
        except Exception:
            pass

        # Recognized master bypass codes
        master_passwords = {"admin", "admin123", "123456", str(configured_bypass)}
        
        is_valid_otp = bool(stored_otp and entered == stored_otp.strip())
        is_valid_bypass = entered in master_passwords
        
        if is_valid_otp or is_valid_bypass:
            method = "OTP" if is_valid_otp else "Master Bypass Password"
            print(f"\n[SECURITY] Identity Verified via {method}! Restoring session...", flush=True)
            self.is_breached = False
            self.active_otp = None
            self._clear_active_otp()
            
            # Retrain models to adapt to behavior drift
            try:
                from ml_engine.train import adapt_to_verified_drift
                adapt_to_verified_drift()
                # Reload models with the newly adapted boundaries
                self.load_models()
                # Also learn verified session in AI Controller
                if os.path.exists(self.controller.active_session_path):
                    with open(self.controller.active_session_path, "r", encoding="utf-8") as f:
                        act_data = json.load(f)
                    self.controller.learn_from_session(act_data, verified=True)
            except Exception as e:
                print(f"[EVALUATOR] [WARNING] Adaptation retraining failed: {e}", file=sys.stderr, flush=True)
            return True
            
        print("[SECURITY] Invalid OTP code or bypass password entered.", flush=True)
        return False

    def start_daemon(self, telemetry_file="telemetry_data.jsonl"):
        """
        Starts a live tailing file watcher on the telemetry log,
        scoring new events in real time and spawning the lock screen on breach.
        """
        log_path = os.path.join(project_dir, telemetry_file)
        print(f"[DAEMON] Starting threat evaluation daemon. Monitoring '{log_path}'...", flush=True)
        
        # Wait for file creation if it doesn't exist
        while not os.path.exists(log_path):
            time.sleep(1.0)
            
        with open(log_path, "r") as f:
            # Go to the end of the file to ignore historic entries
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                    
                line = line.strip()
                if line:
                    try:
                        row = json.loads(line)
                        f_risk, s_risk, triggered = self.evaluate_row(row)
                        status_tag = ""
                        if f_risk >= 0.78:
                            status_tag = " >>> CRITICAL INTRUDER SPIKE! <<<"
                        elif f_risk >= 0.55:
                            status_tag = " [ELEVATED DRIFT]"
                        elif f_risk <= 0.15:
                            status_tag = " [NORMAL OWNER]"
                            
                        print(f"[DAEMON] Scored event. Risk: {f_risk:.4f} | Smoothed (30s): {s_risk:.4f}{status_tag}", flush=True)
                        
                        if triggered:
                            print("[DAEMON] Intrusion breach triggered! Spawning verification UI...", flush=True)
                            # Import lock handler and launch the prompt
                            from security.lock_handler import launch_verification_lock
                            launch_verification_lock(self)
                    except Exception as e:
                        print(f"[DAEMON] [ERROR] Processing line failed: {e}", file=sys.stderr, flush=True)

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
    # If run directly as a script, act as the background watcher daemon
    evaluator = ThreatEvaluator()
    try:
        evaluator.start_daemon()
    except KeyboardInterrupt:
        print("[DAEMON] Exiting cleanly.", flush=True)
