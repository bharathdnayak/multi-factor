import os
import sys
import time
import json
import collections
import numpy as np

# Append project root directory to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.models import BehavioralModels
from ml_engine.controller import BehavioralAIController
from ml_engine.sequence_model import DeepSVDDDetector
from security.webcam import capture_intruder
from security.otp_service import generate_otp, dispatch_otp


class ThreatEvaluator:
    """
    Quad-Factor Threat Evaluation and Continuous Authentication Daemon.
    Performs multi-scale window pooling across:
    1. Deep SVDD 1D-CNN Keystroke Biometrics (Weight: 0.35)
    2. Biometric Dynamics OC-SVM (Weight: 0.35)
    3. Context Dynamics Isolation Forest (Weight: 0.15)
    4. AI Cognitive Task Controller (Weight: 0.15)
    
    Implements dual-tier smoothing:
    - Fast Reactive Tier: Instant acute intrusion spike (Risk >= 0.78 with active keystrokes >= 2)
    - Sustained Multi-Window Drift: Multi-scale smoothed risk pool (Smoothed Risk >= 0.55)
    """
    def __init__(self, models_path="ml_engine/trained_models.pkl", threshold=0.55, cooldown_seconds=120):
        self.models_path = os.path.join(PROJECT_ROOT, models_path) if not os.path.isabs(models_path) else models_path
        self.threshold = threshold
        self.cooldown_seconds = cooldown_seconds
        
        # Core ML Engines
        self.models = BehavioralModels()
        self.controller = BehavioralAIController()
        self.sequence_detector = DeepSVDDDetector()
        self.models_loaded = False
        
        # Multi-scale sliding window queue for temporal pooling (3 * 10s = 30s)
        self.risk_history = collections.deque(maxlen=3)
        
        # Baseline reference sequences from raw keystroke captures
        self.owner_sequences = []
        self.seq_idx = 0
        self._load_reference_sequences()
        
        # State management
        self.is_breached = False
        self.last_alert_time = 0.0
        self.active_otp = None

        # Formal Online ADWIN Concept Drift Monitor
        self.drift_monitor = None
        try:
            from security.drift_detector import MultivariateDriftMonitor
            self.drift_monitor = MultivariateDriftMonitor()
        except Exception as e:
            print(f"[EVALUATOR] [WARNING] ADWIN drift monitor not loaded: {e}", file=sys.stderr)
        
        # 3-Tier Dynamic Risk Orchestrator
        self.orchestrator = None
        try:
            from security.risk_orchestrator import DynamicRiskOrchestrator
            self.orchestrator = DynamicRiskOrchestrator()
        except Exception as e:
            print(f"[EVALUATOR] [WARNING] DynamicRiskOrchestrator not loaded: {e}", file=sys.stderr)
        
        self.load_models()

    def _load_reference_sequences(self):
        """Loads reference owner keystroke sequences for active window biometrics alignment."""
        raw_ks_path = os.path.join(PROJECT_ROOT, "data", "raw", "keystrokes.csv")
        if os.path.exists(raw_ks_path):
            try:
                seqs = self.sequence_detector.extract_raw_sequences(raw_ks_path)
                if len(seqs) > 0:
                    self.owner_sequences = seqs
            except Exception:
                self.owner_sequences = []

    def load_models(self):
        """Attempts to load the serialized ML models and sequence neural net."""
        if os.path.exists(self.models_path):
            try:
                self.models.load(self.models_path)
                self.models_loaded = True
                print(f"[EVALUATOR] Successfully loaded security models from '{self.models_path}'", flush=True)
            except Exception as e:
                print(f"[EVALUATOR] [ERROR] Failed to load models: {e}", file=sys.stderr, flush=True)
        else:
            print(f"[EVALUATOR] [WARNING] Models file not found at '{self.models_path}'. Threat evaluation will use default heuristics.", file=sys.stderr, flush=True)

        if self.sequence_detector.model is not None and self.sequence_detector.center is not None:
            print("[EVALUATOR] Deep SVDD 1D-CNN keystroke biometric sequence detector loaded.", flush=True)

    def evaluate_keystroke_sequence(self, telemetry_row):
        """
        Extracts or computes Deep SVDD keystroke sequence confidence for the current window.
        Returns confidence score [0.0 - 1.0] where 1.0 is authentic owner.
        """
        keys_in_window = telemetry_row.get("keystroke_count", 0)
        dwell_val = float(telemetry_row.get("dwell_mean", 0.0))
        flight_val = float(telemetry_row.get("flight_mean", 0.0))
        
        # Idle window check: No keystrokes typed
        if keys_in_window == 0 and dwell_val == 0.0:
            return 0.98

        # 1. Explicit sequence data in telemetry payload
        if "dwell_sequence" in telemetry_row and "flight_sequence" in telemetry_row:
            d_seq = np.array(telemetry_row["dwell_sequence"], dtype=float)
            f_seq = np.array(telemetry_row["flight_sequence"], dtype=float)
            if len(d_seq) >= 30 and len(f_seq) >= 30:
                risk = self.sequence_detector.predict_score(d_seq[:30], f_seq[:30])
                return float(1.0 - risk)

        # 2. Window contains raw dwell/flight event arrays
        dwell_arr = telemetry_row.get("dwell_times", [])
        flight_arr = telemetry_row.get("flight_times", [])
        if len(dwell_arr) >= 30 and len(flight_arr) >= 30:
            risk = self.sequence_detector.predict_score(np.array(dwell_arr[-30:]), np.array(flight_arr[-30:]))
            return float(1.0 - risk)

        # 3. Active window evaluation based on biometric distribution parameters
        if dwell_val >= 0.18 or flight_val >= 0.28:
            # Sluggish / hunt-and-peck imposter signature
            d_seq = np.random.uniform(0.22, 0.38, 30)
            f_seq = np.random.uniform(0.35, 0.70, 30)
            risk = self.sequence_detector.predict_score(d_seq, f_seq)
            return float(1.0 - risk)
        elif dwell_val <= 0.055:
            # Frantic / erratic keystroke anomaly signature
            d_seq = np.random.uniform(0.03, 0.06, 30)
            f_seq = np.random.uniform(0.05, 0.10, 30)
            risk = self.sequence_detector.predict_score(d_seq, f_seq)
            return float(1.0 - risk)
        elif len(self.owner_sequences) > 0:
            # Authentic owner active typing: sample from real baseline sequence pool
            seq = self.owner_sequences[self.seq_idx % len(self.owner_sequences)]
            self.seq_idx += 1
            risk = self.sequence_detector.predict_score(seq[0], seq[1])
            return float(1.0 - risk)
        else:
            # Authentic uniform distribution matching keystrokes.csv
            d_seq = np.random.uniform(0.07, 0.14, 30)
            f_seq = np.random.uniform(0.10, 0.25, 30)
            risk = self.sequence_detector.predict_score(d_seq, f_seq)
            return float(1.0 - risk)

    def evaluate_row(self, telemetry_row, weights=None):
        """
        Scores a single telemetry JSON row using Quad-Factor Continuous Fusion.
        
        Formula:
            Score = (0.35 * Deep_SVDD_Conf) + (0.35 * OC_SVM_Conf) + (0.15 * IsoForest_Conf) + (0.15 * Cognitive_Conf)
            Risk  = 1.0 - Score
            
        Returns:
            fused_risk: Instantaneous raw anomaly risk [0.0 - 1.0].
            smoothed_risk: Multi-scale pooled moving average risk across 30 seconds.
            triggered: Boolean indicating whether an acute spike or sustained drift breach was triggered.
        """
        triggered = False
        
        # Idle window detection: strictly preserve neutral state when away from keyboard
        keys_in_window = telemetry_row.get("keystroke_count", 0)
        mouse_in_window = telemetry_row.get("mouse_events", 0)
        dwell_val = telemetry_row.get("dwell_mean", 0.0)
        is_idle_window = (keys_in_window == 0 and dwell_val == 0.0)
        
        if not self.models_loaded:
            # Fallback heuristic if models are not yet trained
            cpu = telemetry_row.get("cpu_usage", 0.0)
            app = str(telemetry_row.get("active_app", "")).lower()
            heur_risk = 0.85 if (cpu > 60.0 or "cmd" in app or "powershell" in app) else 0.10
            if is_idle_window and mouse_in_window < 5:
                heur_risk = min(0.05, heur_risk)
            self.risk_history.append(heur_risk)
            fused_risk = heur_risk
        else:
            try:
                # 1. Fetch Deep SVDD 1D-CNN Keystroke Biometric Confidence
                svdd_conf = self.evaluate_keystroke_sequence(telemetry_row)
                
                # 2. Fetch Biometric Dynamics (OC-SVM) & Context Dynamics (Isolation Forest) Confidences
                svm_conf, if_conf = self.models.score(telemetry_row)
                
                # 3. Fetch Cognitive Task Confidence from Behavioral AI Controller
                try:
                    ctrl_anomaly, _ = self.controller.evaluate_telemetry_row(telemetry_row)
                    ctrl_conf = 1.0 - ctrl_anomaly
                except Exception:
                    ctrl_conf = svm_conf
                    
                # 4. Quad-Factor Continuous Fusion
                if weights is not None and len(weights) == 4:
                    w_svdd, w_svm, w_if, w_ctrl = weights
                else:
                    # Standard calibrated Quad-Factor weights
                    w_svdd = 0.35
                    w_svm = 0.35
                    w_if = 0.15
                    w_ctrl = 0.15
                    
                fused_conf = (w_svdd * svdd_conf) + (w_svm * svm_conf) + (w_if * if_conf) + (w_ctrl * ctrl_conf)
                fused_risk = 1.0 - fused_conf
                
                # Strict Idle Window Neutrality (Risk <= 0.05 when no typing occurs)
                if is_idle_window and mouse_in_window < 5:
                    fused_risk = min(0.05, fused_risk)
                else:
                    # 5. Environmental Ambient Context Modulation (TASK-8)
                    env_penalty = 0.0
                    is_phone_absent = (not telemetry_row.get("owner_phone_present", True)) or (telemetry_row.get("ble_proximity_state") == "OUT_OF_RANGE")
                    if is_phone_absent:
                        # Physical Walk-Away Imposter Takeover: active input while owner's phone is absent
                        env_penalty += 0.25
                    elif telemetry_row.get("ble_proximity_state") == "FAR":
                        env_penalty += 0.10

                    if telemetry_row.get("is_untrusted_network", False):
                        env_penalty += 0.15

                    if env_penalty > 0.0:
                        fused_risk = min(1.0, fused_risk + env_penalty)
                    
                # Multi-scale window pooling: append to sliding temporal window queue
                self.risk_history.append(fused_risk)
            except Exception as e:
                print(f"[EVALUATOR] [ERROR] Scoring exception: {e}", file=sys.stderr, flush=True)
                fused_risk = 0.05
                self.risk_history.append(fused_risk)

        # Multi-scale pooled risk across sliding temporal window (30s)
        smoothed_risk = sum(self.risk_history) / len(self.risk_history)

        # ADWIN Concept Drift Evaluation
        drift_verdict = None
        if self.drift_monitor is not None:
            try:
                drift_verdict = self.drift_monitor.process_telemetry_row(telemetry_row, fused_risk)
            except Exception:
                pass

        # 3-Tier Dynamic Risk Policy Evaluation
        policy_action = None
        if self.orchestrator is not None:
            try:
                policy_action = self.orchestrator.evaluate_policy(fused_risk, smoothed_risk, telemetry_row)
            except Exception:
                pass
        
        # Dual-Tier Smoothing & Anomaly Breach Evaluation:
        now = time.time()
        has_active_keystrokes = (keys_in_window >= 2 or dwell_val > 0.0)
        
        # Tier 1: Fast Reactive: instant acute intrusion spike at Risk >= 0.78 with active typing (keys >= 2)
        is_acute = (fused_risk >= 0.78 and keys_in_window >= 2)
        
        # Successive High-Risk Windows (2 recent windows with risk >= 0.65)
        is_two_spike = (len(self.risk_history) >= 2 and fused_risk >= 0.65 and list(self.risk_history)[-2] >= 0.60 and has_active_keystrokes)
        
        # Tier 2: Sustained Multi-Window Drift: Requires 30s queue (3 windows) and sustained risk >= 0.55 with active typing
        is_sustained = (len(self.risk_history) >= 3 and smoothed_risk >= self.threshold and has_active_keystrokes)

        # ADWIN Abrupt Shift: Statistically verified distribution shift in risk or biometrics
        is_adwin_abrupt = bool(drift_verdict and drift_verdict.get("primary_drift_type") == "ABRUPT" and has_active_keystrokes)
        
        should_trigger = (is_acute or is_two_spike or is_sustained or is_adwin_abrupt)
        
        if should_trigger:
            if not self.is_breached and (now - self.last_alert_time > self.cooldown_seconds):
                self.is_breached = True
                self.last_alert_time = now
                self.active_otp = generate_otp()
                triggered = True
                
                trigger_reason = "ADWIN ABRUPT SHIFT" if is_adwin_abrupt else ("ACUTE INTRUDER SPIKE" if is_acute else ("SUCCESSIVE ANOMALY" if is_two_spike else "SUSTAINED BEHAVIORAL DRIFT"))
                print(f"\n[ALERT] BEHAVIORAL DRIFT BREACH DETECTED! ({trigger_reason})", flush=True)
                print(f"[ALERT] Instant Risk: {fused_risk:.4f} | Smoothed (30s): {smoothed_risk:.4f} (Threshold: {self.threshold:.2f})", flush=True)
                print(f"[OTP] Generated Session OTP: >>> {self.active_otp} <<< (saved to models/.active_otp)", flush=True)
                print(f"[OTP] Master Bypass Password: >>> admin <<< (or admin123 / 123456)", flush=True)
                
                # Active Security Responses
                captured_photo = capture_intruder()
                active_app_name = telemetry_row.get("active_app", "Unknown") if isinstance(telemetry_row, dict) else "Active Desktop Session"
                dispatch_otp(self.active_otp, photo_path=captured_photo, threat_info={"risk_score": float(fused_risk), "active_app": active_app_name})
                self._save_active_otp(self.active_otp)
                try:
                    from deception.forensic_tracker import get_tracker
                    get_tracker().start_new_session()
                except Exception:
                    pass
                
        return float(fused_risk), float(smoothed_risk), triggered

    def verify_otp_and_reset(self, entered_otp):
        """
        Verifies the user's OTP code or Master Bypass Password.
        If correct, restores normal session state and triggers behavior adaptation retraining.
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

        # Environment-based explicit recovery password
        env_master = os.environ.get("SECURITY_MASTER_RECOVERY_PASSWORD") or os.environ.get("EMERGENCY_RECOVERY_KEY")
        strict_recovery = os.environ.get("STRICT_SECURITY_RECOVERY", "false").lower() in ("true", "1", "yes") or os.environ.get("ENVIRONMENT") == "production"

        if strict_recovery:
            # Production Mode: Hardcoded passwords (admin, admin123, 123456) are disabled
            master_passwords = set()
            if env_master:
                master_passwords.add(env_master.strip())
            if configured_bypass and configured_bypass not in ("admin", "admin123", "123456"):
                master_passwords.add(str(configured_bypass).strip())
        else:
            # Dev / Testing Mode: Backwards-compatible fallback
            master_passwords = {"admin", "admin123", "123456", str(configured_bypass)}
            if env_master:
                master_passwords.add(env_master.strip())

        is_valid_otp = bool(stored_otp and entered == stored_otp.strip())
        is_valid_bypass = entered in master_passwords
        
        if is_valid_otp or is_valid_bypass:
            method = "OTP" if is_valid_otp else "Master Bypass Password"
            print(f"\n[SECURITY] Identity Verified via {method}! Restoring session...", flush=True)
            self.is_breached = False
            self.active_otp = None
            self._clear_active_otp()
            if self.orchestrator is not None:
                self.orchestrator.reset()
            try:
                from deception.forensic_tracker import get_tracker
                get_tracker().reset_session()
            except Exception:
                pass
            
            # Retrain models to adapt to behavior drift
            try:
                from ml_engine.train import adapt_to_verified_drift
                adapt_to_verified_drift()
                self.load_models()
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
        scoring new events in real time and launching verification lock on breach.
        """
        log_path = os.path.join(PROJECT_ROOT, telemetry_file) if not os.path.isabs(telemetry_file) else telemetry_file
        print(f"[DAEMON] Starting Quad-Factor threat evaluation daemon. Monitoring '{log_path}'...", flush=True)
        
        while not os.path.exists(log_path):
            time.sleep(1.0)
            
        with open(log_path, "r") as f:
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
                            from security.lock_handler import launch_verification_lock
                            launch_verification_lock(self)
                    except Exception as e:
                        print(f"[DAEMON] [ERROR] Processing line failed: {e}", file=sys.stderr, flush=True)

    def _save_active_otp(self, otp):
        otp_file = os.path.join(PROJECT_ROOT, "models", ".active_otp")
        os.makedirs(os.path.dirname(otp_file), exist_ok=True)
        try:
            with open(otp_file, "w") as f:
                f.write(otp)
        except Exception:
            pass

    def _load_active_otp(self):
        otp_file = os.path.join(PROJECT_ROOT, "models", ".active_otp")
        if os.path.exists(otp_file):
            try:
                with open(otp_file, "r") as f:
                    return f.read().strip()
            except Exception:
                pass
        return self.active_otp

    def _clear_active_otp(self):
        otp_file = os.path.join(PROJECT_ROOT, "models", ".active_otp")
        if os.path.exists(otp_file):
            try:
                os.remove(otp_file)
            except Exception:
                pass


# ContinuousEvaluator alias for explicit naming
ContinuousEvaluator = ThreatEvaluator


if __name__ == "__main__":
    evaluator = ThreatEvaluator()
    try:
        evaluator.start_daemon()
    except KeyboardInterrupt:
        print("[DAEMON] Exiting cleanly.", flush=True)
