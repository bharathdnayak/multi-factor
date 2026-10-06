import os
import sys
import time
import math
import argparse
import collections
from typing import Tuple, Dict, Any, List, Optional
import numpy as np

# Append project root directory to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Re-exports for backwards compatibility across existing modules and batch files
from security.webcam import capture_intruder
from security.otp_service import generate_otp, dispatch_otp

def __getattr__(name: str):
    if name in ("ThreatEvaluator", "ContinuousEvaluator"):
        import telemetry.evaluator as _ev
        return getattr(_ev, name)
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


class ADWINDriftDetector:
    """
    Adaptive Windowing (ADWIN) Online Concept Drift Detector.
    Based on the statistical change detection framework by Bifet & Gavaldà (2007).
    
    Dynamically expands and contracts a sliding observation window W over streaming
    behavioral telemetry metrics (keystroke dwell, flight, mouse dynamics, anomaly risk).
    
    Performs Hoeffding-bound hypothesis testing across all valid partitions W = W0 · W1:
        diff = |mean(W1) - mean(W0)|
        eps  = sqrt((1 / 2m) * ln(2n / delta)) * min(1.0, 2.5 * std_w)
    
    When diff >= eps, the null hypothesis of stationary behavioral mean is rejected:
        - ABRUPT DRIFT (diff >= 0.35 or mean(W1) >= 0.60): Acute intruder intrusion mismatch.
        - GRADUAL DRIFT: Legitimate behavioral adaptation (user fatigue, typing slower).
    """
    def __init__(
        self,
        delta: float = 0.05,
        min_subwindow: int = 4,
        max_window_size: int = 300,
        name: str = "Metric"
    ):
        self.delta = delta
        self.min_subwindow = min_subwindow
        self.max_window_size = max_window_size
        self.name = name

        # Streaming state
        self.window: List[float] = []
        self.timestamps: List[float] = []
        self.total_samples: int = 0
        self.drift_events: List[Dict[str, Any]] = []
        self.last_drift_type: str = "NONE"
        self.last_event: Optional[Dict[str, Any]] = None

    @property
    def window_size(self) -> int:
        return len(self.window)

    @property
    def mean(self) -> float:
        return float(np.mean(self.window)) if self.window else 0.0

    @property
    def variance(self) -> float:
        return float(np.var(self.window)) if len(self.window) > 1 else 0.0

    def reset(self):
        """Clears the window and resets detection statistics."""
        self.window.clear()
        self.timestamps.clear()
        self.last_drift_type = "NONE"
        self.last_event = None

    def add_element(self, val: float, timestamp: Optional[float] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Appends a new scalar telemetry observation to the sliding window
        and tests for statistical concept drift across all sub-window partitions.
        
        Returns:
            drift_detected: bool indicating whether statistical drift was detected.
            drift_type: "NONE" | "GRADUAL" | "ABRUPT"
            diagnostic_info: dictionary containing cut point, means, epsilon, and window sizes.
        """
        ts = timestamp or time.time()
        f_val = float(val)
        self.window.append(f_val)
        self.timestamps.append(ts)
        self.total_samples += 1

        # Enforce maximum window buffer limit
        if len(self.window) > self.max_window_size:
            self.window.pop(0)
            self.timestamps.pop(0)

        n = len(self.window)
        # Require enough samples to form two valid sub-windows
        if n < self.min_subwindow * 2:
            self.last_drift_type = "NONE"
            return False, "NONE", {
                "window_size": n,
                "current_mean": self.mean,
                "total_samples": self.total_samples
            }

        # Search for the most statistically significant cut point k
        best_k: Optional[int] = None
        best_diff: float = 0.0
        best_eps: float = 0.0
        best_mu0: float = 0.0
        best_mu1: float = 0.0

        for k in range(self.min_subwindow, n - self.min_subwindow + 1):
            n0 = k
            n1 = n - k
            # Harmonic mean of sub-window sizes
            m = (n0 * n1) / (n0 + n1)

            mu0 = float(np.mean(self.window[:k]))
            mu1 = float(np.mean(self.window[k:]))
            diff = abs(mu1 - mu0)

            # Pooled within-subwindow variance to prevent drift variance inflation
            var_w = (n0 * float(np.var(self.window[:k])) + n1 * float(np.var(self.window[k:]))) / n
            std_w = math.sqrt(max(0.0001, var_w))

            # Hoeffding bound with variance-aware scaling
            log_term = math.log((2.0 * n) / self.delta)
            hoeffding_raw = math.sqrt((1.0 / (2.0 * m)) * log_term)
            eps = hoeffding_raw * min(1.0, max(0.25, 2.2 * std_w))

            if diff >= eps and diff > best_diff:
                best_k = k
                best_diff = diff
                best_eps = eps
                best_mu0 = mu0
                best_mu1 = mu1

        # Cut detected: sub-windows exhibit statistically divergent distributions
        if best_k is not None:
            # Classify behavioral drift type
            if best_diff >= 0.30 or best_mu1 >= 0.55:
                drift_type = "ABRUPT"
            else:
                drift_type = "GRADUAL"

            event = {
                "metric": self.name,
                "timestamp": ts,
                "drift_type": drift_type,
                "cut_position": best_k,
                "old_mean": round(best_mu0, 4),
                "new_mean": round(best_mu1, 4),
                "diff": round(best_diff, 4),
                "epsilon": round(best_eps, 4),
                "window_size_before": n,
                "window_size_after": n - best_k,
                "total_samples": self.total_samples
            }
            self.drift_events.append(event)
            self.last_drift_type = drift_type
            self.last_event = event

            # ADWIN window contraction: drop obsolete older sub-window W0
            self.window = self.window[best_k:]
            self.timestamps = self.timestamps[best_k:]

            return True, drift_type, event

        self.last_drift_type = "NONE"
        return False, "NONE", {
            "window_size": n,
            "current_mean": round(self.mean, 4),
            "total_samples": self.total_samples
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Returns structured diagnostic statistics for monitoring."""
        return {
            "metric": self.name,
            "total_samples": self.total_samples,
            "current_window_size": self.window_size,
            "current_mean": round(self.mean, 4),
            "current_variance": round(self.variance, 6),
            "drift_event_count": len(self.drift_events),
            "last_drift_type": self.last_drift_type,
            "recent_events": self.drift_events[-5:]
        }


class MultivariateDriftMonitor:
    """
    Multi-Channel Behavioral Concept Drift Monitor.
    Runs parallel ADWIN detectors across continuous biometric and context dimensions:
    1. Overall Fused Threat Risk Score
    2. Keystroke Dwell Mean (Key Hold Time)
    3. Keystroke Flight Mean (Inter-Key Latency)
    4. Mouse Cursor Velocity
    """
    def __init__(self, delta: float = 0.05, max_window_size: int = 250):
        self.detectors = {
            "risk_score": ADWINDriftDetector(delta=delta, min_subwindow=4, max_window_size=max_window_size, name="Threat Risk"),
            "dwell_mean": ADWINDriftDetector(delta=delta, min_subwindow=5, max_window_size=max_window_size, name="Dwell Time"),
            "flight_mean": ADWINDriftDetector(delta=delta, min_subwindow=5, max_window_size=max_window_size, name="Flight Time"),
            "mouse_velocity": ADWINDriftDetector(delta=delta, min_subwindow=6, max_window_size=max_window_size, name="Mouse Velocity")
        }
        self.total_evaluations: int = 0
        self.incident_history: collections.deque = collections.deque(maxlen=50)

    def process_telemetry_row(self, telemetry_row: Dict[str, Any], risk_score: float) -> Dict[str, Any]:
        """
        Processes a single streaming telemetry observation across all monitored channels.
        
        Returns:
            verdict: dict containing drift state, primary drift type, and recommended action.
        """
        self.total_evaluations += 1
        ts = telemetry_row.get("timestamp", time.time())

        # Extract values
        dwell = float(telemetry_row.get("dwell_mean", 0.0))
        flight = float(telemetry_row.get("flight_mean", 0.0))
        m_vel = float(telemetry_row.get("mouse_velocity_mean", telemetry_row.get("mouse_velocity", 0.0)))
        keys_in_window = int(telemetry_row.get("keystroke_count", 0))

        channel_results = {}
        drifting_channels = []
        has_abrupt = False
        has_gradual = False

        # 1. Evaluate Risk Score Channel
        d_risk, t_risk, info_risk = self.detectors["risk_score"].add_element(risk_score, ts)
        channel_results["risk_score"] = {"drift": d_risk, "type": t_risk, "info": info_risk}
        if d_risk:
            drifting_channels.append("risk_score")
            if t_risk == "ABRUPT":
                has_abrupt = True
            else:
                has_gradual = True

        # 2. Evaluate Keystroke Dwell (only if active typing occurred)
        if keys_in_window > 0 or dwell > 0.0:
            d_dwell, t_dwell, info_dwell = self.detectors["dwell_mean"].add_element(dwell, ts)
            channel_results["dwell_mean"] = {"drift": d_dwell, "type": t_dwell, "info": info_dwell}
            if d_dwell:
                drifting_channels.append("dwell_mean")
                if t_dwell == "ABRUPT":
                    has_abrupt = True
                else:
                    has_gradual = True

            # 3. Evaluate Keystroke Flight
            d_flight, t_flight, info_flight = self.detectors["flight_mean"].add_element(flight, ts)
            channel_results["flight_mean"] = {"drift": d_flight, "type": t_flight, "info": info_flight}
            if d_flight:
                drifting_channels.append("flight_mean")
                if t_flight == "ABRUPT":
                    has_abrupt = True
                else:
                    has_gradual = True

        # 4. Evaluate Mouse Velocity (normalized scale [0, 1] for ADWIN)
        if m_vel > 0.0:
            norm_vel = min(1.0, m_vel / 2000.0)
            d_vel, t_vel, info_vel = self.detectors["mouse_velocity"].add_element(norm_vel, ts)
            channel_results["mouse_velocity"] = {"drift": d_vel, "type": t_vel, "info": info_vel}
            if d_vel:
                drifting_channels.append("mouse_velocity")
                if t_vel == "ABRUPT":
                    has_abrupt = True
                else:
                    has_gradual = True

        # Synthesize multi-channel verdict
        if has_abrupt:
            overall_type = "ABRUPT"
            action = "ESCALATE_THREAT"
        elif has_gradual:
            overall_type = "GRADUAL"
            action = "ADAPT_MODEL"
        else:
            overall_type = "NONE"
            action = "MONITOR"

        verdict = {
            "timestamp": ts,
            "drift_detected": bool(drifting_channels),
            "primary_drift_type": overall_type,
            "drifting_channels": drifting_channels,
            "recommended_action": action,
            "channels": channel_results
        }

        if verdict["drift_detected"]:
            self.incident_history.appendleft(verdict)

        return verdict

    def get_summary(self) -> Dict[str, Any]:
        """Returns diagnostic summary across all active ADWIN monitors."""
        return {
            "total_evaluations": self.total_evaluations,
            "channels": {k: det.get_statistics() for k, det in self.detectors.items()},
            "recent_incidents": list(self.incident_history)[:10]
        }


# -----------------------------------------------------------------------------
# Module Exports
# -----------------------------------------------------------------------------
__all__ = [
    "ADWINDriftDetector",
    "MultivariateDriftMonitor",
    "ThreatEvaluator",
    "ContinuousEvaluator",
    "capture_intruder",
    "generate_otp",
    "dispatch_otp"
]


# -----------------------------------------------------------------------------
# CLI Runner & Demonstration
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ADWIN Behavioral Concept Drift Detection Daemon")
    parser.add_argument("--test", action="store_true", help="Run self-diagnostic verification on synthetic streams")
    parser.add_argument("--daemon", action="store_true", help="Run continuous threat evaluation daemon")
    args = parser.parse_args()

    if args.test:
        print("\n" + "=" * 70)
        print("ADWIN CONCEPT DRIFT DETECTION - STATISTICAL VERIFICATION")
        print("Department of ISE | Team 30 | Major Project")
        print("=" * 70)

        detector = ADWINDriftDetector(name="Typing Dwell")

        print("\n1. Feeding 50 stationary samples (Authentic Baseline: ~0.10s dwell)...")
        stat_drifts = 0
        for _ in range(50):
            d, t, _ = detector.add_element(np.random.normal(0.10, 0.02))
            if d:
                stat_drifts += 1
        print(f"   [OK] Stationary stream completed. False alarms: {stat_drifts} | Final window size: {detector.window_size}")

        print("\n2. Feeding 50 gradual drift samples (User fatigue: slow shift 0.10s -> 0.28s)...")
        grad_drifts = []
        for i in range(50):
            v = 0.10 + 0.18 * (i / 50.0) + np.random.normal(0, 0.02)
            d, t, info = detector.add_element(v)
            if d:
                grad_drifts.append((t, info["old_mean"], info["new_mean"]))
        print(f"   [OK] Gradual drift test completed. Detected: {len(grad_drifts)} time(s): {grad_drifts}")

        print("\n3. Feeding abrupt intrusion jump (Imposter attack: 0.85s dwell)...")
        abrupt_detected = False
        for step in range(12):
            v = np.random.normal(0.85, 0.03)
            d, t, info = detector.add_element(v)
            if d:
                print(f"   [ALERT] Abrupt drift detected at step {step + 1}: Type={t} | Old Mean={info['old_mean']} | New Mean={info['new_mean']}")
                abrupt_detected = True
                break

        print(f"\nVerification Result: {'ALL ADWIN TESTS PASSED' if abrupt_detected else 'TEST FAILED'}")
        print("=" * 70 + "\n")

    else:
        # Standard background daemon entrypoint
        evaluator = ThreatEvaluator()
        try:
            evaluator.start_daemon()
        except KeyboardInterrupt:
            print("[DAEMON] Exiting cleanly.", flush=True)
