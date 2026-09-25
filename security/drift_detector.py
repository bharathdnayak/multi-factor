import os
import sys

# Append project root directory to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.evaluator import ThreatEvaluator, ContinuousEvaluator
from security.webcam import capture_intruder
from security.otp_service import generate_otp, dispatch_otp

__all__ = ["ThreatEvaluator", "ContinuousEvaluator", "capture_intruder", "generate_otp", "dispatch_otp"]

if __name__ == "__main__":
    evaluator = ThreatEvaluator()
    try:
        evaluator.start_daemon()
    except KeyboardInterrupt:
        print("[DAEMON] Exiting cleanly.", flush=True)
