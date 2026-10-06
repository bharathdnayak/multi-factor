import os
import sys
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from security.risk_orchestrator import DynamicRiskOrchestrator, RiskTier, RiskPolicyAction
from telemetry.evaluator import ThreatEvaluator
from fastapi.testclient import TestClient
from dashboard.app import app


class TestRiskOrchestrationPolicy(unittest.TestCase):
    def setUp(self):
        self.orchestrator = DynamicRiskOrchestrator(
            low_threshold=0.40,
            high_threshold=0.75,
            challenge_cooldown_seconds=10.0,
            max_step_up_failures=3
        )

    def test_01_tier1_low_risk_silent_monitoring(self):
        """
        Tests Tier 1 Policy (Risk < 0.40):
        Behavior is authentic; system executes silent continuous monitoring with zero friction.
        """
        print("\n--- Testing Tier 1: Low Risk (< 0.40) Silent Monitoring ---")
        action = self.orchestrator.evaluate_policy(instant_risk=0.15, smoothed_risk=0.12)
        
        self.assertEqual(action.tier, RiskTier.TIER_1_LOW)
        self.assertEqual(action.action, "SILENT_MONITOR")
        self.assertFalse(action.is_blocking)
        self.assertFalse(self.orchestrator.active_challenge)
        print(f"[OK] Tier 1 verified: Action={action.action} | Blocking={action.is_blocking} | Message='{action.message}'")

    def test_02_tier2_medium_risk_step_up_challenge(self):
        """
        Tests Tier 2 Policy (Risk 0.40 - 0.75):
        Moderate behavioral drift triggers non-blocking step-up MFA challenge.
        Must NOT be blocking (user's desktop workflow is not halted).
        """
        print("\n--- Testing Tier 2: Medium Risk (0.40 - 0.75) Step-Up MFA ---")
        action = self.orchestrator.evaluate_policy(instant_risk=0.55, smoothed_risk=0.48)

        self.assertEqual(action.tier, RiskTier.TIER_2_MEDIUM)
        self.assertEqual(action.action, "STEP_UP_CHALLENGE")
        self.assertFalse(action.is_blocking, "Tier 2 step-up challenge must be non-blocking!")
        self.assertTrue(self.orchestrator.active_challenge)
        print(f"[OK] Tier 2 verified: Action={action.action} | Blocking={action.is_blocking} | Active Challenge={self.orchestrator.active_challenge}")

    def test_03_tier3_high_risk_full_lockdown(self):
        """
        Tests Tier 3 Policy (Risk > 0.75):
        Acute intrusion anomaly triggers full workstation lockdown and Honeypot Deception diversion.
        Must be blocking!
        """
        print("\n--- Testing Tier 3: High Risk (> 0.75) Full Lockdown & Deception ---")
        action = self.orchestrator.evaluate_policy(instant_risk=0.88, smoothed_risk=0.82)

        self.assertEqual(action.tier, RiskTier.TIER_3_HIGH)
        self.assertEqual(action.action, "FULL_LOCKDOWN_HONEYPOT")
        self.assertTrue(action.is_blocking, "Tier 3 action must be blocking!")
        print(f"[OK] Tier 3 verified: Action={action.action} | Blocking={action.is_blocking}")

    def test_04_step_up_verification_success_restores_tier1(self):
        """
        Tests that answering a Tier 2 step-up challenge correctly restores Tier 1 nominal security.
        """
        print("\n--- Testing Tier 2 Step-Up Verification Restoration ---")
        # Put into Tier 2
        self.orchestrator.evaluate_policy(instant_risk=0.60, smoothed_risk=0.55)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_2_MEDIUM)

        # Verify using master bypass password
        success, msg = self.orchestrator.verify_step_up(entered_code="admin")
        self.assertTrue(success)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_1_LOW)
        self.assertFalse(self.orchestrator.active_challenge)
        self.assertEqual(self.orchestrator.step_up_failures, 0)
        print(f"[OK] Step-up challenge passed: New Tier={self.orchestrator.current_tier.value} | Msg={msg}")

    def test_05_step_up_repeated_failure_escalates_to_tier3(self):
        """
        Tests that failing the Tier 2 step-up MFA challenge 3 times escalates directly to Tier 3 Lockdown.
        """
        print("\n--- Testing Tier 2 Step-Up Failure Escalation to Tier 3 ---")
        self.orchestrator.evaluate_policy(instant_risk=0.50, smoothed_risk=0.45)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_2_MEDIUM)

        # Fail attempt 1
        s1, _ = self.orchestrator.verify_step_up("wrong_1")
        self.assertFalse(s1)
        self.assertEqual(self.orchestrator.step_up_failures, 1)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_2_MEDIUM)

        # Fail attempt 2
        s2, _ = self.orchestrator.verify_step_up("wrong_2")
        self.assertFalse(s2)
        self.assertEqual(self.orchestrator.step_up_failures, 2)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_2_MEDIUM)

        # Fail attempt 3 (threshold reached)
        s3, msg = self.orchestrator.verify_step_up("wrong_3")
        self.assertFalse(s3)
        self.assertEqual(self.orchestrator.step_up_failures, 3)
        self.assertEqual(self.orchestrator.current_tier, RiskTier.TIER_3_HIGH)
        print(f"[OK] Escalation verified after 3 failed attempts: Final Tier={self.orchestrator.current_tier.value}")

    def test_06_fastapi_tier_endpoints(self):
        """
        Tests the REST API endpoints for 3-tier policy inquiry and step-up verification.
        """
        print("\n--- Testing FastAPI Tier REST Endpoints ---")
        client = TestClient(app)

        # 1. GET /api/security/tier_status
        status_res = client.get("/api/security/tier_status")
        self.assertEqual(status_res.status_code, 200)
        sdata = status_res.json()
        self.assertIn("current_tier", sdata)
        self.assertIn("thresholds", sdata)
        self.assertEqual(sdata["thresholds"]["low"], 0.40)
        self.assertEqual(sdata["thresholds"]["high"], 0.75)

        # 2. POST /api/security/step_up_verify
        verify_res = client.post("/api/security/step_up_verify", json={"entered_code": "admin"})
        self.assertEqual(verify_res.status_code, 200)
        vdata = verify_res.json()
        self.assertTrue(vdata["success"])
        self.assertEqual(vdata["tier"], "TIER_1_LOW")
        print(f"[OK] REST API verified: Current Tier={sdata['current_tier']} | Step-Up Verify={vdata['success']}")


if __name__ == "__main__":
    unittest.main()
