import sys
import os
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from telemetry.environmental_sensor import EnvironmentalSensorMonitor, get_environmental_sensor
from telemetry.evaluator import ThreatEvaluator


class TestEnvironmentalSensors(unittest.TestCase):
    def setUp(self):
        self.sensor = EnvironmentalSensorMonitor()
        self.evaluator = ThreatEvaluator()

    def tearDown(self):
        self.sensor.clear_simulation()

    def test_01_ble_rssi_distance_propagation(self):
        print("\n--- Testing BLE RSSI Path Loss Distance Propagation ---")
        # TxPower = -59.0, n = 2.0
        # -59 dBm -> 1.0 meter
        d_immediate = self.sensor.calculate_distance_from_rssi(-59.0)
        self.assertAlmostEqual(d_immediate, 1.0, delta=0.1)
        self.assertEqual(self.sensor.classify_proximity_zone(d_immediate), "IMMEDIATE")

        # -65 dBm -> ~2.0 meters (NEAR)
        d_near = self.sensor.calculate_distance_from_rssi(-65.0)
        self.assertTrue(1.5 <= d_near <= 2.5)
        self.assertEqual(self.sensor.classify_proximity_zone(d_near), "NEAR")

        # -75 dBm -> ~6.3 meters (FAR)
        d_far = self.sensor.calculate_distance_from_rssi(-75.0)
        self.assertTrue(5.0 <= d_far <= 7.0)
        self.assertEqual(self.sensor.classify_proximity_zone(d_far), "FAR")

        # -85 dBm -> ~20 meters (OUT_OF_RANGE)
        d_out = self.sensor.calculate_distance_from_rssi(-85.0)
        self.assertGreater(d_out, 7.0)
        self.assertEqual(self.sensor.classify_proximity_zone(d_out), "OUT_OF_RANGE")
        print(f"[OK] BLE distance calculations verified across RF propagation curve: -59dBm={d_immediate}m, -65dBm={d_near}m, -75dBm={d_far}m, -85dBm={d_out}m")

    def test_02_network_context_classification(self):
        print("\n--- Testing Network Context & SSID Trust Classification ---")
        # 1. Trusted Corporate SSID
        self.sensor.set_simulated_network(ssid="CorpSec_Internal_WiFi", is_untrusted=False, vpn_active=True)
        net_trusted = self.sensor.get_network_context()
        self.assertEqual(net_trusted["network_ssid"], "CorpSec_Internal_WiFi")
        self.assertFalse(net_trusted["is_untrusted_network"])
        self.assertTrue(net_trusted["vpn_active"])

        # 2. Untrusted Public Hotspot
        self.sensor.set_simulated_network(ssid="Airport_Free_Guest_WiFi", is_untrusted=True, vpn_active=False)
        net_untrusted = self.sensor.get_network_context()
        self.assertEqual(net_untrusted["network_ssid"], "Airport_Free_Guest_WiFi")
        self.assertTrue(net_untrusted["is_untrusted_network"])
        self.assertFalse(net_untrusted["vpn_active"])
        print("[OK] Trusted enterprise network and untrusted public hotspot correctly differentiated.")

    def test_03_environmental_snapshot_integration(self):
        print("\n--- Testing Environmental Snapshot Metrics Aggregation ---")
        snapshot = self.sensor.get_environmental_snapshot()
        self.assertIn("ble_device_name", snapshot)
        self.assertIn("owner_phone_present", snapshot)
        self.assertIn("ble_rssi_dbm", snapshot)
        self.assertIn("ble_estimated_distance_m", snapshot)
        self.assertIn("ble_proximity_state", snapshot)
        self.assertIn("network_ssid", snapshot)
        self.assertIn("is_untrusted_network", snapshot)
        self.assertIn("vpn_active", snapshot)
        self.assertIn("environmental_risk_penalty", snapshot)
        print(f"[OK] Environmental snapshot complete: Proximity={snapshot['ble_proximity_state']} | SSID={snapshot['network_ssid']} | Penalty={snapshot['environmental_risk_penalty']}")

    def test_04_physical_walkaway_imposter_escalation(self):
        print("\n--- Testing Physical Walk-Away Imposter Takeover Risk Escalation ---")
        normal_telemetry = {
            "dwell_mean": 0.09, "dwell_std": 0.015,
            "flight_mean": 0.12, "flight_std": 0.02,
            "app_dwell_mean": 0.088, "app_flight_mean": 0.115,
            "app_backspace_ratio": 0.12, "app_special_ratio": 0.20,
            "app_click_count": 4, "app_scroll_count": 6, "app_pause_ratio": 0.40,
            "interaction_mode": "ai_chat_or_prompting",
            "mouse_velocity_mean": 250.0, "mouse_acceleration_mean": 12.0,
            "mouse_jerk_mean": 1.1, "mouse_straightness_mean": 0.92,
            "hour_of_day": 14, "cpu_usage": 2.5, "ram_usage_mb": 250.0,
            "active_app": "Antigravity.exe", "keystroke_count": 20
        }

        # Case A: Owner phone is present at desk (IMMEDIATE)
        present_telemetry = dict(normal_telemetry)
        present_telemetry.update({
            "owner_phone_present": True,
            "ble_proximity_state": "IMMEDIATE",
            "is_untrusted_network": False
        })
        fused_present, _, _ = self.evaluator.evaluate_row(present_telemetry)
        print(f"   [Owner Present at Desk] Fused Risk: {fused_present:.4f}")

        # Case B: Owner phone is absent / out of range (> 5m), but keyboard input is happening!
        absent_telemetry = dict(normal_telemetry)
        absent_telemetry.update({
            "owner_phone_present": False,
            "ble_proximity_state": "OUT_OF_RANGE",
            "is_untrusted_network": False
        })
        fused_absent, _, _ = self.evaluator.evaluate_row(absent_telemetry)
        print(f"   [Owner Walked Away (>5m) with Active Typing] Fused Risk: {fused_absent:.4f}")

        # Risk must escalate due to physical walk-away penalty (+0.25)
        self.assertGreater(fused_absent, fused_present)
        self.assertAlmostEqual(fused_absent - fused_present, 0.25, delta=0.05)
        print(f"[OK] Physical walk-away penalty (+0.25) successfully boosted threat sensitivity when owner stepped away.")

    def test_05_untrusted_network_risk_escalation(self):
        print("\n--- Testing Untrusted Public Hotspot Context Escalation ---")
        normal_telemetry = {
            "dwell_mean": 0.09, "dwell_std": 0.015,
            "flight_mean": 0.12, "flight_std": 0.02,
            "app_dwell_mean": 0.088, "app_flight_mean": 0.115,
            "app_backspace_ratio": 0.12, "app_special_ratio": 0.20,
            "app_click_count": 4, "app_scroll_count": 6, "app_pause_ratio": 0.40,
            "interaction_mode": "ai_chat_or_prompting",
            "mouse_velocity_mean": 250.0, "mouse_acceleration_mean": 12.0,
            "mouse_jerk_mean": 1.1, "mouse_straightness_mean": 0.92,
            "hour_of_day": 14, "cpu_usage": 2.5, "ram_usage_mb": 250.0,
            "active_app": "Antigravity.exe", "keystroke_count": 20,
            "owner_phone_present": True,
            "ble_proximity_state": "IMMEDIATE"
        }

        # Trusted
        trusted_telemetry = dict(normal_telemetry)
        trusted_telemetry["is_untrusted_network"] = False
        fused_trusted, _, _ = self.evaluator.evaluate_row(trusted_telemetry)

        # Untrusted
        untrusted_telemetry = dict(normal_telemetry)
        untrusted_telemetry["is_untrusted_network"] = True
        fused_untrusted, _, _ = self.evaluator.evaluate_row(untrusted_telemetry)

        print(f"   [Trusted Network Risk]: {fused_trusted:.4f} | [Untrusted Hotspot Risk]: {fused_untrusted:.4f}")
        self.assertGreater(fused_untrusted, fused_trusted)
        self.assertAlmostEqual(fused_untrusted - fused_trusted, 0.15, delta=0.05)
        print("[OK] Untrusted public network penalty (+0.15) verified.")


if __name__ == "__main__":
    unittest.main()
