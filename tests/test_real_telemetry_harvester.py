import os
import sys
import json
import shutil
import unittest
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.harvest_real_telemetry import (
    RealTelemetryHarvester,
    DatasetPartitioner,
    FieldBenchmarkEvaluator,
    SAMPLE_PROMPTS
)


class TestRealTelemetryHarvester(unittest.TestCase):
    def setUp(self):
        self.test_harvest_dir = os.path.join(PROJECT_ROOT, "data", "test_harvest_tmp")
        self.test_sessions_dir = os.path.join(self.test_harvest_dir, "sessions")
        os.makedirs(self.test_sessions_dir, exist_ok=True)
        self.harvester = RealTelemetryHarvester(output_dir=self.test_sessions_dir)

    def tearDown(self):
        if os.path.exists(self.test_harvest_dir):
            shutil.rmtree(self.test_harvest_dir, ignore_errors=True)

    def test_01_simulated_session_generation(self):
        print("\n--- Testing Simulated Multi-User Session Generation ---")
        # 1. Generate authorized owner coding session
        owner_file = self.harvester.generate_simulated_session(
            user_id="Owner_Test",
            is_authorized=True,
            task_mode="coding",
            num_samples=15,
            seed=42
        )
        self.assertTrue(os.path.exists(owner_file))

        # Validate JSONL rows
        with open(owner_file, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]

        self.assertEqual(len(lines), 15)
        first_row = lines[0]
        self.assertEqual(first_row["session_user_id"], "Owner_Test")
        self.assertTrue(first_row["is_authorized"])
        self.assertEqual(first_row["task_mode"], "coding")
        self.assertIn("dwell_mean", first_row)
        self.assertIn("flight_mean", first_row)
        self.assertIn("dwell_sequence", first_row)
        self.assertIn("flight_sequence", first_row)
        self.assertEqual(len(first_row["dwell_sequence"]), 30)
        self.assertEqual(len(first_row["flight_sequence"]), 30)
        self.assertEqual(first_row["ble_proximity_state"], "IMMEDIATE")

        # 2. Generate imposter mimic session
        imposter_file = self.harvester.generate_simulated_session(
            user_id="Imposter_Test",
            is_authorized=False,
            task_mode="imposter_mimic",
            num_samples=15,
            seed=43
        )
        self.assertTrue(os.path.exists(imposter_file))
        with open(imposter_file, "r", encoding="utf-8") as f:
            imp_lines = [json.loads(l) for l in f if l.strip()]
        self.assertEqual(len(imp_lines), 15)
        self.assertFalse(imp_lines[0]["is_authorized"])
        self.assertEqual(imp_lines[0]["ble_proximity_state"], "OUT_OF_RANGE")
        print(f"[OK] Generated valid sessions for owner ({owner_file}) and imposter ({imposter_file}).")

    def test_02_dataset_partitioning(self):
        print("\n--- Testing Dataset Partitioning & Manifest Creation ---")
        # Generate multi-user sessions
        self.harvester.generate_simulated_session("Owner_A", True, "coding", num_samples=20, seed=1)
        self.harvester.generate_simulated_session("Owner_A", True, "docs", num_samples=20, seed=2)
        self.harvester.generate_simulated_session("Teammate_B", False, "coding", num_samples=15, seed=3)
        self.harvester.generate_simulated_session("Imposter_C", False, "imposter_mimic", num_samples=15, seed=4)

        partitioner = DatasetPartitioner(harvest_dir=self.test_harvest_dir)
        manifest = partitioner.partition_dataset(train_ratio=0.80)

        # Check partitions
        self.assertIn("train_samples", manifest)
        self.assertIn("test_samples", manifest)
        self.assertEqual(manifest["total_owner_samples"], 40)
        self.assertEqual(manifest["total_imposter_samples"], 30)
        self.assertEqual(manifest["train_samples"], 32)  # 80% of 40
        self.assertEqual(manifest["test_samples"], 38)   # 8 held-out owner + 30 imposters

        self.assertTrue(os.path.exists(manifest["train_file"]))
        self.assertTrue(os.path.exists(manifest["val_file"]))
        self.assertTrue(os.path.exists(manifest["test_file"]))
        print(f"[OK] Partition verified: Train={manifest['train_samples']} | Test={manifest['test_samples']} | Users={manifest['user_breakdown']}")

    def test_03_field_benchmark_evaluation(self):
        print("\n--- Testing Field Benchmark Pipeline & ROC Chart Generation ---")
        # Prepare dataset
        self.harvester.generate_simulated_session("Owner_X", True, "coding", num_samples=25, seed=10)
        self.harvester.generate_simulated_session("Owner_X", True, "docs", num_samples=25, seed=11)
        self.harvester.generate_simulated_session("Imposter_Y", False, "imposter_mimic", num_samples=25, seed=12)

        partitioner = DatasetPartitioner(harvest_dir=self.test_harvest_dir)
        partitioner.partition_dataset()

        evaluator = FieldBenchmarkEvaluator(harvest_dir=self.test_harvest_dir)
        results = evaluator.run_benchmark()

        # Validate metrics
        self.assertIn("svm", results)
        self.assertIn("if", results)
        self.assertIn("ctrl", results)
        self.assertIn("svdd", results)
        self.assertIn("fused", results)
        self.assertIn("roc_auc", results["fused"])
        self.assertIn("far", results["fused"])
        self.assertIn("frr", results["fused"])
        self.assertIn("eer", results["fused"])

        # Check ROC chart export
        chart_path = results["chart_path"]
        self.assertTrue(os.path.exists(chart_path))
        self.assertGreater(os.path.getsize(chart_path), 10000)
        print(f"[OK] Benchmark evaluated successfully. Fused ROC-AUC: {results['fused']['roc_auc']:.4f} | Chart Size: {os.path.getsize(chart_path):,} bytes")

    def test_04_harvester_kinematics_and_events(self):
        print("\n--- Testing RealTelemetryHarvester Internal Kinematics ---")
        h = RealTelemetryHarvester(output_dir=self.test_sessions_dir)
        h.running = True

        # Simulate mouse trajectory
        t0 = 1000.0
        h.on_mouse_move(100, 100)
        h.mouse_coords = [
            (100.0, 100.0, t0),
            (150.0, 120.0, t0 + 0.05),
            (210.0, 150.0, t0 + 0.10),
            (280.0, 190.0, t0 + 0.15)
        ]
        h._compute_mouse_kinematics()
        self.assertGreater(len(h.velocities), 0)
        self.assertGreater(len(h.accelerations), 0)
        self.assertGreater(len(h.straightness_scores), 0)
        self.assertTrue(0.0 <= h.straightness_scores[0] <= 1.0)

        # Simulate keystroke events
        class MockKey:
            char = '{'
        h.on_key_press(MockKey())
        self.assertEqual(h.key_count, 1)
        self.assertEqual(h.special_count, 1)

        class MockBackspace:
            char = None
            def __str__(self):
                return "Key.backspace"
        h.on_key_press(MockBackspace())
        self.assertEqual(h.key_count, 2)
        self.assertEqual(h.backspace_count, 1)

        h.running = False
        print("[OK] Kinematics and keystroke event handlers correctly processed coordinates and syntax keys.")

    def test_05_task_prompts_availability(self):
        print("\n--- Testing Task Prompts Availability ---")
        self.assertIn("coding", SAMPLE_PROMPTS)
        self.assertIn("docs", SAMPLE_PROMPTS)
        self.assertIn("browsing", SAMPLE_PROMPTS)
        self.assertIn("imposter_mimic", SAMPLE_PROMPTS)
        for task, text in SAMPLE_PROMPTS.items():
            self.assertGreater(len(text), 50)
        print("[OK] All 4 guided task typing prompts are available and detailed.")


if __name__ == "__main__":
    unittest.main()
