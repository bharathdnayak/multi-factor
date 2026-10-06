import os
import sys
import shutil
import unittest
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.benchmark_cmu_dataset import (
    CMUBenchmarkEngine,
    ensure_cmu_dataset,
    generate_synthetic_cmu_dataset,
    render_benchmark_chart,
    PUBLISHED_IEEE_BASELINES
)


class TestCMUBenchmark(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(PROJECT_ROOT, "data", "test_cmu_tmp")
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_csv = os.path.join(self.test_dir, "test_cmu_data.csv")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_synthetic_generator_schema(self):
        print("\n--- Testing CMU Synthetic Dataset Generator Schema ---")
        path = generate_synthetic_cmu_dataset(self.test_csv, num_subjects=5, reps_per_sub=40)
        self.assertTrue(os.path.exists(path))

        df = pd.read_csv(path)
        self.assertEqual(df.shape[0], 5 * 40)
        self.assertIn("subject", df.columns)
        self.assertIn("sessionIndex", df.columns)
        self.assertIn("rep", df.columns)
        self.assertIn("H.period", df.columns)
        self.assertIn("DD.period.t", df.columns)
        self.assertIn("UD.period.t", df.columns)
        self.assertEqual(len([c for c in df.columns if c not in ["subject", "sessionIndex", "rep"]]), 31)
        print(f"[OK] Generated valid CMU schema: {df.shape[0]} rows, 31 timing features.")

    def test_02_subject_partitions(self):
        print("\n--- Testing Killourhy & Maxion Partitioning Protocol ---")
        # Generate dataset with 6 subjects, 400 reps each
        path = generate_synthetic_cmu_dataset(self.test_csv, num_subjects=6, reps_per_sub=400)
        engine = CMUBenchmarkEngine(dataset_path=path)

        train_x, test_x, y_true, _ = engine._get_subject_partitions("s002")
        self.assertEqual(train_x.shape[0], 200)
        self.assertEqual(test_x.shape[0], 200 + 5 * 5)  # 200 genuine + (5 other subjects * 5 reps)
        self.assertEqual(np.sum(y_true == 1), 200)
        self.assertEqual(np.sum(y_true == 0), 25)
        print(f"[OK] Partitions verified: Train={train_x.shape[0]} | Test Genuine=200 | Test Imposter=25")

    def test_03_evaluate_subject_algorithms(self):
        print("\n--- Testing Benchmark Evaluation on All Algorithms ---")
        path = generate_synthetic_cmu_dataset(self.test_csv, num_subjects=4, reps_per_sub=400)
        engine = CMUBenchmarkEngine(dataset_path=path)

        res = engine.evaluate_subject("s002")
        expected_algos = [
            "Euclidean Distance", "Scaled Manhattan", "Mahalanobis Distance",
            "Standard One-Class SVM", "Deep SVDD 1D-CNN", "Proposed Hybrid Continuous Fusion"
        ]
        for a in expected_algos:
            self.assertIn(a, res)
            self.assertTrue(0.0 <= res[a]["eer"] <= 1.0)
            self.assertTrue(0.0 <= res[a]["auc"] <= 1.0)
            self.assertTrue(0.0 <= res[a]["far"] <= 1.0)
            self.assertTrue(0.0 <= res[a]["frr"] <= 1.0)
            print(f"   [Algorithm OK] {a:<35} : EER={res[a]['eer']*100:.2f}% | AUC={res[a]['auc']:.4f}")

    def test_04_run_benchmark_summary(self):
        print("\n--- Testing Run Benchmark Statistical Aggregator ---")
        path = generate_synthetic_cmu_dataset(self.test_csv, num_subjects=3, reps_per_sub=400)
        engine = CMUBenchmarkEngine(dataset_path=path)

        summary = engine.run_benchmark(max_subjects=3)
        self.assertIn("Proposed Hybrid Continuous Fusion", summary)
        fused = summary["Proposed Hybrid Continuous Fusion"]
        self.assertIn("mean_eer", fused)
        self.assertIn("std_eer", fused)
        self.assertIn("mean_auc", fused)
        self.assertGreater(fused["mean_auc"], 0.50)
        print(f"[OK] Aggregated benchmark summary verified: Fused Mean EER={fused['mean_eer']:.2f}% | AUC={fused['mean_auc']:.4f}")

    def test_05_chart_rendering(self):
        print("\n--- Testing Publication Chart Rendering ---")
        path = generate_synthetic_cmu_dataset(self.test_csv, num_subjects=3, reps_per_sub=400)
        engine = CMUBenchmarkEngine(dataset_path=path)
        summary = engine.run_benchmark(max_subjects=3)

        chart_path = os.path.join(self.test_dir, "test_chart.png")
        render_benchmark_chart(summary, chart_path)
        self.assertTrue(os.path.exists(chart_path))
        self.assertGreater(os.path.getsize(chart_path), 50000)
        print(f"[OK] Rendered valid 4-panel publication figure ({os.path.getsize(chart_path):,} bytes).")

    def test_06_published_baselines_metadata(self):
        print("\n--- Testing Published Baselines Metadata ---")
        self.assertIn("Euclidean Distance", PUBLISHED_IEEE_BASELINES)
        self.assertIn("Scaled Manhattan", PUBLISHED_IEEE_BASELINES)
        self.assertIn("Standard One-Class SVM", PUBLISHED_IEEE_BASELINES)
        self.assertEqual(PUBLISHED_IEEE_BASELINES["Scaled Manhattan"]["eer"], 9.96)
        print("[OK] Published IEEE baseline metadata correctly recorded.")


if __name__ == "__main__":
    unittest.main()
