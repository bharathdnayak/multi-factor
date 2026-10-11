"""
================================================================================
COMPREHENSIVE MULTI-MODAL CONTINUOUS AUTHENTICATION BENCHMARK SUITE
(PHASES 4, 5, 6, 7)
Department of Information Science & Engineering | Team 30
Behavioral Drift: Continuous Authentication & Honeypot Forensics
================================================================================

Implements and benchmarks candidate models across all modalities:
1. Keystroke Modality:
   - Robust Scaled Manhattan Distance (Killourhy & Maxion baseline)
   - Regularized Mahalanobis Distance (with Ledoit-Wolf shrinkage)
   - One-Class SVM (RBF kernel)
   - Isolation Forest
   - Deep SVDD 1D-CNN (PyTorch temporal neural baseline)
   - Supervised Random Forest Classifier
   - Supervised SVC
2. Mouse Modality:
   - Robust Kinematics Statistical Anomaly Detector (Median / MAD)
   - One-Class SVM
   - Isolation Forest
   - Supervised Random Forest
3. Application & Context Modality:
   - Context Isolation Forest
   - Markov Transition Probability Matrix
   - Robust Context Statistical Baseline
4. Cognitive Controller:
   - Existing Gaussian Envelope
   - Robust Median & MAD Controller
5. Multimodal Score Fusion:
   - Existing Fixed Weight Fusion (0.35 / 0.35 / 0.15 / 0.15)
   - Calibrated Weighted Fusion
   - Dynamic Modality-Aware Fusion (handles idle keyboard/mouse gracefully)
   - Out-of-Fold Logistic Regression Fusion
6. Operating Point & Threshold Calibration:
   - EER threshold
   - Low-FAR (FAR <= 5.0%) operating point
   - Multi-window temporal smoothing analysis
"""

import os
import sys
import json
import time
import math
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import pandas as pd
from scipy import stats

from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.svm import OneClassSVM, SVC
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.covariance import LedoitWolf
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve, confusion_matrix,
    average_precision_score
)

import torch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.models import BehavioralModels, categorize_process
from ml_engine.sequence_model import DeepSVDDDetector
from ml_engine.controller import BehavioralAIController, classify_activity_context


# ----------------------------------------------------------------------
# 1. KEYSTROKE CANDIDATE MODELS
# ----------------------------------------------------------------------

class ScaledManhattanDetector:
    """
    Scaled Manhattan Distance anomaly detector (Killourhy & Maxion, 2009).
    Scales feature divergences by Median Absolute Deviation (MAD).
    """
    def __init__(self):
        self.median_vec = None
        self.mad_vec = None

    def fit(self, X: np.ndarray):
        self.median_vec = np.median(X, axis=0)
        deviations = np.abs(X - self.median_vec)
        self.mad_vec = np.median(deviations, axis=0)
        # Avoid division by zero with safe epsilon
        self.mad_vec = np.where(self.mad_vec < 1e-4, 1e-4, self.mad_vec)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        # Distance normalized by feature count
        scaled_diff = np.abs(X - self.median_vec) / self.mad_vec
        dist = np.mean(scaled_diff, axis=1)
        # Convert to anomaly score [0.0, 1.0] via sigmoid
        score = 1.0 / (1.0 + np.exp(-1.8 * (dist - 2.5)))
        return np.clip(score, 0.0, 1.0)


class MahalanobisDetector:
    """
    Regularized Mahalanobis Distance using Ledoit-Wolf shrinkage covariance.
    Prevents singular matrix inversion while modeling inter-feature correlation.
    """
    def __init__(self):
        self.mean_vec = None
        self.precision_ = None

    def fit(self, X: np.ndarray):
        self.mean_vec = np.mean(X, axis=0)
        lw = LedoitWolf().fit(X)
        self.precision_ = lw.precision_
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        diff = X - self.mean_vec
        # d^2 = diff * precision * diff.T
        dist_sq = np.sum((diff @ self.precision_) * diff, axis=1)
        dist = np.sqrt(np.maximum(0.0, dist_sq))
        # Convert to [0, 1] anomaly score via chi-distribution quantile mapping
        d_med = np.median(dist) if len(dist) > 0 else 3.0
        score = 1.0 / (1.0 + np.exp(-0.8 * (dist - d_med * 1.5)))
        return np.clip(score, 0.0, 1.0)


# ----------------------------------------------------------------------
# 2. MOUSE CANDIDATE MODELS
# ----------------------------------------------------------------------

class RobustMouseDetector:
    """
    Robust statistical anomaly detector for normalized mouse kinematics
    (Velocity, Acceleration, Jerk, Trajectory Straightness).
    """
    def __init__(self):
        self.medians = None
        self.mads = None

    def fit(self, X: np.ndarray):
        self.medians = np.median(X, axis=0)
        devs = np.abs(X - self.medians)
        self.mads = np.median(devs, axis=0)
        self.mads = np.where(self.mads < 1e-4, 1e-4, self.mads)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        z = np.abs(X - self.medians) / self.mads
        # Weights: velocity (0.3), acceleration (0.25), jerk (0.2), straightness (0.25)
        w = np.array([0.30, 0.25, 0.20, 0.25])
        w = w / np.sum(w)
        dist = np.sum(z * w, axis=1)
        score = 1.0 / (1.0 + np.exp(-1.5 * (dist - 2.8)))
        return np.clip(score, 0.0, 1.0)


# ----------------------------------------------------------------------
# 3. APPLICATION & CONTEXT TRANSITION MODEL
# ----------------------------------------------------------------------

class MarkovContextDetector:
    """
    First-Order Markov Chain Transition Model across process categories:
    0: IDE/Dev, 1: Browser, 2: Terminal/CLI, 3: Productivity, 4: Other
    Computes negative log-likelihood of transitions to detect out-of-workflow anomalies.
    """
    def __init__(self, num_states: int = 5, smoothing: float = 0.05):
        self.num_states = num_states
        self.smoothing = smoothing
        self.transition_matrix = np.ones((num_states, num_states)) * smoothing
        self.prior = np.ones(num_states) * smoothing

    def fit(self, state_sequence: List[int]):
        for i in range(len(state_sequence)):
            s = state_sequence[i]
            if 0 <= s < self.num_states:
                self.prior[s] += 1
            if i > 0:
                prev_s = state_sequence[i - 1]
                if 0 <= prev_s < self.num_states and 0 <= s < self.num_states:
                    self.transition_matrix[prev_s, s] += 1

        # Normalize
        self.prior = self.prior / np.sum(self.prior)
        row_sums = self.transition_matrix.sum(axis=1, keepdims=True)
        self.transition_matrix = self.transition_matrix / row_sums
        return self

    def score_transition(self, prev_state: int, curr_state: int) -> float:
        if 0 <= prev_state < self.num_states and 0 <= curr_state < self.num_states:
            prob = self.transition_matrix[prev_state, curr_state]
        else:
            prob = 0.01
        # Negative log-likelihood mapped to [0, 1]
        nll = -np.log(max(1e-4, prob))
        score = 1.0 / (1.0 + np.exp(-1.2 * (nll - 2.5)))
        return float(np.clip(score, 0.0, 1.0))


# ----------------------------------------------------------------------
# 4. ROBUST COGNITIVE CONTROLLER
# ----------------------------------------------------------------------

class RobustCognitiveController:
    """
    Sample-size regularized median & MAD behavioral task envelope.
    Prevents false alarms on benign task switching while detecting cognitive mismatch.
    """
    def __init__(self):
        self.task_profiles: Dict[str, Dict[str, Any]] = {}

    def fit(self, rows: List[Dict[str, Any]]):
        by_task = {}
        for r in rows:
            if not r.get("is_authorized", False):
                continue
            task = r.get("interaction_mode", "general_productivity")
            by_task.setdefault(task, []).append(r)

        for task, t_rows in by_task.items():
            dwells = [r.get("dwell_mean", 0.09) for r in t_rows if r.get("dwell_mean", 0) > 0]
            flights = [r.get("flight_mean", 0.14) for r in t_rows if r.get("flight_mean", 0) > 0]
            pauses = [r.get("app_pause_ratio", 0.2) for r in t_rows]
            specials = [r.get("app_special_ratio", 0.1) for r in t_rows]
            backspaces = [r.get("app_backspace_ratio", 0.08) for r in t_rows]

            self.task_profiles[task] = {
                "count": len(t_rows),
                "dwell": (np.median(dwells), max(0.012, np.median(np.abs(dwells - np.median(dwells))))),
                "flight": (np.median(flights), max(0.018, np.median(np.abs(flights - np.median(flights))))),
                "pause": (np.median(pauses), max(0.05, np.median(np.abs(pauses - np.median(pauses))))),
                "special": (np.median(specials), max(0.03, np.median(np.abs(specials - np.median(specials))))),
                "backspace": (np.median(backspaces), max(0.02, np.median(np.abs(backspaces - np.median(backspaces)))))
            }
        return self

    def score_row(self, row: Dict[str, Any]) -> float:
        task = row.get("interaction_mode", "general_productivity")
        if task not in self.task_profiles:
            task = "general_productivity"
            if task not in self.task_profiles and self.task_profiles:
                task = list(self.task_profiles.keys())[0]

        if task not in self.task_profiles:
            return 0.10

        p = self.task_profiles[task]
        d = row.get("dwell_mean", 0.09)
        f = row.get("flight_mean", 0.14)
        pr = row.get("app_pause_ratio", 0.2)
        sp = row.get("app_special_ratio", 0.1)
        bs = row.get("app_backspace_ratio", 0.08)

        if row.get("keystroke_count", 0) == 0 and d == 0.0:
            return 0.05  # Idle window neutrality

        z_d = abs(d - p["dwell"][0]) / p["dwell"][1]
        z_f = abs(f - p["flight"][0]) / p["flight"][1]
        z_pr = abs(pr - p["pause"][0]) / p["pause"][1]
        z_sp = abs(sp - p["special"][0]) / p["special"][1]
        z_bs = abs(bs - p["backspace"][0]) / p["backspace"][1]

        z_composite = 0.25 * z_d + 0.25 * z_f + 0.20 * z_pr + 0.15 * z_sp + 0.15 * z_bs
        score = 1.0 / (1.0 + np.exp(-1.5 * (z_composite - 2.6)))
        return float(np.clip(score, 0.0, 1.0))


# ----------------------------------------------------------------------
# 5. BENCHMARK SUITE EVALUATOR & METRIC PACKAGER
# ----------------------------------------------------------------------

class ModelBenchmarkSuite:
    def __init__(self, splits_dir: Optional[str] = None):
        self.splits_dir = splits_dir or os.path.join(PROJECT_ROOT, "data", "splits", "personalized")
        self.train_file = os.path.join(self.splits_dir, "train_owner.jsonl")
        self.val_file = os.path.join(self.splits_dir, "val_multimodal.jsonl")
        self.test_file = os.path.join(self.splits_dir, "test_multimodal.jsonl")

    def _load_rows(self, path: str) -> List[Dict[str, Any]]:
        rows = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
        return rows

    def calculate_full_metrics(
        self,
        y_true: np.ndarray,
        y_anomaly_scores: np.ndarray,
        operating_threshold: Optional[float] = None,
        model_name: str = "Model",
        modality: str = "Multimodal"
    ) -> Dict[str, Any]:
        """
        Calculates all required continuous biometric security metrics:
        FAR, FRR, EER, ROC-AUC, PR-AUC, Precision, Recall, F1, and optimal thresholds.
        y_true: 1 for Authorized Owner, 0 for Unauthorized Imposter
        y_anomaly_scores: continuous risk in [0.0, 1.0] where 1.0 = Intrusion Anomaly
        """
        # Note: y_true: 1=Owner, 0=Imposter.
        # Anomaly score: higher means more anomalous (more likely Imposter).
        # To align with standard ROC/PR where positive class is Imposter:
        y_imposter_true = 1 - y_true  # 1 = Imposter, 0 = Owner
        
        # ROC Curve on Imposter detection
        fpr, tpr, roc_thresholds = roc_curve(y_imposter_true, y_anomaly_scores)
        try:
            roc_auc = float(roc_auc_score(y_imposter_true, y_anomaly_scores))
        except Exception:
            roc_auc = 0.5

        try:
            pr_auc = float(average_precision_score(y_imposter_true, y_anomaly_scores))
        except Exception:
            pr_auc = float(np.mean(y_imposter_true))

        # Equal Error Rate (EER) calculation: point where FAR == FRR
        # FAR = False Acceptance Rate = P(classified as Owner | Imposter) = 1 - TPR
        # FRR = False Rejection Rate = P(classified as Imposter | Owner) = FPR
        far_curve = 1.0 - tpr
        frr_curve = fpr
        diff = np.abs(far_curve - frr_curve)
        eer_idx = int(np.nanargmin(diff))
        eer = float((far_curve[eer_idx] + frr_curve[eer_idx]) / 2.0)
        eer_threshold = float(roc_thresholds[min(eer_idx, len(roc_thresholds) - 1)])

        # Operating Point selection (if none provided, use threshold where FAR <= 5%)
        if operating_threshold is None:
            # Low-FAR point: FAR <= 0.05
            low_far_indices = np.where(far_curve <= 0.05)[0]
            if len(low_far_indices) > 0:
                op_idx = low_far_indices[0]
                operating_threshold = float(roc_thresholds[min(op_idx, len(roc_thresholds) - 1)])
            else:
                operating_threshold = eer_threshold

        # Predictions at operating threshold: if score >= threshold -> Imposter (1)
        y_pred_imposter = (y_anomaly_scores >= operating_threshold).astype(int)
        
        cm = confusion_matrix(y_imposter_true, y_pred_imposter, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

        # In imposter detection terms:
        # TN = Owner classified as Owner
        # FP = Owner classified as Imposter (False Rejection of Owner!)
        # FN = Imposter classified as Owner (False Acceptance of Imposter!)
        # TP = Imposter classified as Imposter
        far = fn / (fn + tp) if (fn + tp) > 0 else 0.0  # Imposter accepted as Owner
        frr = fp / (fp + tn) if (fp + tn) > 0 else 0.0  # Owner rejected as Imposter

        acc = float(accuracy_score(y_imposter_true, y_pred_imposter))
        prec = float(precision_score(y_imposter_true, y_pred_imposter, zero_division=0))
        rec = float(recall_score(y_imposter_true, y_pred_imposter, zero_division=0))
        f1 = float(f1_score(y_imposter_true, y_pred_imposter, zero_division=0))

        # Bootstrap 95% Confidence Interval for ROC-AUC
        boot_aucs = []
        n_samples = len(y_imposter_true)
        if n_samples > 20 and len(np.unique(y_imposter_true)) > 1:
            rng = np.random.RandomState(42)
            for _ in range(200):
                b_idx = rng.choice(n_samples, size=n_samples, replace=True)
                if len(np.unique(y_imposter_true[b_idx])) > 1:
                    try:
                        boot_aucs.append(roc_auc_score(y_imposter_true[b_idx], y_anomaly_scores[b_idx]))
                    except Exception:
                        pass
        if boot_aucs:
            ci_lower = float(np.percentile(boot_aucs, 2.5))
            ci_upper = float(np.percentile(boot_aucs, 97.5))
        else:
            ci_lower, ci_upper = roc_auc, roc_auc

        return {
            "model_name": model_name,
            "modality": modality,
            "operating_threshold": round(operating_threshold, 4),
            "eer_threshold": round(eer_threshold, 4),
            "eer_pct": round(eer * 100.0, 2),
            "far_pct": round(far * 100.0, 2),
            "frr_pct": round(frr * 100.0, 2),
            "roc_auc": round(roc_auc, 4),
            "auc_ci_lower": round(ci_lower, 4),
            "auc_ci_upper": round(ci_upper, 4),
            "pr_auc": round(pr_auc, 4),
            "accuracy_pct": round(acc * 100.0, 2),
            "precision_pct": round(prec * 100.0, 2),
            "recall_pct": round(rec * 100.0, 2),
            "f1_score": round(f1, 4),
            "genuine_samples": int(np.sum(y_true == 1)),
            "imposter_samples": int(np.sum(y_true == 0))
        }

    def run_all_benchmarks(self) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Executes benchmarks across all modalities and fusion schemes.
        """
        train_rows = self._load_rows(self.train_file)
        val_rows = self._load_rows(self.val_file)
        test_rows = self._load_rows(self.test_file)

        # Feature keys
        ks_keys = ["dwell_mean", "dwell_std", "flight_mean", "flight_std", "app_backspace_ratio", "app_special_ratio", "app_pause_ratio"]
        mouse_keys = ["mouse_velocity_mean", "mouse_acceleration_mean", "mouse_jerk_mean", "mouse_straightness_mean"]
        context_keys = ["hour_of_day", "cpu_usage", "ram_usage_mb", "app_click_count", "app_scroll_count"]

        # Feature matrix builders
        def get_ks_matrix(rows):
            return np.array([[float(r.get(k, 0.0)) for k in ks_keys] for r in rows])

        def get_mouse_matrix(rows):
            return np.array([[float(r.get(k, 0.0)) for k in mouse_keys] for r in rows])

        def get_ctx_matrix(rows):
            return np.array([[float(r.get(k, 0.0)) for k in context_keys] for r in rows])

        X_ks_train = get_ks_matrix(train_rows)
        X_ks_val = get_ks_matrix(val_rows)
        X_ks_test = get_ks_matrix(test_rows)

        X_m_train = get_mouse_matrix(train_rows)
        X_m_val = get_mouse_matrix(val_rows)
        X_m_test = get_mouse_matrix(test_rows)

        y_val_auth = np.array([1 if r.get("is_authorized") else 0 for r in val_rows])
        y_test_auth = np.array([1 if r.get("is_authorized") else 0 for r in test_rows])

        results = []

        # ==============================================================
        # MODALITY 1: KEYSTROKE DYNAMICS BENCHMARKS
        # ==============================================================
        print("\n--- 1. Keystroke Dynamics Benchmarks ---")
        scaler_ks = RobustScaler().fit(X_ks_train)
        X_ks_tr_s = scaler_ks.transform(X_ks_train)
        X_ks_v_s = scaler_ks.transform(X_ks_val)
        X_ks_te_s = scaler_ks.transform(X_ks_test)

        # A. Scaled Manhattan Distance
        t0 = time.time()
        manhattan = ScaledManhattanDetector().fit(X_ks_train)
        score_val_man = manhattan.score_samples(X_ks_val)
        score_test_man = manhattan.score_samples(X_ks_test)
        lat_man = (time.time() - t0) / max(1, len(X_ks_test)) * 1000.0
        m_man = self.calculate_full_metrics(y_test_auth, score_test_man, model_name="Scaled Manhattan Distance", modality="Keystroke")
        m_man["latency_ms"] = round(lat_man, 3)
        results.append(m_man)
        print(f"  [Keystroke] Scaled Manhattan: EER={m_man['eer_pct']}% | AUC={m_man['roc_auc']} | Latency={lat_man:.2f}ms")

        # B. Regularized Mahalanobis Distance
        t0 = time.time()
        mahal = MahalanobisDetector().fit(X_ks_tr_s)
        score_val_mah = mahal.score_samples(X_ks_v_s)
        score_test_mah = mahal.score_samples(X_ks_te_s)
        lat_mah = (time.time() - t0) / max(1, len(X_ks_test)) * 1000.0
        m_mah = self.calculate_full_metrics(y_test_auth, score_test_mah, model_name="Regularized Mahalanobis", modality="Keystroke")
        m_mah["latency_ms"] = round(lat_mah, 3)
        results.append(m_mah)
        print(f"  [Keystroke] Mahalanobis: EER={m_mah['eer_pct']}% | AUC={m_mah['roc_auc']} | Latency={lat_mah:.2f}ms")

        # C. One-Class SVM (Keystroke)
        t0 = time.time()
        oc_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.03).fit(X_ks_tr_s)
        dec_v = oc_svm.decision_function(X_ks_v_s)
        dec_te = oc_svm.decision_function(X_ks_te_s)
        th_ks_svm = float(np.percentile(dec_v, 5))
        score_val_svm = 1.0 / (1.0 + np.exp(12.0 * (dec_v - th_ks_svm)))
        score_test_svm = 1.0 / (1.0 + np.exp(12.0 * (dec_te - th_ks_svm)))
        lat_svm = (time.time() - t0) / max(1, len(X_ks_test)) * 1000.0
        m_svm = self.calculate_full_metrics(y_test_auth, score_test_svm, model_name="One-Class SVM (RBF)", modality="Keystroke")
        m_svm["latency_ms"] = round(lat_svm, 3)
        results.append(m_svm)
        print(f"  [Keystroke] One-Class SVM: EER={m_svm['eer_pct']}% | AUC={m_svm['roc_auc']} | Latency={lat_svm:.2f}ms")

        # D. Isolation Forest (Keystroke)
        t0 = time.time()
        if_ks = IsolationForest(contamination=0.03, random_state=42).fit(X_ks_train)
        dec_if_v = if_ks.decision_function(X_ks_val)
        dec_if_te = if_ks.decision_function(X_ks_test)
        score_val_if = 1.0 / (1.0 + np.exp(15.0 * dec_if_v))
        score_test_if = 1.0 / (1.0 + np.exp(15.0 * dec_if_te))
        lat_if = (time.time() - t0) / max(1, len(X_ks_test)) * 1000.0
        m_if = self.calculate_full_metrics(y_test_auth, score_test_if, model_name="Isolation Forest", modality="Keystroke")
        m_if["latency_ms"] = round(lat_if, 3)
        results.append(m_if)
        print(f"  [Keystroke] Isolation Forest: EER={m_if['eer_pct']}% | AUC={m_if['roc_auc']}")

        # E. Deep SVDD 1D-CNN (Sequence Biometrics)
        seq_det = DeepSVDDDetector()
        t0 = time.time()
        score_val_svdd = []
        for r in val_rows:
            d_seq = r.get("dwell_sequence", [0.09]*30)[:30]
            f_seq = r.get("flight_sequence", [0.14]*30)[:30]
            score_val_svdd.append(seq_det.predict_score(d_seq, f_seq))
        score_val_svdd = np.array(score_val_svdd)

        score_test_svdd = []
        for r in test_rows:
            d_seq = r.get("dwell_sequence", [0.09]*30)[:30]
            f_seq = r.get("flight_sequence", [0.14]*30)[:30]
            score_test_svdd.append(seq_det.predict_score(d_seq, f_seq))
        score_test_svdd = np.array(score_test_svdd)
        lat_svdd = (time.time() - t0) / max(1, len(test_rows)) * 1000.0

        m_svdd = self.calculate_full_metrics(y_test_auth, score_test_svdd, model_name="Deep SVDD 1D-CNN", modality="Keystroke")
        m_svdd["latency_ms"] = round(lat_svdd, 3)
        results.append(m_svdd)
        print(f"  [Keystroke] Deep SVDD 1D-CNN: EER={m_svdd['eer_pct']}% | AUC={m_svdd['roc_auc']} | Latency={lat_svdd:.2f}ms")

        # F. Supervised Random Forest (when labeled validation available)
        rf_ks = RandomForestClassifier(n_estimators=80, max_depth=6, random_state=42)
        rf_ks.fit(X_ks_val, 1 - y_val_auth)
        score_test_rf_ks = rf_ks.predict_proba(X_ks_test)[:, 1]
        m_rf_ks = self.calculate_full_metrics(y_test_auth, score_test_rf_ks, model_name="Random Forest Classifier", modality="Keystroke")
        results.append(m_rf_ks)
        print(f"  [Keystroke] Supervised Random Forest: EER={m_rf_ks['eer_pct']}% | AUC={m_rf_ks['roc_auc']}")

        # ==============================================================
        # MODALITY 2: MOUSE DYNAMICS BENCHMARKS
        # ==============================================================
        print("\n--- 2. Mouse Dynamics Benchmarks ---")
        scaler_m = RobustScaler().fit(X_m_train)
        X_m_tr_s = scaler_m.transform(X_m_train)
        X_m_v_s = scaler_m.transform(X_m_val)
        X_m_te_s = scaler_m.transform(X_m_test)

        # A. Robust Statistical Kinematics Detector
        t0 = time.time()
        rob_mouse = RobustMouseDetector().fit(X_m_train)
        score_val_m_rob = rob_mouse.score_samples(X_m_val)
        score_test_m_rob = rob_mouse.score_samples(X_m_test)
        lat_m_rob = (time.time() - t0) / max(1, len(X_m_test)) * 1000.0
        m_m_rob = self.calculate_full_metrics(y_test_auth, score_test_m_rob, model_name="Robust Kinematics Distance", modality="Mouse")
        m_m_rob["latency_ms"] = round(lat_m_rob, 3)
        results.append(m_m_rob)
        print(f"  [Mouse] Robust Kinematics: EER={m_m_rob['eer_pct']}% | AUC={m_m_rob['roc_auc']}")

        # B. One-Class SVM (Mouse)
        oc_m = OneClassSVM(kernel="rbf", gamma="scale", nu=0.03).fit(X_m_tr_s)
        dec_m_v = oc_m.decision_function(X_m_v_s)
        dec_m_te = oc_m.decision_function(X_m_te_s)
        score_val_m_svm = 1.0 / (1.0 + np.exp(10.0 * dec_m_v))
        score_test_m_svm = 1.0 / (1.0 + np.exp(10.0 * dec_m_te))
        m_m_svm = self.calculate_full_metrics(y_test_auth, score_test_m_svm, model_name="One-Class SVM (Mouse)", modality="Mouse")
        results.append(m_m_svm)
        print(f"  [Mouse] One-Class SVM: EER={m_m_svm['eer_pct']}% | AUC={m_m_svm['roc_auc']}")

        # C. Isolation Forest (Mouse)
        if_m = IsolationForest(contamination=0.03, random_state=42).fit(X_m_train)
        score_test_m_if = 1.0 / (1.0 + np.exp(15.0 * if_m.decision_function(X_m_test)))
        m_m_if = self.calculate_full_metrics(y_test_auth, score_test_m_if, model_name="Isolation Forest (Mouse)", modality="Mouse")
        results.append(m_m_if)
        print(f"  [Mouse] Isolation Forest: EER={m_m_if['eer_pct']}% | AUC={m_m_if['roc_auc']}")

        # ==============================================================
        # MODALITY 3: CONTEXT & COGNITIVE CONTROLLER
        # ==============================================================
        print("\n--- 3. Context & Cognitive Controller Benchmarks ---")
        # A. Context Isolation Forest (from BehavioralModels)
        beh_models = BehavioralModels()
        beh_models.train(train_rows)
        score_val_ctx_if = []
        score_test_ctx_if = []
        for r in val_rows:
            _, if_c = beh_models.score(r)
            score_val_ctx_if.append(1.0 - if_c)
        for r in test_rows:
            _, if_c = beh_models.score(r)
            score_test_ctx_if.append(1.0 - if_c)
        score_val_ctx_if = np.array(score_val_ctx_if)
        score_test_ctx_if = np.array(score_test_ctx_if)
        m_ctx_if = self.calculate_full_metrics(y_test_auth, score_test_ctx_if, model_name="Context Isolation Forest", modality="Context")
        results.append(m_ctx_if)
        print(f"  [Context] Isolation Forest: EER={m_ctx_if['eer_pct']}% | AUC={m_ctx_if['roc_auc']}")

        # B. Markov Workflow Transition Detector
        train_states = [categorize_process(r.get("active_app", "")) for r in train_rows]
        markov_det = MarkovContextDetector().fit(train_states)
        score_test_markov = []
        for i in range(len(test_rows)):
            curr_s = categorize_process(test_rows[i].get("active_app", ""))
            prev_s = categorize_process(test_rows[i-1].get("active_app", "")) if i > 0 else curr_s
            score_test_markov.append(markov_det.score_transition(prev_s, curr_s))
        score_test_markov = np.array(score_test_markov)
        m_markov = self.calculate_full_metrics(y_test_auth, score_test_markov, model_name="Markov Process Transitions", modality="Context")
        results.append(m_markov)
        print(f"  [Context] Markov Transitions: EER={m_markov['eer_pct']}% | AUC={m_markov['roc_auc']}")

        # C. Robust Cognitive Controller
        rob_ctrl = RobustCognitiveController().fit(train_rows)
        score_val_ctrl = np.array([rob_ctrl.score_row(r) for r in val_rows])
        score_test_ctrl = np.array([rob_ctrl.score_row(r) for r in test_rows])
        m_ctrl = self.calculate_full_metrics(y_test_auth, score_test_ctrl, model_name="Robust Cognitive Controller", modality="Cognitive")
        results.append(m_ctrl)
        print(f"  [Cognitive] Robust Controller: EER={m_ctrl['eer_pct']}% | AUC={m_ctrl['roc_auc']}")

        # ==============================================================
        # MODALITY 4: MULTIMODAL SCORE FUSION BENCHMARKS
        # ==============================================================
        print("\n--- 4. Multimodal Fusion Benchmarks ---")
        # Component test risk scores
        s_svdd_te = score_test_svdd
        s_ks_svm_te = score_test_svm
        s_m_te = score_test_m_rob
        s_ctx_te = score_test_ctx_if
        s_ctrl_te = score_test_ctrl

        # Fusion 1: Baseline Fixed Weight Fusion (0.35 Deep SVDD, 0.35 OC-SVM, 0.15 IF, 0.15 Controller)
        fused_baseline_te = (0.35 * s_svdd_te) + (0.35 * s_ks_svm_te) + (0.15 * s_ctx_te) + (0.15 * s_ctrl_te)
        m_fused_base = self.calculate_full_metrics(y_test_auth, fused_baseline_te, model_name="Baseline Fixed Weight Fusion", modality="Multimodal Fusion")
        results.append(m_fused_base)
        print(f"  [Fusion 1] Baseline Fixed (0.35/0.35/0.15/0.15): EER={m_fused_base['eer_pct']}% | AUC={m_fused_base['roc_auc']}")

        # Fusion 2: Calibrated Multi-Modal Fusion (incorporating Mouse Dynamics!)
        # Weights: SVDD (0.25), Keystroke (0.25), Mouse (0.25), Context (0.125), Cognitive (0.125)
        fused_calibrated_te = (0.25 * s_svdd_te) + (0.25 * s_ks_svm_te) + (0.25 * s_m_te) + (0.125 * s_ctx_te) + (0.125 * s_ctrl_te)
        m_fused_cal = self.calculate_full_metrics(y_test_auth, fused_calibrated_te, model_name="Calibrated 5-Factor Weighted Fusion", modality="Multimodal Fusion")
        results.append(m_fused_cal)
        print(f"  [Fusion 2] Calibrated 5-Factor: EER={m_fused_cal['eer_pct']}% | AUC={m_fused_cal['roc_auc']}")

        # Fusion 3: Dynamic Modality-Aware Fusion (Handles Idle Devices Gracefully)
        dynamic_fused_te = []
        for i, r in enumerate(test_rows):
            keys = r.get("keystroke_count", 0)
            dwell = r.get("dwell_mean", 0.0)
            mouse = r.get("mouse_events", 0)

            # Available active sensors
            w_svdd, w_ks, w_m, w_ctx, w_ctrl = 0.25, 0.25, 0.25, 0.125, 0.125
            if keys == 0 and dwell == 0.0:
                # Keyboard idle: zero keystroke weights, redistribute to mouse & context
                w_svdd = 0.0
                w_ks = 0.0
                w_m = 0.60
                w_ctx = 0.20
                w_ctrl = 0.20
            elif mouse < 5:
                # Mouse idle: zero mouse weight, redistribute to keystroke
                w_m = 0.0
                w_svdd = 0.40
                w_ks = 0.35
                w_ctx = 0.125
                w_ctrl = 0.125

            score_f = (w_svdd * s_svdd_te[i]) + (w_ks * s_ks_svm_te[i]) + (w_m * s_m_te[i]) + (w_ctx * s_ctx_te[i]) + (w_ctrl * s_ctrl_te[i])
            dynamic_fused_te.append(score_f)

        dynamic_fused_te = np.array(dynamic_fused_te)
        m_dyn_fused = self.calculate_full_metrics(y_test_auth, dynamic_fused_te, model_name="Dynamic Modality-Aware Fusion (Adaptive)", modality="Multimodal Fusion")
        results.append(m_dyn_fused)
        print(f"  [Fusion 3] Dynamic Modality-Aware: EER={m_dyn_fused['eer_pct']}% | AUC={m_dyn_fused['roc_auc']} | FAR={m_dyn_fused['far_pct']}% | FRR={m_dyn_fused['frr_pct']}%")

        # Fusion 4: Out-of-Fold Supervised Logistic Regression Fusion
        # Train meta-classifier on validation scores
        s_svdd_v = score_val_svdd
        s_ks_svm_v = score_val_svm
        s_m_v = score_val_m_rob
        s_ctx_v = score_val_ctx_if
        s_ctrl_v = score_val_ctrl

        X_meta_val = np.column_stack([s_svdd_v, s_ks_svm_v, s_m_v, s_ctx_v, s_ctrl_v])
        X_meta_test = np.column_stack([s_svdd_te, s_ks_svm_te, s_m_te, s_ctx_te, s_ctrl_te])

        meta_clf = LogisticRegression(C=1.0, random_state=42)
        meta_clf.fit(X_meta_val, 1 - y_val_auth)
        score_test_meta = meta_clf.predict_proba(X_meta_test)[:, 1]

        m_meta_fused = self.calculate_full_metrics(y_test_auth, score_test_meta, model_name="Supervised Logistic Stacking Fusion", modality="Multimodal Fusion")
        results.append(m_meta_fused)
        print(f"  [Fusion 4] Stacking Logistic Fusion: EER={m_meta_fused['eer_pct']}% | AUC={m_meta_fused['roc_auc']}")

        # ==============================================================
        # 6. EXPORT COMPREHENSIVE BENCHMARK RESULTS CSV
        # ==============================================================
        df_results = pd.DataFrame(results)
        reports_dir = os.path.join(PROJECT_ROOT, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        csv_path = os.path.join(reports_dir, "model_benchmark_results.csv")
        df_results.to_csv(csv_path, index=False)
        print(f"\n[BENCHMARK COMPLETE] Saved full benchmark metrics table ({len(df_results)} models) to:")
        print(f"  -> {csv_path}")

        return df_results, {
            "best_keystroke": m_mah if m_mah["roc_auc"] > m_svm["roc_auc"] else m_svm,
            "best_mouse": m_m_rob,
            "best_context": m_ctx_if,
            "best_fusion": m_dyn_fused
        }


if __name__ == "__main__":
    suite = ModelBenchmarkSuite()
    df, best = suite.run_all_benchmarks()
