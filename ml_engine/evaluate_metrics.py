import os
import sys
import json
import random
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, roc_curve, precision_recall_curve, confusion_matrix
)

# Append project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml_engine.models import BehavioralModels
from ml_engine.sequence_model import DeepSVDDDetector
from ml_engine.controller import BehavioralAIController
from ml_engine.train import load_real_data

try:
    import matplotlib.pyplot as plt
    PLOT_AVAILABLE = True
except ImportError:
    PLOT_AVAILABLE = False


def generate_imposter_telemetry(num_samples=350, seed=42):
    """
    Synthesizes diverse imposter telemetry rows covering 4 distinct intruder typologies:
    1. Frantic / Fast Typer: extremely short dwell & flight, erratic bursts
    2. Hunt-and-Peck Typer: sluggish dwell & high inter-key flight times
    3. Rogue Process Intruder: unusual process, elevated CPU, abnormal hours
    4. Cross-User Cognitive Imposter: coding on LeetCode without thinking pauses or syntax symbols
    """
    np.random.seed(seed)
    random.seed(seed)
    
    rows = []
    for i in range(num_samples):
        typology = i % 4
        if typology == 0:
            # Frantic rapid typist
            dwell = max(0.02, float(np.random.normal(0.045, 0.008)))
            flight = max(0.03, float(np.random.normal(0.075, 0.015)))
            mouse_vel = float(np.random.normal(750.0, 90.0))
            mouse_acc = float(np.random.normal(65.0, 15.0))
            straight = float(np.clip(np.random.normal(0.60, 0.08), 0.3, 0.95))
            cpu = float(np.random.normal(5.0, 1.5))
            app = random.choice(["chrome.exe", "code.exe"])
            win = "LeetCode - Solve"
            pause_ratio = 0.05
            sym_ratio = 0.03
            backspace = 0.02
        elif typology == 1:
            # Sluggish hunt-and-peck typist
            dwell = float(np.random.normal(0.240, 0.035))
            flight = float(np.random.normal(0.390, 0.060))
            mouse_vel = float(np.random.normal(120.0, 30.0))
            mouse_acc = float(np.random.normal(8.0, 2.5))
            straight = float(np.clip(np.random.normal(0.70, 0.06), 0.4, 0.95))
            cpu = float(np.random.normal(3.0, 1.0))
            app = random.choice(["notepad.exe", "explorer.exe"])
            win = "Document.txt"
            pause_ratio = 0.08
            sym_ratio = 0.02
            backspace = 0.01
        elif typology == 2:
            # Rogue system context intruder
            dwell = float(np.random.normal(0.180, 0.025))
            flight = float(np.random.normal(0.260, 0.040))
            mouse_vel = float(np.random.normal(500.0, 80.0))
            mouse_acc = float(np.random.normal(35.0, 8.0))
            straight = float(np.clip(np.random.normal(0.65, 0.08), 0.3, 0.95))
            cpu = float(np.random.normal(48.0, 12.0))
            app = random.choice(["cmd.exe", "powershell.exe", "mimikatz.exe"])
            win = "Administrator: Command Prompt"
            pause_ratio = 0.10
            sym_ratio = 0.12
            backspace = 0.04
        else:
            # Cross-user cognitive mismatch (LeetCode copy-paster / prose writer)
            dwell = float(np.random.normal(0.135, 0.020))
            flight = float(np.random.normal(0.220, 0.030))
            mouse_vel = float(np.random.normal(380.0, 60.0))
            mouse_acc = float(np.random.normal(22.0, 5.0))
            straight = float(np.clip(np.random.normal(0.85, 0.05), 0.6, 0.98))
            cpu = float(np.random.normal(4.0, 1.0))
            app = "chrome.exe"
            win = "Two Sum - LeetCode - Google Chrome"
            pause_ratio = 0.02  # No thinking pauses!
            sym_ratio = 0.01    # No code symbols!
            backspace = 0.01

        row = {
            "timestamp": 1790300000 + i * 15,
            "hour_of_day": random.randint(0, 23),
            "keystroke_count": random.randint(25, 80),
            "dwell_mean": dwell,
            "dwell_std": round(dwell * 0.20, 4),
            "flight_mean": flight,
            "flight_std": round(flight * 0.22, 4),
            "app_dwell_mean": dwell,
            "app_flight_mean": flight,
            "app_backspace_ratio": backspace,
            "app_special_ratio": sym_ratio,
            "app_click_count": random.randint(1, 6),
            "app_scroll_count": random.randint(0, 4),
            "app_pause_ratio": pause_ratio,
            "avg_thinking_pause_sec": 0.4 if typology != 3 else 0.2,
            "interaction_mode": "coding_problem_solving" if typology == 3 else "general_productivity",
            "mouse_events": random.randint(30, 150),
            "mouse_velocity_mean": mouse_vel,
            "mouse_acceleration_mean": mouse_acc,
            "mouse_jerk_mean": round(mouse_acc * 0.12, 3),
            "mouse_straightness_mean": straight,
            "active_app": app,
            "active_window": win,
            "cpu_usage": cpu,
            "ram_usage_mb": float(random.randint(250, 750))
        }
        rows.append(row)
    return rows


def calculate_metrics_bundle(y_true, y_pred, y_scores):
    """
    Computes standard classification metrics and biometric security metrics (FAR, FRR, EER).
    y_true: 1 for Owner (Authentic), 0 for Imposter (Intruder)
    y_pred: Binary predicted label (1 = Owner, 0 = Imposter)
    y_scores: Continuous confidence score [0.0, 1.0] where 1.0 is Owner
    """
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    
    try:
        auc_val = roc_auc_score(y_true, y_scores)
    except Exception:
        auc_val = 0.5
        
    far = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    frr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    
    # Calculate Equal Error Rate (EER) via ROC curve
    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    fnr = 1.0 - tpr
    eer_idx = np.nanargmin(np.abs(fpr - fnr))
    eer = float((fpr[eer_idx] + fnr[eer_idx]) / 2.0)
    
    return {
        "accuracy": acc * 100.0,
        "precision": prec * 100.0,
        "recall_tpr": rec * 100.0,
        "specificity_tnr": spec * 100.0,
        "f1_score": f1 * 100.0,
        "roc_auc": auc_val,
        "far": far * 100.0,
        "frr": frr * 100.0,
        "eer": eer * 100.0,
        "cm": cm
    }


def evaluate_all_models():
    """
    Comprehensive scientific evaluation of all continuous authentication model layers:
    1. Biometric Dynamics (One-Class SVM)
    2. Context Dynamics (Isolation Forest)
    3. Deep Keystroke Sequence Biometrics (Deep SVDD 1D-CNN)
    4. Behavioral AI Controller (Cognitive Envelopes)
    5. Tri-Factor Fused Continuous Authentication System
    """
    print("=" * 70)
    print("      COMPREHENSIVE MULTI-FACTOR BEHAVIORAL MODEL EVALUATION")
    print("=" * 70)
    
    # 1. Load real owner records
    telemetry_file = os.path.join(PROJECT_ROOT, "telemetry_data.jsonl")
    owner_rows = load_real_data(telemetry_file)
    if not owner_rows:
        print("[ERROR] No telemetry records found in telemetry_data.jsonl", file=sys.stderr)
        return
        
    print(f"[INFO] Loaded {len(owner_rows)} genuine owner telemetry records.")
    
    # Stratified split: 80% train, 20% test (prevent data leakage)
    random.seed(42)
    shuffled_owner = list(owner_rows)
    random.shuffle(shuffled_owner)
    
    split_idx = int(0.80 * len(shuffled_owner))
    train_owner = shuffled_owner[:split_idx]
    test_owner = shuffled_owner[split_idx:]
    
    # Generate test imposters
    test_imposters = generate_imposter_telemetry(num_samples=len(test_owner), seed=42)
    print(f"[INFO] Test Split: {len(test_owner)} genuine test samples vs. {len(test_imposters)} imposter samples.")
    
    # 2. Train models on training partition
    models = BehavioralModels()
    models.train(train_owner)
    
    # Load AI Controller
    controller = BehavioralAIController()
    
    # Ground truth: 1 for Owner (Normal), 0 for Imposter (Attacker)
    y_true = np.array([1] * len(test_owner) + [0] * len(test_imposters))
    
    # 3. Predict across each model
    svm_scores = []
    if_scores = []
    ctrl_scores = []
    fused_scores = []
    
    combined_test = test_owner + test_imposters
    
    for row in combined_test:
        svm_conf, if_conf = models.score(row)
        
        # AI Controller confidence
        try:
            anomaly, _ = controller.evaluate_telemetry_row(row)
            ctrl_conf = 1.0 - anomaly
        except Exception:
            ctrl_conf = svm_conf
            
        # Tri-factor fusion (0.50 SVM + 0.20 IF + 0.30 Controller)
        fused_conf = 0.50 * svm_conf + 0.20 * if_conf + 0.30 * ctrl_conf
        
        svm_scores.append(svm_conf)
        if_scores.append(if_conf)
        ctrl_scores.append(ctrl_conf)
        fused_scores.append(fused_conf)
        
    svm_scores = np.array(svm_scores)
    if_scores = np.array(if_scores)
    ctrl_scores = np.array(ctrl_scores)
    fused_scores = np.array(fused_scores)
    
    # Predictions using standard decision boundary (Confidence >= 0.50 -> Owner, < 0.50 -> Imposter)
    thresh = 0.50
    m_svm = calculate_metrics_bundle(y_true, (svm_scores >= thresh).astype(int), svm_scores)
    m_if = calculate_metrics_bundle(y_true, (if_scores >= thresh).astype(int), if_scores)
    m_ctrl = calculate_metrics_bundle(y_true, (ctrl_scores >= thresh).astype(int), ctrl_scores)
    m_fused = calculate_metrics_bundle(y_true, (fused_scores >= thresh).astype(int), fused_scores)
    
    # 4. Evaluate Deep SVDD 1D-CNN Keystroke Sequences
    raw_ks = os.path.join(PROJECT_ROOT, "data", "raw", "keystrokes.csv")
    raw_imp = os.path.join(PROJECT_ROOT, "data", "raw", "imposter_keystrokes.csv")
    m_svdd = None
    
    if os.path.exists(raw_ks) and os.path.exists(raw_imp):
        seq_det = DeepSVDDDetector()
        norm_seqs = seq_det.extract_raw_sequences(raw_ks)
        imp_seqs = seq_det.extract_raw_sequences(raw_imp)
        
        if len(norm_seqs) > 0 and len(imp_seqs) > 0:
            y_seq_true = [1] * len(norm_seqs) + [0] * len(imp_seqs)
            seq_scores = []
            for s in norm_seqs:
                risk = seq_det.predict_score(s[0], s[1])
                seq_scores.append(1.0 - risk) # Confidence = 1 - risk
            for s in imp_seqs:
                risk = seq_det.predict_score(s[0], s[1])
                seq_scores.append(1.0 - risk)
                
            seq_scores = np.array(seq_scores)
            m_svdd = calculate_metrics_bundle(np.array(y_seq_true), (seq_scores >= 0.50).astype(int), seq_scores)

    # 5. Print Formatted Benchmark Table
    print("\n" + "=" * 90)
    print(f"{'MODEL LAYER':<32} | {'ACCURACY':<8} | {'PRECISION':<9} | {'RECALL/TPR':<10} | {'F1-SCORE':<8} | {'ROC-AUC':<7} | {'EER':<6}")
    print("-" * 90)
    
    def print_row(name, m):
        print(f"{name:<32} | {m['accuracy']:>7.2f}% | {m['precision']:>8.2f}% | {m['recall_tpr']:>9.2f}% | {m['f1_score']:>7.2f}% | {m['roc_auc']:>7.4f} | {m['eer']:>5.2f}%")
        
    print_row("1. Biometric Dynamics (OC-SVM)", m_svm)
    print_row("2. Context Dynamics (IsoForest)", m_if)
    print_row("3. AI Controller (Cognitive)", m_ctrl)
    if m_svdd:
        print_row("4. Deep SVDD 1D-CNN (Sequences)", m_svdd)
    print("-" * 90)
    print_row(">> TRI-FACTOR FUSED SYSTEM <<", m_fused)
    print("=" * 90)
    
    print(f"\n[SECURITY METRICS SUMMARY]")
    print(f"  - False Acceptance Rate (FAR - Intruder undetected): {m_fused['far']:.2f}%")
    print(f"  - False Rejection Rate  (FRR - Owner false alarm):   {m_fused['frr']:.2f}%")
    print(f"  - Equal Error Rate     (EER - Biometric parity):    {m_fused['eer']:.2f}%")
    print(f"  - Overall System Accuracy:                          {m_fused['accuracy']:.2f}%")
    print(f"  - Overall System F1-Score:                          {m_fused['f1_score']:.2f}%\n")

    # 6. Generate 4-Panel Publication-Quality Figure
    if PLOT_AVAILABLE:
        fig, axes = plt.subplots(2, 2, figsize=(15, 11))
        
        # Panel 1: ROC Curves
        ax_roc = axes[0, 0]
        for name, scores, col in [
            ("Biometrics (OC-SVM)", svm_scores, "#2b5c8f"),
            ("Context (IsoForest)", if_scores, "#e67e22"),
            ("AI Controller", ctrl_scores, "#8e44ad"),
            ("Fused System", fused_scores, "#27ae60")
        ]:
            fpr, tpr, _ = roc_curve(y_true, scores)
            auc_score = roc_auc_score(y_true, scores)
            ax_roc.plot(fpr, tpr, label=f"{name} (AUC = {auc_score:.4f})", linewidth=2.2, color=col)
            
        ax_roc.plot([0, 1], [0, 1], 'k--', alpha=0.5, label="Random Guess (AUC = 0.50)")
        ax_roc.set_title("ROC Curves - Continuous Authentication Layers", fontsize=12, fontweight="bold")
        ax_roc.set_xlabel("False Positive Rate (FAR)", fontsize=10)
        ax_roc.set_ylabel("True Positive Rate (Recall / TPR)", fontsize=10)
        ax_roc.legend(loc="lower right", fontsize=9)
        ax_roc.grid(True, linestyle="--", alpha=0.5)

        # Panel 2: Confusion Matrix Heatmap for Fused System
        ax_cm = axes[0, 1]
        cm = m_fused["cm"]
        # Format labels: Row 0 = Imposter, Row 1 = Owner
        cax = ax_cm.imshow(cm, cmap="Blues", interpolation="nearest")
        fig.colorbar(cax, ax=ax_cm, fraction=0.046, pad=0.04)
        ax_cm.set_xticks([0, 1])
        ax_cm.set_yticks([0, 1])
        ax_cm.set_xticklabels(["Predicted Imposter", "Predicted Owner"], fontsize=10)
        ax_cm.set_yticklabels(["Actual Imposter", "Actual Owner"], fontsize=10)
        ax_cm.set_title(f"Fused System Confusion Matrix (F1: {m_fused['f1_score']:.1f}%)", fontsize=12, fontweight="bold")
        
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                pct = (val / np.sum(cm)) * 100.0
                ax_cm.text(j, i, f"{val}\n({pct:.1f}%)", ha="center", va="center",
                           color="white" if val > np.max(cm)/2 else "black", fontsize=12, fontweight="bold")

        # Panel 3: Risk Score Probability Density Separability
        ax_dist = axes[1, 0]
        owner_risks = 1.0 - fused_scores[y_true == 1]
        imposter_risks = 1.0 - fused_scores[y_true == 0]
        
        ax_dist.hist(owner_risks, bins=25, alpha=0.65, color="#27ae60", label=f"Authentic Owner (Mean Risk: {np.mean(owner_risks):.3f})", density=True)
        ax_dist.hist(imposter_risks, bins=25, alpha=0.65, color="#c0392b", label=f"Intruder Imposter (Mean Risk: {np.mean(imposter_risks):.3f})", density=True)
        ax_dist.axvline(0.55, color="black", linestyle="--", linewidth=2.0, label="Drift Alert Threshold (0.55)")
        ax_dist.set_title("Behavioral Risk Distribution & Decision Boundary", fontsize=12, fontweight="bold")
        ax_dist.set_xlabel("Continuous Anomaly Risk [0.0 = Authentic, 1.0 = Intrusion]", fontsize=10)
        ax_dist.set_ylabel("Probability Density", fontsize=10)
        ax_dist.legend(loc="upper center", fontsize=9)
        ax_dist.grid(True, linestyle="--", alpha=0.5)

        # Panel 4: Metric Comparison Bar Chart
        ax_bar = axes[1, 1]
        metrics_names = ["Accuracy", "Precision", "Recall", "Specificity", "F1-Score"]
        fused_vals = [m_fused["accuracy"], m_fused["precision"], m_fused["recall_tpr"], m_fused["specificity_tnr"], m_fused["f1_score"]]
        svm_vals = [m_svm["accuracy"], m_svm["precision"], m_svm["recall_tpr"], m_svm["specificity_tnr"], m_svm["f1_score"]]
        
        x = np.arange(len(metrics_names))
        w = 0.38
        ax_bar.bar(x - w/2, svm_vals, width=w, label="Biometrics (OC-SVM)", color="#2b5c8f", alpha=0.85)
        ax_bar.bar(x + w/2, fused_vals, width=w, label="Tri-Factor Fused", color="#27ae60", alpha=0.85)
        
        ax_bar.set_xticks(x)
        ax_bar.set_xticklabels(metrics_names, fontsize=10)
        ax_bar.set_ylim(80, 103)
        ax_bar.set_ylabel("Percentage (%)", fontsize=10)
        ax_bar.set_title("Performance Metrics Comparison Across Layers", fontsize=12, fontweight="bold")
        ax_bar.legend(loc="lower right", fontsize=9)
        ax_bar.grid(True, linestyle="--", alpha=0.5, axis="y")
        
        for bar in ax_bar.patches:
            h = bar.get_height()
            ax_bar.annotate(f"{h:.1f}%",
                            (bar.get_x() + bar.get_width() / 2, h),
                            ha="center", va="bottom", fontsize=8, fontweight="bold", xytext=(0, 2),
                            textcoords="offset points")

        plt.suptitle("Multi-Factor Behavioral Drift Continuous Authentication - Scientific Evaluation", fontsize=14, fontweight="bold")
        plt.tight_layout()
        
        out_chart = os.path.join(PROJECT_ROOT, "model_performance.png")
        plt.savefig(out_chart, dpi=300)
        print(f"[SUCCESS] Exported high-resolution 300 DPI evaluation chart to '{out_chart}'")

    # Save models trained on partitioned data
    models.save(os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl"))
    return m_fused


if __name__ == "__main__":
    evaluate_all_models()
