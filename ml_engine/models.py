import os
import pickle
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def categorize_process(proc_name):
    """
    Groups window processes into 5 semantic categories for classification stability:
    0: IDE/Development
    1: Browsers
    2: System Tools & Terminals
    3: Office/Productivity
    4: Other/Background
    """
    proc_name = str(proc_name).lower()
    dev_tools = ["code.exe", "pycharm.exe", "notepad++.exe", "sublime_text.exe", "python.exe", "git.exe", "studio.exe"]
    browsers = ["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "safari.exe"]
    terminals = ["cmd.exe", "powershell.exe", "bash.exe", "conhost.exe", "regedit.exe", "taskmgr.exe", "processhacker.exe"]
    productivity = ["winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "outlook.exe", "acrodist.exe", "acrobat.exe"]
    
    if any(x in proc_name for x in dev_tools):
        return 0
    if any(x in proc_name for x in browsers):
        return 1
    if any(x in proc_name for x in terminals):
        return 2
    if any(x in proc_name for x in productivity):
        return 3
    return 4

class BehavioralModels:
    def __init__(self):
        # Feature selectors matching Member 1's telemetry payload
        self.biometric_feature_keys = [
            "dwell_mean", "dwell_std", 
            "flight_mean", "flight_std", 
            "mouse_velocity_mean", "mouse_acceleration_mean", 
            "mouse_jerk_mean", "mouse_straightness_mean"
        ]
        self.context_feature_keys = [
            "hour_of_day", "cpu_usage", "ram_usage_mb", "app_hash"
        ]

        # ML Models and Preprocessing Scalers
        self.oc_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
        self.i_forest = IsolationForest(contamination=0.01, random_state=42)
        
        self.biometric_scaler = StandardScaler()
        self.context_scaler = StandardScaler()
        
        # Auto-calibrated thresholds
        self.biometric_threshold = 0.0
        self.context_threshold = 0.0
        
        self.is_trained = False

    def extract_features(self, json_data):
        """Extracts and formats biometric and context vectors from a single telemetry row."""
        # Convert app name to numeric feature using semantic categorization
        app_name = json_data.get("active_app", "unknown")
        app_hash = categorize_process(app_name)
        
        # Biometrics vector
        biometrics = []
        for key in self.biometric_feature_keys:
            biometrics.append(json_data.get(key, 0.0))
            
        # Context vector
        context = []
        for key in self.context_feature_keys:
            if key == "app_hash":
                context.append(float(app_hash))
            else:
                context.append(json_data.get(key, 0.0))
                
        return np.array(biometrics), np.array(context)

    def train(self, all_rows):
        """Trains both OneClassSVM (on biometrics) and IsolationForest (on context)."""
        X_bio = []
        X_ctx = []
        
        for row in all_rows:
            bio, ctx = self.extract_features(row)
            X_bio.append(bio)
            X_ctx.append(ctx)
            
        X_bio = np.array(X_bio)
        X_ctx = np.array(X_ctx)
        
        # 1. Scale features
        X_bio_scaled = self.biometric_scaler.fit_transform(X_bio)
        X_ctx_scaled = self.context_scaler.fit_transform(X_ctx)
        
        # 2. Train models
        self.oc_svm.fit(X_bio_scaled)
        self.i_forest.fit(X_ctx_scaled)
        
        # 3. Auto-Calibrate Anomaly Thresholds
        bio_decisions = self.oc_svm.decision_function(X_bio_scaled)
        ctx_decisions = self.i_forest.decision_function(X_ctx_scaled)
        
        # 5th percentile for biometrics (allows 5% False Alarm rate on normal typing)
        self.biometric_threshold = float(np.percentile(bio_decisions, 5))
        # 2nd percentile for context (allows 2% False Alarm rate on normal contexts)
        self.context_threshold = float(np.percentile(ctx_decisions, 2))
        
        self.is_trained = True
        print(f"[INFO] Models trained successfully. Calibrated Biometric Thresh: {self.biometric_threshold:.6f}, Context Thresh: {self.context_threshold:.6f}", flush=True)

    def score(self, json_data):
        """Computes confidence/normality scores in range [0.0, 1.0].
        
        Returns:
            svm_score: Normalized value [0.0, 1.0] where 1.0 is normal, 0.0 is anomalous.
            if_score: Normalized value [0.0, 1.0] where 1.0 is normal, 0.0 is anomalous.
        """
        if not self.is_trained:
            raise Exception("Cannot score data: Models have not been trained yet.")
            
        bio, ctx = self.extract_features(json_data)
        
        bio_scaled = self.biometric_scaler.transform(bio.reshape(1, -1))
        ctx_scaled = self.context_scaler.transform(ctx.reshape(1, -1))
        
        # Get raw decision function scores
        svm_raw = self.oc_svm.decision_function(bio_scaled)[0]
        if_raw = self.i_forest.decision_function(ctx_scaled)[0]
        
        # Sigmoid normalization centered around auto-calibrated thresholds
        svm_score = 1.0 / (1.0 + np.exp(-25.0 * (svm_raw - self.biometric_threshold)))
        if_score = 1.0 / (1.0 + np.exp(-45.0 * (if_raw - (self.context_threshold + 0.02))))
        
        return float(svm_score), float(if_score)

    def save(self, filepath=None):
        """Saves the models, scalers, and thresholds together as a single serialized pickle file."""
        if filepath is None:
            filepath = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl")
        elif not os.path.isabs(filepath):
            filepath = os.path.join(PROJECT_ROOT, filepath)

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data_to_save = {
            "oc_svm": self.oc_svm,
            "i_forest": self.i_forest,
            "biometric_scaler": self.biometric_scaler,
            "context_scaler": self.context_scaler,
            "biometric_threshold": self.biometric_threshold,
            "context_threshold": self.context_threshold,
            "is_trained": self.is_trained
        }
        with open(filepath, "wb") as f:
            pickle.dump(data_to_save, f)
        print(f"[INFO] Saved model checkpoint to '{filepath}'", flush=True)

    def load(self, filepath=None):
        """Loads models, scalers, and thresholds from a pickle file."""
        if filepath is None:
            filepath = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl")
        elif not os.path.isabs(filepath):
            filepath = os.path.join(PROJECT_ROOT, filepath)

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found at '{filepath}'")
            
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            
        self.oc_svm = data["oc_svm"]
        self.i_forest = data["i_forest"]
        self.biometric_scaler = data["biometric_scaler"]
        self.context_scaler = data["context_scaler"]
        self.biometric_threshold = data.get("biometric_threshold", 0.0)
        self.context_threshold = data.get("context_threshold", 0.0)
        self.is_trained = data["is_trained"]
        print(f"[INFO] Loaded model checkpoint from '{filepath}'", flush=True)
