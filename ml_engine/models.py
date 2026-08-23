import os
import pickle
import hashlib
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

class BehavioralModels:
    def __init__(self):
        # Feature selectors
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
        self.i_forest = IsolationForest(contamination=0.05, random_state=42)
        
        self.biometric_scaler = StandardScaler()
        self.context_scaler = StandardScaler()
        
        self.is_trained = False

    def hash_app_name(self, app_name):
        """Converts an executable string (e.g., 'chrome.exe') to a bounded integer [0, 99] using MD5."""
        if not app_name:
            return 0
        return int(hashlib.md5(str(app_name).lower().encode('utf-8')).hexdigest(), 16) % 100

    def extract_features(self, json_data):
        """Extracts and formats biometric and context vectors from a single telemetry row."""
        # Convert app name to numeric feature
        app_name = json_data.get("active_app", "unknown")
        app_hash = self.hash_app_name(app_name)
        
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
        
        # 1. Scale features (essential for SVM)
        X_bio_scaled = self.biometric_scaler.fit_transform(X_bio)
        X_ctx_scaled = self.context_scaler.fit_transform(X_ctx)
        
        # 2. Train models
        self.oc_svm.fit(X_bio_scaled)
        self.i_forest.fit(X_ctx_scaled)
        
        self.is_trained = True
        print("[INFO] Models trained successfully on baseline data.", flush=True)

    def score(self, json_data):
        """Computes anomaly scores.
        
        OC-SVM decision_function: larger values = normal, smaller values = anomalous.
        IsolationForest decision_function: larger values = normal, smaller values = anomalous.
        
        Returns:
            svm_score: Normalized value [0.0, 1.0] where 1.0 is normal, 0.0 is anomalous.
            if_score: Normalized value [0.0, 1.0] where 1.0 is normal, 0.0 is anomalous.
        """
        if not self.is_trained:
            raise Exception("Cannot score data: Models have not been trained yet.")
            
        bio, ctx = self.extract_features(json_data)
        
        # Scale inputs using fitted training scalers
        bio_scaled = self.biometric_scaler.transform(bio.reshape(1, -1))
        ctx_scaled = self.context_scaler.transform(ctx.reshape(1, -1))
        
        # Get raw decision function scores
        svm_raw = self.oc_svm.decision_function(bio_scaled)[0]
        if_raw = self.i_forest.decision_function(ctx_scaled)[0]
        
        # Normalize decision scores into [0, 1] range
        # OC-SVM decision function typically ranges from negative (outlier) to positive (inlier)
        # We apply sigmoid or soft-clipping normalization
        svm_score = 1.0 / (1.0 + np.exp(-5.0 * svm_raw))
        
        # Isolation Forest decision score ranges from roughly -0.5 to +0.5
        # Normalize to [0, 1] using standard Min-Max mapping
        if_score = 1.0 / (1.0 + np.exp(-8.0 * if_raw))
        
        return float(svm_score), float(if_score)

    def save(self, filepath="ml_engine/trained_models.pkl"):
        """Saves the models and scalers together as a single serialized pickle file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        data_to_save = {
            "oc_svm": self.oc_svm,
            "i_forest": self.i_forest,
            "biometric_scaler": self.biometric_scaler,
            "context_scaler": self.context_scaler,
            "is_trained": self.is_trained
        }
        with open(filepath, "wb") as f:
            pickle.dump(data_to_save, f)
        print(f"[INFO] Saved model checkpoint to '{filepath}'", flush=True)

    def load(self, filepath="ml_engine/trained_models.pkl"):
        """Loads models and scalers from a pickle file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found at '{filepath}'")
            
        with open(filepath, "rb") as f:
            data = pickle.load(f)
            
        self.oc_svm = data["oc_svm"]
        self.i_forest = data["i_forest"]
        self.biometric_scaler = data["biometric_scaler"]
        self.context_scaler = data["context_scaler"]
        self.is_trained = data["is_trained"]
        print(f"[INFO] Loaded model checkpoint from '{filepath}'", flush=True)
