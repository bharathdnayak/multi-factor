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
    dev_tools = [
        "code.exe", "antigravity.exe", "cursor.exe", "pycharm.exe", "notepad++.exe", 
        "sublime_text.exe", "python.exe", "git.exe", "studio.exe", "language_server.exe",
        "postgres.exe", "mongod.exe", "ollama.exe", "grafana.exe", "mosquitto.exe"
    ]
    browsers = ["chrome.exe", "brave.exe", "msedge.exe", "firefox.exe", "opera.exe", "safari.exe"]
    terminals = ["cmd.exe", "powershell.exe", "windowsterminal.exe", "bash.exe", "conhost.exe", "regedit.exe", "taskmgr.exe", "processhacker.exe"]
    productivity = [
        "winword.exe", "excel.exe", "powerpnt.exe", "onenote.exe", "outlook.exe", 
        "acrodist.exe", "acrobat.exe", "spotify.exe", "spotifylauncher.exe", "epicgameslauncher.exe", 
        "discord.exe", "slack.exe", "notion.exe", "armourycrate.exe", "lghub.exe"
    ]
    
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
            "mouse_jerk_mean", "mouse_straightness_mean",
            "app_dwell_mean", "app_flight_mean", "app_backspace_ratio"
        ]
        self.context_feature_keys = [
            "hour_sin", "hour_cos", "cpu_usage", "ram_usage_mb", "app_hash",
            "app_special_ratio", "app_pause_ratio", "app_scroll_count"
        ]

        # ML Models and Preprocessing Scalers
        self.oc_svm = OneClassSVM(kernel="rbf", gamma=0.35, nu=0.03)
        self.i_forest = IsolationForest(contamination=0.02, random_state=42)
        
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
        
        # Biometrics vector with fallback to global metrics if app-specific metrics are absent
        dwell_fallback = json_data.get("dwell_mean", 0.0)
        flight_fallback = json_data.get("flight_mean", 0.0)
        
        biometrics = []
        for key in self.biometric_feature_keys:
            if key == "app_dwell_mean":
                val = json_data.get("app_dwell_mean", dwell_fallback)
            elif key == "app_flight_mean":
                val = json_data.get("app_flight_mean", flight_fallback)
            elif key == "mouse_velocity_mean":
                val = min(float(json_data.get(key, 0.0)), 3000.0)
            elif key == "mouse_acceleration_mean":
                raw = float(json_data.get(key, 0.0))
                val = float(np.sign(raw) * np.log1p(abs(raw)))
            elif key == "mouse_jerk_mean":
                raw = float(json_data.get(key, 0.0))
                val = float(np.sign(raw) * np.log1p(abs(raw)))
            elif key == "mouse_straightness_mean":
                val = min(max(float(json_data.get(key, 0.8)), 0.0), 1.0)
            elif key == "app_backspace_ratio":
                val = min(max(float(json_data.get(key, 0.0)), 0.0), 1.0)
            else:
                val = float(json_data.get(key, 0.0))
            biometrics.append(float(val))
            
        # Context vector with cyclical hour encoding: sin(2*pi*hour/24) and cos(2*pi*hour/24)
        hour = float(json_data.get("hour_of_day", 12.0))
        hour_sin = float(json_data.get("hour_sin", np.sin(2.0 * np.pi * hour / 24.0)))
        hour_cos = float(json_data.get("hour_cos", np.cos(2.0 * np.pi * hour / 24.0)))
        
        context = []
        for key in self.context_feature_keys:
            if key == "hour_sin":
                context.append(hour_sin)
            elif key == "hour_cos":
                context.append(hour_cos)
            elif key == "app_hash":
                context.append(float(app_hash))
            elif key in ("app_special_ratio", "app_pause_ratio"):
                context.append(float(np.clip(json_data.get(key, 0.0), 0.0, 1.0)))
            else:
                context.append(float(json_data.get(key, 0.0)))
                
        return np.array(biometrics), np.array(context)

    def train(self, all_rows):
        """Trains both OneClassSVM (on active biometrics) and IsolationForest (on context)."""
        # Train biometrics on active interaction rows to prevent idle zeroes from contaminating support vectors
        active_rows = [r for r in all_rows if r.get("keystroke_count", 0) > 0 or r.get("mouse_events", 0) > 10]
        if len(active_rows) < 30:
            active_rows = all_rows
            
        X_bio = [self.extract_features(r)[0] for r in active_rows]
        X_ctx = [self.extract_features(r)[1] for r in all_rows]
            
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
        
        # 4th percentile for biometrics
        self.biometric_threshold = float(np.percentile(bio_decisions, 4))
        # 3rd percentile for context
        self.context_threshold = float(np.percentile(ctx_decisions, 3))
        
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
        
        ctx_scaled = self.context_scaler.transform(ctx.reshape(1, -1))
        if_raw = self.i_forest.decision_function(ctx_scaled)[0]
        if_score = 1.0 / (1.0 + np.exp(-35.0 * (if_raw - self.context_threshold)))
        
        # If no keys were pressed in this window, biometrics are idle (normal non-intrusion state)
        keys = json_data.get("keystroke_count", 0)
        mouse_events = json_data.get("mouse_events", 0)
        dwell_val = json_data.get("dwell_mean", 0.0)
        
        if (keys == 0 and dwell_val == 0.0):
            svm_score = 0.98
        else:
            bio_scaled = self.biometric_scaler.transform(bio.reshape(1, -1))
            svm_raw = self.oc_svm.decision_function(bio_scaled)[0]
            svm_score = 1.0 / (1.0 + np.exp(-18.0 * (svm_raw - self.biometric_threshold)))
        
        return float(svm_score), float(if_score)

    def save(self, filepath=None):
        """Saves the models, scalers, and thresholds together as a single serialized pickle file."""
        if filepath is None:
            filepath = os.path.join(PROJECT_ROOT, "ml_engine", "trained_models.pkl")
        elif not os.path.isabs(filepath):
            filepath = os.path.join(PROJECT_ROOT, filepath)
        filepath = os.path.normpath(filepath)

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
        filepath = os.path.normpath(filepath)

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
