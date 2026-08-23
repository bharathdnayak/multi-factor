import os
import sys
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd

class KeystrokeCNN(nn.Module):
    """
    1D-CNN Network for Deep SVDD (Support Vector Data Description).
    Maps a sequence of shape (2, 30) representing (dwell_time, flight_time)
    over 30 keys into a compact 16-dimensional embedding space.
    """
    def __init__(self):
        super(KeystrokeCNN, self).__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(in_channels=2, out_channels=16, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2), # output shape: (16, 15)
            
            nn.Conv1d(in_channels=16, out_channels=32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.MaxPool1d(kernel_size=2), # output shape: (32, 7)
        )
        self.fc = nn.Sequential(
            nn.Linear(32 * 7, 64),
            nn.ReLU(),
            nn.Linear(64, 16) # 16-d representation
        )

    def forward(self, x):
        # Input shape: (Batch, 2, 30)
        x = self.conv(x)
        x = x.view(x.size(0), -1) # Flatten
        x = self.fc(x)
        return x

class DeepSVDDDetector:
    """
    Wrapper class to manage training and inference of the Deep SVDD model.
    """
    def __init__(self, models_dir=None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
            
        self.models_dir = models_dir
        self.model_path = os.path.join(models_dir, "sequence_model.pt")
        self.meta_path = os.path.join(models_dir, "sequence_meta.json")
        
        self.model = KeystrokeCNN()
        self.center = None
        self.radius = 0.0
        
        if os.path.exists(self.model_path) and os.path.exists(self.meta_path):
            self.load_model()

    def load_model(self):
        try:
            self.model.load_state_dict(torch.load(self.model_path, map_location=torch.device('cpu')))
            self.model.eval()
            
            import json
            with open(self.meta_path, 'r') as f:
                meta = json.load(f)
                self.center = torch.tensor(meta["center"])
                self.radius = meta["radius"]
        except Exception as e:
            print(f"Error loading sequence model: {e}", file=sys.stderr)

    def extract_raw_sequences(self, filepath, seq_len=30):
        """
        Loads keystrokes.csv and parses it into overlapping sequences of shape (2, seq_len).
        """
        if not os.path.exists(filepath):
            return np.array([])
            
        df = pd.read_csv(filepath).sort_values(by="timestamp")
        press_times = {}
        dwells = []
        flights = []
        last_release = None
        
        for _, row in df.iterrows():
            t = row["timestamp"]
            key = row["key"]
            etype = row["event_type"]
            
            if etype == "press":
                press_times[key] = t
                if last_release is not None:
                    flights.append(t - last_release)
                else:
                    flights.append(0.15) # Default start flight
            elif etype == "release":
                if key in press_times:
                    dwells.append(t - press_times[key])
                    last_release = t
                    del press_times[key]
                    
        min_len = min(len(dwells), len(flights))
        dwells = dwells[:min_len]
        flights = flights[:min_len]
        
        if min_len < seq_len:
            return np.array([])
            
        sequences = []
        for i in range(min_len - seq_len + 1):
            seq = np.vstack([dwells[i:i+seq_len], flights[i:i+seq_len]])
            sequences.append(seq)
            
        return np.array(sequences)

    def train(self, keystroke_csv, epochs=15, lr=0.001):
        """
        Trains the Deep SVDD network: maps normal sequences close to an embedding center.
        """
        sequences = self.extract_raw_sequences(keystroke_csv)
        if len(sequences) == 0:
            print("Warning: Insufficient keystrokes to train sequence model. Needs >=30 keys.")
            return False
            
        X = torch.tensor(sequences, dtype=torch.float32)
        
        self.model.train()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        
        with torch.no_grad():
            outputs = self.model(X)
            center = torch.mean(outputs, dim=0)
            center[abs(center) < 0.1] = 0.1
            
        print(f"Training Deep SVDD 1D-CNN with {len(X)} sequences...")
        
        for epoch in range(epochs):
            optimizer.zero_grad()
            outputs = self.model(X)
            loss = torch.mean(torch.sum((outputs - center) ** 2, dim=1))
            loss.backward()
            optimizer.step()
            
        self.model.eval()
        with torch.no_grad():
            final_outputs = self.model(X)
            dists = torch.sqrt(torch.sum((final_outputs - center) ** 2, dim=1))
            radius = float(np.percentile(dists.numpy(), 95))
            
        os.makedirs(self.models_dir, exist_ok=True)
        torch.save(self.model.state_dict(), self.model_path)
        
        import json
        with open(self.meta_path, 'w') as f:
            json.dump({
                "center": center.tolist(),
                "radius": radius
            }, f, indent=4)
            
        self.center = center
        self.radius = radius
        print("Deep SVDD 1D-CNN sequence model saved successfully!")
        return True

    def predict_score(self, dwell_sequence, flight_sequence):
        """
        Calculates biometric risk for a single sequence of length 30.
        Returns a normalized [0.0, 1.0] score.
        """
        if self.center is None or self.model is None:
            return 0.0
            
        try:
            seq = np.vstack([dwell_sequence, flight_sequence])
            X = torch.tensor(seq, dtype=torch.float32).unsqueeze(0)
            
            self.model.eval()
            with torch.no_grad():
                embedding = self.model(X)
                dist = torch.sqrt(torch.sum((embedding - self.center) ** 2, dim=1)).item()
                
            risk = 1.0 / (1.0 + np.exp(-40.0 * (dist - self.radius * 1.25)))
            return float(np.clip(risk, 0.0, 1.0))
        except Exception:
            return 0.0
