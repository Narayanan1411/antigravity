# app.py (Hardware ML Evaluation)

from collections import deque
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
import joblib
import os

SEQ_LEN = 30
FEATURE_SIZE = 11
# Absolute path so models persist regardless of working directory
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models")
os.makedirs(MODEL_DIR, exist_ok=True)

device_buffers = {}
device_models = {}
device_scalers = {}
device_thresholds = {}

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_size, hidden_size=64):
        super().__init__()
        self.encoder = nn.LSTM(input_size=input_size, hidden_size=hidden_size, batch_first=True)
        self.decoder = nn.LSTM(input_size=hidden_size, hidden_size=input_size, batch_first=True)

    def forward(self, x):
        encoded, (hidden, cell) = self.encoder(x)
        repeated = hidden.repeat(x.shape[1], 1, 1).permute(1, 0, 2)
        decoded, _ = self.decoder(repeated)
        return decoded

def get_model_path(device_id):
    return f"{MODEL_DIR}/{device_id}_hw.pt"

def get_scaler_path(device_id):
    return f"{MODEL_DIR}/{device_id}_hw_scaler.pkl"

def create_new_model():
    return LSTMAutoencoder(FEATURE_SIZE)

def save_model(device_id, model, scaler):
    torch.save(model.state_dict(), get_model_path(device_id))
    joblib.dump(scaler, get_scaler_path(device_id))

def load_model(device_id):
    model_path = get_model_path(device_id)
    scaler_path = get_scaler_path(device_id)
    if not os.path.exists(model_path):
        return None, None
    model = create_new_model()
    model.load_state_dict(torch.load(model_path))
    scaler = joblib.load(scaler_path)
    model.eval()
    return model, scaler

def train_device_model(device_id, sequence):
    X = np.array([sequence])
    scaler = StandardScaler()
    
    X_reshaped = X.reshape(-1, FEATURE_SIZE)
    scaler.fit(X_reshaped)
    X_scaled = scaler.transform(X_reshaped).reshape(X.shape)
    
    X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
    model = create_new_model()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.MSELoss()
    
    model.train()
    for epoch in range(20):
        optimizer.zero_grad()
        output = model(X_tensor)
        loss = criterion(output, X_tensor)
        loss.backward()
        optimizer.step()
        
    model.eval()
    with torch.no_grad():
        recon = model(X_tensor)
        errors = torch.mean((recon - X_tensor) ** 2, dim=(1, 2)).numpy()
        
    threshold = errors.mean() + 3 * errors.std() + 0.1
    
    device_thresholds[device_id] = threshold
    device_models[device_id] = model
    device_scalers[device_id] = scaler
    
    save_model(device_id, model, scaler)
    print(f"[HW-ML] Trained device {device_id} threshold: {threshold:.4f}")

def detect_anomaly(device_id, sequence):
    model = device_models.get(device_id)
    scaler = device_scalers.get(device_id)
    
    if model is None:
        return {"status": "learning"}
        
    X = np.array([sequence])
    X_scaled = scaler.transform(X.reshape(-1, FEATURE_SIZE)).reshape(X.shape)
    X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
    
    with torch.no_grad():
        recon = model(X_tensor)
        error = torch.mean((recon - X_tensor) ** 2).item()
        
    threshold = device_thresholds[device_id]
    return {
        "anomaly": error > threshold,
        "score": float(error),
        "threshold": float(threshold)
    }
