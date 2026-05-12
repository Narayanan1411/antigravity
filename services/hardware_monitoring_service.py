"""
Guardient Hardware Monitoring Service
======================================
Polls local hardware metrics and scores them using the LSTM model in hardware/.
Publishes directly to RAW_EVENTS so the Risk/Trust engines can pick it up.
"""

import sys
import time
import uuid
import threading
from datetime import datetime, timezone
from pathlib import Path
import traceback

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
# Hardware ML module lives in poc Guardient/hardware/ (co-located with the project)
sys.path.insert(0, str(ROOT / "hardware"))

from pipeline.producer import publish_event
from pipeline.topics import RAW_EVENTS
import db.db as _db

# Import the user's hardware modules natively
try:
    from collector import collect
    from features import compute_and_reset
    from app import (
        SEQ_LEN,
        device_buffers,
        device_models,
        train_device_model,
        detect_anomaly,
        load_model
    )
    ML_ENABLED = True
except ImportError as e:
    print(f"[Hardware] ML integration disabled: {e}")
    ML_ENABLED = False

class HardwareMonitoringService:
    def __init__(self):
        self.running = False
        import uuid
        self.mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
        self.device_id = f"dev_{self.mac.replace(':', '')}"

    def start(self):
        print("[Hardware] Starting Hardware Monitoring Service...")
        self.running = True
        _db.set_device_source(self.device_id, "hypervisor")
        
        if ML_ENABLED:
            print("[Hardware] Loading existing ML models if any...")
            if self.device_id not in device_buffers:
                from collections import deque
                device_buffers[self.device_id] = deque(maxlen=SEQ_LEN)
            
            model, scaler = load_model(self.device_id)
            if model and scaler:
                from app import device_models, device_scalers, device_thresholds
                device_models[self.device_id] = model
                device_scalers[self.device_id] = scaler
                # We assume a default threshold if loaded from disk without metadata
                device_thresholds[self.device_id] = 0.5 
                print(f"[Hardware] Loaded ML model for {self.device_id}")

        # Start the native collector loop in background
        print("[Hardware] Starting underlying collector thread...")
        threading.Thread(target=collect, daemon=True).start()

        # Polling loop
        print("[Hardware] Service started. Monitoring local hardware metrics...")
        try:
            while self.running:
                time.sleep(5)
                self.process_metrics()
        except KeyboardInterrupt:
            print("[Hardware] Shutting down...")
            self.running = False

    def process_metrics(self):
        try:
            metrics = compute_and_reset()
            # If all zeroes, wait for collector
            if sum(metrics.values()) == 0:
                return

            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "device_id": self.device_id,
                "source": "hardware",
                "collector": "hardware_lstm",
                "features": metrics,
                "device_type": "server"
            }

            if ML_ENABLED:
                feature_keys = [
                    "cpu_avg", "cpu_spike", "memory_percent", "memory_spike",
                    "load_avg_delta", "disk_io_rate", "disk_io_spike",
                    "process_count", "new_process_rate", "bytes_out_server", "bytes_in_server"
                ]
                vector = [float(metrics.get(k, 0)) for k in feature_keys]
                
                device_buffers[self.device_id].append(vector)
                
                if len(device_buffers[self.device_id]) < SEQ_LEN:
                    # Collecting data
                    pass
                elif self.device_id not in device_models:
                    # Train model
                    seq = list(device_buffers[self.device_id])
                    train_device_model(self.device_id, seq)
                else:
                    # Detect anomaly
                    seq = list(device_buffers[self.device_id])
                    ml_result = detect_anomaly(self.device_id, seq)
                    if "anomaly" in ml_result:
                        event["ml_anomaly_score"] = ml_result["score"]
                        event["ml_is_anomaly"] = ml_result["anomaly"]

            print(f"[Hardware] Publishing event | CPU: {metrics.get('cpu_avg',0):.1f}% | Anomaly: {event.get('ml_anomaly_score', 0):.4f}")
            publish_event(RAW_EVENTS, event)

        except Exception as e:
            print(f"[Hardware] Error processing metrics: {e}")
            traceback.print_exc()

if __name__ == "__main__":
    service = HardwareMonitoringService()
    service.start()
