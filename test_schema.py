from kafka import KafkaConsumer
import json
import requests
import sys
from api.schema import CANONICAL_FIELDS

def run():
    print("Testing CanonicalEvent schema...", flush=True)

    # 1. Send an event
    payload = {
        "identity_events": [{
            "login_timestamp": "2026-03-05T10:00:00Z",
            "user_id": "john.doe",
            "authentication_type": "password",
            "mfa_status": "enabled",
            "login_source_ip": "192.168.1.100",
            "mac_address": "AA:BB:CC:11:22:33",
            "hostname": "john-mac",
            "device_type": "laptop",
            "raw": {"field": "value"}
        }]
    }
    
    try:
        res = requests.post("http://localhost:8000/identity/events", json=payload, headers={"x-api-key": "GUARD_ID_998877"}, timeout=5)
        print("API Response:", res.status_code, res.json(), flush=True)
    except Exception as e:
        print("API Error:", e)
        sys.exit(1)

    # 2. Consume from raw_events
    try:
        consumer = KafkaConsumer(
            "raw_events",
            bootstrap_servers="localhost:9092",
            value_deserializer=lambda x: json.loads(x.decode("utf-8")),
            auto_offset_reset="earliest",
            consumer_timeout_ms=5000
        )
        
        found = False
        for msg in consumer:
            event = msg.value
            if event.get("category") == "identity" and event.get("user_id") == "john.doe":
                found = True
                print("\n--- SCHEMA VALIDATION ---")
                
                missing = set(CANONICAL_FIELDS) - set(event.keys())
                extra = set(event.keys()) - set(CANONICAL_FIELDS)
                
                print(f"Device ID : {event.get('device_id')}")
                print(f"Missing   : {missing}")
                print(f"Extra     : {extra}")
                
                assert not missing, f"Missing keys: {missing}"
                assert not extra, f"Extra keys: {extra}"
                print("\n✅ SCHEMA PERFECTLY MATCHES CanonicalEvent!")
                break
                
        if not found:
            print("❌ Event not found in Kafka!")
            sys.exit(1)
            
    except Exception as e:
        print("Kafka Consumer Error:", e)
        sys.exit(1)

if __name__ == "__main__":
    run()
