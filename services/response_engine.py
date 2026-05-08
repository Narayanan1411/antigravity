"""
Guardient Response Engine
=========================
Consumes: security_actions
Publishes: response_actions
Executes automated containment actions triggered by the Decision Engine.
"""

from __future__ import annotations
import sys
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.consumer import BaseConsumer
from pipeline.producer import publish_event
from pipeline.topics import SECURITY_ACTIONS, RESPONSE_ACTIONS
from db.db import insert_response_action, init_schema
from utils.email_alert import send_soc_alert

class ResponseEngine(BaseConsumer):
    topic = SECURITY_ACTIONS
    group_id = "response-engine-v1"
    service_name = "ResponseEngine"

    def __init__(self):
        super().__init__()
        # Cooldown map: device_id -> timestamp (to prevent email spam)
        self.email_cooldowns = {}
        self.COOLDOWN_SECONDS = 300 # 5 minutes

    def process(self, event: dict):
        trust = float(event.get("trust_score", 100.0))
        device_id = event.get("device_id", "unknown")
        
        # We only execute hard containment actions.
        # "allow", "monitor", and "require_mfa" are informational or handled elsewhere.
        action = event.get("action", "monitor")
        if action in ("allow", "monitor", "require_mfa"):
            return
            
        action_id = f"RSP-{device_id[:8]}-{uuid.uuid4().hex[:6]}"
        now_utc = datetime.now(timezone.utc).isoformat() # Renamed to avoid conflict with time.time()
        
        resp_event = {
            "action_id": action_id,
            "device_id": device_id,
            "trust_score": trust,
            "action": action,
            "triggered_at": now_utc
        }
        
        try:
            # Here is where real API calls to Ansible/k8s/firewalls would happen
            # Example:
            # if action == "isolate_vlan": isolate_switch_port(device_id)
            
            print(f"[RE] Executing: {action} on {device_id} (trust: {trust})")

            insert_response_action(action_id, device_id, trust, action)
            publish_event(RESPONSE_ACTIONS, resp_event)
            print(f"[Response] 🔴 Executed containment: {action:15s} | dev={device_id[:16]} | trust={trust:.1f}")

            # Trigger SMTP Alert if trust score drops critically (<30)
            # Check cooldown to prevent flooding
            if trust < 30:
                current_time = time.time()
                last_alerted = self.email_cooldowns.get(device_id, 0)
                if (current_time - last_alerted) > self.COOLDOWN_SECONDS:
                    print(f"[RE] Trust < 30 detected for {device_id}. Triggering SOC Email Alert...")
                    # We don't have the exact attack_type in the security_action payload, 
                    # but we can pass unknown or extract it if it was nested.
                    send_soc_alert(
                        device_id=device_id,
                        action=action,
                        trust_score=trust,
                        attack_type="Multiple anomalies detected"
                    )
                    self.email_cooldowns[device_id] = current_time
                else:
                    print(f"[RE] Email alert on cooldown for {device_id}")

        except Exception as exc:
            print(f"[Response] Failed to record action or send alert: {exc}")

if __name__ == "__main__":
    init_schema()
    print("=" * 60)
    print("  Guardient Response Engine (Containment Executor)")
    print("=" * 60)
    print("  Consuming: security_actions")
    print("  Publishing: response_actions")
    print("=" * 60 + "\n")
    ResponseEngine().run()
