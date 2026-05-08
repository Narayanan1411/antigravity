"""
Guardient Sandbox Executor
==========================
Generates realistic simulated attack telemetry and injects it directly
into the FEATURE_STREAM, bypassing upstream collectors for precision.
Called by Simulation Controller.
"""

import time
import uuid
import threading
from datetime import datetime, timezone

from pipeline.producer import publish_event
from pipeline.topics import FEATURE_STREAM
from db.db import update_simulation_run_status

def _build_base_event(device_id: str, source: str, event_type: str, features: dict) -> dict:
    """Helper to build a FEATURE_STREAM compatible event."""
    return {
        "event_id": f"SIM-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "device_id": device_id,
        "source": source,
        "metadata": {
            "collector": "simulation",
            "event_type": event_type,
            "ip": "10.0.0.99",
            "device_archetype": 0.0,
            "simulated": True,
        },
        "enrichment": {"geo": None, "asn": None},
        "features": features,
        "simulation": True,
    }


def _run_c2_beaconing(run_id: str, device_id: str, rounds: int, interval_sec: int):
    """
    Simulates C2 beaconing behavior:
    - High DNS entropy queries
    - Periodic HTTPS outbound to rare domains
    Increases Network risk.
    """
    print(f"[Sandbox] Starting C2 Beaconing for {device_id} ({rounds} rounds)")
    for i in range(rounds):
        if i > 0:
            time.sleep(interval_sec)
            
        # 1. DNS Query
        dns_event = _build_base_event(
            device_id=device_id,
            source="network",
            event_type="dns_query",
            features={
                 "dns_entropy": 4.8, # Anomaly!
                 "bytes_total": 85,
                 "port_risk": 0,
                 "dns_query_length": 30,
            }
        )
        publish_event(FEATURE_STREAM, dns_event)
        
        # 2. HTTPS Beacon
        http_event = _build_base_event(
            device_id=device_id,
            source="network",
            event_type="tls_flow",
            features={
                 "dns_entropy": 0.0,
                 "bytes_total": 240,
                 "port_risk": 0,
                 "session_duration": 0.5,
                 "has_tls": 1.0,
                 "dest_port_risk": 0,
            }
        )
        publish_event(FEATURE_STREAM, http_event)
        print(f"[Sandbox] Run {run_id} | C2 Beacon round {i+1}/{rounds}")

    update_simulation_run_status(run_id, "completed")
    print(f"[Sandbox] Finished run {run_id}")


def _run_credential_abuse(run_id: str, device_id: str, rounds: int, interval_sec: int):
    """
    Simulates Credential Abuse:
    - Multiple login failures followed by a success
    - Privilege escalation
    Increases Identity risk.
    """
    print(f"[Sandbox] Starting Credential Abuse for {device_id}")
    for i in range(rounds):
        if i > 0:
             time.sleep(interval_sec)
             
        event = _build_base_event(
            device_id=device_id,
            source="identity",
            event_type="login_failure",
            features={
                "login_failure": 1,
                "failure_count": 1,
                "after_hours": 1.0,
                "after_hours_login": 1.0,
                "legacy_auth": 1.0,
                "has_tls": 0.0,
            }
        )
        publish_event(FEATURE_STREAM, event)
        print(f"[Sandbox] Run {run_id} | Credential Abuse round {i+1}/{rounds}")

    # Add final privilege escalation
    time.sleep(interval_sec)
    priv_event = _build_base_event(
        device_id=device_id,
        source="identity",
        event_type="privilege_escalation",
        features={
            "login_failure": 0,
            "sudo_event": 1.0,
            "privilege_change": 1.0,
        }
    )
    publish_event(FEATURE_STREAM, priv_event)
    
    update_simulation_run_status(run_id, "completed")
    print(f"[Sandbox] Finished run {run_id}")


def _run_lateral_movement(run_id: str, device_id: str, rounds: int, interval_sec: int):
    """
    Simulates Lateral Movement:
    - Target device initiates SSH to internal server
    - Graph Correlator should pick this up
    """
    print(f"[Sandbox] Starting Lateral Movement from {device_id}")
    for i in range(rounds):
        if i > 0:
             time.sleep(interval_sec)
             
        event = _build_base_event(
            device_id=device_id,
            source="network",
            event_type="ssh_session",
            features={
                "bytes_total": 5000,
                "port_risk": 1, # port 22
                "dest_port_risk": 1,
                "is_vm": 1.0,
            }
        )
        publish_event(FEATURE_STREAM, event)
        print(f"[Sandbox] Run {run_id} | Lateral Movement round {i+1}/{rounds}")

    update_simulation_run_status(run_id, "completed")
    print(f"[Sandbox] Finished run {run_id}")


def _run_ransomware(run_id: str, device_id: str, rounds: int, interval_sec: int):
    """
    Simulates Ransomware Activity:
    - High CPU/Memory usage
    - Mass file operations / shadow copy deletion
    Increases Hardware/Visibility risk.
    """
    print(f"[Sandbox] Starting Ransomware Activity for {device_id}")
    for i in range(rounds):
        if i > 0:
             time.sleep(interval_sec)
             
        event = _build_base_event(
            device_id=device_id,
            source="hardware", # hardware/EDR
            event_type="process_anomaly",
            features={
                "cpu_percent": 99.5,
                "memory_percent": 80.0,
                "snapshot_created": 1.0, # reusing this feature flag conceptually
                "high_risk_event": 1.0,
            }
        )
        publish_event(FEATURE_STREAM, event)
        print(f"[Sandbox] Run {run_id} | Ransomware round {i+1}/{rounds}")

    update_simulation_run_status(run_id, "completed")
    print(f"[Sandbox] Finished run {run_id}")


def execute_simulation(run_id: str, device_id: str, attack_type: str, rounds: int, interval_sec: int):
    """Spawns a background thread to run the simulation."""
    runners = {
        "c2_beaconing": _run_c2_beaconing,
        "credential_abuse": _run_credential_abuse,
        "lateral_movement": _run_lateral_movement,
        "ransomware_activity": _run_ransomware,
    }
    
    runner = runners.get(attack_type)
    if not runner:
        print(f"[Sandbox] Unknown attack type: {attack_type}")
        update_simulation_run_status(run_id, "failed")
        return
        
    thread = threading.Thread(target=runner, args=(run_id, device_id, rounds, interval_sec), daemon=True)
    thread.start()

