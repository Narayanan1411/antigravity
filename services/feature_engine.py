"""
Guardient Feature Engine
Consumes: enriched_events
Publishes: feature_stream

Converts enriched telemetry → numeric behavioral features.
Outputs a unified feature vector for downstream ML/rules.
"""

from __future__ import annotations
import sys
import math
import uuid
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import ENRICHED_EVENTS, FEATURE_STREAM
from db.db import insert_features
from services.device_profiles import compute_profile_distance, archetype_for_type


def dns_entropy(domain: str) -> float:
    domain = domain or ""
    if not domain:
        return 0.0
    probs = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum([p * math.log(p) / math.log(2.0) for p in probs])

def port_risk(port) -> int:
    risky_ports = {22, 23, 3389, 445, 4444, 6667}
    try:
        return 1 if int(port) in risky_ports else 0
    except (ValueError, TypeError):
        return 0




def extract_features(event: dict) -> dict:
    """Extract unified numerical features from any event."""
    features = {}

    # Strictly numeric features for ML tracking
    features["dns_entropy"] = round(dns_entropy(event.get("dns_query", "")), 4)
    features["bytes_total"] = float(event.get("bytes_total", 0))
    features["port_risk"] = port_risk(event.get("destination_port"))
    features["login_failure"] = int(event.get("login_failure_flag", 0))
    
    # Map from the device_class string
    features["iot_device_flag"] = 1 if event.get("device_class") == "iot" else 0
    
    features["after_hours"] = event.get("after_hours", 0)

    # Extra features that our existing rules in ml_monitor / trust_engine rely on:
    features["dns_query_length"] = len(event.get("dns_query") or "")
    features["session_duration"] = float(event.get("session_duration", 0))
    features["has_tls"] = 1.0 if event.get("tls_sni") else 0.0
    features["dest_port_risk"] = features["port_risk"]
    features["failure_count"] = features["login_failure"]
    features["mfa_enabled"] = 1.0 if str(event.get("mfa_status")).lower() == "enabled" else 0.0
    features["legacy_auth"] = 1.0 if str(event.get("auth_type")).lower() in ("ntlm", "basic", "password") else 0.0
    features["after_hours_login"] = features["after_hours"]
    features["large_clock_skew"] = 0.0 # From temporal
    
    # Hardware features
    pburst = event.get("raw", {}).get("power_on_burst_pattern", {})
    features["cpu_percent"] = float(pburst.get("cpu_percent", 0))
    features["memory_percent"] = float(pburst.get("memory_percent", 0))
    features["is_vm"] = 1.0 if event.get("raw", {}).get("vm_uuid") else 0.0
    
    # Check boolean risk flags directly from the flat schema if they exist, or raw
    raw = event.get("raw", {})
    features["privilege_change"] = 1.0 if raw.get("privilege_change_event") else 0.0
    features["group_change"] = 1.0 if raw.get("group_membership_change") else 0.0
    features["sudo_event"] = 1.0 if str(event.get("auth_type")).lower() == "sudo" else 0.0
    features["key_created"] = 1.0 if raw.get("risk_flags", {}).get("key_created") else 0.0
    features["snapshot_created"] = 1.0 if raw.get("risk_flags", {}).get("data_exfil_risk") else 0.0
    features["firewall_changed"] = 1.0 if raw.get("risk_flags", {}).get("lateral_exposure") else 0.0
    features["access_denied"] = 1.0 if not raw.get("access_granted", True) else 0.0
    features["iam_changed"] = 1.0 if event.get("event_type") == "iam_policy_change" else 0.0
    features["high_risk_event"] = 1.0 if raw.get("risk_level") == "high" else 0.0
    
    return features


class FeatureEngine(BaseConsumer):
    topic        = ENRICHED_EVENTS
    group_id     = "feature-engine"
    service_name = "FeatureEngine"

    def process(self, event: dict):
        collector   = event.get("collector", "unknown")
        device_type = event.get("device_class") or event.get("device_type") or "unknown"
        
        # Extract numerical features
        features = extract_features(event)
        
        # --- Behavioral Archetype Profiling ---
        arch_dev  = compute_profile_distance(features, device_type)
        archetype = archetype_for_type(device_type)
        features["archetype_deviation"] = arch_dev
        
        # Package for downstream
        feature_event = {
            "event_id":   event.get("event_id") or str(uuid.uuid4()),
            "timestamp":  event.get("timestamp"),
            "device_id":  event.get("device_id"),
            "source":     collector,
            "metadata": {
                "collector":        collector,
                "event_type":       event.get("event_type"),
                "ip":               event.get("source_ip"),
                "device_archetype": archetype,
            },
            "enrichment": {"geo": event.get("geo_destination"), "asn": event.get("destination_asn")},
            "features":   features,
            "ml_anomaly_score": event.get("ml_anomaly_score"),
            "ml_is_anomaly": event.get("ml_is_anomaly"),
        }
        
        publish_event(FEATURE_STREAM, feature_event)
        
        # DB
        try:
            insert_features(feature_event)
        except Exception as exc:
            pass
            
        print(f"[Features] {collector}/{event.get('event_type')} | "
              f"device={event.get('device_id')} | extracted {len(features)} features")


if __name__ == "__main__":
    FeatureEngine().run()
