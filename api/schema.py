"""
Guardient Canonical Event Schema
================================
Enforces a flat, predictable dictionary structure for all telemetry.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any


CANONICAL_FIELDS = [
    "timestamp", "device_id", "collector", "event_type", "category",
    "source_ip", "destination_ip", "source_port", "destination_port",
    "dns_query", "tls_sni", "bytes_sent", "bytes_received",
    "user_id", "login_success", "auth_type", "mfa_status",
    "mac_address", "hostname", "os", "device_type",
    "api_call", "resource", "region", "hardware_fingerprint",
    "interface", "raw", "ml_anomaly_score", "ml_is_anomaly", "source"
]


def make_event(payload: dict) -> dict:
    """Flatten and pad event with nulls for uniform structure."""
    event = {k: None for k in CANONICAL_FIELDS}
    
    # Map incoming fields securely
    for k in CANONICAL_FIELDS:
        if k in payload:
            event[k] = payload[k]

    event["timestamp"] = payload.get("timestamp") or datetime.now(tz=timezone.utc).isoformat()
    return event


# ── Collector Mapping ──────────────────────────────────────────────

def events_from_network(payload: dict) -> list[dict]:
    events = []
    for flow in payload.get("flows", []):
        src_ip = flow.get("source_ip")
        
        # network_data.py sends lists: dns_query_names: [...]
        queries = flow.get("dns_query_names") or []
        first_query = queries[0] if queries else None
        
        ev_type = "dns_query" if first_query else "network_flow"
        
        events.append(make_event({
            "collector": "network",
            "category": "network",
            "event_type": ev_type,
            "source_ip": src_ip,
            "destination_ip": flow.get("destination_ip"),
            "source_port": flow.get("source_port"),
            "destination_port": flow.get("destination_port"),
            "dns_query": first_query,
            "tls_sni": flow.get("tls_sni"),
            "bytes_sent": flow.get("bytes_sent", 0),
            "bytes_received": flow.get("bytes_received", 0),
            "mac_address": flow.get("mac_address"),
            "device_id": flow.get("device_id") or (f"dev_{str(flow.get('mac_address')).replace(':', '')}" if flow.get("mac_address") else None),
            "device_type": flow.get("device_type"),
            "hostname": flow.get("hostname"),
            "interface": flow.get("interface"),
            "raw": flow,
            "ml_anomaly_score": payload.get("ml_anomaly_score"),
            "ml_is_anomaly": payload.get("ml_is_anomaly")
        }))
    return events


def events_from_identity(payload: dict) -> list[dict]:
    events = []
    for ev in payload.get("identity_events", []):
        events.append(make_event({
            "collector": "identity",
            "category": "identity",
            "event_type": ev.get("event_type", "auth_event"),
            "timestamp": ev.get("login_timestamp"),
            "user_id": ev.get("user_id"),
            "login_success": ev.get("mfa_status") is not None,  # Rough proxy
            "auth_type": ev.get("authentication_type"),
            "mfa_status": ev.get("mfa_status"),
            "source_ip": ev.get("login_source_ip"),
            "mac_address": ev.get("mac_address"),
            "hostname": ev.get("hostname"),
            "device_type": ev.get("device_type"),
            "raw": ev
        }))
    return events


def events_from_cloud(payload: dict) -> list[dict]:
    events = []
    for snapshot in payload.get("cloud_events", []):
        for audit_ev in snapshot.get("audit_events", []):
            events.append(make_event({
                "collector": "cloud",
                "category": "cloud",
                "event_type": audit_ev.get("event_type", "api_call"),
                "timestamp": audit_ev.get("timestamp"),
                "source_ip": audit_ev.get("api_source_ip"),
                "api_call": audit_ev.get("method"),
                "resource": audit_ev.get("instance_id") or snapshot.get("project_id"),
                "hostname": audit_ev.get("instance_id"),
                "region": audit_ev.get("region"),
                "raw": audit_ev
            }))
    return events


def events_from_hardware(payload: dict) -> list[dict]:
    # Support multiple formats for MAC addresses
    mac_addr = payload.get("mac_address")
    if not mac_addr:
        macs = payload.get("mac_addresses") or payload.get("all_mac_addresses") or []
        if macs and isinstance(macs, list) and len(macs) > 0:
            m0 = macs[0]
            mac_addr = m0.get("address") or m0.get("mac")

    ip_addr = payload.get("ip_address") or payload.get("source_ip")
    if not ip_addr and "mac_addresses" in payload:
        macs = payload.get("mac_addresses")
        if macs and isinstance(macs, list) and len(macs) > 0:
            ip_addr = macs[0].get("ip")
    
    os_name = payload.get("os", {}).get("name") if isinstance(payload.get("os"), dict) else payload.get("os")
    
    return [make_event({
        "collector": "hardware",
        "category": "hardware",
        "event_type": "hardware_profile",
        "source_ip": ip_addr,
        "mac_address": mac_addr,
        "hostname": payload.get("hostname"),
        "os": os_name,
        "device_type": "laptop" if os_name and "macOS" in os_name else "unknown",
        "hardware_fingerprint": payload.get("machine_id") or payload.get("hardware_uuid") or payload.get("vm_uuid"),
        "raw": payload
    })]
