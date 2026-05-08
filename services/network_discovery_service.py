"""
Guardient Network Discovery Service
====================================
Uses real network sniffing from new_work to collect device data.
Integrates with the Guardient pipeline for real-time device discovery.

Features:
- Real network flow capture using tshark
- Device detection and registration
- User authentication prompts for new devices
- Consistent random device type mapping
- Database updates for new devices
"""

from __future__ import annotations
import sys
import os
import json
import time
import threading
import subprocess
import hashlib
import random
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional
import psutil
import socket
import requests

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

ML_ENABLED = False
try:
    NEW_WORK_ROOT = ROOT.parent / "new_work"
    if NEW_WORK_ROOT.exists():
        sys.path.insert(0, str(NEW_WORK_ROOT))
        from app import (
            Flow as MLFlow,
            SEQ_LEN,
            build_feature_vector,
            device_buffers,
            device_models,
            train_device_model,
            detect_anomaly,
        )
        ML_ENABLED = True
    else:
        print(f"[Discovery] ML model directory not found: {NEW_WORK_ROOT}")
except Exception as exc:
    print(f"[Discovery] ML integration disabled: {exc}")
    ML_ENABLED = False

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics import RAW_EVENTS
from db.db import get_conn, put_conn
from api.device_resolver import resolve_device, lookup_alias, store_device_and_aliases

# Configuration
INTERFACE = "wlp1s0"  # Update this to match your wireless interface (run 'ip link show')  # Update this to match your interface
LOCAL_IP_MASK = None
flows = {}
lock = threading.Lock()

# Device type mapping for consistency
DEVICE_TYPES = ["laptop", "mobile", "iot", "server", "workstation", "router", "printer", "camera"]
device_type_cache = {}  # MAC -> device_type for consistency

# User authentication cache
authenticated_devices = set()

def get_auto_mask(iface):
    """Dynamically detects the local network prefix."""
    try:
        addr_dict = psutil.net_if_addrs()
        if iface in addr_dict:
            for snic in addr_dict[iface]:
                if snic.family == socket.AF_INET:
                    return ".".join(snic.address.split(".")[:3]) + "."
    except Exception as e:
        print(f"[Discovery] Mask detection failed: {e}")
    return "192.168.1."

def get_consistent_device_type(mac: str) -> str:
    """Get consistent random device type for a MAC address."""
    if mac in device_type_cache:
        return device_type_cache[mac]

    # Use MAC as seed for consistent randomness
    seed = int(hashlib.md5(mac.encode()).hexdigest(), 16)
    random.seed(seed)
    device_type = random.choice(DEVICE_TYPES)
    device_type_cache[mac] = device_type
    return device_type

def prompt_user_authentication(device_info: dict) -> bool:
    """Prompt user for device authentication. For now, auto-approve."""
    # TODO: Implement actual user prompt (could use a web interface or CLI)
    # For POC, we'll auto-approve all devices
    print(f"[Discovery] New device detected: {device_info}")
    print(f"[Discovery] Auto-approving device for POC")
    return True

def update_device_database(device_info: dict):
    """Update database with new device information."""
    mac = device_info.get("mac_address")
    ip = device_info.get("ip")
    hostname = device_info.get("hostname", f"unknown-{mac.replace(':', '')}")

    # Generate device ID
    device_id = resolve_device({
        "mac_address": mac,
        "hostname": hostname,
        "source_ip": ip,
        "device_type": device_info.get("device_type")
    })

    # Store additional metadata
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            now = datetime.now(timezone.utc)
            cur.execute(
                """
                UPDATE devices SET
                    enrichment = enrichment || %s,
                    last_seen = %s
                WHERE device_id = %s
                """,
                (json.dumps({
                    "discovered_via": "network_sniffer",
                    "discovery_time": now.isoformat(),
                    "network_info": device_info
                }), now, device_id)
            )
        conn.commit()
        print(f"[Discovery] Updated database for device {device_id}")
    except Exception as exc:
        print(f"[Discovery] Database update error: {exc}")
        conn.rollback()
    finally:
        put_conn(conn)

def get_field(layers, field_name):
    val = layers.get(field_name)
    return val[0] if isinstance(val, list) and val else None

def parse_packet(packet):
    """Parse tshark packet data - same as new_work."""
    global LOCAL_IP_MASK
    if LOCAL_IP_MASK is None:
        LOCAL_IP_MASK = get_auto_mask(INTERFACE)

    layers = packet.get("layers", {})
    src_ip = get_field(layers, "ip_src")
    dst_ip = get_field(layers, "ip_dst")

    if not src_ip or not dst_ip:
        return

    is_src_local = src_ip.startswith(LOCAL_IP_MASK)
    is_dst_local = dst_ip.startswith(LOCAL_IP_MASK)

    if not is_src_local and not is_dst_local:
        return

    pkt_len = int(get_field(layers, "frame_len") or "0")
    src_port = get_field(layers, "tcp_srcport") or get_field(layers, "udp_srcport") or "0"
    dst_port = get_field(layers, "tcp_dstport") or get_field(layers, "udp_dstport") or "0"

    p1, p2 = (src_ip, src_port), (dst_ip, dst_port)
    flow_key = f"{p1}-{p2}" if p1 < p2 else f"{p2}-{p1}"

    with lock:
        if flow_key not in flows:
            device_ip = src_ip if is_src_local else dst_ip
            device_mac = get_field(layers, "eth_src") if is_src_local else get_field(layers, "eth_dst")

            flows[flow_key] = {
                "device_ip": device_ip,
                "remote_ip": dst_ip if is_src_local else src_ip,
                "device_mac": device_mac,
                "device_port": src_port if is_src_local else dst_port,
                "remote_port": dst_port if is_src_local else src_port,
                "bytes_sent": 0,
                "bytes_received": 0,
                "packet_count": 0,
                "dns_query": get_field(layers, "dns_qry_name"),
                "last_seen": time.time()
            }

            # Check if this is a new device
            if device_mac and device_mac not in authenticated_devices:
                device_info = {
                    "mac_address": device_mac,
                    "ip": device_ip,
                    "hostname": None,  # We don't have hostname from network
                    "device_type": get_consistent_device_type(device_mac)
                }

                if prompt_user_authentication(device_info):
                    authenticated_devices.add(device_mac)
                    update_device_database(device_info)

        f = flows[flow_key]

        if is_src_local:
            f["bytes_sent"] += pkt_len
        else:
            f["bytes_received"] += pkt_len

        f["packet_count"] += 1
        f["last_seen"] = time.time()

def process_flow_for_ml(flow_data: dict):
    """Convert a network flow to the LSTM model input and run training/detection."""
    if not ML_ENABLED:
        return None

    mac = flow_data.get("device_mac") or flow_data.get("mac_address")
    if not mac:
        return None

    try:
        ml_flow = MLFlow(
            device_ip=flow_data.get("source_ip") or flow_data.get("device_ip", ""),
            remote_ip=flow_data.get("destination_ip") or flow_data.get("remote_ip", ""),
            device_mac=mac,
            device_port=str(flow_data.get("source_port") or flow_data.get("device_port") or "0"),
            remote_port=str(flow_data.get("destination_port") or flow_data.get("remote_port") or "0"),
            bytes_sent=int(flow_data.get("bytes_sent", 0)),
            bytes_received=int(flow_data.get("bytes_received", 0)),
            packet_count=int(flow_data.get("packet_count", 0)),
            dns_query=flow_data.get("dns_query_name") or flow_data.get("dns_query"),
            last_seen=float(flow_data.get("timestamp", time.time())),
        )
    except Exception as exc:
        print(f"[Discovery] ML flow conversion failed: {exc}")
        return None

    feature_vector = build_feature_vector([ml_flow])
    device_buffers[mac].append(feature_vector)

    if len(device_buffers[mac]) < SEQ_LEN:
        print(f"[Discovery] ML collecting {len(device_buffers[mac])}/{SEQ_LEN} for {mac}")
        return None

    if mac not in device_models:
        train_device_model(mac, [list(device_buffers[mac])])
        return {"status": "model_trained", "mac": mac}

    result = detect_anomaly(mac, list(device_buffers[mac]))
    if result.get("anomaly"):
        print(f"[Discovery] ML anomaly detected for {mac}: score={result.get('score')} threshold={result.get('threshold')}")
    return result


def start_tshark():
    """Start tshark packet capture."""
    cmd = [
        "tshark", "-i", INTERFACE, "-p", "-n", "-l", "-T", "ek",
        "-e", "eth.src", "-e", "eth.dst",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len", "-e", "dns.qry.name"
    ]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    for line in process.stdout:
        if '"layers"' not in line:
            continue
        try:
            parse_packet(json.loads(line))
        except Exception as e:
            print(f"[Discovery] Parse error: {e}")
            continue

def send_network_events():
    """Send accumulated network events to the pipeline."""
    while True:
        time.sleep(30)  # Send every 30 seconds

        with lock:
            current_flows = list(flows.values())
            flows.clear()

        if not current_flows:
            continue

        for flow in current_flows:
            # Create network event in the format expected by the API
            event = {
                "flows": [{
                    "source_ip": flow["device_ip"],
                    "destination_ip": flow["remote_ip"],
                    "source_port": int(flow["device_port"]) if flow["device_port"] else 0,
                    "destination_port": int(flow["remote_port"]) if flow["remote_port"] else 0,
                    "mac_address": flow["device_mac"],
                    "hostname": None,  # We don't have hostname from network
                    "device_type": get_consistent_device_type(flow["device_mac"]),
                    "os": None,  # We don't have OS info from network
                    "dns_query_name": flow["dns_query"],
                    "tls_sni": None,
                    "bytes_sent": flow["bytes_sent"],
                    "bytes_received": flow["bytes_received"],
                    "session_duration": 30.0,  # Approximation
                    "packet_count": flow["packet_count"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }]
            }

            ml_result = process_flow_for_ml({
                "device_ip": flow["device_ip"],
                "remote_ip": flow["remote_ip"],
                "device_mac": flow["device_mac"],
                "device_port": flow["device_port"],
                "remote_port": flow["remote_port"],
                "bytes_sent": flow["bytes_sent"],
                "bytes_received": flow["bytes_received"],
                "packet_count": flow["packet_count"],
                "dns_query": flow["dns_query"],
                "timestamp": event["flows"][0]["timestamp"],
            })
            if ml_result:
                print(f"[Discovery] ML result for {flow['device_mac']}: {ml_result}")

            # Send to API
            try:
                import requests
                response = requests.post(
                    "http://localhost:8000/network/telemetry",
                    json=event,
                    headers={"x-api-key": "NET-KEY-2F4A8C1B"},
                    timeout=5
                )
                if response.status_code == 200:
                    print(f"[Discovery] Sent {len(event['flows'])} network events")
                else:
                    print(f"[Discovery] API error: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[Discovery] Send error: {e}")
            except ImportError:
                print("[Discovery] Requests not available, skipping API send")

class NetworkDiscoveryService:
    """Main network discovery service."""

    def __init__(self):
        self.running = False

    def start(self):
        """Start the network discovery service."""
        print("[Discovery] Starting Network Discovery Service...")
        print(f"[Discovery] Using interface: {INTERFACE}")
        print(f"[Discovery] Local IP mask: {get_auto_mask(INTERFACE)}")

        self.running = True

        # Start tshark in background thread
        threading.Thread(target=start_tshark, daemon=True).start()

        # Start event sender in background thread
        threading.Thread(target=send_network_events, daemon=True).start()

        print("[Discovery] Service started. Monitoring network traffic...")

        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[Discovery] Shutting down...")
            self.running = False


if __name__ == "__main__":
    service = NetworkDiscoveryService()
    service.start()
