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
from collections import deque
import psutil
import socket
import requests

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

ML_ENABLED = False
device_buffers = {}  # Will be defaultdict from imported app.py
device_models = {}
train_device_model = None
detect_anomaly = None
build_feature_vector = None
SEQ_LEN = 30

try:
    NEW_WORK_ROOT = ROOT.parent / "new_work"
    if NEW_WORK_ROOT.exists():
        sys.path.insert(0, str(NEW_WORK_ROOT))
        from app import (
            Flow as MLFlow,
            SEQ_LEN,
            build_feature_vector,
            device_buffers as imported_device_buffers,
            device_models as imported_device_models,
            train_device_model as imported_train_device_model,
            detect_anomaly as imported_detect_anomaly,
        )
        # Use the imported defaultdict directly
        device_buffers = imported_device_buffers
        device_models = imported_device_models
        train_device_model = imported_train_device_model
        detect_anomaly = imported_detect_anomaly
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
import db.db as _db
from api.device_resolver import resolve_device, lookup_alias, store_device_and_aliases

# Configuration
INTERFACE = os.getenv("NETWORK_INTERFACE", None)
DEFAULT_INTERFACES = ("wlp1s0", "eth0", "enp0s3", "enp0s8", "enp1s0", "en0")
# LOCAL_IP_PREFIXES is a set of subnet prefixes refreshed dynamically so
# hotspot subnet changes (e.g. 10.42.0.x appearing after 192.168.x.x) are
# picked up without restarting the service.
LOCAL_IP_PREFIXES: set[str] = set()
LOCAL_IP_MASK = None  # kept for legacy callers, set from first prefix
flows = {}
lock = threading.Lock()

# ARP scanner state — MACs already seen so we only act on new ones
arp_seen_macs: set[str] = set()
arp_lock = threading.Lock()

# New-device counter: incremented only for MACs that were NOT in the DB at
# startup — i.e., genuinely first-ever detections in this run.  Seeded MACs
# (already in DB) do NOT count.  This lets the frontend distinguish "ARP
# scanner found new hardware" from "scanner saw a known device again".
_new_devices_found: int = 0
_new_devices_lock = threading.Lock()

# Device type mapping for consistency
DEVICE_TYPES = ["laptop", "mobile", "iot", "server", "workstation", "router", "printer", "camera"]
device_type_cache = {}  # MAC -> device_type for consistency

# User authentication cache
authenticated_devices = set()

def ensure_device_buffer(mac: str):
    """Ensure device buffer exists for this MAC address."""
    # device_buffers is a defaultdict, so just accessing it creates the buffer
    if ML_ENABLED:
        _ = device_buffers[mac]  # Access to trigger defaultdict creation
        print(f"[Discovery] Initialized buffer for device {mac}")

def detect_interface() -> str:
    """Find the best local network interface to capture traffic from."""
    if INTERFACE:
        return INTERFACE

    interfaces = psutil.net_if_addrs()
    for candidate in DEFAULT_INTERFACES:
        if candidate in interfaces:
            return candidate

    for iface, addrs in interfaces.items():
        if iface.startswith(("lo", "docker", "veth", "br-", "virbr", "tun", "tap")):
            continue
        if any(addr.family == socket.AF_INET for addr in addrs):
            return iface

    return ""


def refresh_local_prefixes() -> set[str]:
    """
    Collect subnet prefixes from ALL non-loopback/docker interfaces and
    update the global LOCAL_IP_PREFIXES set.  Call this periodically so
    hotspot subnet changes are picked up without a restart.
    """
    global LOCAL_IP_PREFIXES, LOCAL_IP_MASK
    prefixes: set[str] = set()
    skip = ("lo", "docker", "veth", "br-", "virbr", "tun", "tap")
    for iface, addrs in psutil.net_if_addrs().items():
        if any(iface.startswith(s) for s in skip):
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            octets = addr.address.split(".")
            if len(octets) != 4:
                continue
            if octets[0] == "10":
                prefixes.add(f"10.{octets[1]}.")   # /16-ish coverage
            elif octets[0] == "192" and octets[1] == "168":
                prefixes.add("192.168.")
            else:
                prefixes.add(f"{octets[0]}.{octets[1]}.")
    LOCAL_IP_PREFIXES = prefixes
    LOCAL_IP_MASK = next(iter(prefixes), "")      # legacy compat
    return prefixes


def get_auto_mask(iface):
    """Dynamically detects the local network prefix (legacy helper)."""
    if not iface:
        return ""
    return next(iter(refresh_local_prefixes()), "")


# Auto-detect the capture interface when not explicitly configured
INTERFACE = detect_interface()


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

def _is_local(ip: str) -> bool:
    """Check if an IP belongs to any known local subnet prefix."""
    if not LOCAL_IP_PREFIXES:
        refresh_local_prefixes()
    return any(ip.startswith(p) for p in LOCAL_IP_PREFIXES)


def parse_packet(packet):
    """Parse tshark packet data."""
    layers = packet.get("layers", {})
    src_ip = get_field(layers, "ip_src")
    dst_ip = get_field(layers, "ip_dst")

    if not src_ip or not dst_ip:
        return

    is_src_local = _is_local(src_ip)
    is_dst_local = _is_local(dst_ip)

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
                    ensure_device_buffer(device_mac)
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
    if not ML_ENABLED or not build_feature_vector:
        return None

    mac = flow_data.get("device_mac") or flow_data.get("mac_address")
    if not mac:
        return None

    # Ensure buffer exists for this device
    ensure_device_buffer(mac)
    
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

    try:
        feature_vector = build_feature_vector([ml_flow])
        device_buffers[mac].append(feature_vector)
    except Exception as exc:
        print(f"[Discovery] Feature extraction error: {exc}")
        return None

    if len(device_buffers[mac]) < SEQ_LEN:
        print(f"[Discovery] ML collecting {len(device_buffers[mac])}/{SEQ_LEN} for {mac}")
        return None

    if mac not in device_models:
        try:
            train_device_model(mac, list(device_buffers[mac]))
            return {"status": "model_trained", "mac": mac}
        except Exception as exc:
            print(f"[Discovery] Model training error: {exc}")
            return None

    try:
        result = detect_anomaly(mac, list(device_buffers[mac]))
        if result and result.get("anomaly"):
            print(f"[Discovery] Network anomaly detected for {mac}: score={result.get('score'):.4f} threshold={result.get('threshold'):.4f}")
        return result
    except Exception as exc:
        print(f"[Discovery] Anomaly detection error: {exc}")
        return None


def get_local_subnets(target_iface: str = "") -> list[str]:
    """
    Return CIDR strings for subnets that should be ping-swept.

    Only the hotspot/ARP-scanner interface is swept — never the internet-uplink
    interface.  Sweeping the upstream interface floods the ISP subnet with 254
    simultaneous pings, which causes routers to rate-limit or drop the connection
    and breaks internet access for every hotspot client while the app is running.

    If target_iface is given (the detected hotspot interface), only that interface's
    subnets are returned.  Otherwise all non-loopback/docker interfaces are included,
    which is the unsafe legacy behaviour — so always pass target_iface.
    """
    subnets = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            # Skip unrelated interfaces
            if iface.startswith(("lo", "docker", "veth", "br-", "virbr", "tun", "tap")):
                continue
            # Skip ethernet/USB uplink interfaces — only sweep the wifi/hotspot iface
            if target_iface and iface != target_iface:
                continue
            if not stats.get(iface, None) or not stats[iface].isup:
                continue
            for addr in addr_list:
                if addr.family != socket.AF_INET:
                    continue
                ip = addr.address
                netmask = addr.netmask or "255.255.255.0"
                bits = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                subnets.append(f"{ip}/{bits}")
    except Exception as exc:
        print(f"[ARP] Subnet detection error: {exc}")
    return subnets


def read_proc_arp() -> list[dict]:
    """
    Read ARP / neighbour table from both /proc/net/arp and `ip neigh show`.
    /proc/net/arp only contains COMPLETE entries; ip neigh also surfaces STALE
    entries (devices that were reachable but haven't been heard from recently),
    which prevents idle-but-connected devices from appearing offline.
    """
    seen: dict[str, str] = {}  # mac → ip

    # Source 1 — /proc/net/arp (flags & 0x2 = ATF_COM, entry has a valid MAC)
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip, _, flags, mac = parts[:4]
                if mac != "00:00:00:00:00:00" and int(flags, 16) & 0x2:
                    seen[mac.lower()] = ip
    except Exception as exc:
        print(f"[ARP] /proc/net/arp read error: {exc}")

    # Source 2 — `ip neigh show` (catches STALE/DELAY/PROBE states too)
    try:
        out = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            # Format: <ip> dev <iface> lladdr <mac> <state>
            parts = line.split()
            if len(parts) < 5:
                continue
            ip = parts[0]
            state = parts[-1].upper()
            # Skip entries with no valid hardware address
            if "FAILED" in state or "INCOMPLETE" in state:
                continue
            if "lladdr" in parts:
                idx = parts.index("lladdr")
                mac = parts[idx + 1].lower()
                if mac != "00:00:00:00:00:00":
                    seen.setdefault(mac, ip)  # don't overwrite proc/arp
    except Exception as exc:
        print(f"[ARP] ip neigh show error: {exc}")

    return [{"ip": ip, "mac": mac} for mac, ip in seen.items()]


def ping_sweep(subnet: str) -> None:
    """
    Ping all hosts in a subnet to populate the ARP cache.

    Thread count is intentionally low (16) to avoid flooding the wifi channel or
    triggering rate-limiting on the upstream router.  This function must ONLY be
    called for the hotspot interface's subnet — never for the internet-uplink
    interface (which would scan the ISP's LAN and disrupt internet for all clients).
    """
    import ipaddress
    import concurrent.futures
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = [str(h) for h in network.hosts()][:254]

        def _ping(ip: str) -> None:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        # 16 threads max — enough to find devices quickly without saturating wifi
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            ex.map(_ping, hosts)
    except Exception as exc:
        print(f"[ARP] Ping sweep error on {subnet}: {exc}")


def register_new_device(ip: str, mac: str) -> str:
    """Register a newly ARP-detected device in the DB and return its device_id."""
    device_id = resolve_device({
        "mac_address": mac,
        "hostname": ip,
        "source_ip": ip,
        "device_type": None,
    })
    _db.set_device_source(device_id, "network")

    # Send a minimal synthetic network event so the device enters the pipeline
    event = {
        "flows": [{
            "source_ip":        ip,
            "destination_ip":   "8.8.8.8",
            "source_port":      0,
            "destination_port": 0,
            "mac_address":      mac,
            "hostname":         None,
            "device_type":      None,
            "os":               None,
            "dns_query_name":   None,
            "tls_sni":          None,
            "bytes_sent":       0,
            "bytes_received":   0,
            "session_duration": 0.0,
            "packet_count":     0,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
        }]
    }
    try:
        import requests as _req
        _req.post(
            "http://localhost:8000/network/telemetry",
            json=event,
            headers={"x-api-key": "NET-KEY-2F4A8C1B"},
            timeout=3,
        )
        print(f"[ARP] Registered new device {mac} ({ip}) → {device_id}")
    except Exception as exc:
        print(f"[ARP] Could not send initial event for {mac}: {exc}")
    return device_id


def get_discovery_stats() -> dict:
    """Return current ARP scanner counters (called by the API transparency endpoint)."""
    with _new_devices_lock:
        new_found = _new_devices_found
    with arp_lock:
        total_tracked = len(arp_seen_macs)
    return {"new_devices_found": new_found, "total_tracked_macs": total_tracked}


def arp_scanner_loop():
    """Background thread: ARP-scan every 5 s, register new devices immediately."""
    global arp_seen_macs, _new_devices_found

    # Seed with existing DB MACs.  These are KNOWN devices — do NOT count them
    # towards _new_devices_found.  Only MACs that appear for the first time
    # (not in DB at startup) increment the counter.
    seeded_macs: set[str] = set()
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT mac_address FROM devices WHERE mac_address IS NOT NULL")
            for (mac,) in cur.fetchall():
                normalized = mac.lower()
                arp_seen_macs.add(normalized)
                seeded_macs.add(normalized)
        put_conn(conn)
        print(f"[ARP] Seeded {len(seeded_macs)} known MACs from DB")
    except Exception as exc:
        print(f"[ARP] DB seed error: {exc}")

    iface = INTERFACE or detect_interface()
    if not iface:
        print("[ARP] No interface found — ARP scanner disabled")
        return

    # Refresh subnet prefixes before first scan
    refresh_local_prefixes()
    print(f"[ARP] Scanner started on {iface}, local prefixes: {LOCAL_IP_PREFIXES}")

    # Run an immediate ping sweep so devices connected before the service started
    # are detected within the first ARP read rather than waiting 30 s.
    # Pass iface so only the hotspot subnet is swept — never the internet-uplink.
    subnets = get_local_subnets(target_iface=iface)
    print(f"[ARP] Sweeping subnets: {subnets}")
    for subnet in subnets:
        threading.Thread(target=ping_sweep, args=(subnet,), daemon=True).start()

    # Track known IPs (mac → ip) so we can keep-alive ping idle devices.
    known_ips: dict[str, str] = {}

    sweep_counter = 0
    while True:
        try:
            # Refresh subnet prefixes every cycle — hotspot subnets can appear at any time
            refresh_local_prefixes()

            # Full subnet ping sweep every 30 s (6 × 5 s ticks).
            # Only sweep the hotspot interface — not internet-uplink interfaces.
            if sweep_counter % 6 == 0 and sweep_counter > 0:
                subnets = get_local_subnets(target_iface=iface)
                for subnet in subnets:
                    threading.Thread(target=ping_sweep, args=(subnet,), daemon=True).start()

            # Read combined ARP + neighbour table (catches STALE entries too)
            results = read_proc_arp()
            current_macs = set()
            for dev in results:
                mac = dev["mac"].lower()
                ip  = dev["ip"]
                current_macs.add(mac)
                known_ips[mac] = ip  # keep most-recent IP for keep-alive

                with arp_lock:
                    if mac not in arp_seen_macs:
                        arp_seen_macs.add(mac)
                        # Only count as "new discovery" if it wasn't in the DB
                        # when the service started — seeded MACs are returning
                        # devices, not first-ever detections.
                        if mac not in seeded_macs:
                            with _new_devices_lock:
                                _new_devices_found += 1
                        print(f"[ARP] *** NEW DEVICE DETECTED: {mac} @ {ip} ***")
                        threading.Thread(
                            target=register_new_device,
                            args=(ip, mac),
                            daemon=True,
                        ).start()
                    else:
                        # Device already known — keep last_seen and last_ip fresh.
                        # last_ip is used by block/unblock to apply iptables rules.
                        _db.touch_device_last_seen(mac, ip=ip)

            # Keep-alive: ping known devices NOT currently in the neighbour table
            # so their ARP entries don't expire and they don't appear offline.
            with arp_lock:
                for mac in list(arp_seen_macs):
                    if mac not in current_macs and mac in known_ips:
                        ip = known_ips[mac]
                        threading.Thread(
                            target=lambda h=ip: subprocess.run(
                                ["ping", "-c", "1", "-W", "1", h],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                            ),
                            daemon=True,
                        ).start()

            sweep_counter += 1
        except Exception as exc:
            print(f"[ARP] Scanner error: {exc}")
        time.sleep(5)


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
        time.sleep(3)  # Send every 3 seconds for real-time updates

        with lock:
            current_flows = list(flows.values())
            flows.clear()

        if not current_flows:
            continue

        # Group flows by device mac so we don't spam the API with 50+ individual requests
        device_groups = {}
        for f in current_flows:
            mac = f["device_mac"]
            if mac not in device_groups:
                device_groups[mac] = []
            device_groups[mac].append(f)

        for mac, dev_flows in device_groups.items():
            # Send top 10 flows by bytes to keep packet size sane and avoid trust inflation
            top_flows = sorted(dev_flows, key=lambda x: x["bytes_sent"] + x["bytes_received"], reverse=True)[:10]
            
            # Combine all flows for this device into one API call
            event = {
                "flows": []
            }
            
            # Aggregate stats for the ML model input
            total_bytes_sent = 0
            total_bytes_received = 0
            total_packets = 0
            
            for flow in top_flows:
                event["flows"].append({
                    "source_ip": flow["device_ip"],
                    "destination_ip": flow["remote_ip"],
                    "source_port": int(flow["device_port"]) if flow["device_port"] else 0,
                    "destination_port": int(flow["remote_port"]) if flow["remote_port"] else 0,
                    "mac_address": flow["device_mac"],
                    "hostname": None,
                    "device_type": get_consistent_device_type(flow["device_mac"]),
                    "os": None,
                    "dns_query_name": flow["dns_query"],
                    "tls_sni": None,
                    "bytes_sent": flow["bytes_sent"],
                    "bytes_received": flow["bytes_received"],
                    "session_duration": 3.0,
                    "packet_count": flow["packet_count"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                total_bytes_sent += flow["bytes_sent"]
                total_bytes_received += flow["bytes_received"]
                total_packets += flow["packet_count"]

            # Run ML anomaly detection on the aggregate for this device
            first_flow = top_flows[0]
            ml_result = process_flow_for_ml({
                "device_ip": first_flow["device_ip"],
                "remote_ip": "aggregate", # Use aggregate for ML context
                "device_mac": mac,
                "device_port": 0,
                "remote_port": 0,
                "bytes_sent": total_bytes_sent,
                "bytes_received": total_bytes_received,
                "packet_count": total_packets,
                "dns_query": first_flow["dns_query"],
                "timestamp": event["flows"][0]["timestamp"],
            })

            if ml_result:
                event["ml_anomaly_score"] = ml_result.get("score", 0.0)
                event["ml_is_anomaly"] = ml_result.get("anomaly", False)

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

        # Start active ARP scanner — detects new hotspot devices within 5 s
        threading.Thread(target=arp_scanner_loop, daemon=True).start()

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
