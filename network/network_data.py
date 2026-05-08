import time
import threading
import os
import hashlib
import requests
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, DNS, Ether
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName
import geoip2.database
from dotenv import load_dotenv
import socket

load_dotenv()

LOCAL_HOSTNAME = socket.gethostname()
# JSON-safe serialiser
# Converts any bytes values to hex strings so requests.post never fails
# ==============================

import json as _json

def _json_default(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Not serialisable: {type(obj)}")

def _safe_json(obj):
    """Strip bytes from any nested dict/list recursively."""
    return _json.loads(_json.dumps(obj, default=_json_default))

# ==============================
# Config & Paths
# ==============================

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
geo_db_path     = os.path.join(BASE_DIR, "geoip", "GeoLite2-City.mmdb")
asn_db_path     = os.path.join(BASE_DIR, "geoip", "GeoLite2-ASN.mmdb")

AGGREGATION_INTERVAL = 3   # seconds between each push
FLOW_TIMEOUT         = 60  # seconds before an idle flow is expired

API_BASE    = os.getenv("TELEMETRY_API_BASE", "http://localhost:8000")
NETWORK_KEY = os.getenv("NETWORK_KEY", "NET-KEY-2F4A8C1B")

def is_local_ip(ip: str) -> bool:
    if ip.endswith(".255") or ip.endswith(".0"):
        return False
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

# ==============================
# GeoIP
# ==============================

try:
    geo_reader = geoip2.database.Reader(geo_db_path)
    asn_reader = geoip2.database.Reader(asn_db_path)
except Exception as e:
    print(f"[GEOIP] Warning: Could not load GeoIP databases: {e}")
    geo_reader = None
    asn_reader = None

def get_geoip(ip):
    if not geo_reader:
        return None
    try:
        r = geo_reader.city(ip)
        return {
            "country":   r.country.name,
            "city":      r.city.name,
            "latitude":  r.location.latitude,
            "longitude": r.location.longitude,
        }
    except Exception:
        return None

def get_asn(ip):
    if not asn_reader:
        return None
    try:
        r = asn_reader.asn(ip)
        return {"asn": r.autonomous_system_number, "org": r.autonomous_system_organization}
    except Exception:
        return None

# ==============================
# In-Memory Stores
# ==============================

flows        = {}  # keyed by 5-tuple (src, sport, dst, dport, proto)
device_stats = defaultdict(lambda: {
    "mac_address":    None,
    "bytes_sent":     0,
    "bytes_received": 0,
    "packets":        0,
    "protocols":      defaultdict(int),
    "destinations":   defaultdict(int),
    "ports":          defaultdict(int),
    "first_seen":     time.time(),
    "last_seen":      time.time(),
})
lock = threading.Lock()

# ==============================
# JA3 Fingerprint
# ==============================

def compute_ja3(packet):
    """Compute a JA3 hash from a TLS ClientHello packet."""
    try:
        if not packet.haslayer(TLSClientHello):
            return None
        hello        = packet[TLSClientHello]
        version      = str(hello.version)
        ciphers      = getattr(hello, "ciphers", [])
        ciphers_str  = "-".join(str(c) for c in ciphers if (c & 0x0f0f) != 0x0a0a)
        extensions   = getattr(hello, "ext", [])
        ext_types, curves, formats = [], [], []
        for ext in (extensions or []):
            ext_type = getattr(ext, "type", None)
            if ext_type is None or (ext_type & 0x0f0f) == 0x0a0a:
                continue
            ext_types.append(str(ext_type))
            if ext_type == 10:
                cl = getattr(ext, "groups", getattr(ext, "named_curve_list", getattr(ext, "curves", [])))
                curves = [str(c) for c in cl if (c & 0x0f0f) != 0x0a0a]
            elif ext_type == 11:
                fl = getattr(ext, "ecpl", getattr(ext, "formats", getattr(ext, "point_formats", [])))
                formats = [str(f) for f in fl]
        ja3_str = f"{version},{ciphers_str},{'-'.join(ext_types)},{'-'.join(curves)},{'-'.join(formats)}"
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None

# ==============================
# Packet Capture
# ==============================

def _flow_key(src, sport, dst, dport, proto):
    return (src, sport, dst, dport, proto)

def _rev_key(src, sport, dst, dport, proto):
    return (dst, dport, src, sport, proto)

def packet_callback(packet, iface="unknown"):
    if not packet.haslayer(IP):
        return

    ip   = packet[IP]
    src  = ip.src
    dst  = ip.dst
    size = len(packet)

    if packet.haslayer(TCP):
        proto = "TCP"
        layer = packet[TCP]
    elif packet.haslayer(UDP):
        proto = "UDP"
        layer = packet[UDP]
    else:
        return

    sport = layer.sport
    dport = layer.dport
    key   = _flow_key(src, sport, dst, dport, proto)
    rev   = _rev_key(src, sport, dst, dport, proto)

    with lock:
        if rev in flows:
            key = rev

        if key not in flows:
            flows[key] = {
                "start_time":      time.time(),
                "last_seen":       time.time(),
                "bytes_sent":      0,
                "bytes_received":  0,
                "packet_count":    0,
                "tcp_flags":       defaultdict(int),
                "dns_queries":     [],
                "dns_response_ip": None,
                "tls_sni":         None,
                "ja3":             None,
                "mac":             None,
                "interface":       iface,
            }

        flow = flows[key]
        flow["last_seen"]    = time.time()
        flow["packet_count"] += 1

        if src == key[0]:
            flow["bytes_sent"]     += size
        else:
            flow["bytes_received"] += size

        # TCP flags
        if proto == "TCP":
            for f in str(layer.flags):
                flow["tcp_flags"][f] += 1

        # DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0 and dns.qd:
                try:
                    qname = dns.qd.qname.decode("utf-8", errors="ignore")
                except Exception:
                    qname = str(dns.qd.qname)
                flow["dns_queries"].append(qname)
            if dns.qr == 1 and dns.an:
                try:
                    rdata = dns.an.rdata
                    if isinstance(rdata, bytes):
                        import socket as _s
                        try:
                            flow["dns_response_ip"] = _s.inet_ntoa(rdata)
                        except Exception:
                            flow["dns_response_ip"] = rdata.hex()
                    else:
                        flow["dns_response_ip"] = str(rdata)
                except Exception:
                    pass

        # TLS SNI + JA3
        if packet.haslayer(TLSClientHello):
            try:
                for ext in packet[TLSClientHello].ext:
                    if isinstance(ext, TLS_Ext_ServerName):
                        sn = ext.servernames[0].servername
                        flow["tls_sni"] = sn.decode("utf-8", errors="ignore") if isinstance(sn, bytes) else str(sn)
                        break
            except Exception:
                pass
            if flow["ja3"] is None:
                flow["ja3"] = compute_ja3(packet)

        # MAC address & per-device aggregation
        src_mac = packet[Ether].src if packet.haslayer(Ether) else None
        dst_mac = packet[Ether].dst if packet.haslayer(Ether) else None

        if is_local_ip(src):
            dev = device_stats[src]
            if src_mac and not dev["mac_address"]:
                dev["mac_address"] = src_mac
            if src_mac and not flow["mac"]:
                flow["mac"] = src_mac
            dev["bytes_sent"]         += size
            dev["packets"]            += 1
            dev["last_seen"]           = time.time()
            dev["protocols"][proto]   += 1
            dev["ports"][dport]       += 1
            dev["destinations"][dst]  += 1

        if is_local_ip(dst):
            dev = device_stats[dst]
            # Track per-device stats but do NOT set flow["mac"] to dst_mac
            # — flow["mac"] must represent the source/initiator's MAC only
            if dst_mac and not dev["mac_address"]:
                dev["mac_address"] = dst_mac
            dev["bytes_received"] += size

# ==============================
# Aggregator — pushes every 3s
# ==============================

def aggregator():
    while True:
        time.sleep(AGGREGATION_INTERVAL)
        flows_payload = []
        now = time.time()

        with lock:
            # Expire idle flows
            expired = [k for k, f in flows.items() if now - f["last_seen"] > FLOW_TIMEOUT]
            for k in expired:
                del flows[k]

            # Build snapshot of current flows
            for key, flow in flows.items():
                src_ip, sport, dst_ip, dport, proto = key
                duration = max(now - flow["start_time"], 0.001)

                # Per-device first_seen / last_seen
                dev        = device_stats.get(src_ip, {})
                first_seen = dev.get("first_seen", flow["start_time"])
                last_seen  = dev.get("last_seen",  flow["last_seen"])

                # Only tag hostname if this src_ip is a locally-sending interface
                # (tracked in device_stats). This prevents remote IPs getting the
                # local hostname and merging into the MacBook's DGID.
                is_local_src = src_ip in device_stats
                host = LOCAL_HOSTNAME if is_local_src else None

                flows_payload.append({
                    "source_ip":        src_ip,
                    "destination_ip":   dst_ip,
                    "source_port":      sport,
                    "destination_port": dport,
                    "protocol":         proto,
                    "bytes_sent":       flow["bytes_sent"],
                    "bytes_received":   flow["bytes_received"],
                    "session_duration": round(duration, 2),
                    "packet_count":     flow["packet_count"],
                    "tcp_flags":        {str(k): v for k, v in dict(flow["tcp_flags"]).items()},
                    "tls_sni":          flow["tls_sni"],
                    "ja3":              flow["ja3"],
                    "dns_query_names":  flow["dns_queries"],
                    "dns_response_ip":  flow["dns_response_ip"],
                    "geoip":            get_geoip(dst_ip),
                    "asn":              get_asn(dst_ip),
                    "mac_address":      flow["mac"],
                    "first_seen":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first_seen)),
                    "last_seen":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_seen)),
                    "flow_direction":   "outbound" if is_local_src else "inbound",
                    "interface":        flow["interface"],
                    "hostname":         host,
                })

        if not flows_payload:
            continue

        # POST to telemetry API
        try:
            payload = _safe_json({"flows": flows_payload})
            resp = requests.post(
                f"{API_BASE}/network/telemetry",
                json=payload,
                headers={"x-api-key": NETWORK_KEY},
                timeout=5,
            )
            print(f"[COLLECTOR] Pushed {len(flows_payload)} flows → {resp.status_code}")
        except Exception as e:
            print(f"[COLLECTOR] Push failed: {e}")

# ==============================
# Interface Detection & Startup
# ==============================

def _start_sniffer_on_iface(iface: str):
    def _sniff():
        try:
            print(f"[SNIFFER] Starting on interface: {iface}")
            sniff(iface=iface, filter="ip", prn=lambda p: packet_callback(p, iface), store=False)
        except Exception as e:
            print(f"[SNIFFER] Error on {iface}: {e}")
    threading.Thread(target=_sniff, daemon=True).start()

def _detect_and_start_sniffers():
    from scapy.all import get_if_addr
    preferred = ["bridge100", "en6", "en0", "en1", "en2"]
    started   = []
    for iface in preferred:
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                _start_sniffer_on_iface(iface)
                started.append(f"{iface}({ip})")
        except Exception:
            pass
    if started:
        print(f"[SNIFFER] Active sniffers: {', '.join(started)}")
    else:
        _start_sniffer_on_iface("bridge100")
        print("[SNIFFER] Fallback: sniffing on bridge100")

_detect_and_start_sniffers()
threading.Thread(target=aggregator, daemon=True).start()

# Keep the process alive
if __name__ == "__main__":
    print("[COLLECTOR] Network telemetry collector running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[COLLECTOR] Stopped.")