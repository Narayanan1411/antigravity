#!/usr/bin/env python3
"""
Guardient Data Simulator
=========================
Sends realistic telemetry events to the local Guardient API to exercise
the full pipeline: API → Kafka → Enrichment → Features → ML → Risk → Trust → Decision

Devices simulated:
  - MacBook (laptop) — normal + attack scenario
  - Samsung Smart TV (iot) — baseline traffic then SSH anomaly
  - Ubuntu Server (server) — api traffic + IAM change
  - iPhone (mobile) — normal push traffic

Run: python3 simulate_data.py
"""

import requests
import time
import random
import math
from datetime import datetime, timezone, timedelta

API = "http://localhost:8000"

HEADERS_NET = {"x-api-key": "NET-KEY-2F4A8C1B"}
HEADERS_ID  = {"x-api-key": "IDN-KEY-7E3B9D2A"}
HEADERS_CLD = {"x-api-key": "CLD-KEY-5C1F4A8E"}
HEADERS_HW  = {"x-api-key": "HW-KEY-3A9D7F2C"}


def now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()

def past(minutes: int) -> str:
    return (datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)).isoformat()


# ──────────────────────────────────────────────────────
# Device profiles
# ──────────────────────────────────────────────────────

DEVICES = {
    "macbook": {
        "mac_address":  "3C:5A:B4:10:20:30",
        "hostname":     "john-macbook",
        "device_type":  "laptop",
        "os":           "macOS 14.3",
        "ip":           "192.168.1.25",
        "user_id":      "john.doe",
    },
    "smart_tv": {
        "mac_address":  "98:4F:EE:AA:BB:CC",
        "hostname":     "samsung-tv-living",
        "device_type":  "smart_tv",
        "os":           "Tizen 7.0",
        "ip":           "192.168.1.42",
        "user_id":      None,
    },
    "server": {
        "mac_address":  "00:50:56:0A:0B:0C",
        "hostname":     "prod-server-01",
        "device_type":  "server",
        "os":           "Ubuntu 22.04 LTS",
        "ip":           "10.0.0.10",
        "user_id":      "svc-account",
    },
    "iphone": {
        "mac_address":  "F4:5C:89:DD:EE:FF",
        "hostname":     "john-iphone",
        "device_type":  "phone",
        "os":           "iOS 17.2",
        "ip":           "192.168.1.88",
        "user_id":      "john.doe",
    },
}


# ──────────────────────────────────────────────────────
# Event factories
# ──────────────────────────────────────────────────────

def network_event(device_key: str, dest_ip: str, dest_port: int,
                  dns: str = None, tls_sni: str = None,
                  bytes_sent: int = 1000, bytes_recv: int = 5000) -> dict:
    d = DEVICES[device_key]
    return {"flows": [{
        "source_ip":        d["ip"],
        "destination_ip":   dest_ip,
        "source_port":      random.randint(1024, 65535),
        "destination_port": dest_port,
        "mac_address":      d["mac_address"],
        "hostname":         d["hostname"],
        "device_type":      d["device_type"],
        "os":               d["os"],
        "dns_query_name":   dns,
        "tls_sni":          tls_sni,
        "bytes_sent":       bytes_sent,
        "bytes_received":   bytes_recv,
        "session_duration": random.uniform(1, 120),
        "packet_count":     random.randint(5, 500),
        "timestamp":        now(),
    }]}


def identity_event(device_key: str, success: bool = True, failures: int = 0,
                   mfa: str = "enabled", auth_type: str = "password",
                   after_hours: bool = False) -> dict:
    d = DEVICES[device_key]
    ts = past(0) if not after_hours else (
        datetime.now(tz=timezone.utc).replace(hour=2).isoformat()
    )
    return {"identity_events": [{
        "user_id":               d["user_id"],
        "login_source_ip":       d["ip"],
        "hostname":              d["hostname"],
        "mac_address":           d["mac_address"],
        "device_type":           d["device_type"],
        "authentication_type":   auth_type,
        "mfa_status":            mfa,
        "failure_count":         failures,
        "login_success":         success,
        "event_type":            "login_success" if success else "login_failure",
        "login_timestamp":       ts,
    }]}


def cloud_event(device_key: str, event_type: str = "api_call",
                risk_flags: dict = None, access_granted: bool = True) -> dict:
    d = DEVICES[device_key]
    return {"cloud_events": [{
        "project_id": "guardient-poc",
        "audit_events": [{
            "event_type":     event_type,
            "instance_id":    d["hostname"],
            "api_source_ip":  d["ip"],
            "method":         "GET",
            "region":         "us-central1",
            "access_granted": access_granted,
            "risk_flags":     risk_flags or {},
            "risk_level":     "high" if risk_flags else "low",
            "timestamp":      now(),
        }]
    }]}


def hardware_event(device_key: str, cpu: float = 20, mem: float = 40,
                   clock_skew: int = 0) -> dict:
    d = DEVICES[device_key]
    mac_list = [{"address": d["mac_address"], "ip": d["ip"]}]
    return {
        "hostname":   d["hostname"],
        "machine_id": d["mac_address"].replace(":", ""),
        "os":         {"name": d["os"]},
        "mac_addresses": mac_list,
        "power_on_burst_pattern": {"cpu_percent": cpu, "memory_percent": mem},
        "clock_skew_ms": clock_skew,
        "timestamp": now(),
    }


# ──────────────────────────────────────────────────────
# Send helpers
# ──────────────────────────────────────────────────────

def send(endpoint: str, headers: dict, payload: dict, label: str):
    try:
        r = requests.post(f"{API}{endpoint}", json=payload, headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            print(f"  ✅ {label} → {data.get('category', endpoint)} | published={data.get('published', '?')}")
        else:
            print(f"  ❌ {label} → HTTP {r.status_code}: {r.text[:80]}")
    except Exception as e:
        print(f"  💥 {label} → {e}")


# ──────────────────────────────────────────────────────
# Scenarios
# ──────────────────────────────────────────────────────

def scenario_normal_baseline(rounds: int = 5):
    """Send normal traffic to build baselines for all devices."""
    print(f"\n{'='*55}\n 📊 Building baselines ({rounds} rounds — normal traffic)\n{'='*55}")
    for i in range(rounds):
        print(f"\n Round {i+1}/{rounds}")
        # MacBook — normal web browsing
        send("/network/telemetry", HEADERS_NET,
             network_event("macbook", "8.8.8.8", 443,
                           dns="google.com", tls_sni="google.com",
                           bytes_sent=random.randint(500, 3000),
                           bytes_recv=random.randint(2000, 20000)),
             "MacBook HTTPS")

        # MacBook — normal login
        send("/identity/events", HEADERS_ID,
             identity_event("macbook", success=True, failures=0, mfa="enabled"),
             "MacBook Login OK")

        # Smart TV — streaming traffic
        send("/network/telemetry", HEADERS_NET,
             network_event("smart_tv", "157.240.241.35", 443,
                           dns="netflix.com", tls_sni="netflix.com",
                           bytes_sent=random.randint(500, 2000),
                           bytes_recv=random.randint(5_000_000, 50_000_000)),
             "Smart TV Netflix stream")

        # Server — cloud API
        send("/cloud/events", HEADERS_CLD,
             cloud_event("server", "api_call"),
             "Server Cloud API call")

        # Hardware profiles
        send("/hardware/profile", HEADERS_HW,
             hardware_event("macbook", cpu=random.uniform(15, 40), mem=random.uniform(30, 60)),
             "MacBook HW profile")

        send("/hardware/profile", HEADERS_HW,
             hardware_event("server", cpu=random.uniform(20, 50), mem=random.uniform(40, 70)),
             "Server HW profile")

        time.sleep(0.5)


def scenario_attack_macbook():
    """Simulate a credential-stuffing + exfiltration attack on the MacBook."""
    print(f"\n{'='*55}\n 🔴 ATTACK: MacBook brute-force + exfiltration\n{'='*55}")

    print("\n Step 1 — Brute-force login (5 failures)")
    send("/identity/events", HEADERS_ID,
         identity_event("macbook", success=False, failures=6, mfa="disabled",
                        auth_type="password"),
         "MacBook BruteForce")

    print("\n Step 2 — After-hours sudo from compromised session")
    send("/identity/events", HEADERS_ID,
         identity_event("macbook", success=True, failures=0,
                        mfa="disabled", auth_type="sudo", after_hours=True),
         "MacBook After-hours Sudo")

    print("\n Step 3 — Massive data exfiltration (100MB outbound)")
    send("/network/telemetry", HEADERS_NET,
         network_event("macbook", "185.220.101.1", 443,
                       dns="pastebin.com", tls_sni="pastebin.com",
                       bytes_sent=100_000_000, bytes_recv=50000),
         "MacBook Data Exfil")

    print("\n Step 4 — DGA-looking DNS query")
    dga = "a9f3kxm8d2z1q7wvplr45.ru"
    send("/network/telemetry", HEADERS_NET,
         network_event("macbook", "91.108.4.1", 80, dns=dga, bytes_sent=200, bytes_recv=400),
         "MacBook DGA DNS")
    time.sleep(0.2)


def scenario_smart_tv_attack():
    """Simulate an IoT attack: SSH from a TV that should only stream."""
    print(f"\n{'='*55}\n 🔴 ATTACK: Smart TV SSH anomaly (IoT breach)\n{'='*55}")

    print("\n Step 1 — TV tries SSH connection")
    send("/network/telemetry", HEADERS_NET,
         network_event("smart_tv", "10.0.0.10", 22,
                       bytes_sent=1000, bytes_recv=500),
         "Smart TV → SSH port 22")

    print("\n Step 2 — TV hits risky RDP port")
    send("/network/telemetry", HEADERS_NET,
         network_event("smart_tv", "10.0.0.10", 3389,
                       bytes_sent=500, bytes_recv=200),
         "Smart TV → RDP port 3389")
    time.sleep(0.2)


def scenario_cloud_compromise():
    """Simulate cloud account takeover: IAM change + key creation + snapshot."""
    print(f"\n{'='*55}\n 🔴 ATTACK: Cloud IAM + persistence + exfil\n{'='*55}")

    print("\n Step 1 — Unauthorized API call")
    send("/cloud/events", HEADERS_CLD,
         cloud_event("server", "api_call", access_granted=False),
         "Cloud API Denied")

    print("\n Step 2 — IAM policy change")
    send("/cloud/events", HEADERS_CLD,
         cloud_event("server", "iam_policy_change",
                     risk_flags={"key_created": True, "lateral_exposure": True}),
         "Cloud IAM Change")

    print("\n Step 3 — Data exfil snapshot")
    send("/cloud/events", HEADERS_CLD,
         cloud_event("server", "snapshot_create",
                     risk_flags={"data_exfil_risk": True}),
         "Cloud Snapshot Exfil")
    time.sleep(0.2)


# ──────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════╗
║       Guardient Telemetry Simulator                 ║
║  Sends events to http://localhost:8000              ║
╚══════════════════════════════════════════════════════╝
""")
    # 1. Build baselines (normal traffic)
    scenario_normal_baseline(rounds=25)

    # 2. Attack wave 1: MacBook
    scenario_attack_macbook()

    # 3. Attack wave 2: Smart TV IoT
    scenario_smart_tv_attack()

    # 4. Attack wave 3: Cloud takeover
    scenario_cloud_compromise()

    print("""
╔══════════════════════════════════════════════════════╗
║  ✅ Simulation complete!                             ║
║  Check terminal logs for ALERT events               ║
║  Query DB: docker exec -it guardient-db psql \\     ║
║            -U guardient -c "SELECT * FROM alerts;"  ║
╚══════════════════════════════════════════════════════╝
""")
