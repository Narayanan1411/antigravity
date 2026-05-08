"""
Guardient Hardware / Hypervisor Collector  v1
=============================================
Collects real hardware fingerprint and hypervisor telemetry from the host.
Polls every 3 seconds. All data is real — zero simulation.

Fields collected:
  VM UUID               → system_profiler / ioreg (macOS)
  Host hypervisor ID    → ioreg / DMI
  MAC address           → psutil / netifaces
  Clock skew            → NTP delta vs local clock
  TCP timestamp drift   → from active connections via psutil
  ARP behavior          → arp -a (real ARP table)
  Switch port mapping   → MAC → IP/iface from ARP table
  Power-on burst pattern → boot_time from psutil

POST → /hardware/profile  with HARDWARE_KEY
"""

import os
import re
import time
import json
import uuid
import socket
import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Optional

import psutil
import requests
from dotenv import load_dotenv

load_dotenv()

# ==============================
# Config
# ==============================

INTERVAL     = 3
API_BASE     = os.getenv("TELEMETRY_API_BASE", "http://localhost:8000")
HARDWARE_KEY = os.getenv("HARDWARE_KEY",       "HW-KEY-3A9D7F2C")
NTP_SERVER   = os.getenv("NTP_SERVER",         "pool.ntp.org")

# ==============================
# VM UUID / Hypervisor ID
# Source: macOS ioreg / system_profiler
# ==============================

def get_vm_uuid() -> Optional[str]:
    """Read the hardware UUID from macOS IOPlatformExpertDevice."""
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

def get_serial_number() -> Optional[str]:
    """Read hardware serial number — used as a stable hardware anchor."""
    try:
        result = subprocess.run(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r'"IOPlatformSerialNumber"\s*=\s*"([^"]+)"', result.stdout)
        return m.group(1) if m else None
    except Exception:
        return None

def get_model_identifier() -> Optional[str]:
    """Read model identifier (e.g. MacBookPro18,1)."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "hw.model"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or None
    except Exception:
        return None

def get_cpu_brand() -> Optional[str]:
    """Read CPU microarchitecture / brand string."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", "machdep.cpu.brand_string"],
            capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip() or None
    except Exception:
        return None

def get_tsc_drift() -> dict:
    """
    Measure CPU TSC (Time Stamp Counter) instruction timing.
    Detects hypervisors and VM time dilation by measuring execution latency of tight loops.
    """
    try:
        samples = []
        for _ in range(15):
            t1 = time.perf_counter_ns()
            for _ in range(1000):
                pass
            t2 = time.perf_counter_ns()
            samples.append(t2 - t1)
        
        min_ns = min(samples)
        max_ns = max(samples)
        drift = max_ns / min_ns if min_ns > 0 else 1.0

        return {
            "samples_ns": samples,
            "min_ns": min_ns,
            "max_ns": max_ns,
            "drift_ratio": round(drift, 2)
        }
    except Exception as exc:
        return {"error": str(exc)}

def get_hypervisor_info() -> dict:
    """
    Detect if running inside a VM/hypervisor.
    Source: sysctl kern.hv_vmm_present (macOS) and DMI strings via ioreg.
    """
    info = {"is_virtual": False, "hypervisor": None, "hypervisor_host_id": None}
    try:
        r = subprocess.run(["sysctl", "-n", "kern.hv_vmm_present"],
                           capture_output=True, text=True, timeout=5)
        info["is_virtual"] = r.stdout.strip() == "1"
    except Exception:
        pass
    try:
        r = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                           capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            for hv in ("VMware", "VirtualBox", "QEMU", "Parallels", "Xen", "HyperV"):
                if hv.lower() in line.lower():
                    info["hypervisor"] = hv
                    m = re.search(r'"([^"]{8,})"', line)
                    if m:
                        info["hypervisor_host_id"] = m.group(1)
                    break
    except Exception:
        pass
    return info

# ==============================
# MAC Addresses
# Source: psutil.net_if_addrs
# ==============================

def get_mac_addresses() -> list:
    """Return all real MAC addresses from active network interfaces."""
    macs = []
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                # AF_LINK = 18 on macOS (link-layer / MAC)
                if addr.family == psutil.AF_LINK if hasattr(psutil, "AF_LINK") else 18:
                    if addr.address and addr.address != "00:00:00:00:00:00":
                        macs.append({"interface": iface, "mac": addr.address})
    except Exception as exc:
        macs.append({"error": str(exc)})
    return macs

# ==============================
# Clock skew
# Source: SNTP query to NTP server
# ==============================

def get_clock_skew_ms() -> Optional[float]:
    """
    Measure clock skew by comparing local time against an NTP server.
    Uses a raw SNTP request (no ntplib dependency) — pure stdlib sockets.
    """
    try:
        NTP_PORT   = 123
        NTP_PACKET = b'\x1b' + b'\0' * 47  # Mode 3 (client), version 3
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(3)
            s.sendto(NTP_PACKET, (NTP_SERVER, NTP_PORT))
            data, _ = s.recvfrom(1024)
        if len(data) < 48:
            return None
        # Transmit timestamp is at bytes 40–47 (NTP epoch = Jan 1, 1900)
        NTP_EPOCH  = 2208988800  # seconds between 1900 and 1970
        t = int.from_bytes(data[40:44], "big") - NTP_EPOCH
        local_t  = time.time()
        skew_ms  = round((local_t - t) * 1000, 3)
        return skew_ms
    except Exception:
        return None

# ==============================
# TCP timestamp drift
# Source: psutil.net_connections (real OS connections)
# ==============================

def get_tcp_timestamp_drift() -> dict:
    """
    Approximate TCP timestamp drift by examining active connections.
    We sample the number of ESTABLISHED connections and TIME_WAIT states
    as a proxy for timestamp behaviour — actual drift requires raw socket
    capture which the network collector does via Scapy.
    """
    try:
        conns = psutil.net_connections(kind="tcp")
        established = sum(1 for c in conns if c.status == "ESTABLISHED")
        time_wait   = sum(1 for c in conns if c.status == "TIME_WAIT")
        syn_sent    = sum(1 for c in conns if c.status == "SYN_SENT")
        return {
            "established_connections": established,
            "time_wait_connections":   time_wait,
            "syn_sent_connections":    syn_sent,
            "total_tcp_connections":   len(conns),
            "note": "Packet-level TCP timestamp drift collected by network_data.py via Scapy",
        }
    except Exception as exc:
        return {"error": str(exc)}

# ==============================
# ARP table
# Source: `arp -a` (real OS ARP cache)
# ==============================

def get_arp_table() -> list:
    """
    Read the live ARP table from the OS.
    Maps IP → MAC → interface (switch port mapping proxy).
    """
    entries = []
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            # Format: hostname (ip) at mac on iface
            m = re.match(
                r"(\S+)\s+\(([\d\.]+)\)\s+at\s+([0-9a-f:]+)\s+on\s+(\S+)",
                line, re.IGNORECASE
            )
            if m:
                entries.append({
                    "hostname":  m.group(1),
                    "ip":        m.group(2),
                    "mac":       m.group(3),
                    "interface": m.group(4),
                    "type":      "static" if "permanent" in line else "dynamic",
                })
    except Exception as exc:
        entries.append({"error": str(exc)})
    return entries

# ==============================
# Boot / power-on burst pattern
# Source: psutil.boot_time
# ==============================

def get_power_on_pattern() -> dict:
    """
    Returns when the system last booted and how long it has been running.
    Power-on burst pattern = CPU / memory spike in first N minutes.
    """
    try:
        boot_epoch  = psutil.boot_time()
        uptime_sec  = time.time() - boot_epoch
        uptime_min  = uptime_sec / 60

        # CPU usage — high early after boot indicates a burst pattern
        cpu_pct     = psutil.cpu_percent(interval=0.2)
        mem          = psutil.virtual_memory()

        return {
            "boot_time":          datetime.fromtimestamp(boot_epoch, tz=timezone.utc).isoformat(),
            "uptime_seconds":     round(uptime_sec, 1),
            "cpu_percent":        cpu_pct,
            "memory_percent":     mem.percent,
            "memory_used_mb":     round(mem.used / 1024 / 1024, 1),
            "memory_total_mb":    round(mem.total / 1024 / 1024, 1),
            "early_burst_detected": uptime_min < 5 and cpu_pct > 40,
        }
    except Exception as exc:
        return {"error": str(exc)}

# ==============================
# BIOS / firmware info
# Source: system_profiler SPHardwareDataType
# ==============================

def get_firmware_info() -> dict:
    """Read BIOS/firmware version from system_profiler (macOS)."""
    try:
        result = subprocess.run(
            ["system_profiler", "SPHardwareDataType", "-json"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        hw   = data.get("SPHardwareDataType", [{}])[0]
        return {
            "model_name":       hw.get("machine_name"),
            "model_identifier": hw.get("machine_model"),
            "chip":             hw.get("chip_type"),
            "cpu_type":         hw.get("cpu_type"),
            "core_count":       hw.get("number_processors"),
            "memory":           hw.get("physical_memory"),
            "serial_number":    hw.get("serial_number"),
            "hardware_uuid":    hw.get("platform_UUID"),
            "firmware_version": hw.get("SMC_version_system") or hw.get("boot_rom_version"),
            "secure_boot":      None,   # requires csrutil — skip to avoid sudo
        }
    except Exception as exc:
        return {"error": str(exc)}

# ==============================
# Collect + push
# ==============================

def collect_once() -> dict:
    now         = datetime.now(tz=timezone.utc).isoformat()
    vm_uuid     = get_vm_uuid()
    serial      = get_serial_number()
    firmware    = get_firmware_info()
    hypervisor  = get_hypervisor_info()
    macs        = get_mac_addresses()
    clock_skew  = get_clock_skew_ms()
    tcp_info    = get_tcp_timestamp_drift()
    arp_table   = get_arp_table()
    power_on    = get_power_on_pattern()
    cpu_brand   = get_cpu_brand()
    tsc_drift   = get_tsc_drift()

    # Primary MAC for DGID anchoring
    primary_mac = macs[0]["mac"] if macs and "mac" in macs[0] else None

    # Stable hardware hash for identification (disk_serial_hash)
    disk_serial_hash = hashlib.sha256(
        (serial or "unknown").encode()).hexdigest() if serial else None

    return {
        "collected_at":    now,
        "collector":       "hardware_collector_v1",
        "source_system":   "macos_hardware_apis",

        # Identity anchors
        "vm_uuid":           vm_uuid,
        "serial_number":     serial,
        "disk_serial_hash":  disk_serial_hash,
        "mac_address":       primary_mac,
        "all_mac_addresses": macs,

        # Hypervisor
        "is_virtual":            hypervisor["is_virtual"],
        "hypervisor":            hypervisor["hypervisor"],
        "hypervisor_host_id":    hypervisor["hypervisor_host_id"],

        # Hardware fingerprint
        "firmware":              firmware,
        "model_identifier":      get_model_identifier(),
        "cpu_microarchitecture": cpu_brand,

        # Timing fingerprints
        "clock_skew_ms":         clock_skew,
        "cpu_tsc_drift":         tsc_drift,
        "tcp_connections":       tcp_info,

        # Network / ARP
        "arp_table":             arp_table,
        "switch_port_mapping":   [
            {"ip": e["ip"], "mac": e["mac"], "interface": e["interface"]}
            for e in arp_table if "error" not in e
        ],

        # Power-on burst
        "power_on_burst_pattern": power_on,

        # Risk signals
        "risk_flags": {
            "high_clock_skew":      abs(clock_skew or 0) > 500,   # > 500 ms = suspicious
            "early_cpu_burst":      power_on.get("early_burst_detected", False),
            "running_in_vm":        hypervisor["is_virtual"],
            "no_clock_sync":        clock_skew is None,
        },
    }

def push_to_api(data: dict) -> Optional[int]:
    try:
        resp = requests.post(
            f"{API_BASE}/hardware/profile",
            json=data,
            headers={"x-api-key": HARDWARE_KEY},
            timeout=10,
        )
        return resp.status_code
    except Exception as exc:
        print(f"[PUSH ERROR] {exc}")
        return None

# ==============================
# Entry point
# ==============================

def run():
    print("=" * 55)
    print("  Guardient Hardware Collector  v1")
    print("=" * 55)
    print(f"  API Base : {API_BASE}")
    print(f"  Interval : {INTERVAL}s")
    print("  Sources  : ioreg, sysctl, arp, psutil, system_profiler")
    print("  Data     : 100% real — no simulation")
    print("=" * 55 + "\n")

    while True:
        tick = time.time()
        try:
            data   = collect_once()
            status = push_to_api(data)
            flags  = [k for k, v in data["risk_flags"].items() if v]
            print(
                f"[{data['collected_at']}] "
                f"UUID: {(data.get('vm_uuid') or 'n/a')[:12]}... | "
                f"ClockSkew: {data.get('clock_skew_ms')}ms | "
                f"ARP: {len(data['arp_table'])} entries | "
                f"VM: {data['is_virtual']} | "
                f"API→{status} | "
                f"Flags: {flags or 'none'}"
            )
        except KeyboardInterrupt:
            print("\n[Hardware Collector] Stopped.")
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")

        time.sleep(max(0, INTERVAL - (time.time() - tick)))

if __name__ == "__main__":
    run()
