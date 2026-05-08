"""
Guardient Temporal Collector  v2
=================================
Computes DERIVED temporal metrics from real OS data — self-contained.
Does NOT depend on GET endpoints from the API server.

Sources (all real, no simulation):
  psutil          → CPU, memory, network I/O counters (live OS metrics)
  psutil.users    → active session count
  macOS log       → auth failure count (same source as identity collector)

Computes every 3 seconds and POSTs to /temporal/metrics:
  deviation_from_baseline  → latest minus rolling mean
  anomaly_frequency        → fraction of recent samples > 2× mean
  burst_rate               → latest / mean
  drift_rate               → OLS linear slope (trend)
  change_velocity          → mean of abs differences between samples
"""

import os
import re
import time
import statistics
import subprocess
import requests
from collections import deque, defaultdict
from datetime import datetime, timezone
from typing import Optional

import psutil
from dotenv import load_dotenv

load_dotenv()

# ==============================
# Config
# ==============================

INTERVAL     = 3
API_BASE     = os.getenv("TELEMETRY_API_BASE", "http://localhost:8000")
NETWORK_KEY  = os.getenv("NETWORK_KEY", "NET-KEY-2F4A8C1B")
WINDOW       = 100   # rolling window — last N samples per metric

# ==============================
# Rolling streams
# ==============================

_streams: dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW))

def _push(name: str, value: float):
    _streams[name].append((value, time.time()))

# ==============================
# Temporal math (no simulation)
# ==============================

def compute_temporal(name: str) -> dict:
    """Compute the 5 temporal metrics for one named stream."""
    stream = list(_streams[name])
    vals   = [v for v, _ in stream]
    n      = len(vals)

    out = {
        "metric":                  name,
        "sample_count":            n,
        "current_value":           vals[-1] if vals else 0,
        "deviation_from_baseline": 0.0,
        "anomaly_frequency":       0.0,
        "burst_rate":              0.0,
        "drift_rate":              0.0,
        "change_velocity":         0.0,
    }
    if n < 2:
        return out

    mean   = statistics.mean(vals)
    latest = vals[-1]

    out["deviation_from_baseline"] = round(latest - mean, 4)
    out["burst_rate"]              = round(latest / mean, 4) if mean > 0 else 0.0

    diffs = [abs(vals[i] - vals[i-1]) for i in range(1, n)]
    out["change_velocity"] = round(statistics.mean(diffs), 4)

    tail  = vals[-20:]
    out["anomaly_frequency"] = round(
        sum(1 for v in tail if v > 2 * mean) / len(tail), 4
    )

    if n >= 5:
        xs    = list(range(n))
        x_bar = statistics.mean(xs)
        y_bar = mean
        num   = sum((xs[i]-x_bar)*(vals[i]-y_bar) for i in range(n))
        den   = sum((x-x_bar)**2 for x in xs)
        out["drift_rate"] = round(num/den, 6) if den else 0.0

    return out

# ==============================
# Real data sources
# ==============================

# Track last network I/O counters for delta computation
_last_net_io   = None
_last_net_time = None

def sample_network():
    """
    Real network I/O bytes from psutil (kernel counters).
    Computes bytes/sec delta since last sample.
    """
    global _last_net_io, _last_net_time
    try:
        counters = psutil.net_io_counters()
        now      = time.time()
        if _last_net_io and _last_net_time:
            dt = max(now - _last_net_time, 0.001)
            sent_rate = (counters.bytes_sent     - _last_net_io.bytes_sent)     / dt
            recv_rate = (counters.bytes_recv     - _last_net_io.bytes_recv)     / dt
            pkt_rate  = (counters.packets_sent   - _last_net_io.packets_sent +
                         counters.packets_recv   - _last_net_io.packets_recv)   / dt
            _push("network.bytes_sent_per_sec",   max(sent_rate, 0))
            _push("network.bytes_recv_per_sec",   max(recv_rate, 0))
            _push("network.packets_per_sec",      max(pkt_rate,  0))
            _push("network.total_bytes_per_sec",  max(sent_rate + recv_rate, 0))
        _last_net_io   = counters
        _last_net_time = now
    except Exception:
        pass

def sample_identity():
    """
    Real identity/auth metrics from the OS.
    - Active session count from psutil
    - Auth failure count from macOS Unified Log (last 10s)
    """
    # Active sessions
    try:
        _push("identity.active_sessions", len(psutil.users()))
    except Exception:
        pass

    # Auth failures from macOS unified log (last 10 seconds)
    try:
        result = subprocess.run(
            [
                "log", "show",
                "--style", "compact",
                "--last", "10s",
                "--predicate",
                (
                    'eventMessage CONTAINS "authentication failure" OR '
                    'eventMessage CONTAINS "Failed password" OR '
                    'eventMessage CONTAINS "Invalid user"'
                ),
            ],
            capture_output=True, text=True, timeout=5,
        )
        failures = len([l for l in result.stdout.splitlines() if l.strip()])
        _push("identity.auth_failures_10s", float(failures))
    except Exception:
        pass

def sample_hardware():
    """
    Real hardware metrics from psutil.
    CPU %, memory %, disk I/O rate, load average.
    """
    try:
        _push("hardware.cpu_percent",    psutil.cpu_percent(interval=None))
        _push("hardware.memory_percent", psutil.virtual_memory().percent)
        load = os.getloadavg()
        _push("hardware.load_1m",  load[0])
        _push("hardware.load_5m",  load[1])
        _push("hardware.load_15m", load[2])
    except Exception:
        pass

def sample_connections():
    """
    Real TCP connection state counts from psutil.
    Number of ESTABLISHED / TIME_WAIT / SYN_SENT connections.
    """
    try:
        conns = psutil.net_connections(kind="tcp")
        _push("network.established_conns",
              sum(1 for c in conns if c.status == "ESTABLISHED"))
        _push("network.time_wait_conns",
              sum(1 for c in conns if c.status == "TIME_WAIT"))
    except Exception:
        pass

# ==============================
# Collect once
# ==============================

ALL_METRICS = [
    "network.bytes_sent_per_sec",
    "network.bytes_recv_per_sec",
    "network.packets_per_sec",
    "network.total_bytes_per_sec",
    "network.established_conns",
    "network.time_wait_conns",
    "identity.active_sessions",
    "identity.auth_failures_10s",
    "hardware.cpu_percent",
    "hardware.memory_percent",
    "hardware.load_1m",
    "hardware.load_5m",
    "hardware.load_15m",
]

def collect_once() -> dict:
    now = datetime.now(tz=timezone.utc).isoformat()

    # Sample all real data sources
    sample_network()
    sample_identity()
    sample_hardware()
    sample_connections()

    # Compute temporal metrics for every stream
    metrics = [compute_temporal(m) for m in ALL_METRICS]

    anomalous = [
        m["metric"] for m in metrics
        if m["burst_rate"] > 2.0 or m["anomaly_frequency"] > 0.3
    ]

    return {
        "collected_at":     now,
        "collector":        "temporal_collector_v2",
        "source_system":    "macos_os_counters",
        "temporal_metrics": metrics,
        "anomalous_streams": anomalous,
        "risk_flags": {
            "network_traffic_burst": compute_temporal(
                "network.total_bytes_per_sec")["burst_rate"] > 2.0,
            "cpu_spike":             compute_temporal(
                "hardware.cpu_percent")["burst_rate"] > 2.0,
            "auth_failure_spike":    compute_temporal(
                "identity.auth_failures_10s")["burst_rate"] > 3.0,
            "connection_surge":      compute_temporal(
                "network.established_conns")["burst_rate"] > 2.0,
            "memory_drift":          abs(compute_temporal(
                "hardware.memory_percent")["drift_rate"]) > 1.0,
        },
    }

def push_to_api(data: dict) -> Optional[int]:
    try:
        resp = requests.post(
            f"{API_BASE}/temporal/metrics",
            json=data,
            headers={"x-api-key": NETWORK_KEY},
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
    print("=" * 60)
    print("  Guardient Temporal Collector  v2")
    print("=" * 60)
    print(f"  API Base  : {API_BASE}")
    print(f"  Interval  : {INTERVAL}s")
    print(f"  Window    : last {WINDOW} samples per stream")
    print("  Sources   : psutil kernel counters + macOS Unified Log")
    print("  Metrics   : deviation, anomaly_freq, burst_rate,")
    print("              drift_rate, change_velocity")
    print("  Data      : 100% real OS counters — no simulation")
    print("=" * 60 + "\n")

    while True:
        tick = time.time()
        try:
            data   = collect_once()
            status = push_to_api(data)
            flags  = [k for k, v in data["risk_flags"].items() if v]
            ready  = sum(1 for m in data["temporal_metrics"] if m["sample_count"] >= 2)
            print(
                f"[{data['collected_at']}] "
                f"Streams: {ready}/{len(data['temporal_metrics'])} active | "
                f"Anomalous: {data['anomalous_streams'] or 'none'} | "
                f"API→{status} | "
                f"Flags: {flags or 'none'}"
            )
        except KeyboardInterrupt:
            print("\n[Temporal Collector] Stopped.")
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")

        time.sleep(max(0, INTERVAL - (time.time() - tick)))

if __name__ == "__main__":
    run()
