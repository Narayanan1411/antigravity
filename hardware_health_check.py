#!/usr/bin/env python3
"""
Guardient Hardware & Device Detection Health Check
===================================================
Run from poc Guardient/ directory:
    python3 hardware_health_check.py

Checks:
  1. Hardware module files present in hardware/
  2. Hardware ML module imports correctly
  3. Hardware model files on disk
  4. ARP / neighbour table — live devices visible to scanner
  5. DB device list with last_seen freshness
  6. API reachability
  7. Kafka connectivity
  8. Running services (by PID files or process name)
"""

import sys
import os
import subprocess
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "hardware"))

OK    = "\033[92m[OK]\033[0m"
WARN  = "\033[93m[WARN]\033[0m"
FAIL  = "\033[91m[FAIL]\033[0m"
INFO  = "\033[94m[INFO]\033[0m"

def section(title: str):
    print(f"\n\033[1m{'─'*55}\033[0m")
    print(f"\033[1m  {title}\033[0m")
    print(f"\033[1m{'─'*55}\033[0m")

# ── 1. Hardware module files ──────────────────────────────
section("1. Hardware Module Files")
HW_DIR = ROOT / "hardware"
required = ["app.py", "collector.py", "features.py", "state.py"]
for f in required:
    path = HW_DIR / f
    if path.exists():
        print(f"  {OK}  hardware/{f}")
    else:
        print(f"  {FAIL} hardware/{f}  ← MISSING")

# ── 2. Hardware ML imports ────────────────────────────────
section("2. Hardware ML Module Imports")
try:
    from app import (
        SEQ_LEN, FEATURE_SIZE, MODEL_DIR,
        device_buffers, device_models, device_scalers, device_thresholds,
        load_model, train_device_model, detect_anomaly, LSTMAutoencoder
    )
    print(f"  {OK}  app.py imported  (SEQ_LEN={SEQ_LEN}, FEATURE_SIZE={FEATURE_SIZE})")
    print(f"  {INFO} MODEL_DIR={MODEL_DIR}")
    if os.path.isdir(MODEL_DIR):
        print(f"  {OK}  MODEL_DIR exists")
    else:
        print(f"  {FAIL} MODEL_DIR does not exist — models will fail to save/load")
except ImportError as e:
    print(f"  {FAIL} Cannot import hardware/app.py: {e}")

try:
    from collector import collect
    print(f"  {OK}  collector.py imported")
except ImportError as e:
    print(f"  {FAIL} Cannot import hardware/collector.py: {e}")

try:
    from features import compute_and_reset
    print(f"  {OK}  features.py imported")
except ImportError as e:
    print(f"  {FAIL} Cannot import hardware/features.py: {e}")

# ── 3. Saved model files ──────────────────────────────────
section("3. Saved LSTM Model Files")
try:
    model_dir = Path(MODEL_DIR)
    pt_files = list(model_dir.glob("*_hw.pt"))
    pkl_files = list(model_dir.glob("*_hw_scaler.pkl"))
    if pt_files:
        for pt in pt_files:
            device_id = pt.stem.replace("_hw", "")
            pkl = model_dir / f"{device_id}_hw_scaler.pkl"
            status = OK if pkl.exists() else WARN
            print(f"  {status} {device_id}: model={pt.name}, scaler={'found' if pkl.exists() else 'MISSING'}")
    else:
        print(f"  {INFO} No trained models found yet (normal on first run — needs {SEQ_LEN} samples)")
except Exception as e:
    print(f"  {FAIL} Error scanning models: {e}")

# ── 4. Live ARP / neighbour table ────────────────────────
section("4. Live ARP / Neighbour Table")
try:
    arp_entries = []
    with open("/proc/net/arp") as f:
        for line in f.readlines()[1:]:
            parts = line.split()
            if len(parts) >= 4:
                ip, _, flags, mac = parts[:4]
                if mac != "00:00:00:00:00:00" and int(flags, 16) & 0x2:
                    arp_entries.append((ip, mac.lower()))

    neigh_entries = []
    result = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5)
    for line in result.stdout.splitlines():
        parts = line.split()
        if "lladdr" in parts and "FAILED" not in line.upper() and "INCOMPLETE" not in line.upper():
            ip = parts[0]
            idx = parts.index("lladdr")
            mac = parts[idx + 1].lower()
            state = parts[-1]
            if mac != "00:00:00:00:00:00":
                neigh_entries.append((ip, mac, state))

    all_macs = {mac for _, mac in arp_entries} | {mac for _, mac, _ in neigh_entries}
    print(f"  {INFO} /proc/net/arp entries: {len(arp_entries)}")
    print(f"  {INFO} ip neigh entries (non-failed): {len(neigh_entries)}")
    print(f"  {INFO} Unique MACs visible to scanner: {len(all_macs)}")
    if neigh_entries:
        print()
        print(f"  {'IP':<18} {'MAC':<20} {'State'}")
        print(f"  {'─'*52}")
        for ip, mac, state in sorted(neigh_entries, key=lambda x: x[0]):
            color = "\033[92m" if "REACHABLE" in state.upper() else "\033[93m"
            print(f"  {ip:<18} {mac:<20} {color}{state}\033[0m")
except Exception as e:
    print(f"  {FAIL} ARP check error: {e}")

# ── 5. DB device freshness ────────────────────────────────
section("5. Database Devices (last_seen freshness)")
try:
    import db.db as _db
    conn = _db.get_conn()
    now = datetime.now(timezone.utc)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT device_id, mac_address, device_source, last_seen
            FROM devices
            ORDER BY last_seen DESC
            LIMIT 20
        """)
        rows = cur.fetchall()
    _db.put_conn(conn)

    ONLINE_THRESHOLD = timedelta(minutes=5)
    print(f"  {'Device ID':<26} {'MAC':<20} {'Src':<12} {'Last Seen':<22} Status")
    print(f"  {'─'*90}")
    for device_id, mac, src, last_seen in rows:
        if last_seen:
            age = now - last_seen
            age_str = f"{int(age.total_seconds())}s ago"
            status = f"\033[92mONLINE\033[0m" if age < ONLINE_THRESHOLD else f"\033[91mOFFLINE\033[0m"
        else:
            age_str = "never"
            status = f"\033[91mNO DATA\033[0m"
        print(f"  {device_id:<26} {str(mac or '—'):<20} {str(src or 'network'):<12} {age_str:<22} {status}")
except Exception as e:
    print(f"  {FAIL} DB check error: {e}")

# ── 6. API reachability ───────────────────────────────────
section("6. API Reachability")
try:
    import urllib.request
    with urllib.request.urlopen("http://localhost:8000/health", timeout=3) as r:
        print(f"  {OK}  API /health → {r.status}")
except Exception:
    try:
        with urllib.request.urlopen("http://localhost:8000/api/v1/entities/", timeout=3) as r:
            print(f"  {OK}  API /api/v1/entities/ → {r.status}")
    except Exception as e:
        print(f"  {FAIL} API not reachable on :8000 — {e}")

# ── 7. Kafka connectivity ─────────────────────────────────
section("7. Kafka Connectivity")
try:
    from kafka import KafkaAdminClient
    admin = KafkaAdminClient(bootstrap_servers="localhost:9092", request_timeout_ms=3000)
    topics = admin.list_topics()
    admin.close()
    expected = {"raw_events", "enriched_events", "feature_stream", "trust_scores", "risk_scores"}
    missing = expected - set(topics)
    if missing:
        print(f"  {WARN} Kafka up but missing topics: {missing}")
    else:
        print(f"  {OK}  Kafka up, all expected topics present ({len(topics)} total)")
except Exception as e:
    print(f"  {FAIL} Kafka not reachable: {e}")

# ── 8. Running services ───────────────────────────────────
section("8. Service Processes")
services = {
    "API (uvicorn)":           "uvicorn api.main",
    "Enrichment":              "enrichment_service",
    "Feature Engine":          "feature_engine",
    "ML Monitor":              "ml_monitor",
    "Risk Engine":             "risk_engine",
    "Graph Correlator":        "graph_correlator",
    "Trust Engine":            "trust_engine",
    "Decision Engine":         "decision_engine",
    "Response Engine":         "response_engine",
    "Network Discovery":       "network_discovery_service",
    "Hardware Monitor":        "hardware_monitoring_service",
}
try:
    ps_out = subprocess.run(["ps", "aux"], capture_output=True, text=True).stdout
    for name, pattern in services.items():
        running = pattern in ps_out
        status = OK if running else FAIL
        print(f"  {status} {name}")
except Exception as e:
    print(f"  {FAIL} ps check error: {e}")

print(f"\n\033[1m{'─'*55}\033[0m")
print(f"\033[1m  Health check complete\033[0m")
print(f"\033[1m{'─'*55}\033[0m\n")
