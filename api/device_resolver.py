"""
Guardient Device Resolver
=========================
Identifies unique endpoints across the telemetry streams using deterministic DGID.

Interface merging:
  - Virtual macOS interfaces (bridge*, utun*, awdl*, llw*) → dev_ignored
  - All physical interfaces on the same host → single DGID via hostname clustering
  - Router/gateway → separate DGID via MAC

DGID = SHA256(MAC + Hostname + DeviceType + HardwareFingerprint)
"""

from __future__ import annotations
import uuid
import hashlib
import socket
from datetime import datetime, timezone
import logging

from db.db import get_conn, put_conn

logger = logging.getLogger(__name__)

# Cache local hostname once at import time
LOCAL_HOSTNAME = socket.gethostname()

IGNORE_PREFIX = ("bridge", "utun", "awdl", "llw")


def _is_local_ip(ip: str) -> bool:
    if not ip:
        return False
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")


def generate_dgid(mac: str = None, hostname: str = None, device_type: str = None, hardware: str = None) -> str:
    """Generate deterministic device ID."""
    key = f"{mac}|{hostname}|{device_type}|{hardware}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return "dev_" + digest


def lookup_alias(alias: str) -> str | None:
    if not alias:
        return None
    
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT device_id FROM device_aliases WHERE alias = %s", (alias,))
            row = cur.fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.error(f"[Resolver] Lookup error for alias {alias}: {exc}")
        conn.rollback()
        return None
    finally:
        put_conn(conn)


def store_device_and_aliases(device_id: str, aliases: list[tuple[str, str]], metadata: dict):
    """Upsert device metadata and array of aliases."""
    now = datetime.now(timezone.utc)
    
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # 1. Update/Create the device record metadata
            cur.execute(
                """
                INSERT INTO devices (device_id, first_seen, last_seen, hostname, os, mac_address, device_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (device_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                    os = COALESCE(EXCLUDED.os, devices.os),
                    mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                    device_type = COALESCE(EXCLUDED.device_type, devices.device_type)
                """,
                (device_id, now, now, metadata.get("hostname"), metadata.get("os"), 
                 metadata.get("mac_address"), metadata.get("device_type"))
            )
            
            # 2. Insert/Backfill all aliases — ON CONFLICT UPDATE so
            #    late-arriving hostnames can re-point orphaned MACs
            for alias, alias_type in aliases:
                if not alias:
                    continue
                cur.execute(
                    """
                    INSERT INTO device_aliases (alias, alias_type, device_id)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (alias) DO UPDATE SET device_id = EXCLUDED.device_id
                    """,
                    (alias, alias_type, device_id)
                )
        conn.commit()
    except Exception as exc:
        logger.error(f"[Resolver] Create device error: {exc}")
        conn.rollback()
    finally:
        put_conn(conn)


def resolve_device(event: dict) -> str:
    """
    Examine incoming CanonicalEvent, compute DGID, and backfill aliases.
    
    Key behaviors:
      1. Virtual interfaces → dev_ignored (never enters pipeline)
      2. Local IPs automatically get LOCAL_HOSTNAME injected
      3. Hostname lookup is tried FIRST so all local interfaces merge
      4. MAC lookup second, IP lookup last
      5. IP alone never creates a new device
    """
    mac = event.get("mac_address")
    hostname = event.get("hostname")
    device_type = event.get("device_type")
    interface = event.get("interface", "")
    source_ip = event.get("source_ip")
    
    # ── Step 0: Ignore macOS internal virtual adapters ──
    if interface and interface.startswith(IGNORE_PREFIX):
        return "dev_ignored"
    
    # ── Step 1: Auto-inject hostname for local IPs ──
    # Even if the sniffer didn't tag it, any local IP on this machine
    # belongs to LOCAL_HOSTNAME — this prevents orphan MAC devices
    if not hostname and _is_local_ip(source_ip):
        hostname = LOCAL_HOSTNAME
        event["hostname"] = hostname
    
    # instance_id / hardware_fingerprint
    hardware = event.get("hardware_fingerprint") or event.get("resource")

    # ── Step 2: Build alias list (hostname first for clustering) ──
    aliases = []
    if hostname:
        aliases.append((hostname, "hostname"))
    if mac:
        aliases.append((mac, "mac"))
    if hardware:
        aliases.append((hardware, "hardware_fingerprint"))

    # Lookup order: hostname > mac > hardware > ip
    lookup_aliases = list(aliases)
    if source_ip:
        lookup_aliases.append((source_ip, "ip"))

    # ── Step 3: Try to find existing device ──
    for alias, _ in lookup_aliases:
        if not alias:
            continue
        existing_id = lookup_alias(alias)
        if existing_id:
            # Found! Backfill any new strong aliases and update metadata
            store_device_and_aliases(existing_id, aliases, event)
            return existing_id

    # ── Step 4: No match → create new device (only with strong aliases) ──
    if not aliases:
        return "dev_unidentified_" + uuid.uuid4().hex[:8]
        
    dgid = generate_dgid(mac=mac, hostname=hostname, device_type=device_type, hardware=hardware)
    store_device_and_aliases(dgid, aliases, event)
    return dgid
