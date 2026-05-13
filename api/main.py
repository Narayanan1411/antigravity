"""
Guardient Ingestion API  v1
============================
FastAPI server. Four endpoints — one per telemetry category.
Each endpoint:
  1. validates the API key
  2. normalises the payload into standard GuardientEvent dicts
  3. publishes each event to Kafka topic: raw_events
  4. saves locally to <category>.jsonl as fallback

Run:
    cd "/Users/kselvanarayanan/Desktop/poc Guardient"
    python3 -m uvicorn api.main:app --port 8000
"""

import os
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.topics import RAW_EVENTS
from api.schema import (
    events_from_network,
    events_from_identity,
    events_from_cloud,
    events_from_hardware,
)
from api.device_resolver import resolve_device
from dotenv import load_dotenv
load_dotenv()

from api.v1 import router as v1_router

# ── API keys ──────────────────────────────────────────────
KEYS = {
    "network":  os.getenv("NETWORK_KEY",  "NET-KEY-2F4A8C1B"),
    "identity": os.getenv("IDENTITY_KEY", "IDN-KEY-7E3B9D2A"),
    "cloud":    os.getenv("CLOUD_KEY",    "CLD-KEY-5C1F4A8E"),
    "hardware": os.getenv("HARDWARE_KEY", "HW-KEY-3A9D7F2C"),
}

LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Guardient Telemetry API", version="1.0")

# ── CORS — allow the Next.js dev server ───────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Frontend bridge: v1 REST API ──────────────────────────
app.include_router(v1_router, prefix="/api/v1")


@app.on_event("startup")
def _startup_block_sync():
    """
    On every API startup:
    1. Create the nft guardient_blocks chain (priority -10) so block/unblock
       works immediately without needing a separate setup step.
       This chain fires BEFORE NM's filter chains, so DROP rules execute
       before any ACCEPT — the device loses internet but stays on the hotspot.
    2. Re-apply nft DROP rules for any device that was blocked in the DB.
       (nftables rules are not persistent across reboots — we recreate them.)
    3. Clear stale DB block records for devices no longer in the devices table.
    """
    try:
        from response_executor.handlers import ensure_guardient_chain, reapply_active_blocks
        import db.db as _db

        # Always ensure the nft chain exists — it's wiped on every reboot
        ok, msg = ensure_guardient_chain()
        if ok:
            print(f"[Startup] nft guardient_blocks chain ready")
        else:
            print(f"[Startup] nft chain setup warning: {msg}")

        # Fetch active DB blocks and re-apply their nft rules
        conn = _db.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT db.device_id, db.action, db.reason, db.blocked_by,
                           d.mac_address, d.last_ip
                    FROM device_blocks db
                    LEFT JOIN devices d ON d.device_id = db.device_id
                    WHERE db.is_active = TRUE
                """)
                rows = cur.fetchall()
                cols = ["device_id", "action", "reason", "blocked_by", "mac_address", "last_ip"]
                active_blocks = [dict(zip(cols, r)) for r in rows]
        finally:
            _db.put_conn(conn)

        if active_blocks:
            print(f"[Startup] Re-applying {len(active_blocks)} active block(s)...")
            reapply_active_blocks(active_blocks)
        else:
            print("[Startup] No active blocks — system is clean")

        # Remove stale is_active=TRUE rows for devices no longer in devices table
        conn = _db.get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE device_blocks
                       SET is_active = FALSE,
                           unblocked_by = 'startup_cleanup',
                           unblocked_at = NOW()
                     WHERE is_active = TRUE
                       AND device_id NOT IN (SELECT device_id FROM devices)
                """)
                stale = cur.rowcount
            conn.commit()
            if stale:
                print(f"[Startup] Cleared {stale} stale block(s) for non-existent devices")
        finally:
            _db.put_conn(conn)

    except Exception as exc:
        print(f"[Startup] Block sync error (non-fatal): {exc}")


def _check_key(category: str, key: Optional[str]):
    if key != KEYS[category]:
        raise HTTPException(status_code=403, detail="Invalid API key")


def _save_local(category: str, events: list):
    path = LOG_DIR / f"{category}.jsonl"
    with open(path, "a") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def _ingest(category: str, events: list) -> dict:
    published = 0
    for ev in events:
        # Resolve stable device ID before it enters Kafka
        device_id = resolve_device(ev)
        ev["device_id"] = device_id
        
        # Drop virtual-interface noise — never enters the pipeline
        if device_id == "dev_ignored":
            continue
        
        if publish_event(RAW_EVENTS, ev):
            published += 1
    _save_local(category, events)
    return {
        "status":        "ok",
        "category":      category,
        "events":        len(events),
        "published":     published,
        "saved_locally": len(events),
        "timestamp":     datetime.now(tz=timezone.utc).isoformat(),
    }


# ═══════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════

@app.post("/network/telemetry")
async def ingest_network(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _check_key("network", x_api_key)
    body   = await request.json()
    events = events_from_network(body)
    
    # Aggregation for Pipeline — prevents 10x risk inflation from flow batches
    # We still log ALL individual flows locally for forensics
    _save_local("network", events)
    
    device_summaries = {}
    for ev in events:
        did = ev["device_id"]
        if did not in device_summaries:
            device_summaries[did] = ev.copy()
            device_summaries[did]["bytes_sent"] = 0
            device_summaries[did]["bytes_received"] = 0
            device_summaries[did]["packet_count"] = 0
            device_summaries[did]["event_type"] = "network_summary"
        
        device_summaries[did]["bytes_sent"] += (ev.get("bytes_sent") or 0)
        device_summaries[did]["bytes_received"] += (ev.get("bytes_received") or 0)
        device_summaries[did]["packet_count"] += (ev.get("packet_count") or 0)
    
    # Attach root ML scores to the summaries
    ml_score = body.get("ml_anomaly_score")
    ml_is_anomaly = body.get("ml_is_anomaly")
    
    published = 0
    for did, summary in device_summaries.items():
        if ml_score is not None:
            summary["ml_anomaly_score"] = ml_score
            summary["ml_is_anomaly"] = ml_is_anomaly
            
        if publish_event(RAW_EVENTS, summary):
            published += 1
            
    return {
        "status": "ok",
        "events": len(events),
        "published_summaries": published,
        "timestamp": datetime.now(tz=timezone.utc).isoformat()
    }


@app.post("/identity/events")
async def ingest_identity(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _check_key("identity", x_api_key)
    body   = await request.json()
    events = events_from_identity(body)
    return _ingest("identity", events)


@app.post("/cloud/events")
async def ingest_cloud(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _check_key("cloud", x_api_key)
    body   = await request.json()
    events = events_from_cloud(body)
    return _ingest("cloud", events)


@app.post("/hardware/profile")
async def ingest_hardware(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    _check_key("hardware", x_api_key)
    body   = await request.json()
    events = events_from_hardware(body)
    return _ingest("hardware", events)


@app.post("/temporal/metrics")
async def ingest_temporal(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
):
    body = await request.json()
    _save_local("temporal", [body])
    return {"status": "ok", "category": "temporal", "saved_locally": 1}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "guardient-api"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
