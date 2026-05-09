"""
Guardient Database Layer
========================
PostgreSQL connection pool + schema bootstrap + write helpers.

All pipeline services import from here.
Connection is lazy — first call to get_conn() opens the pool.

Tables
------
  devices       — device registry (upserted by enrichment_service)
  events        — all enriched events
  features      — feature vectors (feature_engine)
  ml_scores     — anomaly scores (ml_monitor)
  risk_scores   — risk 0-100 (risk_engine)
  trust_scores  — trust 0-100 (trust_engine)
  alerts        — fired alerts (decision_engine)
"""

from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.extras import Json

DB_HOST     = os.getenv("DB_HOST",     "localhost")
DB_PORT     = int(os.getenv("DB_PORT", "5432"))
DB_NAME     = os.getenv("DB_NAME",     "guardient")
DB_USER     = os.getenv("DB_USER",     "guardient")
DB_PASSWORD = os.getenv("DB_PASSWORD", "guardient")

_pool: Optional[pg_pool.SimpleConnectionPool] = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    device_id       TEXT PRIMARY KEY,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    hostname        TEXT,
    os              TEXT,
    mac_address     TEXT,
    device_type     TEXT,
    enrichment      JSONB
);

CREATE TABLE IF NOT EXISTS device_aliases (
    alias       TEXT PRIMARY KEY,
    alias_type  TEXT,
    device_id   TEXT REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    device_id   TEXT,
    source      TEXT,
    event_type  TEXT,
    timestamp   TIMESTAMPTZ,
    ip          TEXT,
    raw         JSONB
);

CREATE TABLE IF NOT EXISTS features (
    event_id    TEXT PRIMARY KEY,
    device_id   TEXT,
    source      TEXT,
    timestamp   TIMESTAMPTZ,
    features    JSONB
);

CREATE TABLE IF NOT EXISTS ml_scores (
    event_id        TEXT PRIMARY KEY,
    device_id       TEXT,
    source          TEXT,
    timestamp       TIMESTAMPTZ,
    anomaly_score   FLOAT,
    anomaly_reasons JSONB
);

CREATE TABLE IF NOT EXISTS risk_scores (
    id          SERIAL PRIMARY KEY,
    event_id    TEXT,
    device_id   TEXT,
    source      TEXT,
    timestamp   TIMESTAMPTZ,
    risk_score  INTEGER,
    severity    TEXT
);

CREATE TABLE IF NOT EXISTS trust_scores (
    id              SERIAL PRIMARY KEY,
    device_id       TEXT,
    source          TEXT,
    timestamp       TIMESTAMPTZ,
    trust_score     FLOAT,
    adjusted_risk   FLOAT,
    device_type     TEXT,
    category        TEXT,
    trust_reasons   JSONB
);

CREATE TABLE IF NOT EXISTS trust_states (
    device_id       TEXT PRIMARY KEY,
    state           JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT PRIMARY KEY,
    device_id       TEXT,
    ip              TEXT,
    source          TEXT,
    event_type      TEXT,
    severity        TEXT,
    risk_score      INTEGER,
    trust_score     INTEGER,
    anomaly_reasons JSONB,
    action          TEXT,
    timestamp       TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS device_baselines (
    device_id       TEXT PRIMARY KEY,
    baseline        JSONB NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_correlation_events (
    id              SERIAL PRIMARY KEY,
    event_id        TEXT,
    device_id       TEXT,
    timestamp       TIMESTAMPTZ,
    attack_path     JSONB,
    path_length     INTEGER,
    graph_caf       FLOAT,
    risk_score      INTEGER
);

CREATE TABLE IF NOT EXISTS feedback_labels (
    id              SERIAL PRIMARY KEY,
    alert_id        TEXT,
    device_id       TEXT,
    detection_type  TEXT,
    label           TEXT,
    analyst         TEXT,
    timestamp       TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS feedback_weights (
    detection_type  TEXT PRIMARY KEY,
    weight          FLOAT NOT NULL DEFAULT 1.0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS simulation_runs (
    run_id          TEXT PRIMARY KEY,
    device_id       TEXT,
    attack_type     TEXT,
    status          TEXT,
    started_at      TIMESTAMPTZ,
    ended_at        TIMESTAMPTZ,
    parameters      JSONB
);

CREATE TABLE IF NOT EXISTS response_actions (
    action_id       TEXT PRIMARY KEY,
    device_id       TEXT,
    trust_score     FLOAT,
    action          TEXT,
    triggered_at    TIMESTAMPTZ
);

-- ── Response Executor (new system) ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS response_executions (
    execution_id      TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL,
    action            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'pending',
    triggered_by      TEXT NOT NULL DEFAULT 'system',
    trust_score       FLOAT,
    risk_score        FLOAT,
    severity          TEXT,
    requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
    approved_by       TEXT,
    rejected_by       TEXT,
    rejection_reason  TEXT,
    description       TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_re_device   ON response_executions(device_id);
CREATE INDEX IF NOT EXISTS idx_re_status   ON response_executions(status);
CREATE INDEX IF NOT EXISTS idx_re_created  ON response_executions(created_at DESC);

CREATE TABLE IF NOT EXISTS device_blocks (
    block_id        TEXT PRIMARY KEY,
    device_id       TEXT NOT NULL UNIQUE,
    action          TEXT NOT NULL DEFAULT 'block_device',
    reason          TEXT,
    blocked_by      TEXT NOT NULL DEFAULT 'system',
    unblocked_by    TEXT,
    blocked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    unblocked_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_db_active ON device_blocks(device_id) WHERE is_active = TRUE;
"""


def _get_pool() -> pg_pool.SimpleConnectionPool:
    global _pool
    if _pool is None:
        _pool = pg_pool.SimpleConnectionPool(
            minconn=1, maxconn=10,
            host=DB_HOST, port=DB_PORT,
            database=DB_NAME, user=DB_USER, password=DB_PASSWORD,
        )
    return _pool


def get_conn():
    return _get_pool().getconn()


def put_conn(conn):
    _get_pool().putconn(conn)


def execute(sql: str, values: tuple):
    """Run a single INSERT/UPDATE. Auto-commits, returns connection to pool."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, values)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"[DB ERROR] {exc}")
    finally:
        put_conn(conn)


def init_schema():
    """Create all tables if they don't exist. Safe to call multiple times."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
        conn.commit()
        print("[DB] Schema initialised.")
    except Exception as exc:
        conn.rollback()
        print(f"[DB] Schema error: {exc}")
    finally:
        put_conn(conn)


# ── Per-stage write helpers ───────────────────────────────

def upsert_device(device_id: str, mac: Optional[str], os: Optional[str],
                  device_type: Optional[str], hostname: Optional[str],
                  enrichment: dict, timestamp: str):
    execute("""
        INSERT INTO devices (device_id, first_seen, last_seen, hostname,
                             os, mac_address, device_type, enrichment)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (device_id) DO UPDATE
            SET last_seen   = EXCLUDED.last_seen,
                hostname    = COALESCE(EXCLUDED.hostname, devices.hostname),
                os          = COALESCE(EXCLUDED.os, devices.os),
                mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                device_type = COALESCE(EXCLUDED.device_type, devices.device_type),
                enrichment  = EXCLUDED.enrichment
    """, (device_id, timestamp, timestamp, hostname, os, mac, device_type, Json(enrichment)))


def insert_event(event: dict):
    execute("""
        INSERT INTO events (event_id, device_id, source, event_type, timestamp, ip, raw)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_id) DO NOTHING
    """, (
        event.get("event_id"), event.get("device_id"),
        event.get("source"),   event.get("event_type"),
        event.get("timestamp"), event.get("ip"),
        Json(event),
    ))


def insert_features(event: dict):
    execute("""
        INSERT INTO features (event_id, device_id, source, timestamp, features)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (event_id) DO NOTHING
    """, (
        event.get("event_id"), event.get("device_id"),
        event.get("source"),   event.get("timestamp"),
        Json(event.get("features", {})),
    ))


def insert_ml_score(event: dict):
    execute("""
        INSERT INTO ml_scores (event_id, device_id, source, timestamp,
                               anomaly_score, anomaly_reasons)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON CONFLICT (event_id) DO NOTHING
    """, (
        event.get("event_id"),       event.get("device_id"),
        event.get("source"),         event.get("timestamp"),
        event.get("anomaly_score"),  Json(event.get("anomaly_reasons", [])),
    ))


def insert_risk_score(event: dict):
    execute("""
        INSERT INTO risk_scores (event_id, device_id, source, timestamp,
                                 risk_score, severity)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        event.get("event_id"),   event.get("device_id"),
        event.get("source"),     event.get("timestamp"),
        event.get("risk_score"), event.get("severity"),
    ))


def insert_trust_score(event: dict):
    execute("""
        INSERT INTO trust_scores (device_id, source, timestamp,
                                  trust_score, adjusted_risk, device_type,
                                  category, trust_reasons)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        event.get("device_id"),       event.get("source"),
        event.get("timestamp"),       event.get("trust_score"),
        event.get("adjusted_risk"),   event.get("device_type"),
        event.get("category"),        Json(event.get("trust_reasons", [])),
    ))


def insert_alert(alert: dict):
    execute("""
        INSERT INTO alerts (alert_id, device_id, ip, source, event_type,
                            severity, risk_score, trust_score,
                            anomaly_reasons, action, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (alert_id) DO NOTHING
    """, (
        alert.get("alert_id"),         alert.get("device_id"),
        alert.get("ip"),               alert.get("source"),
        alert.get("event_type"),       alert.get("severity"),
        alert.get("risk_score"),       alert.get("trust_score"),
        Json(alert.get("anomaly_reasons", [])),
        alert.get("action"),           alert.get("timestamp"),
    ))


def load_baseline(device_id: str) -> dict:
    """Load Welford baseline for a device from the DB. Returns empty dict if new device."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT baseline FROM device_baselines WHERE device_id = %s", (device_id,))
            row = cur.fetchone()
        return row[0] if row else {}
    except Exception as exc:
        conn.rollback()
        print(f"[DB] load_baseline error: {exc}")
        return {}
    finally:
        put_conn(conn)


def save_baseline(device_id: str, baseline: dict):
    """Upsert the Welford baseline state for a device."""
    execute("""
        INSERT INTO device_baselines (device_id, baseline, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (device_id) DO UPDATE
            SET baseline   = EXCLUDED.baseline,
                updated_at = EXCLUDED.updated_at
    """, (device_id, Json(baseline)))


def load_trust_state(device_id: str) -> dict:
    """Load per-device I/C/V/N trust state from DB. Returns fresh state if new device."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT state FROM trust_states WHERE device_id = %s", (device_id,))
            row = cur.fetchone()
        if row:
            return row[0]
        return {"I": 0.0, "C": 0.0, "V": 0.0, "N": 0.0, "AR_prev": 0.0, "last_timestamp": 0.0}
    except Exception as exc:
        conn.rollback()
        print(f"[DB] load_trust_state error: {exc}")
        return {"I": 0.0, "C": 0.0, "V": 0.0, "N": 0.0, "AR_prev": 0.0, "last_timestamp": 0.0}
    finally:
        put_conn(conn)


def save_trust_state(device_id: str, state: dict):
    """Upsert the I/C/V/N trust state for a device."""
    execute("""
        INSERT INTO trust_states (device_id, state, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (device_id) DO UPDATE
            SET state      = EXCLUDED.state,
                updated_at = EXCLUDED.updated_at
    """, (device_id, Json(state)))


def insert_graph_event(event: dict):
    """Persist a graph correlation event to PostgreSQL."""
    execute("""
        INSERT INTO graph_correlation_events
            (event_id, device_id, timestamp, attack_path, path_length, graph_caf, risk_score)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        event.get("event_id"),  event.get("device_id"),
        event.get("timestamp"), Json(event.get("attack_path", [])),
        event.get("path_length", 0),
        event.get("graph_caf", 1.0),
        event.get("risk_score", 0),
    ))


def insert_feedback_label(alert_id: str, device_id: str, detection_type: str,
                           label: str, analyst: str):
    """Record an analyst feedback label for an alert."""
    execute("""
        INSERT INTO feedback_labels (alert_id, device_id, detection_type, label, analyst)
        VALUES (%s, %s, %s, %s, %s)
    """, (alert_id, device_id, detection_type, label, analyst))


def load_feedback_weights() -> dict:
    """Load all per-detection feedback weights. Returns {detection_type: weight}."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT detection_type, weight FROM feedback_weights")
            rows = cur.fetchall()
        return {r[0]: float(r[1]) for r in rows} if rows else {}
    except Exception as exc:
        conn.rollback()
        print(f"[DB] load_feedback_weights error: {exc}")
        return {}
    finally:
        put_conn(conn)


def upsert_feedback_weight(detection_type: str, weight: float):
    """Upsert the learned feedback weight for a detection type."""
    execute("""
        INSERT INTO feedback_weights (detection_type, weight, updated_at)
        VALUES (%s, %s, NOW())
        ON CONFLICT (detection_type) DO UPDATE
            SET weight     = EXCLUDED.weight,
                updated_at = EXCLUDED.updated_at
    """, (detection_type, weight))


def insert_simulation_run(run_id: str, device_id: str, attack_type: str, status: str, parameters: dict):
    execute("""
        INSERT INTO simulation_runs (run_id, device_id, attack_type, status, started_at, parameters)
        VALUES (%s, %s, %s, %s, NOW(), %s)
    """, (run_id, device_id, attack_type, status, Json(parameters)))


def update_simulation_run_status(run_id: str, status: str):
    execute("""
        UPDATE simulation_runs
        SET status = %s,
            ended_at = CASE WHEN %s IN ('completed', 'failed', 'stopped') THEN NOW() ELSE ended_at END
        WHERE run_id = %s
    """, (status, status, run_id))


def get_simulation_runs() -> list:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT run_id, device_id, attack_type, status, started_at, ended_at, parameters FROM simulation_runs ORDER BY started_at DESC LIMIT 100")
            rows = cur.fetchall()
            return [
                {
                    "run_id": r[0],
                    "device_id": r[1],
                    "attack_type": r[2],
                    "status": r[3],
                    "started_at": r[4].isoformat() if r[4] else None,
                    "ended_at": r[5].isoformat() if r[5] else None,
                    "parameters": r[6]
                }
                for r in rows
            ]
    except Exception as exc:
        conn.rollback()
        print(f"[DB] get_simulation_runs error: {exc}")
        return []
    finally:
        put_conn(conn)


def insert_response_action(action_id: str, device_id: str, trust_score: float, action: str):
    execute("""
        INSERT INTO response_actions (action_id, device_id, trust_score, action, triggered_at)
        VALUES (%s, %s, %s, %s, NOW())
    """, (action_id, device_id, trust_score, action))


def get_response_actions(limit=50) -> list:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT action_id, device_id, trust_score, action, triggered_at FROM response_actions ORDER BY triggered_at DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
            return [
                {
                    "action_id": r[0],
                    "device_id": r[1],
                    "trust_score": r[2],
                    "action": r[3],
                    "triggered_at": r[4].isoformat() if r[4] else None
                }
                for r in rows
            ]
    except Exception as exc:
        conn.rollback()
        print(f"[DB] get_response_actions error: {exc}")
        return []
    finally:
        put_conn(conn)


# ── Response Executor DB helpers ─────────────────────────────────────────────

def insert_response_execution(record: dict):
    """Insert a new execution record. Called by ResponseExecutor.execute()."""
    execute("""
        INSERT INTO response_executions (
            execution_id, device_id, action, status, triggered_by,
            trust_score, risk_score, severity, requires_approval,
            approved_by, rejected_by, rejection_reason, description,
            metadata, created_at, updated_at, executed_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (execution_id) DO NOTHING
    """, (
        record["execution_id"], record["device_id"], record["action"],
        record["status"], record["triggered_by"],
        record.get("trust_score"), record.get("risk_score"), record.get("severity"),
        record.get("requires_approval", False),
        record.get("approved_by"), record.get("rejected_by"),
        record.get("rejection_reason"), record.get("description"),
        Json(record.get("metadata", {})),
        record.get("created_at"), record.get("updated_at"), record.get("executed_at"),
    ))


def update_execution_status(
    execution_id: str,
    status: str,
    approved_by: Optional[str] = None,
    rejected_by: Optional[str] = None,
    rejection_reason: Optional[str] = None,
    executed_at: Optional[str] = None,
    metadata_extra: Optional[dict] = None,
):
    """Update status + optional fields on an execution record."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE response_executions SET
                    status           = %s,
                    updated_at       = NOW(),
                    approved_by      = COALESCE(%s, approved_by),
                    rejected_by      = COALESCE(%s, rejected_by),
                    rejection_reason = COALESCE(%s, rejection_reason),
                    executed_at      = COALESCE(%s::TIMESTAMPTZ, executed_at),
                    metadata         = CASE
                                         WHEN %s::JSONB IS NOT NULL
                                         THEN metadata || %s::JSONB
                                         ELSE metadata
                                       END
                WHERE execution_id = %s
            """, (
                status,
                approved_by, rejected_by, rejection_reason,
                executed_at,
                Json(metadata_extra) if metadata_extra else None,
                Json(metadata_extra) if metadata_extra else None,
                execution_id,
            ))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"[DB] update_execution_status error: {exc}")
    finally:
        put_conn(conn)


def get_execution(execution_id: str) -> Optional[dict]:
    """Fetch a single execution record by ID."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT execution_id, device_id, action, status, triggered_by,
                       trust_score, risk_score, severity, requires_approval,
                       approved_by, rejected_by, rejection_reason, description,
                       metadata, created_at, updated_at, executed_at
                FROM response_executions
                WHERE execution_id = %s
            """, (execution_id,))
            row = cur.fetchone()
        if not row:
            return None
        cols = [
            "execution_id","device_id","action","status","triggered_by",
            "trust_score","risk_score","severity","requires_approval",
            "approved_by","rejected_by","rejection_reason","description",
            "metadata","created_at","updated_at","executed_at",
        ]
        rec = dict(zip(cols, row))
        for ts_field in ("created_at", "updated_at", "executed_at"):
            if rec.get(ts_field) and hasattr(rec[ts_field], "isoformat"):
                rec[ts_field] = rec[ts_field].isoformat()
        return rec
    except Exception as exc:
        conn.rollback()
        print(f"[DB] get_execution error: {exc}")
        return None
    finally:
        put_conn(conn)


def list_response_executions(
    device_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 200,
) -> list:
    """List execution records, optionally filtered by device and/or status."""
    conn = get_conn()
    try:
        filters, params = [], []
        if device_id:
            filters.append("device_id = %s"); params.append(device_id)
        if status:
            filters.append("status = %s"); params.append(status)
        where = ("WHERE " + " AND ".join(filters)) if filters else ""
        params.append(limit)

        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT execution_id, device_id, action, status, triggered_by,
                       trust_score, risk_score, severity, requires_approval,
                       approved_by, rejected_by, rejection_reason, description,
                       metadata, created_at, updated_at, executed_at
                FROM response_executions
                {where}
                ORDER BY created_at DESC
                LIMIT %s
            """, params)
            cols = [
                "execution_id","device_id","action","status","triggered_by",
                "trust_score","risk_score","severity","requires_approval",
                "approved_by","rejected_by","rejection_reason","description",
                "metadata","created_at","updated_at","executed_at",
            ]
            rows = []
            for row in cur.fetchall():
                rec = dict(zip(cols, row))
                for ts_field in ("created_at", "updated_at", "executed_at"):
                    if rec.get(ts_field) and hasattr(rec[ts_field], "isoformat"):
                        rec[ts_field] = rec[ts_field].isoformat()
                rows.append(rec)
        return rows
    except Exception as exc:
        conn.rollback()
        print(f"[DB] list_response_executions error: {exc}")
        return []
    finally:
        put_conn(conn)


def upsert_device_block(device_id: str, action: str, blocked_by: str):
    """Register or refresh a device block in the device_blocks table."""
    import uuid as _uuid
    block_id = f"BLK-{device_id[:8]}-{_uuid.uuid4().hex[:6]}"
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO device_blocks (block_id, device_id, action, blocked_by, blocked_at, is_active)
                VALUES (%s, %s, %s, %s, NOW(), TRUE)
                ON CONFLICT (device_id) DO UPDATE
                    SET block_id     = EXCLUDED.block_id,
                        action       = EXCLUDED.action,
                        blocked_by   = EXCLUDED.blocked_by,
                        blocked_at   = NOW(),
                        unblocked_by = NULL,
                        unblocked_at = NULL,
                        is_active    = TRUE
            """, (block_id, device_id, action, blocked_by))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"[DB] upsert_device_block error: {exc}")
    finally:
        put_conn(conn)


def remove_device_block(device_id: str, unblocked_by: str):
    """Mark a device block as inactive (unblocked)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE device_blocks
                SET is_active    = FALSE,
                    unblocked_by = %s,
                    unblocked_at = NOW()
                WHERE device_id = %s AND is_active = TRUE
            """, (unblocked_by, device_id))
        conn.commit()
    except Exception as exc:
        conn.rollback()
        print(f"[DB] remove_device_block error: {exc}")
    finally:
        put_conn(conn)


def list_device_blocks(active_only: bool = True) -> list:
    """List all device blocks, optionally only active ones."""
    conn = get_conn()
    try:
        where = "WHERE is_active = TRUE" if active_only else ""
        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT block_id, device_id, action, reason, blocked_by,
                       unblocked_by, blocked_at, unblocked_at, is_active
                FROM device_blocks
                {where}
                ORDER BY blocked_at DESC
                LIMIT 500
            """)
            cols = [
                "block_id","device_id","action","reason","blocked_by",
                "unblocked_by","blocked_at","unblocked_at","is_active",
            ]
            rows = []
            for row in cur.fetchall():
                rec = dict(zip(cols, row))
                for ts_field in ("blocked_at", "unblocked_at"):
                    if rec.get(ts_field) and hasattr(rec[ts_field], "isoformat"):
                        rec[ts_field] = rec[ts_field].isoformat()
                rows.append(rec)
        return rows
    except Exception as exc:
        conn.rollback()
        print(f"[DB] list_device_blocks error: {exc}")
        return []
    finally:
        put_conn(conn)


def is_device_blocked(device_id: str) -> bool:
    """Quick check: is this device currently in an active block?"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM device_blocks WHERE device_id = %s AND is_active = TRUE LIMIT 1",
                (device_id,)
            )
            return cur.fetchone() is not None
    except Exception as exc:
        conn.rollback()
        return False
    finally:
        put_conn(conn)


if __name__ == "__main__":
    init_schema()
    print("[DB] Ready.")
