"""
Guardient API v1 — Frontend Bridge
====================================
Mounted at /api/v1 by api/main.py.
Reads real-time data from PostgreSQL to serve the techgium frontend.

Endpoints
----------
GET  /api/v1/entities/           → all devices + latest trust/risk
GET  /api/v1/audit/              → alerts table shaped as AuditLog[]
GET  /api/v1/transparency/stats  → aggregate event counts + severity
POST /api/v1/response/approve    → simulated SOC action (logs to alerts table)
"""

from __future__ import annotations
import uuid
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from db.db import get_conn, put_conn, get_simulation_runs, get_response_actions

router = APIRouter()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

import json
import math
import time

# ─────────────────────────────────────────────
# Trust Decay Constants (Mirrors services/trust_engine.py)
# ─────────────────────────────────────────────
K_DECAY = 2.5
ALPHA_CAF = 0.6
WEIGHTS = {"I": 0.40, "C": 0.25, "V": 0.20, "N": 0.15}
BASE_LAMBDA = 0.002

DEVICE_DECAY_FACTORS = {
    "server": 0.4, "domain_controller": 0.3, "network_device": 0.5,
    "laptop": 1.0, "workstation": 1.0, "phone": 1.2, "iot": 0.7,
    "unknown": 1.0
}

def _apply_read_time_decay(state: dict | str, device_type: str) -> tuple[float, float, dict]:
    """
    Applies mathematical decay to the I/C/V/N risk states based on time elapsed.
    Returns (decayed_trust, decayed_adj_risk, updated_state_dict).
    """
    if not state:
        return 80.0, 0.0, {"I": 0, "C": 0, "V": 0, "N": 0}

    # Handle Postgres JSONB potentially coming back as string or dict
    if isinstance(state, str):
        try:
            state = json.loads(state)
        except:
            return 80.0, 0.0, {"I": 0, "C": 0, "V": 0, "N": 0}

    last_ts = float(state.get("last_timestamp", 0))
    if last_ts == 0:
        return 80.0, 0.0, state

    now = time.time()
    dt = max(0, now - last_ts)

    # If dt is very small, return pre-decay values to avoid math noise
    if dt < 1.0:
        # Re-calc for current state
        AR = (WEIGHTS["I"] * float(state.get("I", 0)) +
              WEIGHTS["C"] * float(state.get("C", 0)) +
              WEIGHTS["V"] * float(state.get("V", 0)) +
              WEIGHTS["N"] * float(state.get("N", 0)))
        active = sum(float(state.get(c, 0)) for c in "ICVN")
        max_val = max(float(state.get(c, 0)) for c in "ICVN")
        CAF = 1.0 + ALPHA_CAF * (active - max_val)
        adj = AR * CAF
        trust = round(100.0 * math.exp(-K_DECAY * adj), 2)
        return trust, adj, state

    d_fact = DEVICE_DECAY_FACTORS.get(str(device_type).lower(), 1.0)
    lam = BASE_LAMBDA * d_fact

    # 1. Decay each category risk
    decayed_state = {}
    for cat in ["I", "C", "V", "N"]:
        val = float(state.get(cat, 0))
        decayed_state[cat] = val * math.exp(-lam * dt)

    # 2. Re-calculate AR (Aggregated Risk)
    AR = (WEIGHTS["I"] * decayed_state["I"] +
          WEIGHTS["C"] * decayed_state["C"] +
          WEIGHTS["V"] * decayed_state["V"] +
          WEIGHTS["N"] * decayed_state["N"])

    # 3. Re-calculate CAF (Correlation Amplification)
    active = sum(decayed_state.values())
    max_val = max(decayed_state.values()) if decayed_state.values() else 0
    CAF = 1.0 + ALPHA_CAF * (active - max_val)

    # 4. Re-calculate Adjusted Risk
    adj = AR * CAF

    # 5. Re-calculate Trust Score
    trust = round(100.0 * math.exp(-K_DECAY * adj), 2)

    return trust, adj, decayed_state


def _trust_to_decision(trust: float) -> dict:
    """Map numeric trust score to frontend decision/action fields."""
    trust = float(trust or 80)
    if trust >= 80:
        return {"decision": "trusted",   "active_actions": [],                    "approval_required": False}
    if trust >= 60:
        return {"decision": "monitor",   "active_actions": ["monitor"],           "approval_required": False}
    if trust >= 40:
        return {"decision": "monitor",   "active_actions": ["require_mfa"],       "approval_required": False}
    if trust >= 20:
        return {"decision": "isolate",   "active_actions": ["restrict_network"],  "approval_required": True}
    return     {"decision": "emergency", "active_actions": ["lock_account"],      "approval_required": True}


def _pct(v) -> float:
    return round(min(100.0, float(v or 0) * 100), 1)


def _build_category_breakdown(state: dict) -> dict:
    """Convert I/C/V/N risk magnitudes from trust_states to frontend category_breakdown."""
    return {
        "network":  _pct(state.get("N", 0)),
        "identity": _pct(state.get("I", 0)),
        "cloud":    _pct(state.get("C", 0)),
        "hardware": _pct(state.get("V", 0)),
        "temporal": 0,
    }


def _build_trust_evaluation(device_id: str, trust: float, adj: float,
                             state: dict, ts) -> dict:
    """Build the TrustEvaluation object the entity detail page expects."""
    n = float(state.get("N", 0) or 0)
    i = float(state.get("I", 0) or 0)
    c = float(state.get("C", 0) or 0)
    v = float(state.get("V", 0) or 0)

    def _cat(rc, signals):
        return {"weight": 0.25, "Rc": round(float(rc), 4), "delta": 0.0, "signals": signals}

    ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts or "")

    return {
        "entity_id":            device_id,
        "timestamp":            ts_str,
        "simulation":           False,
        "final_trust_score":    round(float(trust), 1),
        "previous_trust_score": round(float(trust), 1),
        "confidence":           round(min(100, max(0, (1 - adj) * 100)), 1),
        "decision":             _trust_to_decision(trust)["decision"],
        "trust_evaluation": {
            "network":  _cat(n, ["bytes_total", "port_risk"] if n > 0 else []),
            "identity": _cat(i, ["login_failure"]         if i > 0 else []),
            "cloud":    _cat(c, ["api_call"]              if c > 0 else []),
            "hardware": _cat(v, ["cpu_spike"]             if v > 0 else []),
            "temporal": _cat(0, []),
        },
    }


# ─────────────────────────────────────────────
# GET /entities/
# ─────────────────────────────────────────────

@router.get("/entities/")
def get_entities():
    """
    Returns all devices with their latest trust score and metadata.

    Strategy:
    - Fetch all devices from the `devices` table
    - For EACH device, LATERAL-join its latest trust_score
    - Join trust_states on device_id (supports dev_* format ids)
    - Handles NULL adjusted_risk gracefully
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    d.device_id,
                    d.hostname,
                    d.mac_address,
                    d.os,
                    d.device_type,
                    d.last_seen,
                    COALESCE(ts.trust_score, 80)       AS trust_score,
                    COALESCE(ts.adjusted_risk, 0.0)    AS adjusted_risk,
                    COALESCE(ts.timestamp, d.last_seen) AS score_ts,
                    tst.state                           AS trust_state,
                    (
                        SELECT ip FROM events
                        WHERE device_id = d.device_id
                        ORDER BY timestamp DESC LIMIT 1
                    ) AS last_ip
                FROM devices d
                LEFT JOIN LATERAL (
                    SELECT trust_score, adjusted_risk, timestamp
                    FROM trust_scores
                    WHERE device_id = d.device_id
                    ORDER BY timestamp DESC
                    LIMIT 1
                ) ts ON true
                LEFT JOIN trust_states tst ON tst.device_id = d.device_id
                ORDER BY d.last_seen DESC NULLS LAST
                LIMIT 500
            """)
            rows = [dict(zip([d[0] for d in cur.description], r))
                    for r in cur.fetchall()]

        entities = []
        for row in rows:
            device_id = row["device_id"]
            dev_type  = row.get("device_type") or "unknown"
            state     = row.get("trust_state") or {}
            
            # Apply real-time decay so scores don't look static
            decay_trust, decay_adj, decayed_state = _apply_read_time_decay(state, dev_type)
            
            # Use decayed values if they are fresher/lower than DB (or always use decayed for consistency)
            # In this case, we always use decayed because state decay is a natural recovery.
            trust  = decay_trust
            adj    = decay_adj
            state  = decayed_state
            
            ts_val = row.get("score_ts") or row.get("last_seen")
            dec    = _trust_to_decision(trust)
            confidence = round(min(100, max(0, (1 - adj) * 100)), 1)
            cat_bd = _build_category_breakdown(state)
            te     = _build_trust_evaluation(
                device_id, trust, adj, state, ts_val
            )

            ts_str = datetime.now(timezone.utc).isoformat()

            entities.append({
                "entity_id":         row["device_id"],
                "trust_score":       round(trust, 1),
                "confidence":        confidence,
                "decision":          dec["decision"],
                "category_breakdown": cat_bd,
                "last_updated":      ts_str,
                "active_actions":    dec["active_actions"],
                "last_action":       dec["active_actions"][0] if dec["active_actions"] else None,
                "approval_required": dec["approval_required"],
                "metadata": {
                    "ip":       row.get("last_ip"),
                    "mac":      row.get("mac_address"),
                    "hostname": row.get("hostname"),
                    "os":       row.get("os"),
                    "type":     row.get("device_type") or "workstation",
                    "simulated": "false",
                },
                "trust_evaluation": te,
                "trust_history":    [],
            })

        return entities

    except Exception as exc:
        import traceback
        print(f"[v1/entities] Error: {exc}")
        traceback.print_exc()
        return []
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /audit/
# ─────────────────────────────────────────────

@router.get("/audit/")
def get_audit():
    """
    Returns the audit log for the frontend.
    Sourced from the `alerts` table (real pipeline output from decision_engine).
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    timestamp,
                    device_id,
                    event_type,
                    severity,
                    COALESCE(risk_score, 0)  AS risk_score,
                    COALESCE(trust_score, 0) AS trust_score,
                    action,
                    source
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
            rows = cur.fetchall()

        logs = []
        for row in rows:
            ts, device_id, event_type, severity, risk_score, trust_score, action, source = row
            reason = (
                f"trust={trust_score}, risk={risk_score}, "
                f"event={event_type or source}, severity={severity}"
            )
            logs.append({
                "timestamp":   ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                "entity_id":   device_id,
                "action_type": (action or "monitor").upper(),
                "status":      "success",
                "reason":      reason,
                "approved_by": None,
                "simulated":   False,
            })

        return logs

    except Exception as exc:
        print(f"[v1/audit] Error: {exc}")
        return []
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /transparency/stats
# ─────────────────────────────────────────────

@router.get("/transparency/stats")
def get_transparency_stats():
    """
    Returns aggregate statistics across all pipeline events.
    Draws from 'features' instead of 'events' as a reliable proxy,
    since raw network events might skip the 'events' table if event_id is missing.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM features")
            total_events = cur.fetchone()[0] or 0

            cur.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE UPPER(severity) IN ('CRITICAL', 'HIGH') OR risk_score >= 70
            """)
            high_sev = cur.fetchone()[0] or 0

            cur.execute("""
                SELECT source, COUNT(*)
                FROM features
                WHERE source IS NOT NULL
                GROUP BY source
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """)
            by_category = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT device_id, severity, risk_score, action, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            recent_alerts = [
                {
                    "entity_id":  r[0],
                    "severity":   r[1],
                    "risk_score": r[2],
                    "action":     r[3],
                    "timestamp":  r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
                }
                for r in cur.fetchall()
            ]

        return {
            "total_events":        total_events,
            "high_severity_count": high_sev,
            "by_category":         by_category,
            "by_source_type":      by_category,
            "by_event_type":       {},
            "category_severity":   {},
            "source_activity":     {},
            "recent_events":       recent_alerts,
            "last_updated":        datetime.now(timezone.utc).isoformat(),
        }

    except Exception as exc:
        print(f"[v1/transparency] Error: {exc}")
        return {
            "total_events": 0, "high_severity_count": 0,
            "by_category": {}, "by_source_type": {}, "by_event_type": {},
            "category_severity": {}, "source_activity": {}, "recent_events": [],
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /entities/{entity_id}  — Detail view
# ─────────────────────────────────────────────

@router.get("/entities/{entity_id}")
def get_entity_detail(entity_id: str):
    """
    Returns detailed per-entity data for the Adaptive Trust page:
    - Core entity fields (same as list)
    - trust_history: last 50 trust_score rows (for timeline chart)
    - anomaly_history: last 50 ml_scores (for ML chart)
    - risk_history:   last 50 risk_scores
    - ml_state:       latest device_baselines Welford state
    - category_risks: I/C/V/N from trust_states
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Core device row
            cur.execute("""
                SELECT d.device_id, d.hostname, d.mac_address, d.os, d.device_type, d.last_seen,
                       COALESCE(ts.trust_score, 80)    AS trust_score,
                       COALESCE(ts.adjusted_risk, 0.0) AS adjusted_risk,
                       COALESCE(ts.timestamp, d.last_seen) AS score_ts,
                       tst.state AS trust_state,
                       (SELECT ip FROM events WHERE device_id = d.device_id ORDER BY timestamp DESC LIMIT 1) AS last_ip
                FROM devices d
                LEFT JOIN LATERAL (
                    SELECT trust_score, adjusted_risk, timestamp
                    FROM trust_scores WHERE device_id = d.device_id
                    ORDER BY timestamp DESC LIMIT 1
                ) ts ON true
                LEFT JOIN trust_states tst ON tst.device_id = d.device_id
                WHERE d.device_id = %s
            """, (entity_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "not found"}
            cols = [d[0] for d in cur.description]
            row = dict(zip(cols, row))

            # Trust score history (last 50)
            cur.execute("""
                SELECT timestamp, trust_score, COALESCE(adjusted_risk, 0) AS adjusted_risk
                FROM trust_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            trust_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 80), "adjusted_risk": float(r[2] or 0)}
                for r in cur.fetchall()
            ][::-1]  # oldest first for charts

            # ML anomaly history (last 50)
            cur.execute("""
                SELECT timestamp, anomaly_score, anomaly_reasons
                FROM ml_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            anomaly_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 0), "reasons": r[2] or []}
                for r in cur.fetchall()
            ][::-1]

            # Risk score history (last 50)
            cur.execute("""
                SELECT timestamp, risk_score, severity
                FROM risk_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            risk_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 0), "severity": r[2]}
                for r in cur.fetchall()
            ][::-1]

            # ML Welford baseline
            cur.execute("SELECT baseline FROM device_baselines WHERE device_id = %s", (entity_id,))
            bl_row = cur.fetchone()
            ml_state = bl_row[0] if bl_row else None

        # Re-calc latest with read-time decay
        trust  = float(row.get("trust_score") or 80)
        adj    = float(row.get("adjusted_risk") or 0)
        state  = row.get("trust_state") or {}
        
        trust, adj, state = _apply_read_time_decay(state, row.get("device_type") or "unknown")

        ts_val = row.get("score_ts") or row.get("last_seen")
        dec    = _trust_to_decision(trust)
        cat_bd = _build_category_breakdown(state)
        te     = _build_trust_evaluation(entity_id, trust, adj, state, ts_val)
        ts_str = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val or "")

        return {
            "entity_id":    entity_id,
            "trust_score":  round(trust, 1),
            "confidence":   round(min(100, max(0, (1 - adj) * 100)), 1),
            "decision":     dec["decision"],
            "category_breakdown": cat_bd,
            "last_updated": ts_str,
            "active_actions":    dec["active_actions"],
            "last_action":  dec["active_actions"][0] if dec["active_actions"] else None,
            "approval_required": dec["approval_required"],
            "metadata": {
                "ip":       row.get("last_ip"),
                "mac":      row.get("mac_address"),
                "hostname": row.get("hostname"),
                "os":       row.get("os"),
                "type":     row.get("device_type") or "workstation",
                "simulated": "false",
            },
            "trust_evaluation":  te,
            "trust_history":     trust_history,
            "anomaly_history":   anomaly_history,
            "risk_history":      risk_history,
            "ml_state":          ml_state,
            "category_risks":    {
                "N": round(float(state.get("N", 0) or 0), 4),
                "I": round(float(state.get("I", 0) or 0), 4),
                "C": round(float(state.get("C", 0) or 0), 4),
                "V": round(float(state.get("V", 0) or 0), 4),
            },
        }
    except Exception as exc:
        import traceback; traceback.print_exc()
        return {"error": str(exc)}
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# POST /response/approve  (SIMULATED)
# ─────────────────────────────────────────────

class ApprovalRequest(BaseModel):
    entity_id:   str
    action:      str
    approved:    bool
    approved_by: Optional[str] = "SOC_ANALYST"


@router.post("/response/approve")
def approve_response(payload: ApprovalRequest):
    """
    Simulated response engine: logs the SOC approval to the alerts table.
    Does NOT perform real network isolation/account lock (TBD).
    """
    action_id = f"ACT-{payload.entity_id[:8]}-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (
                    alert_id, device_id, source, event_type,
                    severity, risk_score, trust_score,
                    anomaly_reasons, action, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO NOTHING
            """, (
                action_id,
                payload.entity_id,
                "soc_analyst",
                "manual_response",
                "INFO",
                0, 0, '[]',
                f"{'approved' if payload.approved else 'rejected'}:{payload.action}",
                now,
            ))
        conn.commit()
    except Exception as exc:
        print(f"[v1/response] Error: {exc}")
        conn.rollback()
    finally:
        put_conn(conn)

    return {
        "status":    "ok",
        "action_id": action_id,
        "entity_id": payload.entity_id,
        "action":    payload.action,
        "approved":  payload.approved,
        "simulated": True,
        "timestamp": now.isoformat(),
    }


# ─────────────────────────────────────────────
# POST /feedback  — Adaptive Trust Feedback Loop
# GET  /feedback/weights — Current learned weights
# ─────────────────────────────────────────────

class FeedbackRequest(BaseModel):
    alert_id:        str
    label:           str            # "true_attack" or "false_positive"
    detection_type:  str
    analyst:         Optional[str] = "soc_analyst"
    device_id:       Optional[str] = "unknown"


@router.post("/feedback")
def submit_analyst_feedback(payload: FeedbackRequest):
    """
    Record an analyst label for a fired alert and update the severity
    weight for the given detection_type.

    Body:
      {
        "alert_id":       "ALERT-abc123",
        "label":          "true_attack" | "false_positive",
        "detection_type": "dns_entropy",
        "analyst":        "analyst@company.com",   (optional)
        "device_id":      "dev-xxxx"               (optional)
      }

    Response:
      {
        "status":         "ok",
        "old_weight":     1.0,
        "new_weight":     0.9,
        "detection_type": "dns_entropy",
        ...
      }

    Math: weight_new = weight_old × (1 + 0.2 × (label - 0.5))
      true_attack    → ×1.10  (+10% severity)
      false_positive → ×0.90  (-10% severity)
    """
    from services.feedback_service import submit_feedback
    try:
        result = submit_feedback(
            alert_id       = payload.alert_id,
            label          = payload.label,
            detection_type = payload.detection_type,
            analyst        = payload.analyst or "soc_analyst",
            device_id      = payload.device_id or "unknown",
        )
        return result
    except ValueError as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"Feedback error: {exc}")


@router.get("/feedback/weights")
def get_feedback_weights():
    """
    Returns the current per-detection-type severity weight table.
    Weights start at 1.0 and drift based on analyst labels.
    weight > 1.0 = confirmed attacks of this type are more common
    weight < 1.0 = this type triggers too many false positives
    """
    from services.feedback_service import get_weights_summary
    try:
        return get_weights_summary()
    except Exception as exc:
        return {"error": str(exc), "weights": {}}

# ─────────────────────────────────────────────
# GET /simulation/runs
# ─────────────────────────────────────────────

@router.get("/simulation/runs")
def list_simulation_runs():
    """Returns recent simulation runs."""
    return get_simulation_runs()


# ─────────────────────────────────────────────
# GET /response/actions
# ─────────────────────────────────────────────

@router.get("/response/actions")
def list_response_actions():
    """Returns recent automated response actions."""
    return get_response_actions()


# ─────────────────────────────────────────────
# GET /devices  — For the frontend dropdown
# ─────────────────────────────────────────────

@router.get("/devices")
def get_device_list():
    """Returns a simplified list of devices for dropdown pickers."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT device_id, hostname, device_type, last_seen
                FROM devices
                ORDER BY last_seen DESC
                LIMIT 200
            """)
            rows = cur.fetchall()
            return [
                {
                    "device_id": r[0],
                    "hostname": r[1] or r[0],
                    "device_type": r[2] or "unknown",
                    "last_seen": r[3].isoformat() if r[3] else None
                }
                for r in rows
            ]
    except Exception as exc:
        print(f"[v1/devices] Error: {exc}")
        return []
    finally:
        put_conn(conn)
