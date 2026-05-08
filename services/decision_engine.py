"""
Guardient Decision Engine  v2
==============================
Consumes : trust_scores
Publishes: alerts, security_actions
"""

from __future__ import annotations
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics import TRUST_SCORES, ALERTS, SECURITY_ACTIONS
from db.db import insert_alert, get_conn, put_conn

# Suppress the stale ALERT_RISK/TRUST_THRESHOLD constants — no longer used



# ── Graduated trust thresholds ───────────────────────────────────────────
#
T_ALLOW    = 80.0   # >= 80: allow
T_MONITOR  = 60.0   # 60–80: monitor
T_MFA      = 40.0   # 40–60: step-up MFA
T_RESTRICT = 20.0   # 20–40: restrict network
# below 20: isolate / lock / kill


def decide_action(trust: float, device_role: str) -> str:
    """
    Graduated response based on trust score + device role.

    Trust 80-100 → allow
    Trust 60-80  → monitor
    Trust 40-60  → require_mfa
    Trust 20-40  → restrict_network
    Trust  0-20  → role-specific isolation
    """
    if trust >= T_ALLOW:
        return "allow"
    if trust >= T_MONITOR:
        return "monitor"
    if trust >= T_MFA:
        return "require_mfa"
    if trust >= T_RESTRICT:
        return "restrict_network"

    # Trust < 20 — role-specific hard action
    actions = {
        "iot":            "isolate_vlan",
        "server":          "kill_process",
        "user_device":     "lock_account",
        "network_device":  "firewall_block",
    }
    return actions.get(device_role, "lock_account")


def alert_severity(trust: float, risk: float = 0) -> str:
    if trust <= 10 or risk >= 90: return "CRITICAL"
    if trust <= 20 or risk >= 70: return "HIGH"
    if trust <= 40 or risk >= 50: return "MEDIUM"
    return "LOW"


# ── DB helper: latest trust event for device ─────────────────────────────

def _get_latest_risk(device_id: str) -> dict:
    """Fetch the latest risk score event for a device (for alert enrichment)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT risk_score, severity FROM risk_scores "
                "WHERE device_id = %s ORDER BY timestamp DESC LIMIT 1",
                (device_id,)
            )
            row = cur.fetchone()
        return {"risk_score": row[0], "severity": row[1]} if row else {"risk_score": 0, "severity": "info"}
    except Exception:
        conn.rollback()
        return {"risk_score": 0, "severity": "info"}
    finally:
        put_conn(conn)


class DecisionEngine(BaseConsumer):
    topic        = TRUST_SCORES
    group_id     = "decision-engine-v3"
    service_name = "DecisionEngine"

    def process(self, event: dict):
        device_id   = event.get("device_id", "unknown")
        trust       = float(event.get("trust_score",   100.0))
        adj         = float(event.get("adjusted_risk",   0.0))
        device_type = event.get("device_type", "unknown")
        device_role = event.get("device_role") or _role_from_type(device_type)
        source      = event.get("source", "unknown")
        category    = event.get("category", "N")

        # Fetch latest risk score from DB for alert enrichment
        risk_data = _get_latest_risk(device_id)
        risk      = risk_data["risk_score"]

        action  = decide_action(trust, device_role)
        sev     = alert_severity(trust, risk)

        # Security action event — always emitted for every trust update
        sec_action = {
            "event_id":    f"ACT-{device_id[:8]}-{uuid.uuid4().hex[:6]}",
            "timestamp":   datetime.now(tz=timezone.utc).isoformat(),
            "device_id":   device_id,
            "device_type": device_type,
            "device_role": device_role,
            "source":      source,
            "category":    category,
            "trust_score": trust,
            "adjusted_risk": adj,
            "risk_score":  risk,
            "action":      action,
            "severity":    sev,
            "state": {
                "I": event.get("state_I", 0),
                "C": event.get("state_C", 0),
                "V": event.get("state_V", 0),
                "N": event.get("state_N", 0),
                "AR": event.get("AR", 0),
                "CAF": event.get("CAF", 0),
            },
        }

        # Publish security action (enforcement layer)
        publish_event(SECURITY_ACTIONS, sec_action)

        # Print current status
        trust_bar = round(trust / 10)
        bar = "█" * max(0, trust_bar) + "░" * max(0, 10 - trust_bar)
        action_icon = {
            "allow":          "🟢",
            "monitor":        "🔵",
            "require_mfa":    "🟡",
            "restrict_network": "🟠",
            "lock_account":   "🔴",
            "isolate_vlan":   "🔴",
            "kill_process":   "🔴",
            "firewall_block": "🔴",
        }.get(action, "⚪")
        print(
            f"[Decision] [{bar}] T={trust:5.1f} | {action_icon} {action:20s} "
            f"| adj={adj:.3f} risk={risk} | {device_type:10s}/{device_role} "
            f"| {device_id[:16]}"
        )

        # Only fire an alert when trust is below MFA threshold AND risk is significant
        if trust <= T_MFA and risk > 0:
            sev_alert = alert_severity(trust, risk)
            alert = {
                "alert_id":        f"ALERT-{device_id[:8]}-{uuid.uuid4().hex[:6]}",
                "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
                "device_id":       device_id,
                "ip":              event.get("ip"),
                "source":          source,
                "event_type":      event.get("event_type"),
                "severity":        sev_alert,
                "risk_score":      risk,
                "trust_score":     trust,
                "adjusted_risk":   adj,
                "anomaly_score":   event.get("adjusted_risk"),
                "anomaly_reasons": event.get("trust_reasons", []),
                "device_role":     device_role,
                "device_type":     device_type,
                "action":          action,
                "category":        category,
            }
            publish_event(ALERTS, alert)
            try:
                insert_alert(alert)
            except Exception as exc:
                print(f"[Decision] DB alert write: {exc}")

            border = "═" * 64
            print(f"\n🚨 ALERT fired | sev={sev_alert} | trust={trust:.1f} | risk={risk} | {action}")
            print(border)


def _role_from_type(device_type: str) -> str:
    dt = (device_type or "unknown").lower()
    if dt in ("server", "domain_controller"): return "server"
    if dt in ("iot", "smart_tv", "printer", "camera"): return "iot"
    if dt == "network_device": return "network_device"
    return "user_device"


if __name__ == "__main__":
    print("=" * 64)
    print("  Guardient Decision Engine v2 — Graduated Trust Thresholds")
    print("=" * 64)
    print(f"  ALLOW    trust >= {T_ALLOW}")
    print(f"  MONITOR  trust >= {T_MONITOR}")
    print(f"  MFA      trust >= {T_MFA}")
    print(f"  RESTRICT trust >= {T_RESTRICT}")
    print(f"  ISOLATE  trust <  {T_RESTRICT}")
    print(f"  Consuming: trust_scores")
    print(f"  Publishing: security_actions | alerts")
    print("=" * 64 + "\n")
    DecisionEngine().run()
