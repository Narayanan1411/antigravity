"""
Guardient Risk Engine  v2
==========================
Consumes: ml_scores
Publishes: risk_scores

Formula:
  RiskContribution = Severity × Anomaly_norm × Confidence × Impact
  risk_score (0-100) = RiskContribution × 100

Each risk event also carries `category` ∈ {I, C, V, N} so the Trust Engine
can correctly route it into the right state bucket:
  I  Identity  — login / auth anomalies
  C  Compute   — process / privilege / cloud events
  V  Visibility — device drift / hardware / behavior anomalies
  N  Network   — traffic / DNS / port anomalies
"""

from __future__ import annotations
import math
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import ML_SCORES, RISK_SCORES
from db.db import insert_risk_score
from services.feedback_service import get_cached_weight, refresh_cache


# ── Feedback weight cache refresh ────────────────────────────────────────────
# Loads feedback weights from PostgreSQL at startup and every REFRESH_INTERVAL
# seconds in a background daemon thread.
REFRESH_INTERVAL = 300   # 5 minutes

def _start_weight_refresh():
    def _loop():
        while True:
            try:
                refresh_cache()
            except Exception as exc:
                print(f"[Risk] weight refresh error: {exc}")
            time.sleep(REFRESH_INTERVAL)
    t = threading.Thread(target=_loop, daemon=True, name="risk-weight-refresh")
    t.start()

_start_weight_refresh()  # Fire immediately on import


# ── Detection type → Risk Category ─────────────────────────────
# Maps the kind of anomaly to one of the 4 Trust Engine domains.
DETECTION_CATEGORY: dict[str, str] = {
    # Identity
    "login_failure":              "I",
    "mfa_failure":                "I",
    "after_hours":                "I",
    "brute_force":                "I",
    "credential_stuffing":        "I",
    "login_anomaly":              "I",
    # Compute / cloud
    "process_injection":          "C",
    "privilege_escalation":        "C",
    "iam_changed":                "C",
    "key_created":                "C",
    "snapshot_created":           "C",
    "access_denied":              "C",
    "api_anomaly":                "C",
    # Visibility / hardware
    "large_clock_skew":           "V",
    "clock_skew":                 "V",
    "cpu_spike":                  "V",
    "behavior_anomaly":           "V",
    "device_drift":               "V",
    "above_avg_transfer":         "V",
    # Network
    "dns_entropy":                "N",
    "dns_query_length":           "N",
    "port_risk":                  "N",
    "bytes_total":                "N",
    "port_scan":                  "N",
    "ssh_activity":               "N",
    "dns_anomaly":                "N",
    "large_data_transfer":        "N",
    "suspicious_dest_port":       "N",
    "high_dns_entropy_possible_DGA": "N",
    "session_duration":           "N",
}

# ── Per-detection severity (intrinsic threat level) ─────────────
SEVERITY_TABLE: dict[str, float] = {
    # Identity — direct account/access path
    "login_failure":       0.65,
    "mfa_failure":         0.70,
    "after_hours":         0.60,
    "brute_force":         0.85,
    "login_anomaly":       0.70,
    # Compute — code execution / privilege
    "privilege_escalation": 1.00,
    "process_injection":   0.90,
    "iam_changed":         0.90,
    "key_created":         0.85,
    "snapshot_created":    0.80,
    "access_denied":       0.65,
    "api_anomaly":         0.70,
    # Visibility / hardware
    "large_clock_skew":    0.75,
    "cpu_spike":           0.55,
    "behavior_anomaly":    0.65,
    "device_drift":        0.60,
    "above_avg_transfer":  0.50,
    # Network
    "port_scan":           0.80,
    "ssh_activity":        0.75,
    "dns_anomaly":         0.65,
    "dns_entropy":         0.70,
    "dns_query_length":    0.60,
    "port_risk":           0.75,
    "bytes_total":         0.55,
    "large_data_transfer": 0.75,
    "suspicious_dest_port":0.80,
    "high_dns_entropy_possible_DGA": 0.90,
    "session_duration":    0.40,
}

# ── Source-level severity fallback (when detection unknown) ──────
SOURCE_SEVERITY: dict[str, float] = {
    "cloud":    0.95,
    "identity": 0.90,
    "hardware": 0.85,
    "network":  0.85,
}

# ── Device Type → Impact multiplier ────────────────────────
DEVICE_IMPACT: dict[str, float] = {
    "server":           1.5,
    "domain_controller":1.8,
    "laptop":           1.0,
    "workstation":      1.0,
    "phone":            0.9,
    "mobile":           0.9,
    "iot":              0.7,
    "smart_tv":         0.5,
    "printer":          0.6,
    "camera":           0.65,
    "network_device":   1.2,
    "unknown":          0.8,
}


# ── Device Role ───────────────────────────────────────────────
def _device_role(device_type: str) -> str:
    dt = (device_type or "unknown").lower()
    if dt in ("server", "domain_controller"):     return "server"
    if dt in ("laptop", "workstation"):           return "user_device"
    if dt in ("phone", "mobile"):                 return "user_device"
    if dt in ("iot", "smart_tv", "printer", "camera"): return "iot"
    if dt in ("network_device",):                 return "network_device"
    return "user_device"


# ── Severity label ────────────────────────────────────────────
def _severity_label(score: int) -> str:
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 40: return "medium"
    if score >= 20: return "low"
    return "info"


# ── Classify detection type from anomaly_reasons ──────────────
def _parse_detection(anomaly_reasons: list[str]) -> str:
    """
    Extract the primary detection keyword from the anomaly_reasons list.
    anomaly_reasons examples:
      ['dns_entropy:z=5.20', 'bytes_total:z=2.1']  → 'dns_entropy'
      ['brute_force_attempt']                        → 'brute_force'
      ['high_dns_entropy_possible_DGA']              → 'high_dns_entropy_possible_DGA'
    Returns the detection key that has the highest severity in SEVERITY_TABLE.
    """
    best_key   = ""
    best_score = 0.0
    for reason in (anomaly_reasons or []):
        # Handle both 'key:z=val' and 'plain_reason' formats
        key = reason.split(":")[0].strip()
        sev = SEVERITY_TABLE.get(key, 0.0)
        if sev > best_score:
            best_score = sev
            best_key   = key
    return best_key or "behavior_anomaly"


def compute_risk(
    anomaly: float, source: str, features: dict,
    device_type: str, anomaly_reasons: list[str]
) -> tuple[int, str, float, float, float, float, str, str]:
    """
    Returns:
        risk_score (0-100), severity_label, severity_val,
        anomaly_norm, confidence, impact, detection_type, category
    """
    # 1. Identify the primary detection type from ML reasons
    detection = _parse_detection(anomaly_reasons)

    # 2. Severity — detection-specific first, source fallback
    #    Apply learned feedback weight: Severity_new = Severity_old × feedback_weight
    base_severity    = SEVERITY_TABLE.get(detection) or SOURCE_SEVERITY.get(source, 0.70)
    feedback_weight  = get_cached_weight(detection)
    severity         = min(1.0, base_severity * feedback_weight)

    # 3. Category from detection (I / C / V / N)
    category = DETECTION_CATEGORY.get(detection) or {
        "identity": "I", "cloud": "C", "hardware": "V", "network": "N"
    }.get(source, "N")

    # 4. Anomaly — normalise Welford z-score via tanh: z=1→0.76, z=2→0.96
    anomaly_norm = round(float(min(1.0, math.tanh(anomaly))), 4)

    # 5. Confidence — rises with anomaly strength
    confidence = round(float(min(1.0, math.tanh(max(anomaly, 0.1) * 1.5))), 4)

    # 6. Impact — device type multiplier capped at 1.0
    multiplier = DEVICE_IMPACT.get((device_type or "unknown").lower(), DEVICE_IMPACT["unknown"])
    impact = round(min(1.0, multiplier), 4)

    # 7. Composite formula
    raw = severity * anomaly_norm * confidence * impact * 100
    risk_score = min(100, round(raw))

    return (risk_score, _severity_label(risk_score),
            severity, anomaly_norm, confidence, impact,
            detection, category)


class RiskEngine(BaseConsumer):
    topic        = ML_SCORES
    group_id     = "risk-engine-v2"
    service_name = "RiskEngine"

    def process(self, event: dict):
        anomaly          = float(event.get("anomaly_score", 0.0))
        meta             = event.get("metadata", {})
        source           = meta.get("collector") or event.get("source", "network")
        features         = event.get("features", {})
        anomaly_reasons  = event.get("anomaly_reasons", [])
        device_type      = (
            event.get("device_type") or
            features.get("device_type") or
            event.get("enrichment", {}).get("device_class") or
            "unknown"
        )

        (risk, sev, severity_val, anomaly_norm,
         confidence, impact, detection, category) = compute_risk(
            anomaly, source, features, device_type, anomaly_reasons
        )

        role = _device_role(device_type)

        risk_event = {
            "event_id":         event.get("event_id"),
            "timestamp":        event.get("timestamp"),
            "source":           source,
            "device_id":        event.get("device_id"),
            "ip":               meta.get("ip"),
            "event_type":       meta.get("event_type"),
            "device_type":      device_type,
            "device_role":      role,
            "enrichment":       event.get("enrichment", {}),
            "features":         features,
            # Detection classification
            "detection":        detection,
            "category":         category,
            # Anomaly signals
            "anomaly_score":    anomaly,
            "anomaly_reasons":  anomaly_reasons,
            "feature_breakdown": event.get("feature_breakdown", {}),
            # Risk output
            "risk_score":       risk,
            "severity":         sev,
            # Formula components (passed to trust engine)
            "risk_factors": {
                "severity":    severity_val,
                "anomaly":     anomaly_norm,
                "confidence":  confidence,
                "impact":      impact,
                "detection":   detection,
                "category":    category,
                "device_type": device_type,
            },
        }

        publish_event(RISK_SCORES, risk_event)
        try:
            insert_risk_score(risk_event)
        except Exception as exc:
            print(f"[Risk] DB write skipped: {exc}")

        cat_icon = {"I": "🔑", "C": "💻", "V": "👁", "N": "🌐"}.get(category, "❓")
        color    = "🔴" if sev == "critical" else "🟠" if sev == "high" else "🟡" if sev == "medium" else "🟢"
        print(
            f"[Risk] {color} {sev.upper():8s} | {cat_icon} cat={category} "
            f"detect={detection:35s} | score={risk:3d} | "
            f"sev={severity_val:.2f}×anom={anomaly_norm:.2f}×conf={confidence:.2f}×imp={impact:.2f} "
            f"| {device_type:10s}/{role} | {str(event.get('device_id'))[:16]}"
        )


if __name__ == "__main__":
    RiskEngine().run()
