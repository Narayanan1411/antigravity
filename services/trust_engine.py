"""
Guardient Trust Engine  — 9-Step Mathematical Model
=====================================================
Consumes  : risk_scores  (from Risk Engine)
Publishes : trust_scores (to Decision Engine)
Persists  : per-device I/C/V/N state in PostgreSQL (trust_states table)

Mathematical pipeline per event
────────────────────────────────
Step 1  Category risk evolution  Rx += e^(-λΔt)·Rx_prev + Severity×Anomaly×CI×Impact
Step 2  Aggregated Risk          AR = 0.40·I + 0.25·C + 0.20·V + 0.15·N
Step 3  Correlation Amplification CAF = 1 + α·(Σ − max(I,C,V,N))
Step 4  Confidence Index         CI  = 1 − Π(1−ci)
Step 5  Risk Velocity            RV  = |AR − AR_prev| / Δt   (normalised)
Step 6  Adjusted Risk            adj = AR × CAF × CI × (1 + β·RV_norm)
Step 7  Trust Score              T   = 100·e^(−k·adj)
Step 8  Natural Recovery         T recovers automatically when no events arrive
Step 9  Hard Override            T = min(T, 10) if device is flagged compromised

Device-specific parameters (formulas never change):
  • baseline behaviour  – ML Monitor Welford baselines
  • impact multiplier   – DEVICE_IMPACT per device type
  • decay rate λ        – DEVICE_DECAY × BASE_LAMBDA × (1 + anomaly)
"""

from __future__ import annotations
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import GRAPH_SCORES, TRUST_SCORES
from db.db import insert_trust_score, load_trust_state, save_trust_state, init_schema

# ──────────────────────────────────────────────────────────────
# 4️⃣  Adaptive Decay λ parameters
# ──────────────────────────────────────────────────────────────

BASE_LAMBDA: dict[str, float] = {
    "I": 0.05,   # Identity
    "C": 0.05,   # Cloud
    "V": 0.05,   # Vulnerability / Hardware
    "N": 0.20,   # Network — fast decay because traffic is bursty
}

# Multiplier per device type — slower decay = anomaly persists longer
DEVICE_DECAY: dict[str, float] = {
    "server":           0.6,
    "domain_controller":0.4,
    "network_device":   0.8,
    "laptop":           2.0,   # User devices recover 2x faster
    "workstation":      2.0,
    "phone":            2.5,   # Mobile recovers 2.5x faster
    "mobile":           2.5,
    "iot":              0.9,
    "smart_tv":         1.0,
    "printer":          1.0,
    "camera":           0.8,
    "unknown":          1.5,
}

# ──────────────────────────────────────────────────────────────
# 3️⃣  Device Impact multipliers
# ──────────────────────────────────────────────────────────────

DEVICE_IMPACT: dict[str, float] = {
    "server":           1.5,
    "domain_controller":1.8,
    "network_device":   1.2,
    "laptop":           1.0,
    "workstation":      1.0,
    "phone":            0.9,
    "mobile":           0.9,
    "iot":              0.7,
    "smart_tv":         0.5,
    "printer":          0.4,
    "camera":           0.4,
    "unknown":          0.8,
}

# ──────────────────────────────────────────────────────────────
# 2️⃣  Device type classifier from signals
# ──────────────────────────────────────────────────────────────

def classify_device(event: dict) -> str:
    """
    Infer device type from collected signals.
    Priority: declared device_type > protocol signals > DNS/port heuristics.
    """
    # 1. Trust any explicitly set device_type from DGID resolver or risk engine
    explicit = (
        event.get("device_type") or
        event.get("enrichment", {}).get("device_class") or
        event.get("features", {}).get("device_type") or
        event.get("risk_factors", {}).get("device_type")
    )
    if explicit:
        return str(explicit).lower()

    features = event.get("features", {})
    enrichment = event.get("enrichment", {})

    # 2. Protocol signals
    protocols = str(features.get("protocols", "")).lower()
    if "rtsp" in protocols:
        return "camera"

    # 3. Port heuristics
    dest_port = features.get("dest_port") or enrichment.get("dest_port") or 0
    if dest_port == 9100:
        return "printer"
    if dest_port == 554:
        return "camera"

    # 4. DNS / SNI heuristics
    dns = str(features.get("dns_query") or enrichment.get("dns_reverse", "")).lower()
    if any(d in dns for d in ["netflix", "youtube", "primevideo", "disneyplus", "hulu"]):
        return "smart_tv"
    if any(d in dns for d in ["print", "cups"]):
        return "printer"
    if any(d in dns for d in ["android", "googleapis"]):
        return "phone"
    if any(d in dns for d in ["apple", "icloud", "facetime"]):
        return "phone"

    # 5. OS hints
    os_str = str(features.get("os") or enrichment.get("os", "")).lower()
    if "android" in os_str or "ios" in os_str:
        return "phone"
    if "ubuntu" in os_str or "rhel" in os_str or "debian" in os_str:
        return "server"
    if "windows server" in os_str:
        return "server"

    # 6. Mac vendor from enrichment
    mac_vendor = str(enrichment.get("mac_vendor", "")).lower()
    if any(v in mac_vendor for v in ["samsung", "lg", "sony", "roku", "vizio"]):
        return "smart_tv"
    if any(v in mac_vendor for v in ["cisco", "aruba", "juniper", "paloalto"]):
        return "network_device"

    return "unknown"

# ──────────────────────────────────────────────────────────────
# Collector → Category mapping
# ──────────────────────────────────────────────────────────────

CATEGORY_MAP: dict[str, str] = {
    "identity": "I",
    "cloud":    "C",
    "hardware": "V",    # Vulnerability/hardware signals
    "network":  "N",
}

# ──────────────────────────────────────────────────────────────
# Severity per source
# ──────────────────────────────────────────────────────────────

SOURCE_SEVERITY: dict[str, float] = {
    "cloud":    0.95,
    "identity": 0.90,
    "hardware": 0.85,
    "network":  0.85,
}

# ──────────────────────────────────────────────────────────────
# Tuning constants
# ──────────────────────────────────────────────────────────────

WEIGHTS: dict[str, float] = {"I": 0.40, "C": 0.25, "V": 0.20, "N": 0.15}
ALPHA   = 0.6   # CAF correlation amplification
BETA    = 0.8   # Risk velocity amplification
K       = 2.5   # Trust decay steepness
RV_THRESHOLD = 1.0
TRUST_OVERRIDE_THRESHOLD = 10   # Force trust cap on confirmed compromise

# ──────────────────────────────────────────────────────────────
# Step 1: Adaptive lambda
# ──────────────────────────────────────────────────────────────

def adaptive_lambda(category: str, device_type: str, anomaly: float) -> float:
    """λ = BASE × device_decay_factor × (1 + anomaly)
    High anomaly → slower decay → threat persists in memory.
    """
    base   = BASE_LAMBDA.get(category, 0.05)
    d_fact = DEVICE_DECAY.get(device_type, 1.0)
    # Corrected: lambda = base / (1 + anomaly)
    # High anomaly -> small lambda -> slow decay -> threat persists.
    return (base * d_fact) / (1.0 + anomaly)


def apply_decay(prev_risk: float, lam: float, dt: float) -> float:
    """Rx_decayed = Rx(t-1) × e^(-λ·Δt)"""
    return prev_risk * math.exp(-lam * dt)


def event_contribution(severity: float, anomaly: float,
                        confidence: float, impact: float) -> float:
    """contribution = Severity × Anomaly × Confidence × Impact"""
    return severity * anomaly * confidence * impact


def update_category_risk(category: str, state: dict, events: list[dict],
                          dt: float, device_type: str) -> float:
    """Decay existing category risk then add contributions from new events."""
    prev   = float(state.get(category, 0.0))
    max_an = max((e["anomaly"] for e in events), default=0.0)
    lam    = adaptive_lambda(category, device_type, max_an)
    decayed = apply_decay(prev, lam, dt)

    # Only add contributions if they are significant (>0.01) to filter out INFO noise
    total = 0.0
    for e in events:
        contrib = event_contribution(e["severity"], e["anomaly"], e["confidence"], e["impact"])
        if contrib > 0.01:
            total += contrib
    
    res = decayed + total
    # Clamp to a sane range to prevent runaway values during bursts
    # A single category risk of 10.0 is already effectively 100% trust loss
    return min(10.0, res)

# ──────────────────────────────────────────────────────────────
# Step 2-7
# ──────────────────────────────────────────────────────────────

def compute_AR(state: dict) -> float:
    """AR = 0.40·I + 0.25·C + 0.20·V + 0.15·N"""
    return (WEIGHTS["I"] * float(state["I"]) +
            WEIGHTS["C"] * float(state["C"]) +
            WEIGHTS["V"] * float(state["V"]) +
            WEIGHTS["N"] * float(state["N"]))


def compute_CAF(state: dict, graph_caf: float = 1.0) -> float:
    """CAF = max( 1 + α·(Σ(I,C,V,N) − max(I,C,V,N)),  graph_caf )

    The graph_caf override (from the Graph Correlator) reflects lateral
    movement chain length: CAF_graph = 1 + 0.3 × path_length.
    We take the maximum so a confirmed attack chain always wins.
    """
    I, C, V, N = (float(state["I"]), float(state["C"]),
                  float(state["V"]), float(state["N"]))
    active = I + C + V + N
    local_caf = 1.0 + ALPHA * (active - max(I, C, V, N))
    return max(local_caf, graph_caf)


def compute_CI(confidences: list[float]) -> float:
    """CI = 1 − Π(1 − ci)
    Rises with each additional confirming source (never shrinks evidence).
    """
    if not confidences:
        return 0.1   # minimal confidence if no signals
    p = 1.0
    for c in confidences:
        p *= (1.0 - max(0.0, min(1.0, c)))
    return 1.0 - p


def compute_velocity(AR: float, prev_AR: float, dt: float) -> float:
    """RV = |AR − AR_prev| / Δt"""
    if dt <= 0:
        return 0.0
    return abs(AR - prev_AR) / dt


def normalize_velocity(rv: float) -> float:
    return min(1.0, rv / RV_THRESHOLD)


def compute_adjusted_risk(AR: float, CAF: float, CI: float, RV_norm: float) -> float:
    """AdjustedRisk = AR × CAF × CI × (1 + β·RV_norm)"""
    return AR * CAF * CI * (1.0 + BETA * RV_norm)


def compute_trust_score(adjusted: float) -> float:
    """Trust = 100·e^(−k·adjusted)
    • adjusted=0   → Trust=100 (pristine)
    • adjusted=0.5 → Trust≈29
    • adjusted=1   → Trust≈8
    • adjusted=2   → Trust≈<1  (compromised)
    """
    return round(100.0 * math.exp(-K * adjusted), 2)


def apply_override(trust: float, compromised: bool) -> float:
    """Step 9: Hard override — cap trust at TRUST_OVERRIDE_THRESHOLD if confirmed compromised."""
    if compromised:
        return min(trust, TRUST_OVERRIDE_THRESHOLD)
    return trust

# ──────────────────────────────────────────────────────────────
# Full pipeline
# ──────────────────────────────────────────────────────────────

def trust_pipeline(state: dict, events: list[dict],
                    now_ts: float, device_type: str,
                    graph_caf: float = 1.0) -> tuple[float, float, dict]:
    """
    Run all 9 steps for a batch of events arriving at time now_ts.
    graph_caf is supplied by the Graph Correlator when a lateral-movement
    chain has been detected.  Returns (trust_score, adjusted_risk, updated_state).
    """
    last_ts = float(state.get("last_timestamp", 0.0))
    dt = max(0.0, now_ts - last_ts)

    # Bucket events by category
    buckets: dict[str, list[dict]] = {"I": [], "C": [], "V": [], "N": []}
    confidences: list[float] = []

    for e in events:
        cat = e.get("category", "N")
        if cat in buckets:
            buckets[cat].append(e)
        confidences.append(float(e.get("confidence", 0.5)))

    # Step 1: Update each category
    for cat in ("I", "C", "V", "N"):
        state[cat] = update_category_risk(cat, state, buckets[cat], dt, device_type)

    # Step 2
    AR = compute_AR(state)

    # Step 3 — use graph_caf if the Graph Correlator detected a chain
    CAF = compute_CAF(state, graph_caf)

    # Step 4
    CI = compute_CI(confidences)

    # Step 5
    prev_AR = float(state.get("AR_prev", 0.0))
    RV      = compute_velocity(AR, prev_AR, max(dt, 1.0))
    RV_norm = normalize_velocity(RV)

    # Step 6
    adj = compute_adjusted_risk(AR, CAF, CI, RV_norm)

    # Step 7
    trust = compute_trust_score(adj)

    # Step 8: Natural recovery when no events arrive (handled by decay in step 1)
    # Step 9: Hard override (only if risk_score >= 90 = "CRITICAL")
    compromised = any(e.get("risk_score", 0) >= 90 for e in events)
    trust = apply_override(trust, compromised)

    # Persist updated state
    state["AR_prev"]        = AR
    state["last_timestamp"] = now_ts

    return trust, adj, state


# ──────────────────────────────────────────────────────────────
# Kafka consumer
# ──────────────────────────────────────────────────────────────

class TrustEngine(BaseConsumer):
    topic        = GRAPH_SCORES   # Now reads from Graph Correlator output
    group_id     = "trust-engine-v2"
    service_name = "TrustEngine"

    def process(self, event: dict):
        print(f"[TrustEngine] Processing event: {event.get('event_id', 'unknown')}")
        device_id   = event.get("device_id", "unknown")
        source      = event.get("source") or event.get("collector", "network")
        category    = CATEGORY_MAP.get(source, "N")
        device_type = classify_device(event)

        # Build event contribution dict for the pipeline using RiskEngine's outputs
        # This ensures normalized scores (tanh) are used instead of raw z-scores.
        rf = event.get("risk_factors", {})
        
        # If RiskEngine didn't provide factors (unlikely but safe), fall back to defaults
        severity   = float(rf.get("severity")   or SOURCE_SEVERITY.get(source, 0.85))
        anomaly    = float(rf.get("anomaly")    or min(1.0, float(event.get("anomaly_score", 0.0))))
        confidence = float(rf.get("confidence") or min(1.0, math.tanh(max(anomaly, 0.1) * 1.5)))
        impact     = float(rf.get("impact")     or min(1.0, DEVICE_IMPACT.get(device_type, 0.8)))
        category   = rf.get("category")         or CATEGORY_MAP.get(source, "N")

        contrib = {
            "category":   category,
            "severity":   severity,
            "anomaly":    anomaly,
            "confidence": confidence,
            "impact":     impact,
            "risk_score": event.get("risk_score", 0),
        }
        
        if anomaly > 0.1:
            print(f"[Trust] DEBUG dev={device_id} cat={category} sev={severity:.2f} anom={anomaly:.2f} conf={confidence:.2f} imp={impact:.2f} -> contrib={event_contribution(severity, anomaly, confidence, impact):.4f}")


        # Load persisted state
        state = load_trust_state(device_id)
        now_ts = time.time()

        # Run the 9-step pipeline with graph_caf from Graph Correlator
        graph_caf = float(event.get("graph_caf", 1.0))
        trust, adj, updated_state = trust_pipeline(
            state, [contrib], now_ts, device_type, graph_caf
        )

        # Persist updated state
        try:
            save_trust_state(device_id, updated_state)
        except Exception as exc:
            print(f"[Trust] state save failed: {exc}")

        # Build output event
        trust_event = {
            "event_id":     event.get("event_id"),
            "timestamp":    datetime.now(tz=timezone.utc).isoformat(),
            "device_id":    device_id,
            "ip":           event.get("ip"),
            "source":       source,
            "event_type":   event.get("event_type"),
            "device_type":  device_type,
            "category":     category,
            # Core outputs
            "trust_score":    trust,
            "adjusted_risk":  round(adj, 6),
            # State snapshot for transparency
            "state_I":        round(updated_state["I"], 4),
            "state_C":        round(updated_state["C"], 4),
            "state_V":        round(updated_state["V"], 4),
            "state_N":        round(updated_state["N"], 4),
            "AR":             round(compute_AR(updated_state), 4),
            "CAF":            round(compute_CAF(updated_state, graph_caf), 4),
            "graph_caf":      graph_caf,
            "attack_path":    event.get("attack_path", []),
            "trust_reasons": event.get("anomaly_reasons", []),
        }

        publish_event(TRUST_SCORES, trust_event)

        try:
            insert_trust_score(trust_event)
        except Exception as exc:
            print(f"[Trust] DB write skipped: {exc}")

        # Console output
        bar_len = max(0, min(10, round(trust / 10)))
        bar = "█" * bar_len + "░" * (10 - bar_len)
        flag = ""
        if trust < 10:
            flag = "  ⚠️  CRITICAL — override triggered" if adj > 1 else "  🔴 VERY LOW"
        elif trust < 30:
            flag = "  🟠 LOW"
        elif trust < 60:
            flag = "  🟡 MODERATE"
        else:
            flag = "  🟢 OK"

        print(
            f"[Trust] [{bar}] {trust:6.1f}/100 | "
            f"adj={adj:.3f} | I={updated_state['I']:.3f} C={updated_state['C']:.3f} "
            f"V={updated_state['V']:.3f} N={updated_state['N']:.3f} | "
            f"cat={category} dev={device_type:10s} | {device_id[:16]}{flag}"
        )


if __name__ == "__main__":
    init_schema()   # Creates trust_states table if not present
    print("=" * 70)
    print("  Guardient Trust Engine — 9-Step Mathematical Model")
    print("=" * 70)
    print(f"  AR  = 0.40·I + 0.25·C + 0.20·V + 0.15·N")
    print(f"  CAF = 1 + {ALPHA}·(Σ − max(I,C,V,N))")
    print(f"  adj = AR × CAF × CI × (1 + {BETA}·RV_norm)")
    print(f"  T   = 100·e^(-{K}·adj)")
    print(f"  Consuming: risk_scores → trust_scores")
    print("=" * 70 + "\n")
    TrustEngine().run()
