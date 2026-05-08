"""
Guardient ML Monitor — Welford Statistical Baseline Engine
============================================================
Consumes: feature_stream
Publishes: ml_scores

Algorithm:
  1. Load per-device Welford baseline from PostgreSQL
  2. Compute z-score deviation for each numerical feature
  3. Emit anomaly_score (sum of z-scores) + feature_breakdown to Kafka
  4. Persist updated baseline back to PostgreSQL

Hybrid design:
  - NEW devices (count < WARMUP_SAMPLES): use rule-based scoring as fallback
    so the pipeline still generates real alerts before baselines are warm.
  - WARM devices: z-score based statistical deviation only.
"""

from __future__ import annotations
import sys
import json
import uuid
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import FEATURE_STREAM, ML_SCORES
from db.db import insert_ml_score, load_baseline, save_baseline, init_schema

# ─── Tuning constants ──────────────────────────────────────
WARMUP_SAMPLES = 20          # observations before z-score kicks in
Z_CAP          = 10.0        # cap individual z-scores to avoid single outlier domination
DECAY_ALPHA    = 0.01        # EMA decay for very long-running devices (optional future use)

# Metrics we track — all must be numeric in the feature vector
TRACKED_METRICS = [
    "bytes_total",
    "dns_entropy",
    "port_risk",
    "login_failure",
    "after_hours",
    "session_duration",
    "cpu_percent",
    "memory_percent",
    "dns_query_length",
    "archetype_deviation",   # Behavioral archetype distance (NEW)
]

ARCHETYPE_WEIGHT     = 0.4   # Blend weight for archetype deviation
ARCHETYPE_THRESHOLD  = 1.5   # Deviation above this triggers an archetype_violation reason


# ─── Welford online statistics ────────────────────────────

class Welford:
    """Single-pass online mean & variance using Welford's algorithm."""

    __slots__ = ("count", "mean", "M2")

    def __init__(self, state: dict | None = None):
        if state:
            self.count = state.get("count", 0)
            self.mean  = state.get("mean",  0.0)
            self.M2    = state.get("M2",    0.0)
        else:
            self.count = 0
            self.mean  = 0.0
            self.M2    = 0.0

    def update(self, value: float):
        self.count += 1
        delta        = value - self.mean
        self.mean   += delta / self.count
        delta2       = value - self.mean
        self.M2     += delta * delta2

    def variance(self) -> float:
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)

    def std(self) -> float:
        return self.variance() ** 0.5

    def to_dict(self) -> dict:
        return {"count": self.count, "mean": self.mean, "M2": self.M2}


def z_score(value: float, mean: float, std: float) -> float:
    """Absolute z-score, capped at Z_CAP to prevent domination by outliers."""
    if std == 0:
        return 0.0
    return min(abs((value - mean) / std), Z_CAP)


# ─── Rule-based fallback (warmup period) ─────────────────

def rule_score(features: dict, collector: str) -> tuple[float, list[str]]:
    """
    Heuristic rules fire during the warmup period before baselines are warm.
    Returns a z-score equivalent (0–10 scale) to match Welford output.
    """
    score   = 0.0
    reasons = []

    dns_e = features.get("dns_entropy", 0)
    if dns_e > 3.5:
        score += 9.0; reasons.append("high_dns_entropy_possible_DGA")
    if features.get("port_risk", 0):
        score += 7.0; reasons.append("suspicious_dest_port")
    failures = features.get("login_failure", 0)
    if failures > 5:
        score += 8.5; reasons.append("brute_force_attempt")
    elif failures > 2:
        score += 4.0; reasons.append("moderate_failures")
    if features.get("after_hours", 0) and failures > 2:
        score += 8.0; reasons.append("after_hours_with_failures")
    if features.get("cpu_percent", 0) > 90:
        score += 7.0; reasons.append("cpu_spike")
    bytes_total = features.get("bytes_total", 0)
    if bytes_total > 50_000_000:
        score += 8.0; reasons.append("large_data_transfer")
    elif bytes_total > 10_000_000:
        score += 4.0; reasons.append("above_avg_transfer")

    return round(score, 4), reasons


# ─── Core baseline processor ─────────────────────────────

def process_features(device_id: str, features: dict, collector: str) -> tuple[float, dict, list[str]]:
    """
    Returns:
      anomaly_score     — cumulative z-score sum (or rule score during warmup)
      feature_breakdown — { metric: z_score }
      reasons           — human-readable list (warmup only)
    """
    baseline = load_baseline(device_id)
    breakdown: dict[str, float] = {}
    reasons: list[str] = []

    # Determine if we have a warm baseline
    first_metric = next(iter(TRACKED_METRICS), None)
    is_warm = (
        first_metric is not None
        and baseline.get(first_metric, {}).get("count", 0) >= WARMUP_SAMPLES
    )

    if not is_warm:
        # --- Warmup phase: update stats but use rule-based scoring ---
        for metric in TRACKED_METRICS:
            raw = features.get(metric)
            if raw is None:
                continue
            try:
                value = float(raw)
            except (ValueError, TypeError):
                continue
            w = Welford(baseline.get(metric))
            w.update(value)
            baseline[metric] = w.to_dict()

        save_baseline(device_id, baseline)
        rule_s, reasons = rule_score(features, collector)
        return rule_s, {}, reasons

    # --- Warm phase: z-score statistical anomaly detection ---
    total_z = 0.0
    for metric in TRACKED_METRICS:
        raw = features.get(metric)
        if raw is None:
            continue
        try:
            value = float(raw)
        except (ValueError, TypeError):
            continue

        state = baseline.get(metric, {})
        w = Welford(state if state else None)

        if w.count >= 2:
            z = z_score(value, w.mean, w.std())
            breakdown[metric] = round(z, 4)
            total_z += z

        # Always update baseline online
        w.update(value)
        baseline[metric] = w.to_dict()

    save_baseline(device_id, baseline)

    # Normalize total z by count of tracked metrics to keep scale sensible
    tracked_count = len([m for m in TRACKED_METRICS if features.get(m) is not None])
    anomaly_score = round(total_z / max(tracked_count, 1), 4) if tracked_count else 0.0

    # Add top-3 anomalous features as reasons for decision engine context
    if breakdown:
        top = sorted(breakdown.items(), key=lambda x: -x[1])[:3]
        reasons = [f"{m}:z={z:.2f}" for m, z in top if z > 1.5]

    return anomaly_score, breakdown, reasons


# ─── Kafka Consumer ──────────────────────────────────────

class MLMonitor(BaseConsumer):
    topic        = FEATURE_STREAM
    group_id     = "ml-monitor"
    service_name = "MLMonitor"

    def process(self, event: dict):
        device_id = event.get("device_id") or "unknown"
        meta      = event.get("metadata", {})
        collector = meta.get("collector") or event.get("source", "unknown")
        features  = event.get("features", {})

        anomaly_score, breakdown, reasons = process_features(device_id, features, collector)

        # --- Archetype blending ---
        # Blend archetype_deviation (computed in FeatureEngine) into anomaly score.
        # Formula: Anomaly_final = anomaly_score + ARCHETYPE_WEIGHT × archetype_deviation
        arch_dev = float(features.get("archetype_deviation", 0.0))
        archetype = meta.get("device_archetype", "unknown")
        if arch_dev > 0:
            anomaly_score = round(anomaly_score + ARCHETYPE_WEIGHT * arch_dev, 4)
        if arch_dev > ARCHETYPE_THRESHOLD and "archetype_violation" not in reasons:
            reasons.append(f"archetype_violation:{archetype}:dist={arch_dev:.2f}")

        ml_event = {
            "event_id":          event.get("event_id") or str(uuid.uuid4()),
            "timestamp":         event.get("timestamp"),
            "source":            collector,
            "device_id":         device_id,
            "ip":                meta.get("ip"),
            "event_type":        meta.get("event_type"),
            "enrichment":        event.get("enrichment", {}),
            "features":          features,
            "anomaly_score":     anomaly_score,
            "feature_breakdown": breakdown,
            "anomaly_reasons":   reasons,
        }

        publish_event(ML_SCORES, ml_event)

        try:
            insert_ml_score(ml_event)
        except Exception as exc:
            print(f"[ML] DB write skipped: {exc}")

        warmup_left = max(0, WARMUP_SAMPLES - (
            load_baseline(device_id).get(TRACKED_METRICS[0], {}).get("count", 0)
        ))
        status = f"WARM | score={anomaly_score}" if warmup_left == 0 else f"WARMUP({warmup_left} left) | rule_score={anomaly_score}"
        print(f"[ML] {collector} | dev={device_id[:16]} | {status} | reasons={reasons or 'clean'}")


if __name__ == "__main__":
    init_schema()
    MLMonitor().run()
