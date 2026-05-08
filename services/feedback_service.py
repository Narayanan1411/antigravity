"""
Guardient Feedback Service — Adaptive Trust Feedback Loop
==========================================================
Provides the learning bridge between analyst decisions and pipeline weights.

When a security analyst reviews an alert and labels it:
  • "true_attack"    → the detection type was correct; raise severity weight
  • "false_positive" → the detection was wrong; lower severity weight

Math
----
  feedback_weight_new = weight_old × (1 + α × (label - 0.5))

  α = 0.2  (learning rate — conservative by design)
  label = 1 (true_attack)  → multiplier = 1.10  → +10% severity
  label = 0 (false_positive) → multiplier = 0.90 → -10% severity

  Weights are clamped to [0.3, 2.0] to prevent runaway learning.

Architecture
------------
  Decision Engine
        ↓
  Feedback Service (this module)  ← analyst labels via REST API
        ↓
  feedback_weights table (PostgreSQL)
        ↓
  Risk Engine (loads weights at startup + every 5 min)

Usage
-----
  Imported by the API layer:
    from services.feedback_service import submit_feedback, get_weights_summary

  Called from POST /api/v1/feedback with:
    {alert_id, label, detection_type, analyst, device_id?}
"""

from __future__ import annotations
import sys
import threading
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from db.db import (
    insert_feedback_label,
    load_feedback_weights,
    upsert_feedback_weight,
)

# ── Tuning ──────────────────────────────────────────────────────────────────
ALPHA         = 0.2           # Learning rate
WEIGHT_MIN    = 0.3           # Minimum severity weight (prevent suppression)
WEIGHT_MAX    = 2.0           # Maximum severity weight (prevent explosion)
VALID_LABELS  = {"true_attack", "false_positive"}

# In-memory cache (refreshed by Risk Engine every N minutes)
_weights_lock   = threading.Lock()
_weights_cache: dict[str, float] = {}


def _label_to_value(label: str) -> float:
    """Convert label string to numeric: true_attack=1, false_positive=0."""
    return 1.0 if label == "true_attack" else 0.0


def _clamp(value: float) -> float:
    return max(WEIGHT_MIN, min(WEIGHT_MAX, value))


def submit_feedback(
    alert_id: str,
    label: str,
    detection_type: str,
    analyst: str = "system",
    device_id: str = "unknown",
) -> dict:
    """
    Process an analyst feedback label and update the severity weight for
    the given detection_type.

    Returns a dict with the old weight, new weight, and update metadata.
    Raises ValueError if label is invalid.
    """
    label = label.strip().lower()
    if label not in VALID_LABELS:
        raise ValueError(f"Invalid label '{label}'. Must be one of {VALID_LABELS}")

    # 1. Persist the raw label
    try:
        insert_feedback_label(alert_id, device_id, detection_type, label, analyst)
    except Exception as exc:
        print(f"[Feedback] DB label write skipped: {exc}")

    # 2. Load current weight for this detection_type
    weights   = load_feedback_weights()
    old_weight = weights.get(detection_type, 1.0)

    # 3. Compute new weight: w_new = w_old × (1 + α × (label_val − 0.5))
    label_val  = _label_to_value(label)
    multiplier = 1.0 + ALPHA * (label_val - 0.5)
    new_weight = _clamp(old_weight * multiplier)
    new_weight = round(new_weight, 4)

    # 4. Persist updated weight
    try:
        upsert_feedback_weight(detection_type, new_weight)
    except Exception as exc:
        print(f"[Feedback] DB weight write skipped: {exc}")

    # 5. Update local cache immediately
    with _weights_lock:
        _weights_cache[detection_type] = new_weight

    direction_icon = "📈" if label_val == 1.0 else "📉"
    print(
        f"[Feedback] {direction_icon} {label} | {detection_type} | "
        f"weight {old_weight:.4f} → {new_weight:.4f} | analyst={analyst}"
    )

    return {
        "status":         "ok",
        "alert_id":       alert_id,
        "detection_type": detection_type,
        "label":          label,
        "old_weight":     old_weight,
        "new_weight":     new_weight,
        "analyst":        analyst,
        "timestamp":      datetime.now(tz=timezone.utc).isoformat(),
    }


def get_weights_summary() -> dict:
    """Return current feedback weights for all detection types."""
    weights = load_feedback_weights()
    total  = len(weights)
    above  = sum(1 for w in weights.values() if w > 1.0)
    below  = sum(1 for w in weights.values() if w < 1.0)
    return {
        "total_detection_types_tuned": total,
        "severity_increased":          above,
        "severity_decreased":          below,
        "weights":                     weights,
    }


def refresh_cache() -> dict:
    """Reload weights from DB into local cache. Called by Risk Engine timer."""
    global _weights_cache
    fresh = load_feedback_weights()
    with _weights_lock:
        _weights_cache = fresh
    return fresh


def get_cached_weight(detection_type: str) -> float:
    """Fast in-process lookup of the current feedback weight for a detection_type."""
    with _weights_lock:
        return _weights_cache.get(detection_type, 1.0)
