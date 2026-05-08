"""
Guardient Device Profiles — Behavioral Archetype Baseline Library
==================================================================
Defines per-device-type archetype feature centroids and computes
Mahalanobis-style distance between an observed feature vector and the
expected profile for that device type.

Archetypes defined (from network security research):
  laptop    — user workstation, bursty DNS, mixed ports, moderate logins
  server    — high throughput, fixed ports, rare logins, low DNS entropy
  printer   — minimal traffic, specific ports (9100), almost zero DNS
  iot       — very low throughput, raw protocols, almost no DNS
  camera    — continuous RTSP stream, low DNS entropy
  phone     — high DNS (app updates), HTTPS heavy, moderate login
  smart_tv  — streaming ports (443, 8443), high bytes, low DNS entropy
  unknown   — neutral fallback (wide variance = tolerant)

Distance formula (diagonal Mahalanobis without numpy)
------------------------------------------------------
  D² = Σ  ( (x_i - μ_i) / σ_i )²
       i

  distance = sqrt(D²) / n_features   (normalised to 0-1 friendly range)

  A distance of 0.0 = perfectly matches archetype.
  A distance of 1.0+ = significantly atypical for this device class.

Usage
-----
  from services.device_profiles import compute_profile_distance

  dist = compute_profile_distance(features_dict, "printer")
  # dist ∈ [0, ∞) — attach to feature vector as "archetype_deviation"
"""

from __future__ import annotations
import math
from typing import Optional


# ── Feature dimensions tracked (must match FeatureEngine output) ────────────
# Format: (mean, std_dev) — std derived from expected natural variance
#
# Features: bytes_total, dns_entropy, port_risk, login_failure,
#           after_hours, session_duration, cpu_percent, memory_percent,
#           dns_query_length

ARCHETYPES: dict[str, dict[str, tuple[float, float]]] = {
    # ── Laptop — bursty user traffic ───────────────────────────────────────
    "laptop": {
        "bytes_total":      (2_000_000,  3_000_000),   # μ=2 MB, σ=3 MB
        "dns_entropy":      (2.8,        0.8),
        "port_risk":        (0.05,       0.15),
        "login_failure":    (0.5,        1.0),
        "after_hours":      (0.1,        0.2),
        "session_duration": (300,        200),
        "cpu_percent":      (25,         20),
        "memory_percent":   (55,         20),
        "dns_query_length": (20,         10),
    },

    # ── Server — high throughput, rare logins ───────────────────────────────
    "server": {
        "bytes_total":      (50_000_000, 30_000_000),
        "dns_entropy":      (1.2,        0.5),
        "port_risk":        (0.02,       0.05),
        "login_failure":    (0.1,        0.3),
        "after_hours":      (0.05,       0.1),
        "session_duration": (3600,       1200),
        "cpu_percent":      (40,         25),
        "memory_percent":   (65,         20),
        "dns_query_length": (10,         5),
    },

    # ── Printer — almost no DNS, port 9100 ─────────────────────────────────
    "printer": {
        "bytes_total":      (50_000,     80_000),
        "dns_entropy":      (0.5,        0.5),
        "port_risk":        (0.0,        0.05),
        "login_failure":    (0.0,        0.1),
        "after_hours":      (0.0,        0.05),
        "session_duration": (60,         30),
        "cpu_percent":      (5,          5),
        "memory_percent":   (10,         5),
        "dns_query_length": (5,          5),
    },

    # ── IoT — constrained, raw protocols ───────────────────────────────────
    "iot": {
        "bytes_total":      (100_000,    200_000),
        "dns_entropy":      (1.0,        0.5),
        "port_risk":        (0.01,       0.05),
        "login_failure":    (0.0,        0.1),
        "after_hours":      (0.0,        0.0),     # IoT runs 24/7
        "session_duration": (120,        60),
        "cpu_percent":      (10,         10),
        "memory_percent":   (20,         10),
        "dns_query_length": (8,          5),
    },

    # ── Camera — continuous RTSP, minimal DNS ──────────────────────────────
    "camera": {
        "bytes_total":      (5_000_000,  3_000_000),
        "dns_entropy":      (0.8,        0.4),
        "port_risk":        (0.0,        0.05),
        "login_failure":    (0.0,        0.1),
        "after_hours":      (0.0,        0.0),
        "session_duration": (86400,      21600),   # continuous
        "cpu_percent":      (20,         15),
        "memory_percent":   (30,         15),
        "dns_query_length": (6,          4),
    },

    # ── Phone — app updates, HTTPS heavy ───────────────────────────────────
    "phone": {
        "bytes_total":      (500_000,    800_000),
        "dns_entropy":      (3.0,        0.7),
        "port_risk":        (0.03,       0.1),
        "login_failure":    (0.3,        0.5),
        "after_hours":      (0.2,        0.3),
        "session_duration": (180,        120),
        "cpu_percent":      (15,         15),
        "memory_percent":   (40,         20),
        "dns_query_length": (25,         12),
    },

    # ── Smart TV — streaming, high bytes, low DNS entropy ──────────────────
    "smart_tv": {
        "bytes_total":      (20_000_000, 15_000_000),
        "dns_entropy":      (1.5,        0.5),
        "port_risk":        (0.01,       0.05),
        "login_failure":    (0.0,        0.1),
        "after_hours":      (0.3,        0.3),
        "session_duration": (7200,       3600),
        "cpu_percent":      (20,         15),
        "memory_percent":   (40,         20),
        "dns_query_length": (12,         6),
    },

    # ── Network device — switches/routers, huge traffic ────────────────────
    "network_device": {
        "bytes_total":      (100_000_000, 50_000_000),
        "dns_entropy":      (2.0,         0.5),
        "port_risk":        (0.05,        0.1),
        "login_failure":    (0.1,         0.2),
        "after_hours":      (0.0,         0.0),
        "session_duration": (86400,       0),
        "cpu_percent":      (30,          20),
        "memory_percent":   (50,          20),
        "dns_query_length": (12,          6),
    },

    # ── Unknown/workstation — broad tolerance ──────────────────────────────
    "unknown": {
        "bytes_total":      (2_000_000,  10_000_000),
        "dns_entropy":      (2.5,        1.5),
        "port_risk":        (0.05,       0.2),
        "login_failure":    (0.5,        2.0),
        "after_hours":      (0.1,        0.3),
        "session_duration": (300,        600),
        "cpu_percent":      (25,         30),
        "memory_percent":   (50,         30),
        "dns_query_length": (15,         15),
    },
}

# Alias mappings
ARCHETYPES["workstation"] = ARCHETYPES["laptop"]
ARCHETYPES["mobile"]      = ARCHETYPES["phone"]


# Feature dimension order (must be a stable subset of the feature vector)
PROFILE_FEATURES = [
    "bytes_total", "dns_entropy", "port_risk", "login_failure",
    "after_hours", "session_duration", "cpu_percent", "memory_percent",
    "dns_query_length",
]


def compute_profile_distance(features: dict, device_type: Optional[str]) -> float:
    """
    Compute the normalised diagonal-Mahalanobis distance between the
    observed feature vector and the archetype centroid for `device_type`.

    Returns:
      float ≥ 0.0 — 0.0 = perfect match, >1.0 = significant deviation

    Safe: missing features are skipped (not penalised).
    """
    dt = (device_type or "unknown").lower()
    profile = ARCHETYPES.get(dt, ARCHETYPES["unknown"])

    d_squared = 0.0
    n_used    = 0

    for feat in PROFILE_FEATURES:
        val = features.get(feat)
        if val is None:
            continue
        try:
            x = float(val)
        except (ValueError, TypeError):
            continue

        mu, sigma = profile.get(feat, (0.0, 1.0))
        # Avoid division by zero: if archetype has no variance, use 1.0
        if sigma <= 0:
            sigma = 1.0

        z = (x - mu) / sigma
        d_squared += z * z
        n_used    += 1

    if n_used == 0:
        return 0.0

    # Normalise by sqrt(n_used) to get per-feature-dimension distance
    distance = math.sqrt(d_squared) / math.sqrt(n_used)
    return round(distance, 4)


def archetype_for_type(device_type: Optional[str]) -> str:
    """Return the canonical archetype name for a given device_type string."""
    dt = (device_type or "unknown").lower()
    return dt if dt in ARCHETYPES else "unknown"
