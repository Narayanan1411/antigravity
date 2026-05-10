# Guardient — ML Model Documentation

The ML pipeline has two layers: a **statistical anomaly detector** (Welford + z-score) and an optional **deep learning layer** (LSTM autoencoder). Both feed into the Trust Engine's 9-step mathematical model.

---

## Stage 1 — Feature Extraction (`feature_engine.py`)

Before any ML, raw enriched events are converted to a numeric feature vector.

### Extracted Features

| Feature | Source | Notes |
|---------|--------|-------|
| `bytes_total` | Network payload | Raw transfer volume |
| `dns_entropy` | DNS query string | Shannon entropy — high values suggest DGA |
| `port_risk` | Destination port | Binary: 1 if port ∈ {22, 23, 445, 3389, 4444, 6667} |
| `login_failure` | Auth events | Count of failed login attempts |
| `after_hours` | Timestamp | Binary: 1 if activity outside business hours |
| `session_duration` | Auth events | Session length in seconds |
| `cpu_percent` | Hardware monitor | Current CPU utilisation |
| `memory_percent` | Hardware monitor | Current RAM utilisation |
| `dns_query_length` | DNS query | String length of domain name |
| `archetype_deviation` | Device profiles | Euclidean distance from device-type archetype |
| `cpu_avg` | Hardware monitor | Rolling average CPU |
| `cpu_spike` | Hardware monitor | Peak CPU in window |
| `disk_io_rate` | Hardware monitor | Disk read+write MB/s |
| `process_count` | Hardware monitor | Number of running processes |

### DNS Entropy (DGA Detection)

```
entropy = -Σ p(c) × log₂(p(c))
```

High entropy (> 3.5) indicates random-looking domain names typical of Domain Generation Algorithms used by C2 malware.

### Archetype Deviation

Each device type has a reference archetype (mean feature vector). The Euclidean distance between the observed feature vector and the archetype centroid is computed and included as `archetype_deviation`. A deviation > 1.5 triggers an `archetype_violation` reason in the ML output.

---

## Stage 2 — Statistical Anomaly Detection (`ml_monitor.py`)

### Welford Online Algorithm

Guardient uses Welford's single-pass online algorithm to maintain a running mean and variance **per device, per feature** without storing raw history. This is memory-efficient and works on streaming data.

**Update rule per observation:**

```
count  += 1
delta   = value − mean
mean   += delta / count
delta2  = value − mean
M2     += delta × delta2

variance = M2 / (count − 1)    [Bessel corrected]
std      = √variance
```

State stored in PostgreSQL as `{count, mean, M2}` per (device_id, metric).

### Warmup Phase (count < 100 observations)

During warmup, statistical baselines are not yet reliable. The ML monitor still **updates** Welford state with each observation but uses **rule-based heuristics** for scoring:

| Rule | Score Added | Label |
|------|------------|-------|
| DNS entropy > 3.5 | +9.0 | `high_dns_entropy_possible_DGA` |
| Risky port detected | +7.0 | `suspicious_dest_port` |
| Login failures > 5 | +8.5 | `brute_force_attempt` |
| Login failures 2–5 | +4.0 | `moderate_failures` |
| After-hours + failures | +8.0 | `after_hours_with_failures` |
| CPU > 90% | +7.0 | `cpu_spike` |
| Bytes > 500 MB | +8.0 | `critical_data_exfiltration_threshold` |
| Bytes > 100 MB | +4.0 | `large_data_transfer` |

The warmup guard in `api/v1.py` also forces `trust=100, decision=trusted` for devices with fewer than 100 trust_score entries to prevent false positives from influencing the dashboard before baselines are warm.

### Warm Phase (count ≥ 100)

Each feature is scored by its absolute z-score against the device's personal baseline:

```
z = min( |value − mean| / std,  Z_CAP )    where Z_CAP = 10.0
```

The cap prevents a single extreme outlier from dominating. The final `anomaly_score` is the mean of all individual z-scores across tracked features that have data:

```
anomaly_score = Σz / count(tracked_features_present)
```

### Archetype Blending

After z-score computation, archetype deviation is blended in:

```
anomaly_score += ARCHETYPE_WEIGHT × archetype_deviation    (ARCHETYPE_WEIGHT = 0.4)
```

This ensures devices that deviate from their category norms (e.g. a printer suddenly running SSH) get flagged even if individual features look normal in isolation.

### LSTM Integration (optional)

`network_discovery_service.py` optionally feeds an LSTM autoencoder reconstruction error as `ml_anomaly_score`. The ML monitor normalises it via tanh and merges it with the statistical score:

```
lstm_norm = min(1.0, tanh(lstm_score / 10.0))
anomaly_score = max(anomaly_score, lstm_norm)
```

If the LSTM model file is absent, `ML_ENABLED=False` and this step is skipped.

---

## Stage 3 — Risk Normalisation (`risk_engine.py`)

The anomaly score from ML monitor is a raw z-score (range ~0–10). Risk engine normalises it and routes it to the correct Trust Engine category.

### Category Routing (I/C/V/N)

Each detection type is mapped to one of four trust domains:

| Category | Label | Example detections |
|----------|-------|-------------------|
| **I** | Identity | `login_failure`, `mfa_failure`, `brute_force`, `after_hours` |
| **C** | Compute/Cloud | `privilege_escalation`, `process_injection`, `iam_changed`, `api_anomaly` |
| **V** | Visibility/Hardware | `cpu_spike`, `device_drift`, `clock_skew`, `behavior_anomaly` |
| **N** | Network | `dns_entropy`, `port_risk`, `port_scan`, `ssh_activity`, `large_data_transfer` |

### Risk Contribution Formula

```
RiskContribution = Severity × Anomaly_norm × Confidence × Impact
risk_score (0–100) = RiskContribution × 100
```

Where:
- **Severity** — intrinsic threat level per detection type (table in `risk_engine.py`; range 0.4–1.0)
- **Anomaly_norm** — `tanh(anomaly_score / 5)` normalised to [0, 1]
- **Confidence** — `tanh(anomaly_score × 1.5)` — rises with anomaly strength
- **Impact** — device-type multiplier (domain_controller=1.8, server=1.5, laptop=1.0, IoT=0.7…)

### Feedback Loop

Severity weights are adjustable via analyst feedback. When a SOC analyst labels an alert as `true_attack` or `false_positive`, the weight for that detection type is updated in `feedback_weights` (PostgreSQL). Risk engine refreshes these weights every 5 minutes from a background thread.

---

## Stage 4 — Graph Correlation (`graph_correlator.py`)

Runs in **parallel with trust_engine** (both consume `risk_scores`).

Maintains an in-memory directed graph of devices. When a risky event arrives for device D, edges are inferred from detection signals (ssh_activity, privilege_escalation, login…). A DFS finds the longest active attack chain originating from D.

```
CAF_graph = 1 + 0.3 × path_length

path_length = 0 → CAF_graph = 1.00  (isolated anomaly)
path_length = 1 → CAF_graph = 1.30  (one hop)
path_length = 3 → CAF_graph = 1.90  (phishing → server → DC)
path_length = 6 → CAF_graph = 2.80  (full kill-chain)
```

This `graph_caf` is attached to the event and published to `graph_scores` for the Trust Engine to consume.

---

## Stage 5 — Trust Engine: 9-Step Mathematical Model (`trust_engine.py`)

### Constants

```python
WEIGHTS = {"I": 0.40, "C": 0.25, "V": 0.20, "N": 0.15}
ALPHA   = 0.6      # CAF correlation amplification factor
BETA    = 0.8      # Risk velocity amplification factor
K       = 2.5      # Trust decay rate constant
RV_THRESHOLD = 1.0  # Velocity normalisation ceiling
TRUST_OVERRIDE_THRESHOLD = 10  # Hard cap for confirmed-compromised devices
```

### Step-by-Step

**Step 1 — Category Risk Evolution**

Each of the four categories (I, C, V, N) maintains an independent risk value that decays exponentially between events and accumulates when new anomalies arrive:

```
λ = BASE_LAMBDA[category] × DEVICE_DECAY[device_type] / (1 + anomaly)

Rx_decayed = Rx_prev × e^(−λ × Δt)
contribution = Severity × Anomaly × Confidence × Impact
Rx_new = min(10.0, Rx_decayed + contribution)
```

High anomaly → smaller λ → slower decay → threat stays in memory longer.

Device-type decay multipliers (slower = persists longer):
- domain_controller: 0.4 — threats persist longest
- server: 0.6
- network_device: 0.8
- IoT: 0.9
- laptop/workstation: 2.0 — recover 2× faster
- phone/mobile: 2.5 — recover fastest

**Step 2 — Aggregated Risk**

```
AR = 0.40·I + 0.25·C + 0.20·V + 0.15·N
```

**Step 3 — Correlation Amplification Factor**

```
CAF_local  = 1 + 0.6 × (I + C + V + N − max(I,C,V,N))
CAF_graph  = 1 + 0.3 × lateral_movement_path_length
CAF        = max(CAF_local, CAF_graph)
```

CAF rises when multiple categories are simultaneously anomalous (correlated attack) or when a lateral movement chain is confirmed. The graph CAF overrides local when the confirmed attack chain is longer.

**Step 4 — Confidence Index**

```
CI = 1 − Π(1 − cᵢ)    for all confirming sources
```

Combining independent confirmation signals: two sources each 50% confident → CI = 0.75. Never shrinks — each additional confirming source can only raise CI.

**Step 5 — Risk Velocity**

```
RV = |AR − AR_prev| / Δt
RV_norm = min(1.0, RV / 1.0)
```

A rapidly increasing risk score (attack accelerating) amplifies the adjusted risk.

**Step 6 — Adjusted Risk**

```
adj = AR × CAF × CI × (1 + 0.8 × RV_norm)
```

**Step 7 — Trust Score**

```
Trust = 100 × e^(−2.5 × adj)
```

Key reference points:
- `adj = 0.0` → Trust = 100 (no risk)
- `adj = 0.2` → Trust ≈ 61
- `adj = 0.5` → Trust ≈ 29
- `adj = 1.0` → Trust ≈ 8
- `adj = 2.0` → Trust < 1

**Step 8 — Natural Recovery**

No special step needed: exponential decay in Step 1 means category risks naturally approach zero when no new events arrive. Trust recovers automatically without any intervention.

**Step 9 — Hard Override**

If any event in the batch carries `risk_score ≥ 90` (pipeline CRITICAL), the device is flagged as compromised and trust is capped at 10:

```
if compromised: Trust = min(Trust, 10)
```

---

## Stage 6 — Decision Engine (`decision_engine.py`)

Maps the trust score to a graduated action and severity:

| Trust Range | Decision | Action |
|-------------|----------|--------|
| 80–100 | allow | no action |
| 60–80 | monitor | passive monitoring |
| 40–60 | monitor | `require_mfa` |
| 20–40 | isolate | `restrict_network` |
| < 20 | emergency | role-specific: `isolate_vlan` / `kill_process` / `lock_account` / `firewall_block` |

---

## Read-Time Decay

When the frontend requests entity data, `api/v1.py` recomputes the trust score at read time using the same formula as the Trust Engine. This ensures trust scores decrease naturally on the dashboard even between pipeline events, without requiring a live pipeline event every few seconds.

---

## Simulation Isolation

The `/simulation` page uses `POST /api/v1/simulation/run`, which computes trajectories **entirely in memory**. The Welford baselines in `device_baselines`, the trust states in `trust_states`, and the Kafka topics `feature_stream` / `ml_scores` / `trust_scores` are **never touched during simulation**. Real device scores on other pages are completely unaffected.
