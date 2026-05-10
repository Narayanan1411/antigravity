# Guardient — Data Flow Reference

This document traces every event from the moment a device generates telemetry to the moment a SOC analyst sees a trust score and a response action on the dashboard.

---

## Write Path (Telemetry → Pipeline → Database)

```
Device / Collector
       │
       │  HTTP POST  (with X-API-Key header)
       ▼
┌─────────────────────────────────────────────────────────┐
│  api/main.py  (port 8000)                               │
│                                                         │
│  1. Validate API key per collector type:                │
│       /network/telemetry  → NETWORK_KEY                 │
│       /identity/events    → IDENTITY_KEY                │
│       /cloud/events       → CLOUD_KEY                   │
│       /hardware/telemetry → HARDWARE_KEY                │
│                                                         │
│  2. Normalise into canonical schema (api/schema.py)     │
│     → extracts: device_id, ip, mac, hostname,           │
│       event_type, timestamp, source, raw payload        │
│                                                         │
│  3. Resolve Device Global ID (api/device_resolver.py)   │
│     → lookup MAC/IP/hostname in device_aliases table    │
│     → if new: generate DGID (dev_<mac_hex>),            │
│       upsert into devices + device_aliases              │
│                                                         │
│  4. Aggregate flows (network only)                      │
│     → collapses per-flow batch into one summary event   │
│       (prevents trust inflation from large flow counts) │
│                                                         │
│  5. Publish to Kafka: raw_events                        │
│  6. Append to logs/<category>.jsonl (fallback)          │
└────────────────────────┬────────────────────────────────┘
                         │ raw_events (Kafka)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  enrichment_service.py                                  │
│                                                         │
│  Adds external intelligence context:                    │
│  • GeoIP / ASN lookup (MaxMind .mmdb)                   │
│  • Reverse DNS resolution                               │
│  • MAC vendor lookup (OUI table)                        │
│  • Device class inference (IoT, server, camera…)        │
│  • Behavioral flags (after_hours, VPN detected…)        │
│                                                         │
│  Writes: devices table (upsert), events table (audit)   │
│  Publishes: enriched_events                             │
└────────────────────────┬────────────────────────────────┘
                         │ enriched_events (Kafka)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  feature_engine.py                                      │
│                                                         │
│  Converts enriched event → 14-dimensional numeric       │
│  feature vector:                                        │
│    bytes_total, dns_entropy, port_risk, login_failure,  │
│    after_hours, session_duration, cpu_percent,          │
│    memory_percent, dns_query_length,                    │
│    archetype_deviation, cpu_avg, cpu_spike,             │
│    disk_io_rate, process_count                          │
│                                                         │
│  Also computes archetype_deviation (distance from       │
│  device-type centroid in feature space).                │
│                                                         │
│  Writes: features table                                 │
│  Publishes: feature_stream                              │
└────────────────────────┬────────────────────────────────┘
                         │ feature_stream (Kafka)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  ml_monitor.py                                          │
│                                                         │
│  Welford online statistics per (device_id, metric):     │
│                                                         │
│  WARMUP (count < 100):                                  │
│    • Still updates Welford state                        │
│    • Uses rule-based scoring (heuristics)               │
│    • Returns anomaly_score on 0–10 scale                │
│                                                         │
│  WARM (count ≥ 100):                                    │
│    • z-score per metric: |value − mean| / std           │
│    • Capped at 10 to prevent outlier domination         │
│    • anomaly_score = mean(z_scores)                     │
│    • Blends archetype_deviation (weight 0.4)            │
│    • Optionally blends LSTM reconstruction error        │
│                                                         │
│  Writes: ml_scores + device_baselines tables            │
│  Publishes: ml_scores                                   │
└────────────────────────┬────────────────────────────────┘
                         │ ml_scores (Kafka)
                         ▼
┌─────────────────────────────────────────────────────────┐
│  risk_engine.py                                         │
│                                                         │
│  Normalises anomaly_score and routes to I/C/V/N:        │
│    Anomaly_norm = tanh(anomaly_score / 5)               │
│    Severity     = per-detection-type table (0.4–1.0)    │
│    Confidence   = tanh(anomaly_score × 1.5)             │
│    Impact       = per-device-type multiplier            │
│                                                         │
│    risk_score (0–100) = Sev × Anom × Conf × Impact × 100│
│                                                         │
│  Refreshes feedback weights every 5 min from DB.        │
│                                                         │
│  Writes: risk_scores table                              │
│  Publishes: risk_scores  ← consumed by TWO services     │
└──────────┬─────────────────────────┬───────────────────┘
           │ risk_scores             │ risk_scores
           ▼                         ▼
┌───────────────────────┐  ┌─────────────────────────────┐
│  graph_correlator.py  │  │  trust_engine.py             │
│                       │  │                              │
│  In-memory directed   │  │  9-step math model per device│
│  attack graph:        │  │  (see ML_MODEL.md for full   │
│  • Nodes = devices    │  │  derivation)                 │
│  • Edges = lateral    │  │                              │
│    movement signals   │  │  State persisted per device: │
│  • DFS finds longest  │  │  I, C, V, N risk categories  │
│    active chain       │  │  AR_prev, last_timestamp     │
│                       │  │                              │
│  CAF_graph =          │  │  Output: trust score 0–100   │
│  1 + 0.3 × path_len   │  │                              │
│                       │  │  Writes: trust_scores,       │
│  Writes:              │  │          trust_states tables │
│  graph_correlation_   │  │  Publishes: trust_scores     │
│  events table         │  └──────────────┬──────────────┘
│  Publishes: graph_    │                 │ trust_scores
│  scores → trust_engine│                 ▼
└───────────────────────┘  ┌─────────────────────────────┐
   graph_scores →           │  decision_engine.py          │
   trust_engine             │                              │
                            │  Graduated trust thresholds: │
                            │   ≥ 80 → allow               │
                            │  60–80 → monitor             │
                            │  40–60 → require_mfa         │
                            │  20–40 → restrict_network    │
                            │   < 20 → isolate/lock/kill   │
                            │  (role-specific at < 20)     │
                            │                              │
                            │  Writes: alerts table        │
                            │  Publishes: alerts           │
                            │             security_actions │
                            └──────────────┬──────────────┘
                                           │ security_actions
                                           ▼
                            ┌─────────────────────────────┐
                            │  response_engine.py (SHIM)   │
                            │  ↓ delegates to              │
                            │  response_executor/          │
                            │  executor.py                 │
                            │                              │
                            │  Deduplication check:        │
                            │  if pending record exists    │
                            │  for (device_id, action)     │
                            │  → return existing, no insert│
                            │                              │
                            │  Approval-required actions   │
                            │  → status=pending            │
                            │  Auto-approved actions       │
                            │  → dispatch handler          │
                            │                              │
                            │  Writes: response_executions │
                            │          device_blocks       │
                            │  Publishes: response_        │
                            │             executions       │
                            │  Emails:  trust < 30         │
                            │          (5-min cooldown)    │
                            └─────────────────────────────┘
```

---

## Read Path (Dashboard ← PostgreSQL)

The frontend **never reads from Kafka**. All dashboard data comes from PostgreSQL queries in `api/v1.py`.

```
Browser (Next.js)
       │
       │  GET /api/v1/entities/          → trust + decision per device
       │  GET /api/v1/audit/             → alert log
       │  GET /api/v1/transparency/stats → pipeline throughput stats
       │  GET /api/v1/response/executions → response action history
       │  GET /api/v1/devices            → list of pipeline-processed devices
       │  GET /api/v1/entities/{id}      → per-device detail + trust history
       ▼
┌─────────────────────────────────────────────────────────┐
│  api/v1.py  (FastAPI router, mounted at /api/v1)        │
│                                                         │
│  Queries PostgreSQL directly.                           │
│  Key behaviour: read-time trust decay                   │
│    • Fetches latest trust state (I, C, V, N)            │
│    • Re-runs trust formula using wall-clock Δt          │
│    • Dashboard shows decayed score even between events  │
│                                                         │
│  Warmup guard:                                          │
│    • Devices with < 100 trust_score entries             │
│    • Force-return trust=100, decision=trusted           │
│    • Prevents false positives before baselines warm     │
│                                                         │
│  Device filter for /devices:                            │
│    • Only returns devices with at least one trust_score  │
│    • Excludes network-discovered devices without data   │
└─────────────────────────────────────────────────────────┘
```

---

## Simulation Path (Isolated — no writes to pipeline)

```
Browser → POST /api/v1/simulation/run
              │
              ▼
         api/v1.py  (in-memory only)
              │
              ├── Read device record (SELECT, read-only)
              ├── Compute 7-point trust trajectory using trust_engine math
              ├── Fire response_executor.execute() at trust thresholds
              │     trust < 70 → require_mfa   (auto-approved)
              │     trust < 40 → restrict_network (pending)
              │     trust < 20 → containment action (pending)
              │
              └── Return: {run_id, trajectory, triggered_executions}
                          │
                          ▼
              Frontend animates trajectory at 3s intervals
              Response Center shows sim executions tagged
              triggered_by = "sim:<run_id>:<attack_type>"

NO writes to: feature_stream, ml_scores, trust_scores,
              trust_states, device_baselines, events, features
```

---

## Feedback Path (Analyst → Risk Weights)

```
SOC Analyst → POST /api/v1/feedback
                    │  { alert_id, label: "true_attack" | "false_positive" }
                    ▼
              feedback_service.py
                    │  writes feedback_labels table
                    │  recalculates severity weight for detection_type
                    │  writes feedback_weights table
                    ▼
              risk_engine.py  (background thread)
                    │  refreshes weight cache every 5 minutes
                    ▼
              next risk computation uses updated severity
```

---

## Collector Endpoints

| Endpoint | Collector | Category |
|----------|-----------|----------|
| `POST /network/telemetry` | `network_discovery_service.py` + Scapy | N (Network) |
| `POST /identity/events` | `colud and identity/` auth collector | I (Identity) |
| `POST /cloud/events` | `colud and identity/` cloud collector | C (Compute/Cloud) |
| `POST /hardware/telemetry` | `hardware_monitoring_service.py` | V (Visibility/Hardware) |

All endpoints require the respective API key in the `X-API-Key` header. Development defaults are hardcoded in `api/main.py`.

---

## Event Shape (through the pipeline)

Each Kafka message is a JSON object. Key fields that grow as the event moves through stages:

| Field | Added by | Consumers |
|-------|---------|-----------|
| `event_id` | api/main.py | all stages (correlation) |
| `device_id` | device_resolver | all stages |
| `timestamp` | api/main.py | all stages |
| `source` | api/main.py | risk_engine (category routing) |
| `enrichment` | enrichment_service | feature_engine |
| `features` | feature_engine | ml_monitor |
| `anomaly_score` | ml_monitor | risk_engine |
| `feature_breakdown` | ml_monitor | risk_engine |
| `anomaly_reasons` | ml_monitor | risk_engine |
| `risk_score` | risk_engine | trust_engine |
| `risk_factors` | risk_engine | trust_engine |
| `category` | risk_engine | trust_engine |
| `graph_caf` | graph_correlator | trust_engine |
| `trust_score` | trust_engine | decision_engine |
| `decision` | decision_engine | response_executor |
