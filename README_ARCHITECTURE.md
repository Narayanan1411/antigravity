# Guardient POC — Architecture & Data Flow Reference

> **Stack:** FastAPI (port 8000) · Kafka · PostgreSQL · Next.js frontend (port 3000)

## Project Overview

Guardient is a **Zero-Trust Telemetry Analysis Platform**. It ingests raw device telemetry
(network traffic, identity/auth events, cloud API calls, hardware profiles) through a FastAPI
ingestion layer, streams all data through Kafka, and processes it through a sequential
multi-stage pipeline of services that ultimately produce a **Trust Score** per device and
take automated security action.

---

## Folder Structure

```
poc Guardient/
│
├── api/                        # HTTP Ingestion + Frontend Bridge (FastAPI)
│   ├── main.py                 # Entry point — telemetry endpoints + CORS + v1 router mount
│   ├── v1.py                   # ★ Frontend bridge: GET /api/v1/entities|audit|transparency/stats, POST /response/approve
│   ├── schema.py               # Canonical event normalisation (network/identity/cloud/hardware)
│   └── device_resolver.py      # DGID generation & device identity resolution (DB lookup/upsert)
│
├── pipeline/                   # Kafka Infrastructure
│   ├── topics.py               # All topic name constants + admin topic creation
│   ├── producer.py             # Singleton KafkaProducer wrapper (publish_event)
│   ├── consumer.py             # BaseConsumer — all services inherit this
│   └── __init__.py
│
├── db/                         # PostgreSQL Database Layer
│   └── db.py                   # Connection pool, schema DDL, per-stage write helpers
│
├── services/                   # Pipeline Microservices (each is an independent process)
│   ├── enrichment_service.py   # Stage 1: Geo/ASN, reverse DNS, MAC vendor, device class
│   ├── feature_engine.py       # Stage 2: → Numeric feature vector (30+ features)
│   ├── ml_monitor.py           # Stage 3: Welford statistical baseline + z-score anomaly detection
│   ├── risk_engine.py          # Stage 4: Composite risk score (0-100) with category routing (I/C/V/N)
│   ├── trust_engine.py         # Stage 5: 9-step mathematical trust model per device
│   └── decision_engine.py      # Stage 6: Graduated action (allow/monitor/MFA/restrict/isolate)
│
├── utils/                      # Shared utility helpers
│   ├── geoip_lookup.py         # MaxMind GeoLite2 city + ASN lookup
│   ├── dns_utils.py            # Reverse DNS lookup (socket.gethostbyaddr)
│   ├── mac_lookup.py           # OUI prefix → vendor name (in-memory table)
│   ├── device_classifier.py    # OS string → device class (laptop/mobile/iot/unknown)
│   └── __init__.py
│
├── network/                    # Network Telemetry Collector
│   ├── network_data.py         # Scapy packet sniffer; produces raw flows + device stats
│   └── geoip/                  # MaxMind .mmdb database files
│       ├── GeoLite2-City.mmdb
│       └── GeoLite2-ASN.mmdb
│
├── colud and identity/         # Cloud & Identity Collectors (separate process)
│   ├── cloud/                  # Cloud API event simulator/collector
│   ├── identity/               # Identity/auth event collector
│   ├── hardware_collector.py   # Hardware profile collector (CPU, RAM, disks, VM)
│   ├── temporal_collector.py   # Temporal metrics collector (NTP, clock skew)
│   └── README.md
│
├── kafka/                      # Kafka utility scripts & setup
│   ├── topics.py               # (duplicate — use pipeline/topics.py as canonical)
│   ├── producer.py             # (duplicate — use pipeline/producer.py)
│   ├── consumer.py             # (duplicate — use pipeline/consumer.py)
│   ├── kafka_consumer.py       # Standalone consumer example
│   ├── kafka_producer.py       # Standalone producer example
│   ├── system_monitor_kafka.py # System metrics → Kafka publisher
│   └── KAFKA_SETUP.md
│
├── techgium frontend/           # Next.js SOC Dashboard (port 3000)
│   ├── src/app/                # Pages: dashboard, entities, audit, incidents, responses
│   ├── src/hooks/usePolling.ts # SWR polling hook → GET /api/v1/* every 3 s
│   ├── src/lib/api.ts          # Base URL + fetch helpers (POST /api/v1/response/approve)
│   ├── src/types/index.ts      # Entity, AuditLog, TrustEvaluation TypeScript types
│   └── next.config.mjs         # Proxy rewrite: /api/v1/* → http://localhost:8000/api/v1/*
│
├── logs/                       # JSONL fallback logs (one file per telemetry category)
│   ├── network.jsonl
│   ├── identity.jsonl
│   ├── cloud.jsonl
│   ├── hardware.jsonl
│   └── temporal.jsonl
│
├── simulate_data.py            # Test data generator (sends HTTP requests to local API)
├── test_schema.py              # Basic schema validation tests
├── docker-compose.yml          # Kafka + PostgreSQL containers
├── requirements.txt            # Python dependencies
└── start.sh                    # Startup script (Kafka topics + all services)
```

---

## Frontend ↔ Backend Connection

The **techgium frontend** (Next.js) polls the FastAPI backend every 3 seconds via SWR:

```
browser (localhost:3000)
  │  GET /api/v1/entities/          → Next.js proxy rewrites →  FastAPI :8000/api/v1/entities/
  │  GET /api/v1/audit/             →                         →  FastAPI :8000/api/v1/audit/
  │  GET /api/v1/transparency/stats →                         →  FastAPI :8000/api/v1/transparency/stats
  │  POST /api/v1/response/approve  →                         →  FastAPI :8000/api/v1/response/approve  (simulated)
```

`api/v1.py` reads directly from PostgreSQL — no Kafka involved for the read path.

### API v1 Endpoint → DB Source Mapping

| Endpoint | DB Tables Read | Notes |
|---|---|---|
| `GET /api/v1/entities/` | `devices`, `trust_scores`, `trust_states`, `events` | Latest trust score per device |
| `GET /api/v1/audit/` | `alerts` | Decision engine output, shaped as AuditLog |
| `GET /api/v1/transparency/stats` | `events`, `alerts` | Aggregate counts + recent alerts |
| `POST /api/v1/response/approve` | `alerts` (INSERT) | Simulated — logs SOC action, no real enforcement yet |

---

## End-to-End Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        COLLECTOR LAYER (Agents)                             │
│                                                                              │
│  network/network_data.py      →  POST /network/telemetry  (API key: NET-…) │
│  colud and identity/          →  POST /identity/events    (API key: IDN-…) │
│  colud and identity/cloud/    →  POST /cloud/events       (API key: CLD-…) │
│  colud and identity/          →  POST /hardware/profile   (API key: HW-…)  │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  HTTP POST with raw telemetry payload
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        API LAYER  (api/main.py)                             │
│                                                                              │
│  1.  _check_key()           validate category-specific API key              │
│  2.  schema.events_from_*() normalise payload → list of canonical events    │
│  3.  device_resolver.resolve_device()  assign stable DGID (device_id)      │
│      └─ SHA256(mac|hostname|device_type|hardware)  → "dev_<12hex>"         │
│      └─ DB lookup in device_aliases (mac → ip → hostname fallback chain)   │
│  4.  pipeline.publish_event(RAW_EVENTS, event)  emit to Kafka               │
│  5.  _save_local()          append to logs/<category>.jsonl (fallback)      │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: raw_events
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 1 — Enrichment Service (services/enrichment_service.py) │
│                                                                              │
│  Consumes: raw_events                                                        │
│  Publishes: enriched_events                                                  │
│  DB Writes: devices (upsert), events (audit log)                            │
│                                                                              │
│  Adds to every event:                                                        │
│    geo_destination  ← utils/geoip_lookup.py → MaxMind GeoLite2-City        │
│    asn              ← utils/geoip_lookup.py → MaxMind GeoLite2-ASN         │
│    dns_reverse      ← utils/dns_utils.py    → socket.gethostbyaddr          │
│    mac_vendor       ← utils/mac_lookup.py   → OUI prefix table             │
│    device_class     ← utils/device_classifier.py → OS string heuristics    │
│    bytes_total      = bytes_sent + bytes_received                            │
│    login_failure_flag = 1 if login_success is False                         │
│    after_hours      = 1 if event hour < 06:00 or > 22:00                   │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: enriched_events
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 2 — Feature Engine (services/feature_engine.py)         │
│                                                                              │
│  Consumes: enriched_events                                                   │
│  Publishes: feature_stream                                                   │
│  DB Writes: features                                                         │
│                                                                              │
│  Converts telemetry → numeric feature vector (30+ features):                │
│    dns_entropy        Shannon entropy of DNS query (DGA detection)          │
│    bytes_total        Total bytes (float)                                    │
│    port_risk          1 if dest port ∈ [22,23,3389,445,4444,6667]          │
│    login_failure      Count of auth failures                                 │
│    after_hours        Binary flag (0/1)                                      │
│    session_duration   Session length in seconds                              │
│    has_tls            1 if TLS SNI present                                   │
│    mfa_enabled        1 if mfa_status == "enabled"                           │
│    legacy_auth        1 if auth_type ∈ {ntlm, basic, password}             │
│    cpu_percent        CPU utilisation (from hardware raw payload)            │
│    memory_percent     RAM utilisation                                        │
│    is_vm              1 if vm_uuid present in raw                           │
│    privilege_change   1 if privilege_change_event in raw                    │
│    key_created        1 if risk_flags.key_created                            │
│    high_risk_event    1 if risk_level == "high"                              │
│    … (and more)                                                              │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: feature_stream
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 3 — ML Monitor (services/ml_monitor.py)                 │
│                                                                              │
│  Consumes: feature_stream                                                    │
│  Publishes: ml_scores                                                        │
│  DB Writes: ml_scores, device_baselines                                     │
│                                                                              │
│  Algorithm: Welford Online Statistics + Hybrid Rule Fallback                │
│                                                                              │
│  NEW device (< 20 samples):                                                  │
│    → rule_score():  heuristic checks on dns_entropy, port_risk,             │
│                     login_failure, after_hours, cpu_percent, bytes_total    │
│    → Returns rule-based anomaly_score (0–10 scale)                          │
│                                                                              │
│  WARM device (≥ 20 samples):                                                │
│    → z_score(value, mean, std)  per tracked metric, capped at Z_CAP=10     │
│    → anomaly_score = mean(z_scores across tracked metrics)                  │
│    → anomaly_reasons = top-3 metrics with z > 1.5                          │
│                                                                              │
│  Welford state persisted per device in device_baselines (PostgreSQL JSONB)  │
│  Metrics tracked: bytes_total, dns_entropy, port_risk, login_failure,       │
│                   after_hours, session_duration, cpu_percent,               │
│                   memory_percent, dns_query_length                           │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: ml_scores
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 4 — Risk Engine (services/risk_engine.py)               │
│                                                                              │
│  Consumes: ml_scores                                                         │
│  Publishes: risk_scores                                                      │
│  DB Writes: risk_scores                                                      │
│                                                                              │
│  Formula:                                                                    │
│    anomaly_norm = tanh(anomaly)               [0→1 normalisation]           │
│    confidence   = tanh(anomaly × 1.5)         [rises with anomaly strength] │
│    impact       = min(1.0, DEVICE_IMPACT[device_type])                       │
│    severity     = SEVERITY_TABLE[detection_type]                             │
│    risk_score   = severity × anomaly_norm × confidence × impact × 100       │
│                                                                              │
│  detection_type parsed from anomaly_reasons (picks highest-severity match)  │
│                                                                              │
│  DEVICE_IMPACT:                                                              │
│    domain_controller=1.8, server=1.5, network_device=1.2, laptop/ws=1.0    │
│    phone=0.9, iot=0.7, camera=0.65, printer=0.6, smart_tv=0.5              │
│                                                                              │
│  Category routing (I/C/V/N):                                                │
│    I (Identity)   — login_failure, mfa_failure, brute_force, after_hours    │
│    C (Compute)    — privilege_escalation, iam_changed, key_created          │
│    V (Visibility) — cpu_spike, device_drift, large_clock_skew              │
│    N (Network)    — dns_entropy, port_risk, large_data_transfer, port_scan  │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: risk_scores
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 5 — Trust Engine (services/trust_engine.py)             │
│                                                                              │
│  Consumes: risk_scores                                                       │
│  Publishes: trust_scores                                                     │
│  DB Writes: trust_scores, trust_states (per-device persistent state)        │
│                                                                              │
│  9-Step Mathematical Model (per device, stateful):                           │
│                                                                              │
│  Step 1: Category risk evolution (per I/C/V/N bucket)                       │
│    λ = BASE_LAMBDA × DEVICE_DECAY[device_type] × (1 + anomaly)             │
│    Rx = Rx_prev × e^(-λ·Δt) + Σ(severity × anomaly × confidence × impact)  │
│                                                                              │
│  Step 2: Aggregated Risk                                                     │
│    AR = 0.40·I + 0.25·C + 0.20·V + 0.15·N                                 │
│                                                                              │
│  Step 3: Correlation Amplification Factor                                    │
│    CAF = 1 + α·(I+C+V+N − max(I,C,V,N))   [α=0.6]                        │
│    (rises when multiple categories are simultaneously active)                │
│                                                                              │
│  Step 4: Confidence Index                                                    │
│    CI = 1 − Π(1 − ci)   (never collapses independent evidence)              │
│                                                                              │
│  Step 5: Risk Velocity                                                       │
│    RV = |AR − AR_prev| / Δt                                                 │
│    RV_norm = min(1.0, RV / RV_THRESHOLD)                                    │
│                                                                              │
│  Step 6: Adjusted Risk                                                       │
│    adj = AR × CAF × CI × (1 + β·RV_norm)   [β=0.8]                        │
│                                                                              │
│  Step 7: Trust Score                                                         │
│    T = 100 × e^(-k·adj)   [k=2.5]                                          │
│    adj=0 → T=100, adj=0.5 → T≈29, adj=1 → T≈8, adj≥2 → T≈0               │
│                                                                              │
│  Step 8: Natural Recovery                                                    │
│    Handled automatically — if no events arrive, I/C/V/N decay over time     │
│    (via the e^(-λ·Δt) term in step 1)                                       │
│                                                                              │
│  Step 9: Hard Override                                                       │
│    If any event has risk_score ≥ 90 → T = min(T, 10)  (confirmed breach)   │
│                                                                              │
│  Device state (I,C,V,N, AR_prev, last_timestamp) persisted in trust_states  │
└────────────────────┬────────────────────────────────────────────────────────┘
                     │  Kafka topic: trust_scores
                     ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│               STAGE 6 — Decision Engine (services/decision_engine.py)       │
│                                                                              │
│  Consumes: trust_scores                                                      │
│  Publishes: security_actions (always), alerts (when trust ≤ 40 & risk > 0) │
│  DB Writes: alerts                                                           │
│                                                                              │
│  Graduated Actions (trust score thresholds):                                 │
│    T ≥ 80  →  allow                                                          │
│    T ≥ 60  →  monitor                                                        │
│    T ≥ 40  →  require_mfa                                                    │
│    T ≥ 20  →  restrict_network                                               │
│    T < 20  →  role-specific hard action:                                     │
│               iot           → isolate_vlan                                   │
│               server        → kill_process                                   │
│               user_device   → lock_account                                  │
│               network_device→ firewall_block                                 │
│                                                                              │
│  Alert severity:                                                             │
│    trust ≤ 10 or risk ≥ 90  → CRITICAL                                      │
│    trust ≤ 20 or risk ≥ 70  → HIGH                                          │
│    trust ≤ 40 or risk ≥ 50  → MEDIUM                                        │
│    otherwise                → LOW                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### Trust Score → Frontend Decision Mapping

| Trust Score | Frontend `decision` | `active_actions` | `approval_required` |
|---|---|---|---|
| ≥ 80 | `trusted` | `[]` | false |
| ≥ 60 | `monitor` | `["monitor"]` | false |
| ≥ 40 | `monitor` | `["require_mfa"]` | false |
| ≥ 20 | `isolate` | `["restrict_network"]` | **true** |
| < 20 | `emergency` | `["lock_account"]` | **true** |

---

## Kafka Topic Map

| Topic              | Producer           | Consumer            | Purpose                            |
|--------------------|--------------------|---------------------|------------------------------------|
| `raw_events`       | `api/main.py`      | `enrichment_service`| Normalised canonical events        |
| `enriched_events`  | `enrichment_service`| `feature_engine`   | Events + geo/DNS/vendor enrichment |
| `feature_stream`   | `feature_engine`   | `ml_monitor`        | Numeric feature vectors            |
| `ml_scores`        | `ml_monitor`       | `risk_engine`       | Anomaly scores + reasons           |
| `risk_scores`      | `risk_engine`      | `trust_engine`      | Risk score + category (I/C/V/N)    |
| `trust_scores`     | `trust_engine`     | `decision_engine`   | Per-device trust score (0–100)     |
| `alerts`           | `decision_engine`  | (frontend/SIEM)     | Security alerts                    |
| `security_actions` | `decision_engine`  | (enforcement layer) | Automated enforcement actions      |

---

## PostgreSQL Database Schema

| Table               | Written by             | Purpose                                    |
|---------------------|------------------------|--------------------------------------------|
| `devices`           | enrichment_service     | Device registry (hostname, OS, MAC, type)  |
| `device_aliases`    | device_resolver (API)  | MAC/IP/hostname → DGID mapping table       |
| `events`            | enrichment_service     | Full audit log of all enriched events      |
| `features`          | feature_engine         | Per-event feature vectors (JSONB)          |
| `ml_scores`         | ml_monitor             | Anomaly scores + feature breakdown         |
| `device_baselines`  | ml_monitor             | Welford statistical baselines per device   |
| `risk_scores`       | risk_engine            | Risk scores + severity + detection type    |
| `trust_scores`      | trust_engine           | Trust scores + adjusted risk per event     |
| `trust_states`      | trust_engine           | Persistent I/C/V/N state per device        |
| `alerts`            | decision_engine        | Fired alerts with action taken             |

---

## File-Level Logic Reference

### `api/v1.py`  ★ NEW — Frontend Bridge
**Role:** REST read API for the techgium SOC dashboard.

- **`GET /entities/`** — Joins `devices` + `trust_scores` + `trust_states` + `events` (latest IP). Computes `decision`, `active_actions`, `approval_required`, `category_breakdown` from the Trust Engine state. Returns the full `Entity[]` array the frontend expects.
- **`GET /audit/`** — Reads `alerts` table (decision_engine output), maps columns to `AuditLog[]` with human-readable `reason` strings.
- **`GET /transparency/stats`** — Counts rows in `events` and `alerts`, groups by source, returns aggregate telemetry stats.
- **`POST /response/approve`** — Simulated: inserts a SOC action record into `alerts`. No real enforcement (response engine TBD). Always returns `{status: "ok", simulated: true}`.

---

### `api/main.py`
**Role:** HTTP ingestion gateway.

- Defines 4 POST endpoints: `/network/telemetry`, `/identity/events`, `/cloud/events`, `/hardware/profile`
- Uses 4 isolated API keys (one per telemetry category), loaded from env vars
- Per request: validates key → normalises payload via `schema.py` → resolves DGID via `device_resolver.py` → publishes to `raw_events` Kafka topic → saves JSONL fallback
- Also exposes `/health` (GET) and `/temporal/metrics` (POST, no processing, local save only)
- **CORS** enabled for `localhost:3000` and `localhost:3001` (Next.js dev server)
- Mounts `api/v1.py` router at `/api/v1` prefix

---

### `api/schema.py`
**Role:** Canonical event normalisation.

- Defines `CANONICAL_FIELDS` — the 22 standard fields every event carries
- `make_event(payload)`: fills a dict with all canonical fields, nulls for missing ones
- `events_from_network(payload)`: extracts flows list → maps MAC/ports/bytes/DNS/TLS
- `events_from_identity(payload)`: extracts identity_events → maps user_id/auth_type/MFA/login
- `events_from_cloud(payload)`: extracts cloud_events → nested audit_events → API call/region/resource
- `events_from_hardware(payload)`: single hardware profile → MAC/IP/hostname/OS/fingerprint

---

### `api/device_resolver.py`
**Role:** Stable device identity (DGID) resolution.

- `generate_dgid(mac, hostname, device_type, hardware)`: SHA256(fields joined with `|`), first 12 hex chars → `"dev_<12hex>"`
- Priority chain: MAC > hardware_fingerprint > hostname > IP (IP never creates new device alone)
- `lookup_alias(alias)`: queries `device_aliases` table for existing DGID
- `store_device_and_aliases(device_id, aliases, metadata)`: upserts `devices` + `device_aliases`
- `resolve_device(event)`: tries all known aliases in order; on miss → computes new DGID and stores it; on unidentifiable → returns `"dev_unidentified_<uuid>"`

---

### `db/db.py`
**Role:** All database I/O for the pipeline.

- Maintains a `psycopg2.SimpleConnectionPool` (1–10 connections), lazy-initialised
- `init_schema()`: runs the DDL to create all tables if missing (idempotent)
- `get_conn()` / `put_conn()`: borrow/return from pool
- One write-helper per pipeline stage:
  - `upsert_device()` — enrichment stage
  - `insert_event()` — enrichment stage (audit)
  - `insert_features()` — feature engine
  - `insert_ml_score()` — ml_monitor
  - `insert_risk_score()` — risk engine
  - `insert_trust_score()` — trust engine
  - `insert_alert()` — decision engine
  - `load_baseline()` / `save_baseline()` — ml_monitor Welford state
  - `load_trust_state()` / `save_trust_state()` — trust engine per-device state

---

### `pipeline/producer.py`
**Role:** Singleton Kafka publisher used by all services.

- `publish_event(topic, event)`: serialises event to JSON, sends to Kafka, flushes
- Gracefully returns `False` (instead of crashing) if Kafka broker is unreachable
- Used by: `api/main.py`, `enrichment_service`, `feature_engine`, `ml_monitor`, `risk_engine`, `trust_engine`, `decision_engine`

---

### `pipeline/consumer.py`
**Role:** Reusable Kafka consumer base class.

- `BaseConsumer`: wraps `KafkaConsumer`, handles SIGINT/SIGTERM gracefully
- Subclasses override `topic`, `group_id`, `service_name`, and `process(event)`
- All 6 pipeline services extend `BaseConsumer`

---

### `pipeline/topics.py`
**Role:** Single source of truth for all Kafka topic names.

- 8 named constants: `RAW_EVENTS`, `ENRICHED_EVENTS`, `FEATURE_STREAM`, `ML_SCORES`, `RISK_SCORES`, `TRUST_SCORES`, `ALERTS`, `SECURITY_ACTIONS`
- `create_all_topics()`: bootstrap utility — creates all topics via `KafkaAdminClient`

---

### `services/enrichment_service.py`
**Role:** Stage 1 — Enrich raw events with context signals.

- Extends `BaseConsumer`, consumes `raw_events`
- Performs geo/ASN lookup, reverse DNS, MAC vendor lookup, device classification
- Computes `bytes_total = bytes_sent + bytes_received`
- Sets `login_failure_flag` and `after_hours` binary flags
- Writes enriched device record to `devices` table and full raw event to `events` table
- Publishes extended event dict to `enriched_events`

---

### `services/feature_engine.py`
**Role:** Stage 2 — Convert telemetry to numeric features.

- Extends `BaseConsumer`, consumes `enriched_events`
- `extract_features(event)`: all values are floats/ints — ML and rules need numeric-only input
- Key computed features: `dns_entropy` (Shannon entropy on DNS query for DGA detection), `port_risk`, `login_failure`, `after_hours_login`, `mfa_enabled`, `legacy_auth`
- Publishes `feature_event` bundle (event metadata + `features` dict) to `feature_stream`
- Writes feature vector to `features` table (JSONB)

---

### `services/ml_monitor.py`
**Role:** Stage 3 — Statistical anomaly detection.

- Extends `BaseConsumer`, consumes `feature_stream`
- **Welford Online Algorithm**: single-pass computation of running mean and variance per metric per device — no need to store full history
  - `update(value)`: O(1) update of count, mean, M2
  - `variance()` = M2 / (count − 1)
  - `std()` = √variance
- **Warmup phase** (< 20 samples): uses `rule_score()` — fast heuristic rules give early signal
- **Warm phase** (≥ 20 samples): z-score per metric, capped at 10, averaged across tracked metrics
- Tracked metrics: bytes_total, dns_entropy, port_risk, login_failure, after_hours, session_duration, cpu_percent, memory_percent, dns_query_length
- Persists Welford state as JSONB in `device_baselines`; publishes `ml_scores` event with `anomaly_score` and `anomaly_reasons`

---

### `services/risk_engine.py`
**Role:** Stage 4 — Composite risk scoring with category classification.

- Extends `BaseConsumer`, consumes `ml_scores`
- `_parse_detection(anomaly_reasons)`: scans reason strings for highest-severity keyword match in `SEVERITY_TABLE`
- `compute_risk()`:
  - `anomaly_norm = tanh(anomaly)` — maps z-score to (0,1)
  - `confidence = tanh(anomaly × 1.5)` — confidence rises with anomaly strength
  - `impact = min(1.0, DEVICE_IMPACT[device_type])`
  - `risk_score = severity × anomaly_norm × confidence × impact × 100`
- Maps detection → category (I/C/V/N) via `DETECTION_CATEGORY` table
- Severity table covers 27 detection types with values 0.40–1.00
- Adds `risk_factors` sub-dict to the event for the trust engine to consume

---

### `services/trust_engine.py`
**Role:** Stage 5 — 9-step mathematical trust model, stateful per device.

- Extends `BaseConsumer`, consumes `risk_scores`
- Maintains `state = {I, C, V, N, AR_prev, last_timestamp}` per device in PostgreSQL
- `classify_device(event)`: 6-level priority resolution (explicit type → protocol → port → DNS → OS → MAC vendor)
- `adaptive_lambda(category, device_type, anomaly)`: λ = BASE × DEVICE_DECAY × (1 + anomaly)
  - Servers have slow decay (0.4×), mobiles fast (1.2×) — threat persists longer on high-value targets
- `trust_pipeline(state, events, now_ts, device_type)`: runs all 9 steps, returns (trust, adj_risk, updated_state)
- Output: trust score 0–100 + per-category state snapshot
- Publishes `trust_scores` event; writes to `trust_scores` and `trust_states` tables

---

### `services/decision_engine.py` (Stage 6 — Action & Alerting)

- **Role:** Maps numerical trust scores to graduated action tiers.
- Emits `security_actions` event (always).
- Emits `alerts` event (only when trust ≤ 40).

### `services/response_engine.py` (Stage 7 — Containment Enforcer)

- **Role:** Consumes `security_actions` and simulates SOAR (Security Orchestration, Automation, and Response) enforcement.
- Writes physical execution records to `response_actions` DB table.
- **SMTP SOC Alerting:** Triggers a real-time email alert via `utils/email_alert.py` (secure-smtplib on smtp.gmail.com:587) when a device's trust score drops `< 30`. Relies on `SMTP_USER` and `SMTP_PASS` environment variables and incorporates a 5-minute cooldown cache to prevent email fatigue.

---

### `utils/geoip_lookup.py`
- Opens GeoLite2-City and GeoLite2-ASN MaxMind `.mmdb` files on startup
- `geo_lookup(ip)` → `{country, asn}` (returns `{None, None}` if DB missing or private IP)

### `utils/dns_utils.py`
- `reverse_dns(ip)` → hostname string or `None` (stdlib `socket.gethostbyaddr`)

### `utils/mac_lookup.py`
- In-memory OUI table (7 vendors: Apple, Samsung, Dell, VMware, VirtualBox, Docker)
- `mac_vendor(mac)` → vendor string or `None`

### `utils/device_classifier.py`
- `classify_device(os_name)` → `"laptop" | "mobile" | "iot" | "unknown"`
- Simple OS string matching (Windows/Mac/Ubuntu/Linux → laptop, Android/iOS → mobile, Tizen → iot)

---

## Key Identifiers

| Identifier | Description | Example |
|---|---|---|
| `device_id` (DGID) | Stable device identity across all telemetry streams | `dev_a3f2b1c9e801` |
| `event_id` | UUID per event, used as PK across pipeline tables | `uuid4()` |
| `alias` | Any identifier that maps to a DGID (MAC, IP, hostname, hardware fingerprint) | `3C:5A:B4:01:02:03` |
| `category` | Risk domain: I=Identity, C=Compute, V=Visibility, N=Network | `"N"` |

---

## How to Run

```bash
# 1. Export SMTP credentials for real-time alerting
export SMTP_USER="your_email@gmail.com"
export SMTP_PASS="your_app_password"

# 2. Start infrastructure
docker-compose up -d        # Kafka + PostgreSQL

# 3. Initialise Kafka topics
python3 -m pipeline.topics

# 4. Initialise DB schema
python3 -m db.db

# 5. Start the API  (serves telemetry ingestion + /api/v1 frontend endpoints)
python3 -m uvicorn api.main:app --port 8000 --reload

# 6. Start each pipeline service in a separate terminal
python3 services/enrichment_service.py
python3 services/feature_engine.py
python3 services/ml_monitor.py
python3 services/risk_engine.py
python3 services/trust_engine.py
python3 services/decision_engine.py
python3 services/response_engine.py
python3 services/simulation_controller.py

# Or use the startup script
bash start.sh

# 7. Start the Next.js SOC dashboard
cd "techgium frontend"
npm run dev            # → http://localhost:3000

# Data will start appearing in ~15s from the network sniffer
```

> The dashboard **"API Online"** badge turns green once the FastAPI backend is reachable.

> **`simulate_data.py`** — only needed if you want to test the pipeline *without* the network sniffer running (e.g. in CI or on a device that can't sniff packets). With all services running normally, **do not run it** — it injects fake devices into the DB.
