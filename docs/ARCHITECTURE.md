# Guardient — System Architecture

## Overview

Guardient is a Zero-Trust Telemetry Analysis Platform. Every device on the network is continuously scored on a **Trust Scale of 0–100**. The score decreases when anomalies are detected and recovers naturally over time when behaviour normalises. Scores drive automated response actions — from passive monitoring to network isolation.

---

## Component Map

```
┌─────────────────────────────────────────────────────────────────────┐
│                        COLLECTORS  (data sources)                    │
│  Network Sniffer · Identity/Auth · Cloud APIs · Hardware Monitor     │
└────────────────────────┬────────────────────────────────────────────┘
                         │  HTTP POST (API key auth)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     FastAPI Ingestion Layer  :8000                   │
│   api/main.py  ─  validates key, normalises schema, resolves DGID   │
│   api/v1.py    ─  frontend read bridge (PostgreSQL queries)          │
└────────────────────────┬────────────────────────────────────────────┘
                         │  publishes to raw_events (Kafka)
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Kafka  :9092  (KRaft, single broker)             │
│   13 topics  ·  3 partitions each  ·  no ZooKeeper                  │
└──┬────────────────────────────────────────────────────────────┬─────┘
   │  pipeline microservices consume → transform → publish      │
   ▼                                                            ▼
┌──────────────────────────────────┐       ┌────────────────────────────┐
│   8-Stage Processing Pipeline    │       │   PostgreSQL  :5432         │
│                                  │       │   17 tables                 │
│   1. enrichment_service          │──────▶│   devices, events,          │
│   2. feature_engine              │       │   features, ml_scores,      │
│   3. ml_monitor                  │       │   risk_scores, trust_scores │
│   4. risk_engine         ──┐     │       │   alerts, response_         │
│   5. graph_correlator ◀──┘ │     │       │   executions, device_blocks │
│      trust_engine  ◀───────┘     │       │   trust_states, ...         │
│   6. decision_engine             │──────▶└────────────────────────────┘
│   7. response_engine (shim)      │
│   8. response_executor           │──────▶ SMTP alerts  (trust < 30)
└──────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│               Next.js SOC Dashboard  :3000                          │
│   Reads from PostgreSQL via api/v1.py  (never directly from Kafka)  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
poc Guardient/                  ← all Python commands run from here
│
├── api/
│   ├── main.py                 ← FastAPI app: telemetry endpoints, CORS, router mount
│   ├── v1.py                   ← Frontend bridge: GET entities/audit/transparency + POST response/*
│   ├── schema.py               ← Canonical normalisation for network/identity/cloud/hardware
│   └── device_resolver.py      ← DGID generation and MAC/IP/hostname → device_id resolution
│
├── pipeline/                   ← Kafka infrastructure (CANONICAL — use this, not kafka/)
│   ├── topics.py               ← All 13 topic name constants + create_all_topics()
│   ├── producer.py             ← Singleton KafkaProducer (publish_event)
│   └── consumer.py             ← BaseConsumer — all services inherit from this
│
├── services/                   ← 11 independent pipeline microservices
│   ├── enrichment_service.py
│   ├── feature_engine.py
│   ├── ml_monitor.py
│   ├── risk_engine.py
│   ├── graph_correlator.py
│   ├── trust_engine.py
│   ├── decision_engine.py
│   ├── response_engine.py      ← DEPRECATED SHIM — only delegates to response_executor/
│   ├── simulation_controller.py ← FastAPI on :8001 (legacy sandbox; new sim uses api/v1.py)
│   ├── network_discovery_service.py ← Scapy sniffer + optional LSTM
│   └── hardware_monitoring_service.py
│
├── response_executor/          ← Active response orchestration (single source of truth)
│   ├── executor.py             ← ResponseExecutor class + get_executor() singleton
│   ├── models.py               ← ActionStatus, APPROVAL_REQUIRED_ACTIONS, ACTION_DESCRIPTIONS
│   ├── handlers.py             ← One stub per action — replace with real enforcement APIs
│   └── app/                    ← (internal helpers)
│
├── db/
│   └── db.py                   ← Connection pool, full DDL, per-stage write helpers
│
├── utils/                      ← GeoIP, DNS, MAC vendor lookup, device classifier
├── network/                    ← Scapy packet capture, MaxMind .mmdb GeoIP databases
├── colud and identity/         ← Cloud/identity/hardware/temporal telemetry collectors
│
├── techgium frontend/          ← Next.js 14 SOC dashboard (TypeScript)
│   └── src/
│       ├── app/                ← Page routes (dashboard, entities, responses, simulation…)
│       ├── hooks/usePolling.ts ← SWR polling hook used by all pages
│       ├── lib/api.ts          ← Typed fetch wrappers for POST endpoints
│       └── types/index.ts      ← Shared TypeScript interfaces
│
├── kafka/                      ← STALE DUPLICATE of pipeline/ — do not import from here
├── logs/                       ← JSONL fallback per telemetry category
├── docker-compose.yml          ← Kafka + PostgreSQL containers
├── start.sh                    ← Full Linux stack startup (auto-detect NIC, health checks)
└── hard_reset.sh               ← Wipes all DB, Kafka, ML models, logs back to clean state
```

---

## Ports

| Service | Port | Notes |
|---------|------|-------|
| FastAPI backend | 8000 | All API routes including `/api/v1/` |
| Simulation controller | 8001 | Legacy; new simulation uses `/api/v1/simulation/run` |
| Next.js frontend | 3000 | Dev server with proxy → 8000 |
| Kafka broker | 9092 | PLAINTEXT, KRaft |
| PostgreSQL | 5432 | user=guardient, db=guardient |

---

## Frontend Pages

| Route | Description |
|-------|-------------|
| `/` | Dashboard: live trust score overview, alert counts |
| `/entities` | Device list with real-time trust scores and decisions |
| `/adaptive-trust` | Per-device trust history charts and ML signal breakdown |
| `/audit` | Alert audit log from `decision_engine` |
| `/responses` | Response Center: approval queue, active blocks, execution history |
| `/simulation` | Attack Simulation Lab — isolated sandbox, no ML contamination |
| `/data-transparency` | Aggregate pipeline throughput and severity distribution |
| `/how-it-works` | Architecture walkthrough |

All pages use `usePolling` (SWR + direct HTTP to `:8000`) for live data. POST actions go through the Next.js proxy (`/api/v1/…` → `localhost:8000/api/v1/…`) to avoid CORS.

---

## Response Executor Architecture

```
decision_engine ──► security_actions (Kafka)
                        │
                        ▼
              response_engine.py (DEPRECATED SHIM)
                        │  delegates every call to
                        ▼
              response_executor/executor.py
                        │
              ┌─────────┴──────────┐
              │                    │
    requires_approval?           auto-approved?
              │                    │
         status=pending        dispatch handler immediately
              │                    │
         wait for SOC          response_executor/handlers.py
         /approve or /reject        (stub — replace with real enforcement)
              │                    │
              └─────────┬──────────┘
                        │
                 write response_executions (PostgreSQL)
                 update device_blocks (containment only)
                 publish to response_executions (Kafka)
                 send SMTP if trust < 30  (5-min cooldown)
```

**Deduplication:** Before creating any pending/running record, `executor.execute()` calls `find_active_execution(device_id, action)`. If one already exists in pending or running state, the existing record is returned and no duplicate is inserted. This prevents the pipeline from flooding the Response Center with repeated entries for the same outstanding action.

**Actions requiring SOC approval:** `restrict_network`, `isolate_vlan`, `lock_account`, `firewall_block`, `kill_process`

**Always auto-approved:** `allow`, `monitor`, `require_mfa`, `block_device` (manual), `unblock_device` (manual)

---

## Simulation Architecture

The `/simulation` page uses `POST /api/v1/simulation/run` — a pure in-memory endpoint that:

1. Reads the device record (read-only, no writes)
2. Computes a 7-point trust trajectory using the same math as the Trust Engine
3. Fires `response_executor.execute()` at thresholds (trust < 70 / 40 / 20)
4. Returns the full trajectory and triggered execution IDs

**ML baselines are never touched.** No events are written to `feature_stream`, `ml_scores`, `trust_scores`, or `trust_states`. The simulation is completely isolated from the real pipeline.

---

## Infrastructure (Docker Compose)

```yaml
services:
  kafka:     apache/kafka:3.7.0    # KRaft mode, single broker, port 9092
  postgres:  postgres:15           # port 5432, user/pass/db = guardient
```

Both use named Docker volumes (`kafka_data`, `pg_data`) so data persists across container restarts.
