# Guardient — Kafka Reference

## Setup

Kafka runs in a Docker container using **KRaft mode** (no ZooKeeper). A single broker handles all topics.

```yaml
image: apache/kafka:3.7.0
container_name: guardient-kafka
ports:
  - "9092:9092"
environment:
  KAFKA_PROCESS_ROLES: broker,controller   # single node handles both roles
  KAFKA_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
  KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
  KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"
```

Bootstrap server used by all services: `localhost:9092`

All topics are created with `3 partitions` and `replication_factor=1` (single broker). Run `python3 -m pipeline.topics` to create or verify all topics.

---

## Topic Map

```
Collector HTTP POST
    │
    ▼
raw_events ──────────► enrichment_service
                              │
                        enriched_events ──────────► feature_engine
                                                           │
                                                     feature_stream ──► ml_monitor
                                                                              │
                                                                        ml_scores ──► risk_engine
                                                                                          │
                                                                                    risk_scores
                                                                                    ┌────┴────┐
                                                                                    ▼         ▼
                                                                         graph_correlator  trust_engine
                                                                                    │         │
                                                                              graph_scores    │
                                                                                    └────►────┘
                                                                                    trust_scores
                                                                                          │
                                                                                    decision_engine
                                                                                    ┌────┴──────────┐
                                                                                    ▼               ▼
                                                                                 alerts      security_actions
                                                                                                    │
                                                                              response_engine (shim) │
                                                                                                    ▼
                                                                                        response_executions
```

---

## All Topics

| Topic | Producer | Consumer(s) | Purpose |
|-------|----------|-------------|---------|
| `raw_events` | `api/main.py` | `enrichment_service` | Normalised telemetry events, one per device per batch |
| `enriched_events` | `enrichment_service` | `feature_engine` | + geo, DNS, MAC vendor, device class |
| `feature_stream` | `feature_engine` | `ml_monitor` | 14-feature numeric vector per event |
| `ml_scores` | `ml_monitor` | `risk_engine` | Anomaly score + feature breakdown |
| `risk_scores` | `risk_engine` | `graph_correlator`, `trust_engine` | Risk 0–100 + I/C/V/N category — **fan-out to two consumers** |
| `graph_scores` | `graph_correlator` | `trust_engine` | Risk event enriched with `graph_caf` lateral movement amplifier |
| `trust_scores` | `trust_engine` | `decision_engine` | Per-device trust 0–100 + adjusted risk |
| `alerts` | `decision_engine` | (frontend / SIEM) | Fired security alerts |
| `security_actions` | `decision_engine` | `response_engine` (shim) | Action directives (action + device_id + severity) |
| `response_executions` | `response_executor` | (SIEM / audit) | Full execution records including status, approver, timestamps |
| `feedback_events` | `feedback_service` | (future) | Analyst labels for active learning |
| `simulation_events` | `sandbox_executor` | (unused) | Legacy sandbox injection — superseded by `/simulation/run` |
| `response_actions` | `response_engine` (old) | — | **Legacy / deprecated** — no longer written |

---

## Consumer Groups

Each service that reads from Kafka registers its own consumer group. Kafka tracks the read offset per group independently, so all groups can read the same topic at different paces.

| Consumer Group | Service | Topic |
|----------------|---------|-------|
| `enrichment-service` | enrichment_service | `raw_events` |
| `feature-engine` | feature_engine | `enriched_events` |
| `ml-monitor` | ml_monitor | `feature_stream` |
| `risk-engine` | risk_engine | `ml_scores` |
| `graph-correlator` | graph_correlator | `risk_scores` |
| `trust-engine-v2` | trust_engine | `graph_scores` |
| `decision-engine` | decision_engine | `trust_scores` |
| `response-engine` | response_engine (shim) | `security_actions` |
| `feedback-service` | feedback_service | (internal) |

The startup health check validates `≥ 8 active consumer groups` against the Kafka broker to confirm the pipeline is running.

---

## Producer/Consumer Pattern

### BaseConsumer (`pipeline/consumer.py`)

All pipeline services inherit from `BaseConsumer`. To build a new service:

```python
class MyService(BaseConsumer):
    topic        = SOME_INPUT_TOPIC   # reads from this
    group_id     = "my-service"
    service_name = "MyService"

    def process(self, event: dict):
        # transform event, publish to output topic
        publish_event(SOME_OUTPUT_TOPIC, transformed)
```

`BaseConsumer.run()` is a blocking loop: it polls Kafka and calls `process()` for each message. SIGINT / SIGTERM are handled cleanly.

Configuration:
- `auto_offset_reset="earliest"` — new consumer groups start from the beginning
- `enable_auto_commit=True` — offsets committed automatically after delivery
- `value_deserializer` — JSON decode on receive

### Producer (`pipeline/producer.py`)

A singleton `KafkaProducer` is shared across all calls in a single process:

```python
from pipeline.producer import publish_event
from pipeline.topics import RISK_SCORES

publish_event(RISK_SCORES, {"device_id": "...", "risk_score": 45.2, ...})
```

`publish_event` serialises to JSON, publishes synchronously (blocks until broker ACK), and silently catches exceptions to prevent pipeline crashes.

---

## Parallelism: risk_scores Fan-Out

The `risk_scores` topic has **two independent consumers**:

1. **graph_correlator** — correlates across devices to detect lateral movement chains
2. **trust_engine** — waits for `graph_scores` (which wraps the enriched risk event)

The flow is:

```
risk_engine → risk_scores
                 ├─► graph_correlator → graph_scores → trust_engine
                 └─► trust_engine  (direct, no graph_caf attached)
```

In practice `trust_engine` only subscribes to `graph_scores`, which means **every risk event must pass through graph_correlator first** before trust_engine processes it. If graph_correlator is not running, trust_engine starves.

---

## Topic Lifecycle (hard_reset.sh)

During a hard reset:

1. Each topic is deleted via the Kafka admin CLI inside the container:
   ```bash
   docker exec guardient-kafka /opt/kafka/bin/kafka-topics.sh \
     --bootstrap-server localhost:9092 --delete --topic <name>
   ```
2. A 2-second pause allows deletion to propagate.
3. All topics are recreated via `pipeline.topics.create_all_topics(partitions=3, replication=1)`.

`kafka-topics.sh` is not on the container's PATH — always use the absolute path `/opt/kafka/bin/kafka-topics.sh`.

---

## Configuration Notes

- **No ZooKeeper** — Kafka 3.7 KRaft mode manages metadata internally.
- **Single broker** — no replication (`replication_factor=1`). This is a dev/POC setup; production would require ≥ 3 brokers and replication.
- **`KAFKA_AUTO_CREATE_TOPICS_ENABLE=true`** — topics are auto-created if a producer publishes before `pipeline.topics` runs. This is a safety net, not the intended flow.
- **`kafka/` directory** — a stale duplicate of `pipeline/`. Never import from it. Always use `from pipeline.producer import ...` and `from pipeline.topics import ...`.
