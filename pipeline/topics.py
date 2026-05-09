"""
Guardient Kafka Topics
All topic names centralised here. Import this everywhere.
"""

from __future__ import annotations

KAFKA_AVAILABLE = False
KafkaAdminClient = None
NewTopic = None
TopicAlreadyExistsError = None

try:
    from kafka import KafkaAdminClient as _KafkaAdminClient
    from kafka.admin import NewTopic as _NewTopic
    from kafka.errors import TopicAlreadyExistsError as _TopicAlreadyExistsError
    KafkaAdminClient = _KafkaAdminClient
    NewTopic = _NewTopic
    TopicAlreadyExistsError = _TopicAlreadyExistsError
    KAFKA_AVAILABLE = True
except ImportError:
    print("[Kafka] Warning: kafka-python not installed, topics disabled")
    KAFKA_AVAILABLE = False

BOOTSTRAP = "localhost:9092"

# ── Topic names ──────────────────────────────────
RAW_EVENTS       = "raw_events"        # collectors → API
ENRICHED_EVENTS  = "enriched_events"   # enrichment service out
FEATURE_STREAM   = "feature_stream"    # feature engine out
ML_SCORES        = "ml_scores"         # ml_monitor out
RISK_SCORES      = "risk_scores"       # risk_engine out
GRAPH_SCORES     = "graph_scores"      # graph_correlator out  (NEW)
TRUST_SCORES     = "trust_scores"      # trust_engine out
ALERTS           = "alerts"            # decision_engine alerts
SECURITY_ACTIONS = "security_actions"  # decision_engine enforcement actions
FEEDBACK_EVENTS  = "feedback_events"   # feedback_service out  (NEW)
SIMULATION_EVENTS= "simulation_events" # sandbox_executor out
RESPONSE_ACTIONS     = "response_actions"      # response_engine out (deprecated)
RESPONSE_EXECUTIONS  = "response_executions"   # response_executor out (active)

ALL_TOPICS = [
    RAW_EVENTS,
    ENRICHED_EVENTS,
    FEATURE_STREAM,
    ML_SCORES,
    RISK_SCORES,
    GRAPH_SCORES,
    TRUST_SCORES,
    ALERTS,
    SECURITY_ACTIONS,
    FEEDBACK_EVENTS,
    SIMULATION_EVENTS,
    RESPONSE_ACTIONS,
    RESPONSE_EXECUTIONS,
]


def create_all_topics(partitions: int = 3, replication: int = 1):
    """
    Bootstrap all Guardient Kafka topics.
    Run once before starting any service.
    Safe to re-run — skips topics that already exist.
    """
    if not KAFKA_AVAILABLE:
        print("[Topics] Kafka not available, skipping topic creation")
        return
    
    admin = KafkaAdminClient(bootstrap_servers=BOOTSTRAP, client_id="guardient-admin")
    specs = [
        NewTopic(name=t, num_partitions=partitions, replication_factor=replication)
        for t in ALL_TOPICS
    ]
    try:
        admin.create_topics(new_topics=specs, validate_only=False)
        print(f"[Topics] Created: {ALL_TOPICS}")
    except TopicAlreadyExistsError:
        print("[Topics] All topics already exist.")
    finally:
        admin.close()


if __name__ == "__main__":
    create_all_topics()
    print("Done.")
