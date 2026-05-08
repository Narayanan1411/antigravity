"""
Guardient Kafka Topics
All topic names centralised here. Import this everywhere.
"""

from __future__ import annotations
from kafka import KafkaAdminClient
from kafka.admin import NewTopic
from kafka.errors import TopicAlreadyExistsError

BOOTSTRAP = "localhost:9092"

# ── Topic names ──────────────────────────────────
RAW_EVENTS       = "raw_events"        # collectors → API
ENRICHED_EVENTS  = "enriched_events"   # enrichment service out
FEATURE_STREAM   = "feature_stream"    # feature engine out
ML_SCORES        = "ml_scores"         # ml_monitor out
RISK_SCORES      = "risk_scores"       # risk_engine out
TRUST_SCORES     = "trust_scores"      # trust_engine out
ALERTS           = "alerts"            # decision_engine out

ALL_TOPICS = [
    RAW_EVENTS,
    ENRICHED_EVENTS,
    FEATURE_STREAM,
    ML_SCORES,
    RISK_SCORES,
    TRUST_SCORES,
    ALERTS,
]


def create_all_topics(partitions: int = 3, replication: int = 1):
    """
    Bootstrap all Guardient Kafka topics.
    Run once before starting any service.
    Safe to re-run — skips topics that already exist.
    """
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
