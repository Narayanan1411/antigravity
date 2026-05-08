"""
Guardient Kafka Producer
publish_event(topic, event_dict) — used by API and services.
"""

from __future__ import annotations
import json
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

BOOTSTRAP = "localhost:9092"

_producer = None   # singleton

def _get_producer() -> KafkaProducer:
    global _producer
    if _producer is None:
        _producer = KafkaProducer(
            bootstrap_servers=BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            acks="all",
            retries=3,
        )
    return _producer


def publish_event(topic: str, event: dict) -> bool:
    """
    Publish an event dict to a Kafka topic.
    Returns True on success, False if Kafka is unreachable.
    """
    try:
        _get_producer().send(topic, event)
        _get_producer().flush()
        return True
    except NoBrokersAvailable:
        print(f"[Kafka] No broker available — event dropped on topic '{topic}'")
        return False
    except Exception as exc:
        print(f"[Kafka] Publish error: {exc}")
        return False


def close():
    global _producer
    if _producer:
        _producer.close()
        _producer = None
