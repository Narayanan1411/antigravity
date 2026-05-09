"""
Guardient Kafka Producer
publish_event(topic, event_dict) — used by API and services.
"""

from __future__ import annotations
import json

KAFKA_AVAILABLE = False
KafkaProducer = None
NoBrokersAvailable = None

try:
    from kafka import KafkaProducer as _KafkaProducer
    from kafka.errors import NoBrokersAvailable as _NoBrokersAvailable
    KafkaProducer = _KafkaProducer
    NoBrokersAvailable = _NoBrokersAvailable
    KAFKA_AVAILABLE = True
except ImportError:
    print("[Kafka] Warning: kafka-python not installed, publishing disabled")
    KAFKA_AVAILABLE = False

BOOTSTRAP = "localhost:9092"

_producer = None   # singleton

def _get_producer():
    global _producer
    if not KAFKA_AVAILABLE:
        return None
    if _producer is None:
        _producer = KafkaProducer(
            bootstrap_servers=BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            acks=1,
            retries=3,
            request_timeout_ms=5000,
        )
    return _producer


def publish_event(topic: str, event: dict) -> bool:
    """
    Publish an event dict to a Kafka topic.
    Returns True on success, False if Kafka is unreachable or not available.
    """
    if not KAFKA_AVAILABLE:
        return False
    
    try:
        producer = _get_producer()
        if producer is None:
            return False
        producer.send(topic, event)
        producer.flush()
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
