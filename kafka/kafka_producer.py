"""
Kafka Producer for Guardient Telemetry
Sends system metrics to Kafka topic
"""
from kafka import KafkaProducer
import json
import time
from datetime import datetime


def create_producer():
    """Initialize Kafka producer"""
    producer = KafkaProducer(
        bootstrap_servers="localhost:9092",
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks='all',  # Wait for all replicas to acknowledge
        retries=3
    )
    return producer


def send_telemetry(producer, topic="telemetry", **metrics):
    """
    Send telemetry data to Kafka
    
    Args:
        producer: KafkaProducer instance
        topic: Kafka topic name
        **metrics: System metrics (cpu, memory, disk, etc.)
    """
    payload = {
        "timestamp": datetime.utcnow().isoformat(),
        **metrics
    }
    
    future = producer.send(topic, payload)
    record_metadata = future.get(timeout=10)
    
    print(f"✓ Sent to {record_metadata.topic} "
          f"[partition {record_metadata.partition}] "
          f"offset {record_metadata.offset}")
    
    return record_metadata


def main():
    """Example usage"""
    producer = create_producer()
    
    try:
        # Send sample telemetry data
        for i in range(5):
            send_telemetry(
                producer,
                cpu=50 + i * 5,
                memory=70 + i * 2,
                disk=45,
                network_in=1024 * i,
                network_out=512 * i
            )
            time.sleep(1)
    finally:
        producer.flush()
        producer.close()
        print("Producer closed")


if __name__ == "__main__":
    main()
