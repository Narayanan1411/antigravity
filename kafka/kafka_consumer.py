"""
Kafka Consumer for Guardient Telemetry
Consumes system metrics from Kafka topic
"""
from kafka import KafkaConsumer
import json
import signal
import sys


def create_consumer(topic="telemetry", group_id="guardient-consumer"):
    """Initialize Kafka consumer"""
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers="localhost:9092",
        group_id=group_id,
        value_deserializer=lambda x: json.loads(x.decode("utf-8")),
        auto_offset_reset='earliest',
        enable_auto_commit=True
    )
    return consumer


def main():
    """Consume and print telemetry messages"""
    consumer = create_consumer()
    
    print(f"Listening on telemetry topic... (Press Ctrl+C to stop)")
    
    def signal_handler(sig, frame):
        print("\nShutting down consumer...")
        consumer.close()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        for msg in consumer:
            data = msg.value
            print(f"\n📊 Telemetry Update:")
            print(f"   Timestamp: {data.get('timestamp')}")
            print(f"   CPU: {data.get('cpu')}%")
            print(f"   Memory: {data.get('memory')}%")
            print(f"   Disk: {data.get('disk')}%")
            if 'network_in' in data:
                print(f"   Network In: {data.get('network_in')} bytes")
                print(f"   Network Out: {data.get('network_out')} bytes")
    except Exception as e:
        print(f"Error: {e}")
        consumer.close()


if __name__ == "__main__":
    main()
