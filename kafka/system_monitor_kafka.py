"""
System Monitor with Kafka Telemetry Integration
Enhanced version of system-monitor.py that sends metrics to Kafka
"""
import psutil
import platform
import socket
import os
import time
import threading
from fastapi import FastAPI
from typing import Dict
import docker
from kafka import KafkaProducer
import json
from datetime import datetime

app = FastAPI()
telemetry_cache: Dict = {}

docker_client = docker.from_env()

# Kafka producer
kafka_producer = None


def init_kafka_producer():
    """Initialize Kafka producer"""
    global kafka_producer
    try:
        kafka_producer = KafkaProducer(
            bootstrap_servers="localhost:9092",
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            acks='all',
            retries=3,
            request_timeout_ms=10000
        )
        print("✓ Kafka producer initialized")
    except Exception as e:
        print(f"⚠️  Kafka connection failed: {e}")
        kafka_producer = None


def send_to_kafka(data: dict, topic: str = "telemetry"):
    """Send telemetry data to Kafka"""
    if not kafka_producer:
        return
    
    try:
        kafka_producer.send(topic, data)
    except Exception as e:
        print(f"Error sending to Kafka: {e}")


def get_docker_info():
    containers_data = []

    try:
        containers = docker_client.containers.list(all=True)
    except:
        return []

    for container in containers:
        try:
            stats = container.stats(stream=False)

            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                        stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                           stats["precpu_stats"]["system_cpu_usage"]

            cpu_percent = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0

        except:
            stats = {}
            cpu_percent = 0.0

        containers_data.append({
            "id": container.id,
            "name": container.name,
            "image": container.image.tags,
            "status": container.status,
            "created": container.attrs.get("Created"),
            "cpu_percent": cpu_percent,
            "memory_usage": stats.get("memory_stats", {}).get("usage", 0),
            "memory_limit": stats.get("memory_stats", {}).get("limit", 0),
            "privileged": container.attrs.get("HostConfig", {}).get("Privileged"),
            "port_bindings": container.attrs.get("HostConfig", {}).get("PortBindings"),
            "mounts": container.attrs.get("Mounts"),
            "networks": container.attrs.get("NetworkSettings", {}).get("Networks")
        })

    return containers_data


def get_process_summary():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
        processes.append(proc.info)
    return processes


def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connections.append({
            "local_address": str(conn.laddr),
            "remote_address": str(conn.raddr),
            "status": conn.status,
            "pid": conn.pid
        })
    return connections


def collect_data():
    global telemetry_cache

    while True:
        telemetry_cache = {
            "system": {
                "hostname": socket.gethostname(),
                "os": platform.platform(),
                "kernel": platform.release(),
                "uptime_seconds": time.time() - psutil.boot_time(),
                "cpu_cores": psutil.cpu_count(),
                "total_memory": psutil.virtual_memory().total,
                "total_disk": psutil.disk_usage('/').total,
            },
            "resources": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "network_bytes_sent": psutil.net_io_counters().bytes_sent,
                "network_bytes_recv": psutil.net_io_counters().bytes_recv,
                "load_average": os.getloadavg()
            },
            "process_count": len(psutil.pids()),
            "processes": get_process_summary(),
            "active_connections": get_network_connections(),
            "docker": get_docker_info(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Send core metrics to Kafka
        kafka_metrics = {
            "timestamp": telemetry_cache["timestamp"],
            "hostname": telemetry_cache["system"]["hostname"],
            "cpu": telemetry_cache["resources"]["cpu_percent"],
            "memory": telemetry_cache["resources"]["memory_percent"],
            "disk": telemetry_cache["resources"]["disk_percent"],
            "network_in": telemetry_cache["resources"]["network_bytes_recv"],
            "network_out": telemetry_cache["resources"]["network_bytes_sent"],
            "load_avg": telemetry_cache["resources"]["load_average"],
            "process_count": telemetry_cache["process_count"]
        }
        
        send_to_kafka(kafka_metrics)

        time.sleep(3)


@app.get("/")
def root():
    return {"status": "Monitoring API Running (with Kafka Integration)"}


@app.get("/telemetry")
def get_telemetry():
    return telemetry_cache


@app.get("/health")
def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "kafka_connected": kafka_producer is not None
    }


if __name__ == "__main__":
    init_kafka_producer()
    threading.Thread(target=collect_data, daemon=True).start()
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8091)
