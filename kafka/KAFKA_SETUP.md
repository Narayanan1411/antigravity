# Guardient Kafka Configuration Guide

## Installation & Setup

### 1. kafka-python Package
✓ Already installed via pip

```bash
cd /home/aswin/Guardient
source myenv/bin/activate
pip install kafka-python
```

## Kafka Data Persistence

### Current Setup (Needs Update)
Your Kafka logs are currently stored in `/tmp/kraft-combined-logs`
⚠️ **Problem**: /tmp gets cleared on system reboot

### Fix: Persistent Storage

1. **Create kafka-data directory:**
```bash
mkdir -p /home/aswin/kafka-data
chmod 755 /home/aswin/kafka-data
```

2. **Update Kafka server.properties:**
Find and modify the line (usually around line 60):
```properties
# BEFORE:
log.dirs=/tmp/kraft-combined-logs

# AFTER:
log.dirs=/home/aswin/kafka-data
```

3. **Apply changes:**
- Stop Kafka broker
- Copy data if needed: `cp -r /tmp/kraft-combined-logs/* /home/aswin/kafka-data/`
- Restart Kafka broker

## Scripts Available

### 1. Producer: `kafka_producer.py`
Sends sample telemetry to Kafka
```bash
python kafka_producer.py
```

### 2. Consumer: `kafka_consumer.py`
Listens for telemetry messages
```bash
python kafka_consumer.py
```

### 3. Enhanced Monitor: `system_monitor_kafka.py`
Your system monitor with Kafka integration
```bash
python system_monitor_kafka.py
```

## Testing

**Terminal 1 - Start Consumer:**
```bash
source myenv/bin/activate
python kafka_consumer.py
```

**Terminal 2 - Run Producer:**
```bash
source myenv/bin/activate
python kafka_producer.py
```

**Terminal 3 - Start Enhanced Monitor:**
```bash
source myenv/bin/activate
python system_monitor_kafka.py
```

## Telemetry Data Sent to Kafka

Each metric includes:
- `timestamp`: ISO 8601 datetime
- `hostname`: System hostname
- `cpu`: CPU usage percentage
- `memory`: Memory usage percentage
- `disk`: Disk usage percentage
- `network_in`: Bytes received
- `network_out`: Bytes sent
- `load_avg`: System load average
- `process_count`: Active process count

## Kafka Topic: `telemetry`

All metrics are published to the "telemetry" topic with:
- Consumer group: `guardient-consumer`
- Auto offset reset: earliest (new subscribers get history)
- Auto commit: enabled

## Monitoring API Endpoints

- `GET /` - Status check
- `GET /telemetry` - Get cached telemetry data
- `GET /health` - Health check (includes Kafka connection status)

Base URL: `http://localhost:8091`

## Troubleshooting

**No Kafka connection?**
- Ensure Kafka broker is running on `localhost:9092`
- Check logs: `/home/aswin/kafka-data/`

**Producer sends but consumer doesn't receive?**
- Check topic exists: `kafka topics list`
- Verify consumer group: `kafka consumer groups list`

**Data loss after reboot?**
- Confirm `log.dirs` points to `/home/aswin/kafka-data`
- Verify directory permissions: `ls -ld /home/aswin/kafka-data`
