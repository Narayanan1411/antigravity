"""
Guardient Enrichment Service
Consumes: raw_events
Publishes: enriched_events

Adds to every event:
  - geo_destination, asn, destination_asn
  - dns_reverse
  - mac_vendor
  - device_class
  - bytes_total
  - login_failure_flag
  - after_hours
"""

from __future__ import annotations
import sys
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.producer import publish_event
from pipeline.consumer import BaseConsumer
from pipeline.topics  import RAW_EVENTS, ENRICHED_EVENTS
from db.db import init_schema, upsert_device, insert_event

from utils.geoip_lookup import geo_lookup
from utils.dns_utils import reverse_dns
from utils.mac_lookup import mac_vendor
from utils.device_classifier import classify_device


def after_hours(timestamp: str) -> int:
    """Returns 1 if timestamp is outside 06:00-22:00, else 0."""
    try:
        hour = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).hour
        if hour < 6 or hour > 22:
            return 1
        return 0
    except Exception:
        return 0


class EnrichmentService(BaseConsumer):
    topic        = RAW_EVENTS
    group_id     = "enrichment-service"
    service_name = "EnrichmentService"

    def process(self, event: dict):
        # 0. Ensure event_id exists for DB
        import uuid
        if "event_id" not in event:
            event["event_id"] = f"evt_{uuid.uuid4().hex[:12]}"

        dest_ip = event.get("destination_ip")
        mac = event.get("mac_address")
        
        # 1. Geo & ASN Enrichment
        geo = geo_lookup(dest_ip)
        event["geo_destination"] = geo.get("country")
        event["destination_asn"] = geo.get("asn") # required by feature engine
        
        # 2. DNS & MAC Enrichment
        try:
            event["dns_reverse"] = reverse_dns(dest_ip)
        except Exception:
            event["dns_reverse"] = None
        event["mac_vendor"] = mac_vendor(mac)
        
        # 3. Device Classification
        # Use device_type from network discovery if available, otherwise classify
        if event.get("device_type"):
            event["device_class"] = event["device_type"]
        else:
            event["device_class"] = classify_device(event.get("os"), event.get("mac_vendor"))
        
        # 4. Math & Logical Flags
        sent = event.get("bytes_sent") or 0
        recv = event.get("bytes_received") or 0
        event["bytes_total"] = sent + recv
        
        event["login_failure_flag"] = int(event.get("login_success") is False)
        event["after_hours"] = after_hours(event.get("timestamp", ""))

        # Kafka
        publish_event(ENRICHED_EVENTS, event)

        # DB — device registry + event log (Audit)
        try:
            # We want to keep updating the device registry with metadata we discover
            upsert_device(
                device_id=event.get("device_id", "unknown"),
                mac=mac,
                os=event.get("os"),
                device_type=event["device_class"],
                hostname=event.get("hostname"),
                enrichment={"geo": event["geo_destination"], "asn": event.get("destination_asn")},
                timestamp=event.get("timestamp") or datetime.utcnow().isoformat()
            )
            # Full audit log
            insert_event(event)
        except Exception as exc:
            print(f"[Enrich] DB write skipped: {exc}")

        print(f"[Enrich] dev={event.get('device_id')} | {event.get('collector')}/{event.get('event_type')} | "
              f"geo={event.get('geo_destination')} | bytes={event.get('bytes_total')}")


if __name__ == "__main__":
    init_schema()   # create tables if missing
    EnrichmentService().run()
