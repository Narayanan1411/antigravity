"""
Guardient Kafka Consumer
BaseConsumer class — all pipeline services inherit from this.
"""

from __future__ import annotations
import json
import signal
import sys
from kafka import KafkaConsumer as _KafkaConsumer

BOOTSTRAP = "localhost:9092"


class BaseConsumer:
    """
    Wraps KafkaConsumer with clean startup/shutdown and a process() hook.
    Subclass it and override process(event) to build a service.
    """

    topic: str = ""          # override in subclass
    group_id: str = ""       # override in subclass
    service_name: str = ""   # for logging

    def __init__(self):
        self._consumer = _KafkaConsumer(
            self.topic,
            bootstrap_servers=BOOTSTRAP,
            group_id=self.group_id,
            value_deserializer=lambda x: json.loads(x.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
        )
        signal.signal(signal.SIGINT,  self._shutdown)
        signal.signal(signal.SIGTERM, self._shutdown)

    def process(self, event: dict):
        """Override in subclass. Receives one event dict."""
        raise NotImplementedError

    def run(self):
        print(f"[{self.service_name}] Listening on '{self.topic}'  (Ctrl+C to stop)")
        try:
            for msg in self._consumer:
                try:
                    self.process(msg.value)
                except Exception as exc:
                    print(f"[{self.service_name}] Process error: {exc}")
        except Exception as exc:
            print(f"[{self.service_name}] Consumer error: {exc}")
        finally:
            self._consumer.close()

    def _shutdown(self, *_):
        print(f"\n[{self.service_name}] Shutting down.")
        self._consumer.close()
        sys.exit(0)
