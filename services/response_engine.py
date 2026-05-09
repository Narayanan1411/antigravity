"""
DEPRECATED — Guardient Legacy Response Engine
===============================================
This file is kept only so the start.sh process list doesn't break.
All logic has moved to response_executor/.

This shim:
  1. Consumes security_actions (unchanged — decision_engine still publishes them)
  2. Delegates every event to response_executor.executor.ResponseExecutor
  3. Does NOT duplicate any DB writes or email logic (executor handles all of that)

To stop running this service, remove it from start.sh and update process management.
"""

from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from pipeline.consumer import BaseConsumer
from pipeline.topics import SECURITY_ACTIONS
from db.db import init_schema
from response_executor.executor import get_executor


class ResponseEngine(BaseConsumer):
    """
    DEPRECATED shim — delegates to ResponseExecutor.
    No logic lives here; everything is in response_executor/.
    """
    topic        = SECURITY_ACTIONS
    group_id     = "response-engine-v2"   # new group_id avoids offset conflict with old v1
    service_name = "ResponseEngine[DEPRECATED→Executor]"

    def __init__(self):
        super().__init__()
        self._executor = get_executor()
        print("[ResponseEngine] ⚠  DEPRECATED — delegating to response_executor")

    def process(self, event: dict):
        action     = event.get("action", "monitor")
        device_id  = event.get("device_id", "unknown")
        trust      = float(event.get("trust_score", 100.0))
        risk       = float(event.get("risk_score", 0.0))
        severity   = event.get("severity", "LOW")
        source     = event.get("source", "pipeline")

        # Informational-only actions don't need execution records
        if action in ("allow", "monitor"):
            return

        self._executor.execute(
            action       = action,
            device_id    = device_id,
            trust_score  = trust,
            risk_score   = risk,
            severity     = severity,
            triggered_by = f"pipeline:{source}",
            metadata     = {
                "ip":          event.get("ip"),
                "device_type": event.get("device_type"),
                "category":    event.get("category"),
            },
        )


if __name__ == "__main__":
    init_schema()
    print("=" * 60)
    print("  Guardient Response Engine (DEPRECATED SHIM)")
    print("  Real logic lives in response_executor/executor.py")
    print("=" * 60 + "\n")
    ResponseEngine().run()
