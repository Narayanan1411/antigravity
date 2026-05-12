"""
Guardient Response Executor — Core Orchestrator
=================================================
Single source of truth for all response action execution.
Replaces services/response_engine.py completely.

Responsibilities:
  • Determine if an action requires admin approval
  • Create execution records in PostgreSQL (response_executions)
  • Dispatch to action handlers (response_executor/handlers.py)
  • Maintain device block registry (device_blocks table)
  • Emit execution events to Kafka (response_executions topic)
  • Send SMTP email alerts for critical trust drops (cooldown-gated)

Thread safety: all state is in PostgreSQL — multiple API workers are safe.
"""
from __future__ import annotations

import sys
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from response_executor.models import (
    ActionStatus,
    APPROVAL_REQUIRED_ACTIONS,
    CONTAINMENT_ACTIONS,
    ACTION_DESCRIPTIONS,
)
from response_executor.handlers import dispatch

import db.db as _db
from pipeline.producer import publish_event
from pipeline.topics import RESPONSE_EXECUTIONS


class ResponseExecutor:
    """
    Stateless orchestrator — all state lives in PostgreSQL.
    Instantiate once as a singleton via get_executor().
    """

    COOLDOWN_SECONDS = 300  # 5-minute email alert cooldown per device
    _email_cooldowns: dict[str, float] = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def execute(
        self,
        action: str,
        device_id: str,
        trust_score: float = 100.0,
        risk_score: float = 0.0,
        severity: str = "LOW",
        triggered_by: str = "system",
        metadata: Optional[dict] = None,
        auto_approve: bool = False,
    ) -> dict:
        """
        Execute or queue a response action for a device.

        If the action is in APPROVAL_REQUIRED_ACTIONS and auto_approve is False,
        the record is created with status=pending and waits for approve() or reject().

        Returns the full execution record dict.
        """
        metadata = metadata or {}
        requires_approval = (action in APPROVAL_REQUIRED_ACTIONS) and not auto_approve

        # Deduplicate: return an existing record rather than creating a new one if:
        #   - approval-required: any pending/running record, OR a recently resolved
        #     record within the last 10 minutes.
        #   - auto-approved pipeline actions: absorb high-frequency cycles (3 min).
        #   - manual admin actions (block_device, unblock_device): never deduplicate —
        #     they have their own pre-checks (is_device_blocked) and must always write
        #     to device_blocks so block state stays in sync.
        if action in ("block_device", "unblock_device"):
            cooldown = 0   # bypass deduplication entirely for manual admin actions
        elif requires_approval:
            cooldown = 10
        else:
            cooldown = 3
        if cooldown > 0:
            existing = _db.find_active_execution(device_id, action, cooldown_minutes=cooldown)
            if existing:
                return existing

        status = ActionStatus.PENDING.value if requires_approval else ActionStatus.RUNNING.value

        execution_id = f"EXEC-{device_id[:8]}-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc)

        record: dict = {
            "execution_id":       execution_id,
            "device_id":          device_id,
            "action":             action,
            "status":             status,
            "triggered_by":       triggered_by,
            "trust_score":        trust_score,
            "risk_score":         risk_score,
            "severity":           severity,
            "requires_approval":  requires_approval,
            "approved_by":        None,
            "rejected_by":        None,
            "rejection_reason":   None,
            "metadata":           metadata,
            "created_at":         now.isoformat(),
            "updated_at":         now.isoformat(),
            "executed_at":        None,
            "description":        ACTION_DESCRIPTIONS.get(action, action),
        }

        _db.insert_response_execution(record)

        if not requires_approval:
            self._do_execute(execution_id, action, device_id, metadata)
            self._sync_block_registry(action, device_id, triggered_by, metadata)

        if trust_score < 30:
            self._maybe_send_alert(device_id, action, trust_score)

        result = _db.get_execution(execution_id)
        self._publish(result)
        return result

    def approve(self, execution_id: str, approver: str) -> dict:
        """Approve a pending execution and run it immediately."""
        record = _db.get_execution(execution_id)
        if not record:
            raise ValueError(f"Execution {execution_id} not found")
        if record["status"] != ActionStatus.PENDING.value:
            raise ValueError(
                f"Cannot approve execution {execution_id}: status is '{record['status']}'"
            )

        action    = record["action"]
        device_id = record["device_id"]
        metadata  = record.get("metadata") or {}

        # Close any duplicate pending records for the same (device_id, action)
        # before dispatching, so the approval queue clears on a single click.
        _db.close_duplicate_pending(device_id, action, execution_id)

        _db.update_execution_status(
            execution_id, ActionStatus.RUNNING.value, approved_by=approver
        )

        self._do_execute(execution_id, action, device_id, metadata)
        self._sync_block_registry(action, device_id, approver, metadata)

        result = _db.get_execution(execution_id)
        self._publish(result)
        return result

    def reject(self, execution_id: str, rejector: str, reason: str = "") -> dict:
        """Reject a pending execution. No handler is called."""
        record = _db.get_execution(execution_id)
        if not record:
            raise ValueError(f"Execution {execution_id} not found")
        if record["status"] != ActionStatus.PENDING.value:
            raise ValueError(
                f"Cannot reject execution {execution_id}: status is '{record['status']}'"
            )

        # Close any duplicate pending records for the same (device_id, action).
        _db.close_duplicate_pending(record["device_id"], record["action"], execution_id)

        _db.update_execution_status(
            execution_id,
            ActionStatus.REJECTED.value,
            rejected_by=rejector,
            rejection_reason=reason,
        )
        result = _db.get_execution(execution_id)
        self._publish(result)
        return result

    def block_device(self, device_id: str, reason: str, triggered_by: str,
                     metadata: Optional[dict] = None) -> dict:
        """Admin-initiated immediate device block — no approval gate."""
        # Refuse to re-block a device that is already blocked.
        if _db.is_device_blocked(device_id):
            existing = _db.get_active_block(device_id)
            return {
                "status": "already_blocked",
                "message": f"Device {device_id} is already blocked.",
                "existing_block": existing,
            }
        # Enrich metadata with MAC and last-known IP so the handler can apply
        # real system-level enforcement (iptables + dnsmasq).
        device_info = _db.get_device_info(device_id)
        meta = {
            "reason": reason,
            "mac":    device_info.get("mac_address") if device_info else None,
            "ip":     device_info.get("last_ip")     if device_info else None,
            **(metadata or {}),
        }
        return self.execute(
            action="block_device",
            device_id=device_id,
            triggered_by=triggered_by,
            auto_approve=True,
            metadata=meta,
        )

    def unblock_device(self, device_id: str, unblocked_by: str) -> dict:
        """Admin-initiated immediate device unblock — no approval gate.

        The DB block is cleared unconditionally BEFORE going through execute()
        so that deduplication cannot prevent the block from being lifted.
        MAC/IP are fetched so the handler can remove system-level rules.
        """
        # Enrich metadata with MAC so handler can remove iptables / dnsmasq rules.
        device_info = _db.get_device_info(device_id)
        meta = {
            "mac": device_info.get("mac_address") if device_info else None,
            "ip":  device_info.get("last_ip")     if device_info else None,
        }
        # Always clear DB block first — execute() has cooldown=0 so it always
        # creates a fresh audit record regardless of prior unblocks.
        _db.remove_device_block(device_id, unblocked_by)

        return self.execute(
            action="unblock_device",
            device_id=device_id,
            triggered_by=unblocked_by,
            auto_approve=True,
            metadata=meta,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _do_execute(
        self,
        execution_id: str,
        action: str,
        device_id: str,
        metadata: dict,
    ) -> None:
        """Dispatch to handler and update DB status with result."""
        try:
            result = dispatch(action, device_id, metadata)
            _db.update_execution_status(
                execution_id,
                ActionStatus.SUCCESS.value,
                executed_at=datetime.now(timezone.utc).isoformat(),
                metadata_extra=result,
            )
            print(
                f"[Executor] ✓  {action:20s} | dev={device_id[:16]} "
                f"| result={result.get('result')}"
            )
        except Exception as exc:
            _db.update_execution_status(
                execution_id,
                ActionStatus.FAILED.value,
                metadata_extra={"error": str(exc)},
            )
            print(f"[Executor] ✗  {action} on {device_id[:16]} FAILED: {exc}")

    def _sync_block_registry(self, action: str, device_id: str, actor: str,
                             metadata: Optional[dict] = None) -> None:
        """Keep the device_blocks table consistent with action outcome."""
        if action in CONTAINMENT_ACTIONS:
            reason = (metadata or {}).get("reason", "")
            _db.upsert_device_block(device_id, action, actor, reason=reason)
        elif action == "unblock_device":
            _db.remove_device_block(device_id, actor)

    def _publish(self, record: dict) -> None:
        """Emit execution record to Kafka (best-effort, never raises)."""
        try:
            publish_event(RESPONSE_EXECUTIONS, record)
        except Exception:
            pass

    def _maybe_send_alert(
        self, device_id: str, action: str, trust_score: float
    ) -> None:
        """SMTP alert with per-device cooldown to prevent spam."""
        now = time.time()
        last = ResponseExecutor._email_cooldowns.get(device_id, 0)
        if (now - last) > self.COOLDOWN_SECONDS:
            try:
                from utils.email_alert import send_soc_alert
                send_soc_alert(
                    device_id=device_id,
                    action=action,
                    trust_score=trust_score,
                    attack_type="Multiple anomalies detected",
                )
                ResponseExecutor._email_cooldowns[device_id] = now
                print(f"[Executor] Email alert sent for {device_id}")
            except Exception as exc:
                print(f"[Executor] Email alert skipped: {exc}")
        else:
            remaining = int(self.COOLDOWN_SECONDS - (now - last))
            print(f"[Executor] Email cooldown for {device_id} — {remaining}s remaining")


# ── Singleton ─────────────────────────────────────────────────────────────────

_executor: Optional[ResponseExecutor] = None


def get_executor() -> ResponseExecutor:
    global _executor
    if _executor is None:
        _executor = ResponseExecutor()
    return _executor
