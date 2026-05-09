"""
Guardient Response Executor Package
=====================================
The active response orchestration system for Guardient.
Replaces services/response_engine.py.

Usage:
    from response_executor.executor import get_executor
    executor = get_executor()
    executor.execute(action="block_device", device_id="dev_abc123", triggered_by="system")
"""
from response_executor.executor import get_executor, ResponseExecutor
from response_executor.models import ActionStatus, APPROVAL_REQUIRED_ACTIONS, CONTAINMENT_ACTIONS

__all__ = ["get_executor", "ResponseExecutor", "ActionStatus", "APPROVAL_REQUIRED_ACTIONS", "CONTAINMENT_ACTIONS"]
