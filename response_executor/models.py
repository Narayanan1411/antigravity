"""
Response Executor — Data Models
=================================
Canonical constants and enums for the response execution system.
"""
from __future__ import annotations
from enum import Enum


class ActionStatus(str, Enum):
    PENDING  = "pending"   # Waiting for human approval
    RUNNING  = "running"   # Handler dispatched, not yet confirmed
    SUCCESS  = "success"   # Handler completed successfully
    FAILED   = "failed"    # Handler raised an exception
    REJECTED = "rejected"  # SOC analyst rejected the action


# Hard containment actions that require explicit admin approval before execution
APPROVAL_REQUIRED_ACTIONS: set[str] = {
    "restrict_network",
    "isolate_vlan",
    "lock_account",
    "firewall_block",
    "kill_process",
}

# Actions that register the device in the block registry
CONTAINMENT_ACTIONS: set[str] = {
    "isolate_vlan",
    "lock_account",
    "firewall_block",
    "kill_process",
    "restrict_network",
    "block_device",
}

# Human-readable descriptions shown in the admin UI
ACTION_DESCRIPTIONS: dict[str, str] = {
    "allow":            "Device allowed — no action required",
    "monitor":          "Device under passive monitoring",
    "require_mfa":      "Step-up MFA challenge triggered",
    "restrict_network": "Network access restricted to essential services",
    "isolate_vlan":     "Device moved to isolated quarantine VLAN",
    "lock_account":     "User account locked and sessions terminated",
    "firewall_block":   "Device blocked at perimeter firewall",
    "kill_process":     "Malicious process terminated on endpoint",
    "block_device":     "Device manually blocked by SOC admin",
    "unblock_device":   "Device manually unblocked by SOC admin",
}

# Severity thresholds that auto-set action approval requirement
SEVERITY_APPROVAL_MAP: dict[str, bool] = {
    "CRITICAL": True,
    "HIGH":     True,
    "MEDIUM":   False,
    "LOW":      False,
}

ALL_ACTIONS = list(ACTION_DESCRIPTIONS.keys())
