"""
Response Executor — Action Handlers
======================================
One handler function per action type.
Currently simulated. Replace function bodies with real API calls:
  - restrict_network  → SDN controller ACL push (OpenFlow, Cisco DNA)
  - isolate_vlan      → SNMP/SSH to managed switch, port → quarantine VLAN
  - lock_account      → AD/LDAP disable + OAuth token revoke
  - firewall_block    → pfSense / Fortinet REST API
  - kill_process      → EDR API (CrowdStrike RTR, SentinelOne Remote)
  - require_mfa       → Push notification to authenticator app
"""
from __future__ import annotations
import time


def handle_allow(device_id: str, metadata: dict) -> dict:
    return {"result": "allowed", "device_id": device_id}


def handle_monitor(device_id: str, metadata: dict) -> dict:
    return {"result": "monitoring_enabled", "device_id": device_id}


def handle_require_mfa(device_id: str, metadata: dict) -> dict:
    # Real: POST to identity provider to trigger step-up MFA push
    print(f"[Executor] MFA CHALLENGE → {device_id}")
    return {"result": "mfa_challenge_sent", "device_id": device_id, "channel": "push"}


def handle_restrict_network(device_id: str, metadata: dict) -> dict:
    # Real: push ACL rule to SDN controller / managed switch
    print(f"[Executor] RESTRICT NETWORK → {device_id}")
    time.sleep(0.05)  # simulate network call latency
    return {
        "result":      "network_restricted",
        "acl_applied": True,
        "device_id":   device_id,
        "allowed_subnets": ["10.0.0.0/8"],  # only internal traffic allowed
    }


def handle_isolate_vlan(device_id: str, metadata: dict) -> dict:
    # Real: SNMP/SSH to managed switch — move port to VLAN 999 (quarantine)
    print(f"[Executor] ISOLATE VLAN → {device_id}")
    time.sleep(0.1)
    return {
        "result":    "isolated_vlan",
        "vlan":      "quarantine-999",
        "device_id": device_id,
        "switch_port_updated": True,
    }


def handle_lock_account(device_id: str, metadata: dict) -> dict:
    # Real: AD userAccountControl disable + OAuth token revoke
    print(f"[Executor] LOCK ACCOUNT → {device_id}")
    return {
        "result":           "account_locked",
        "sessions_revoked": True,
        "device_id":        device_id,
        "tokens_revoked":   True,
    }


def handle_firewall_block(device_id: str, metadata: dict) -> dict:
    # Real: pfSense API POST /api/v1/firewall/rule or Fortinet REST
    ip = metadata.get("ip") or "unknown"
    print(f"[Executor] FIREWALL BLOCK → {device_id}  ip={ip}")
    return {
        "result":     "firewall_blocked",
        "rule_id":    f"FW-BLOCK-{device_id[:8].upper()}",
        "ip_blocked": ip,
        "device_id":  device_id,
    }


def handle_kill_process(device_id: str, metadata: dict) -> dict:
    # Real: CrowdStrike RTR or SentinelOne remote script execution
    process = metadata.get("process_name", "unknown")
    print(f"[Executor] KILL PROCESS → {device_id}  process={process}")
    return {
        "result":       "process_killed",
        "process_name": process,
        "device_id":    device_id,
        "pid_terminated": metadata.get("pid"),
    }


def handle_block_device(device_id: str, metadata: dict) -> dict:
    # Combines firewall block + restrict network in one manual admin action
    ip = metadata.get("ip")
    reason = metadata.get("reason", "manual SOC block")
    print(f"[Executor] BLOCK DEVICE → {device_id}  reason='{reason}'")
    return {
        "result":     "device_blocked",
        "device_id":  device_id,
        "ip_blocked": ip,
        "reason":     reason,
    }


def handle_unblock_device(device_id: str, metadata: dict) -> dict:
    print(f"[Executor] UNBLOCK DEVICE → {device_id}")
    return {
        "result":    "device_unblocked",
        "device_id": device_id,
    }


# ── Dispatch table ────────────────────────────────────────────────────────────

_HANDLERS: dict = {
    "allow":            handle_allow,
    "monitor":          handle_monitor,
    "require_mfa":      handle_require_mfa,
    "restrict_network": handle_restrict_network,
    "isolate_vlan":     handle_isolate_vlan,
    "lock_account":     handle_lock_account,
    "firewall_block":   handle_firewall_block,
    "kill_process":     handle_kill_process,
    "block_device":     handle_block_device,
    "unblock_device":   handle_unblock_device,
}


def dispatch(action: str, device_id: str, metadata: dict) -> dict:
    """Route an action to its handler. Returns the handler result dict."""
    handler = _HANDLERS.get(action)
    if handler is None:
        print(f"[Executor] WARNING: unknown action '{action}' — no handler registered")
        return {"result": "unhandled", "action": action, "device_id": device_id}
    return handler(device_id, metadata)
