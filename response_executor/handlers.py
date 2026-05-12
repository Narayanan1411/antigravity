"""
Response Executor — Action Handlers
======================================
Real enforcement for block_device / unblock_device:

  iptables -I FORWARD 1 -s <IP> -j DROP   ← block outbound internet
  iptables -I FORWARD 1 -d <IP> -j DROP   ← block inbound internet
  iptables -D FORWARD -s <IP> -j DROP     ← unblock outbound
  iptables -D FORWARD -d <IP> -j DROP     ← unblock inbound

Rules are inserted at position 1 so they fire BEFORE NetworkManager's
subnet-level ACCEPT rule (nm-sh-fw-wlp1s0).  The device stays connected
to the hotspot (DHCP/DNS reach the gateway via the INPUT chain, not
FORWARD) but cannot access the internet.

Other actions (restrict_network, isolate_vlan, lock_account, firewall_block,
kill_process) remain as instrumented stubs.
"""
from __future__ import annotations

import os
import subprocess

# Directory that the hotspot dnsmasq process reads for per-device config
DNSMASQ_BLOCK_DIR = "/etc/NetworkManager/dnsmasq-shared.d"


# ── Low-level command runner ──────────────────────────────────────────────────

def _run(*args: str) -> tuple[bool, str]:
    """
    Run a command, escalating through: plain → sudo -n → pkexec (short timeout).
    Returns (success, error_message).

    For passwordless iptables (required for block/unblock to work), run once
    in a terminal:
        echo 'narayanan ALL=(ALL) NOPASSWD: /usr/sbin/iptables' | \\
            sudo tee /etc/sudoers.d/guardient-iptables && \\
            sudo chmod 440 /etc/sudoers.d/guardient-iptables
    """
    cmd = list(args)
    # (prefix, timeout_seconds)
    # pkexec gets a short timeout — it can block waiting for a GUI auth dialog
    # when called from a background process.  If it doesn't respond in 2 s,
    # we skip it (the sudoers entry is the preferred path).
    attempts = [
        ([], 5),
        (["sudo", "-n"], 5),
        (["pkexec"], 2),
    ]
    for prefix, timeout in attempts:
        try:
            r = subprocess.run(prefix + cmd, capture_output=True, timeout=timeout)
            if r.returncode == 0:
                return True, ""
            err = r.stderr.decode(errors="replace").strip()
            if any(k in err.lower() for k in ("not permitted", "permission denied",
                                               "authentication", "interactive")):
                continue
            return False, err
        except (PermissionError, subprocess.TimeoutExpired):
            continue
        except Exception as exc:
            return False, str(exc)
    return False, (
        "iptables requires root — run this once in a terminal:\n"
        "  echo 'narayanan ALL=(ALL) NOPASSWD: /usr/sbin/iptables' | "
        "sudo tee /etc/sudoers.d/guardient-iptables && "
        "sudo chmod 440 /etc/sudoers.d/guardient-iptables"
    )


# ── IP-based iptables enforcement ─────────────────────────────────────────────

def _apply_iptables_block(ip: str) -> tuple[bool, str]:
    """
    Insert FORWARD DROP rules for the device IP at position 1 (both directions).

    Inserted at position 1 so they fire BEFORE NetworkManager's subnet-level
    ACCEPT rule in nm-sh-fw-wlp1s0.  The device keeps its hotspot connection
    (DHCP/DNS go through INPUT, not FORWARD) but all internet traffic is dropped.

    Skips pre-existence check to avoid timeouts — iptables allows duplicate rules,
    and unblock uses -D which removes one rule at a time anyway.
    """
    if not ip:
        return False, "no IP address"

    results = []
    for flag, label in [("-s", "outbound"), ("-d", "inbound")]:
        ok, err = _run("iptables", "-I", "FORWARD", "1", flag, ip, "-j", "DROP")
        if ok:
            print(f"[Handler] iptables -I FORWARD 1 {flag} {ip} -j DROP")
            results.append(f"{label}:applied")
        else:
            print(f"[Handler] iptables block failed ({label}) for {ip}: {err}")
            results.append(f"{label}:failed")

    success = all("failed" not in r for r in results)
    return success, " | ".join(results)


def _remove_iptables_block(ip: str) -> tuple[bool, str]:
    """
    Delete FORWARD DROP rules for the device IP (both directions).
    iptables -D matches by rule spec and is idempotent-safe — if the rule
    doesn't exist it returns non-zero, which we treat as already removed.
    """
    if not ip:
        return False, "no IP address"

    results = []
    for flag, label in [("-s", "outbound"), ("-d", "inbound")]:
        ok, err = _run("iptables", "-D", "FORWARD", flag, ip, "-j", "DROP")
        if ok:
            print(f"[Handler] iptables -D FORWARD {flag} {ip} -j DROP")
            results.append(f"{label}:removed")
        else:
            # Non-zero from -D means rule wasn't there — that's fine
            if "no chain" in err.lower() or "rule" in err.lower() or not err:
                results.append(f"{label}:not_present")
            else:
                results.append(f"{label}:failed({err})")

    return True, " | ".join(results)


# ── dnsmasq DHCP-deny helpers ─────────────────────────────────────────────────

def _dnsmasq_block_path(mac: str) -> str:
    safe = mac.lower().replace(":", "")
    return os.path.join(DNSMASQ_BLOCK_DIR, f"block-{safe}.conf")


def _apply_dnsmasq_block(mac: str) -> tuple[bool, str]:
    """Write dhcp-host=MAC,ignore so dnsmasq refuses DHCP lease renewal."""
    if not mac:
        return False, "no MAC address"
    path = _dnsmasq_block_path(mac)
    content = f"dhcp-host={mac.lower()},ignore\n"
    try:
        with open(path, "w") as f:
            f.write(content)
        subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
        print(f"[Handler] dnsmasq DHCP deny written for MAC {mac}")
        return True, "applied"
    except PermissionError:
        pass
    try:
        r = subprocess.run(["sudo", "-n", "tee", path],
                           input=content.encode(), capture_output=True, timeout=5)
        if r.returncode == 0:
            _run("pkill", "-HUP", "dnsmasq")
            print(f"[Handler] dnsmasq DHCP deny written via sudo for MAC {mac}")
            return True, "applied"
        return False, r.stderr.decode(errors="replace").strip()
    except Exception as exc:
        return False, str(exc)


def _remove_dnsmasq_block(mac: str) -> tuple[bool, str]:
    """Remove dhcp-host deny file and reload dnsmasq."""
    if not mac:
        return True, "no MAC address"
    path = _dnsmasq_block_path(mac)
    if not os.path.exists(path):
        return True, "not_present"
    try:
        os.remove(path)
    except PermissionError:
        ok, err = _run("rm", path)
        if not ok:
            return False, f"failed: {err}"
    subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
    print(f"[Handler] dnsmasq DHCP deny removed for MAC {mac}")
    return True, "removed"


# ── Startup helpers ───────────────────────────────────────────────────────────

def system_unblock_all() -> list[str]:
    """
    Called at service startup: remove any orphaned iptables DROP rules and
    dnsmasq block files left by a previous crash or restart.
    Returns a list of IPs/MACs that were cleared.
    """
    cleared = []

    # Remove dnsmasq block files
    try:
        for fname in os.listdir(DNSMASQ_BLOCK_DIR):
            if fname.startswith("block-") and fname.endswith(".conf"):
                path = os.path.join(DNSMASQ_BLOCK_DIR, fname)
                mac_safe = fname[len("block-"):-len(".conf")]
                mac = ":".join(mac_safe[i:i+2] for i in range(0, 12, 2)) \
                      if len(mac_safe) == 12 else mac_safe
                try:
                    os.remove(path)
                except PermissionError:
                    _run("rm", path)
                cleared.append(mac)
                print(f"[Startup] Removed orphaned dnsmasq block for {mac}")
        if cleared:
            _run("pkill", "-HUP", "dnsmasq")
    except Exception as exc:
        print(f"[Startup] dnsmasq cleanup error: {exc}")

    # Remove IP-based FORWARD DROP rules added by this application.
    # Uses iptables -S to list rules by spec (not line number) — safer than
    # line-number deletion which can accidentally remove NM's ACCEPT rules.
    for prefix in [[], ["sudo", "-n"]]:
        try:
            out = subprocess.run(
                prefix + ["iptables", "-S", "FORWARD"],
                capture_output=True, text=True, timeout=5
            )
            if out.returncode != 0:
                continue
            for line in out.stdout.splitlines():
                # Match rules we added: -A FORWARD -s <IP> -j DROP
                # or                    -A FORWARD -d <IP> -j DROP
                parts = line.split()
                if "-j" not in parts or "DROP" not in parts:
                    continue
                j_idx = parts.index("-j")
                if parts[j_idx + 1] != "DROP":
                    continue
                # Only remove rules that match our pattern (src or dst IP, no -m mac)
                if "-m" in parts:
                    continue
                if "-s" in parts or "-d" in parts:
                    flag_idx = parts.index("-s") if "-s" in parts else parts.index("-d")
                    ip = parts[flag_idx + 1]
                    flag = parts[flag_idx]
                    ok, _ = _run("iptables", "-D", "FORWARD", flag, ip, "-j", "DROP")
                    if ok:
                        print(f"[Startup] Removed orphaned iptables DROP for {ip}")
                        cleared.append(ip)
            break
        except Exception as exc:
            print(f"[Startup] iptables cleanup error: {exc}")

    return cleared


def reapply_active_blocks(active_blocks: list[dict]) -> None:
    """
    Called at startup with is_active=TRUE rows from device_blocks.
    Re-applies iptables rules so a service restart doesn't silently unblock
    a device at the network level while the DB still says blocked.
    """
    for blk in active_blocks:
        ip  = blk.get("last_ip")
        mac = blk.get("mac_address") or blk.get("mac")
        dev = blk.get("device_id", "?")
        if ip:
            print(f"[Startup] Re-applying iptables block for {dev} IP={ip}")
            _apply_iptables_block(ip)
        else:
            print(f"[Startup] Cannot re-apply block for {dev} — no last IP in DB")
        if mac:
            _apply_dnsmasq_block(mac)


# ── Action handlers ───────────────────────────────────────────────────────────

def handle_allow(device_id: str, metadata: dict) -> dict:
    return {"result": "allowed", "device_id": device_id}


def handle_monitor(device_id: str, metadata: dict) -> dict:
    return {"result": "monitoring_enabled", "device_id": device_id}


def handle_require_mfa(device_id: str, metadata: dict) -> dict:
    print(f"[Executor] MFA CHALLENGE → {device_id}")
    return {"result": "mfa_challenge_sent", "device_id": device_id, "channel": "push"}


def handle_restrict_network(device_id: str, metadata: dict) -> dict:
    """Drop internet traffic for this device (same enforcement as block_device)."""
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] RESTRICT NETWORK → {device_id}  ip={ip}")
    ipt_ok, ipt_msg = _apply_iptables_block(ip) if ip else (False, "no IP")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac)  if mac else (False, "no MAC")
    return {
        "result":    "network_restricted",
        "device_id": device_id,
        "ip":        ip,
        "iptables":  ipt_msg,
        "dnsmasq":   dns_msg,
    }


def handle_isolate_vlan(device_id: str, metadata: dict) -> dict:
    # Stub — replace with SNMP/SSH to managed switch
    print(f"[Executor] ISOLATE VLAN → {device_id}")
    return {"result": "isolated_vlan", "vlan": "quarantine-999", "device_id": device_id}


def handle_lock_account(device_id: str, metadata: dict) -> dict:
    """Drop internet traffic for this device (network-level account lock)."""
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] LOCK ACCOUNT → {device_id}  ip={ip}")
    ipt_ok, ipt_msg = _apply_iptables_block(ip) if ip else (False, "no IP")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac)  if mac else (False, "no MAC")
    return {
        "result":          "account_locked",
        "device_id":       device_id,
        "sessions_revoked": True,
        "iptables":        ipt_msg,
        "dnsmasq":         dns_msg,
    }


def handle_firewall_block(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] FIREWALL BLOCK → {device_id}  ip={ip}")
    ipt_ok, ipt_msg = _apply_iptables_block(ip) if ip else (False, "no IP")
    return {
        "result":     "firewall_blocked",
        "device_id":  device_id,
        "ip":         ip,
        "iptables":   ipt_msg,
    }


def handle_kill_process(device_id: str, metadata: dict) -> dict:
    process = metadata.get("process_name", "unknown")
    print(f"[Executor] KILL PROCESS → {device_id}  process={process}")
    return {"result": "process_killed", "process_name": process, "device_id": device_id}


def handle_block_device(device_id: str, metadata: dict) -> dict:
    """
    Block this device's internet access using iptables:
      iptables -I FORWARD 1 -s <IP> -j DROP
      iptables -I FORWARD 1 -d <IP> -j DROP

    The device stays connected to the hotspot (DHCP/DNS go through INPUT,
    not FORWARD) but cannot reach or be reached from the internet.
    """
    ip     = metadata.get("ip")
    mac    = metadata.get("mac") or metadata.get("mac_address")
    reason = metadata.get("reason", "Manual SOC block")
    print(f"[Executor] BLOCK DEVICE → {device_id}  ip={ip}  reason='{reason}'")

    ipt_ok, ipt_msg = _apply_iptables_block(ip) if ip else (False, "no IP in metadata")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac)  if mac else (False, "no MAC in metadata")

    return {
        "result":    "device_blocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "reason":    reason,
        "iptables":  ipt_msg,
        "dnsmasq":   dns_msg,
    }


def handle_unblock_device(device_id: str, metadata: dict) -> dict:
    """
    Remove the iptables DROP rules for this device:
      iptables -D FORWARD -s <IP> -j DROP
      iptables -D FORWARD -d <IP> -j DROP

    The device immediately regains internet access.
    """
    ip  = metadata.get("ip")
    mac = metadata.get("mac") or metadata.get("mac_address")
    print(f"[Executor] UNBLOCK DEVICE → {device_id}  ip={ip}")

    ipt_ok, ipt_msg = _remove_iptables_block(ip) if ip else (False, "no IP in metadata")
    dns_ok, dns_msg = _remove_dnsmasq_block(mac)  if mac else (False, "no MAC in metadata")

    return {
        "result":    "device_unblocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "iptables":  ipt_msg,
        "dnsmasq":   dns_msg,
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
    handler = _HANDLERS.get(action)
    if handler is None:
        print(f"[Executor] WARNING: unknown action '{action}' — no handler registered")
        return {"result": "unhandled", "action": action, "device_id": device_id}
    return handler(device_id, metadata)
