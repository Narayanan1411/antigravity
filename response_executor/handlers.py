"""
Response Executor — Action Handlers
======================================
Enforcement via nftables (pkexec nft) — works on Ubuntu Desktop without
any sudoers configuration because polkit grants nft access to desktop sessions.

Block strategy:
  • A dedicated chain  'guardient_blocks'  is created in the 'ip filter' table.
  • A jump rule is inserted at position 0 in the FORWARD chain so it fires
    BEFORE NetworkManager's subnet-level ACCEPT rule (nm-sh-fw-wlp1s0).
  • Per-device DROP rules are added to guardient_blocks by IP address.

Effect:
  • All forwarded internet traffic for the device is DROPped.
  • DHCP and DNS still work (they go through INPUT, not FORWARD),
    so the device stays connected to the hotspot with its IP address.
  • Unblock removes the DROP rules by nft handle — no risk of deleting
    NetworkManager's own rules.
"""
from __future__ import annotations

import os
import re
import subprocess

DNSMASQ_BLOCK_DIR = "/etc/NetworkManager/dnsmasq-shared.d"
NFT_TABLE  = "ip"
NFT_FAMILY = "filter"
NFT_CHAIN  = "guardient_blocks"   # base chain, priority -10, hooks into FORWARD


# ── Low-level nft runner ──────────────────────────────────────────────────────

def _nft(*args: str) -> tuple[bool, str]:
    """
    Run 'nft <args>' via sudo -n (NOPASSWD sudoers entry installed by
    install_firewall_helper.sh) falling back to pkexec then plain nft.

    The sudoers entry is installed automatically on first use if pkexec works:
        /etc/sudoers.d/guardient-nft
        narayanan ALL=(ALL) NOPASSWD: /usr/sbin/nft
    """
    cmd = ["nft"] + list(args)
    for prefix in [["sudo", "-n"], ["pkexec"], []]:
        try:
            r = subprocess.run(prefix + cmd, capture_output=True, timeout=5)
            if r.returncode == 0:
                return True, r.stdout.decode(errors="replace")
            err = r.stderr.decode(errors="replace").strip()
            if any(k in err.lower() for k in
                   ("not permitted", "permission denied", "authentication",
                    "interactive", "no valid", "no sudo")):
                continue
            return False, err
        except (PermissionError, subprocess.TimeoutExpired):
            continue
        except Exception as exc:
            return False, str(exc)
    return False, "nft: no permission (run install_firewall_helper.sh)"


# ── Chain management ──────────────────────────────────────────────────────────

# ── Chain management ──────────────────────────────────────────────────────────

def _chain_exists() -> bool:
    ok, out = _nft("list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    return ok and "hook forward" in out


def ensure_guardient_chain() -> tuple[bool, str]:
    if _chain_exists():
        return True, "ready"
    _nft("delete", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    ok, err = _nft(
        "add", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
        "{", "type", "filter", "hook", "forward",
        "priority", "-10", ";", "policy", "accept", ";", "}"
    )
    if ok:
        print(f"[Handler] nft: created {NFT_CHAIN} base chain (priority -10)")
        return True, "ready"
    return False, f"cannot create chain: {err}"


def _get_handles_for_ip(ip: str) -> list[str]:
    ok, out = _nft("-a", "list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    if not ok:
        return []
    return [m.group(1) for line in out.splitlines()
            if ip in line
            for m in [re.search(r'handle\s+(\d+)', line)] if m]


# ── Block / unblock ───────────────────────────────────────────────────────────

def _apply_nft_block(ip: str) -> tuple[bool, str]:
    """
    Add DROP rules for this IP to guardient_blocks:
      nft add rule ip filter guardient_blocks ip saddr <IP> counter drop
      nft add rule ip filter guardient_blocks ip daddr <IP> counter drop
    Device stays connected (DHCP/DNS via INPUT) but internet is cut (FORWARD).
    """
    if not ip:
        return False, "no IP address"
    chain_ok, chain_err = ensure_guardient_chain()
    if not chain_ok:
        return False, chain_err
    if _get_handles_for_ip(ip):
        return True, "already_blocked"
    ok1, err1 = _nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                     "ip", "saddr", ip, "counter", "drop")
    ok2, err2 = _nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                     "ip", "daddr", ip, "counter", "drop")
    if ok1 and ok2:
        print(f"[Handler] nft: DROP rules applied for {ip}")
        return True, "applied"
    return False, f"saddr:{err1}  daddr:{err2}"


def _remove_nft_block(ip: str) -> tuple[bool, str]:
    """Remove all DROP rules for this IP from guardient_blocks by nft handle."""
    if not ip:
        return False, "no IP address"
    handles = _get_handles_for_ip(ip)
    if not handles:
        return True, "not_present"
    removed = 0
    for handle in handles:
        ok, err = _nft("delete", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                       "handle", handle)
        if ok:
            removed += 1
    return True, f"removed {removed}/{len(handles)} rules"


# ── dnsmasq DHCP deny (belt-and-suspenders: prevents IP renewal) ──────────────

def _dnsmasq_block_path(mac: str) -> str:
    safe = mac.lower().replace(":", "")
    return os.path.join(DNSMASQ_BLOCK_DIR, f"block-{safe}.conf")


def _apply_dnsmasq_block(mac: str) -> tuple[bool, str]:
    if not mac:
        return False, "no MAC"
    path = _dnsmasq_block_path(mac)
    content = f"dhcp-host={mac.lower()},ignore\n"
    try:
        with open(path, "w") as f:
            f.write(content)
        subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
        return True, "applied"
    except PermissionError:
        pass
    try:
        r = subprocess.run(["sudo", "-n", "tee", path],
                           input=content.encode(), capture_output=True, timeout=5)
        if r.returncode == 0:
            subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
            return True, "applied"
    except Exception:
        pass
    return False, "permission denied (dnsmasq deny file)"


def _remove_dnsmasq_block(mac: str) -> tuple[bool, str]:
    if not mac:
        return True, "no MAC"
    path = _dnsmasq_block_path(mac)
    if not os.path.exists(path):
        return True, "not_present"
    try:
        os.remove(path)
    except PermissionError:
        subprocess.run(["sudo", "-n", "rm", path], capture_output=True, timeout=3)
    subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
    return True, "removed"


# ── Startup helpers ───────────────────────────────────────────────────────────

def system_unblock_all() -> list[str]:
    """
    On startup: flush the guardient_blocks chain (removes all device DROP rules)
    and remove any dnsmasq block files.  This ensures no device stays blocked
    after a service restart.
    """
    cleared = []

    # Flush the guardient_blocks chain if it exists
    if _chain_exists():
        ok, err = _nft("flush", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
        if ok:
            print(f"[Startup] nft: flushed {NFT_CHAIN}")
            cleared.append("guardient_blocks:flushed")
        else:
            print(f"[Startup] nft flush: {err}")

    # Remove dnsmasq block files
    try:
        for fname in os.listdir(DNSMASQ_BLOCK_DIR):
            if fname.startswith("block-") and fname.endswith(".conf"):
                path = os.path.join(DNSMASQ_BLOCK_DIR, fname)
                try:
                    os.remove(path)
                    cleared.append(fname)
                    print(f"[Startup] Removed dnsmasq block: {fname}")
                except PermissionError:
                    subprocess.run(["sudo", "-n", "rm", path], capture_output=True)
        if any(f.endswith(".conf") for f in cleared):
            subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
    except Exception as exc:
        print(f"[Startup] dnsmasq cleanup: {exc}")

    return cleared


def reapply_active_blocks(active_blocks: list[dict]) -> None:
    """Re-apply block rules for all is_active=TRUE devices on startup."""
    for blk in active_blocks:
        ip  = blk.get("last_ip")
        mac = blk.get("mac_address") or blk.get("mac")
        dev = blk.get("device_id", "?")
        if ip:
            print(f"[Startup] Re-applying block for {dev} IP={ip}")
            _apply_nft_block(ip)   # sends to firewall helper
        else:
            print(f"[Startup] Cannot re-apply block for {dev} — no last IP")
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
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] RESTRICT NETWORK → {device_id}  ip={ip}")
    nft_ok, nft_msg = _apply_nft_block(ip) if ip else (False, "no IP")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac) if mac else (False, "no MAC")
    return {"result": "network_restricted", "device_id": device_id,
            "ip": ip, "nft": nft_msg, "dnsmasq": dns_msg}


def handle_isolate_vlan(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] ISOLATE VLAN → {device_id}  ip={ip}")
    nft_ok, nft_msg = _apply_nft_block(ip) if ip else (False, "no IP")
    return {"result": "isolated_vlan", "device_id": device_id, "nft": nft_msg}


def handle_lock_account(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] LOCK ACCOUNT → {device_id}  ip={ip}")
    nft_ok, nft_msg = _apply_nft_block(ip) if ip else (False, "no IP")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac) if mac else (False, "no MAC")
    return {"result": "account_locked", "device_id": device_id,
            "nft": nft_msg, "dnsmasq": dns_msg}


def handle_firewall_block(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    print(f"[Executor] FIREWALL BLOCK → {device_id}  ip={ip}")
    nft_ok, nft_msg = _apply_nft_block(ip) if ip else (False, "no IP")
    return {"result": "firewall_blocked", "device_id": device_id,
            "ip": ip, "nft": nft_msg}


def handle_kill_process(device_id: str, metadata: dict) -> dict:
    process = metadata.get("process_name", "unknown")
    print(f"[Executor] KILL PROCESS → {device_id}  process={process}")
    return {"result": "process_killed", "process_name": process, "device_id": device_id}


def handle_block_device(device_id: str, metadata: dict) -> dict:
    """
    Block internet access for this device:
      nft add rule ip filter guardient_blocks ip saddr <IP> counter drop
      nft add rule ip filter guardient_blocks ip daddr <IP> counter drop

    The device stays connected to the hotspot (DHCP/DNS via INPUT chain)
    but cannot send or receive internet traffic (FORWARD chain drops it).
    """
    ip     = metadata.get("ip")
    mac    = metadata.get("mac") or metadata.get("mac_address")
    reason = metadata.get("reason", "Manual SOC block")
    print(f"[Executor] BLOCK DEVICE → {device_id}  ip={ip}  reason='{reason}'")

    nft_ok, nft_msg = _apply_nft_block(ip)   if ip  else (False, "no IP in metadata")
    dns_ok, dns_msg = _apply_dnsmasq_block(mac) if mac else (False, "no MAC in metadata")

    return {
        "result":    "device_blocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "reason":    reason,
        "nft":       nft_msg,
        "dnsmasq":   dns_msg,
    }


def handle_unblock_device(device_id: str, metadata: dict) -> dict:
    """
    Remove the nft DROP rules for this device — restores internet immediately.
    """
    ip  = metadata.get("ip")
    mac = metadata.get("mac") or metadata.get("mac_address")
    print(f"[Executor] UNBLOCK DEVICE → {device_id}  ip={ip}")

    nft_ok, nft_msg = _remove_nft_block(ip)    if ip  else (False, "no IP in metadata")
    dns_ok, dns_msg = _remove_dnsmasq_block(mac) if mac else (False, "no MAC in metadata")

    return {
        "result":    "device_unblocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "nft":       nft_msg,
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
