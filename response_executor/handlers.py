"""
Response Executor — Action Handlers
======================================
Block / Unblock enforcement for Linux hotspot clients.

Three-layer enforcement (applied on block, reversed on unblock):

  1. nft DROP  — base chain 'guardient_blocks' at priority -10 fires BEFORE
                  NetworkManager's filter chain (priority 0).  Drops all
                  FORWARD traffic to/from the device by IP.
                  → blocks NEW packets immediately.

  2. conntrack flush  — deletes connection-tracking entries for that IP so
                         existing TCP sessions break instantly rather than
                         surviving until natural timeout.
                         → kills ESTABLISHED connections immediately.

  3. iw station del  — sends a Wi-Fi deauthentication frame to the device.
                        It reconnects within seconds, but by then layers 1 & 2
                        are in place, so it has no internet on reconnect.
                        → provides instant user-visible "no internet" effect.

The device keeps its DHCP lease and stays associated with the Wi-Fi SSID
(DHCP/DNS traffic uses the INPUT hook, not FORWARD).

Sudoers entry (installed once via install_firewall_helper.sh or pkexec):
    narayanan ALL=(ALL) NOPASSWD: /usr/sbin/nft, /usr/sbin/conntrack, /usr/sbin/iw
"""
from __future__ import annotations

import os
import re
import subprocess

DNSMASQ_BLOCK_DIR = "/etc/NetworkManager/dnsmasq-shared.d"
NFT_TABLE  = "ip"
NFT_FAMILY = "filter"
NFT_CHAIN  = "guardient_blocks"   # base chain, hook forward, priority -10


# ── Privileged command runner ─────────────────────────────────────────────────

def _run(*args: str, timeout: int = 5) -> tuple[bool, str]:
    """Run a command via sudo -n → pkexec → plain. Returns (success, stdout/err)."""
    cmd = list(args)
    for prefix in [["sudo", "-n"], ["pkexec"], []]:
        try:
            r = subprocess.run(prefix + cmd, capture_output=True, timeout=timeout)
            if r.returncode == 0:
                return True, r.stdout.decode(errors="replace")
            err = r.stderr.decode(errors="replace").strip()
            if any(k in err.lower() for k in
                   ("not permitted", "permission denied", "authentication",
                    "interactive", "no valid", "password")):
                continue
            return False, err
        except (PermissionError, subprocess.TimeoutExpired):
            continue
        except Exception as exc:
            return False, str(exc)
    return False, f"permission denied running: {' '.join(cmd[:3])}"


def _nft(*args: str) -> tuple[bool, str]:
    return _run("nft", *args)


# ── nft chain management ──────────────────────────────────────────────────────

def _chain_exists() -> bool:
    ok, out = _nft("list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    return ok and "hook forward" in out


def ensure_guardient_chain() -> tuple[bool, str]:
    """
    Create the guardient_blocks base chain if absent.

    Base chain at priority -10 means it fires BEFORE the FORWARD chain at
    priority 0 (where NetworkManager puts nm-sh-fw-wlp1s0).  The DROP rules
    we add here execute before NM's 'ip saddr 10.42.0.0/24 accept' rule, so
    the blocked device's packets are dropped regardless of NM's config.

    The chain has policy 'accept' so non-blocked devices are unaffected.
    """
    if _chain_exists():
        return True, "ready"
    # Remove any old regular chain with the same name
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


# ── Enforcement layers ────────────────────────────────────────────────────────

def _apply_nft_block(ip: str) -> tuple[bool, str]:
    if not ip:
        return False, "no IP"
    chain_ok, chain_err = ensure_guardient_chain()
    if not chain_ok:
        return False, chain_err
    if _get_handles_for_ip(ip):
        return True, "already_present"
    ok1, _ = _nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                   "ip", "saddr", ip, "counter", "drop")
    ok2, _ = _nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                   "ip", "daddr", ip, "counter", "drop")
    if ok1 and ok2:
        print(f"[Handler] nft DROP applied for {ip}")
        return True, "applied"
    return False, "nft rule insert failed"


def _remove_nft_block(ip: str) -> tuple[bool, str]:
    if not ip:
        return False, "no IP"
    handles = _get_handles_for_ip(ip)
    if not handles:
        return True, "not_present"
    removed = sum(1 for h in handles
                  if _nft("delete", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN, "handle", h)[0])
    return True, f"removed {removed}/{len(handles)} rules"


def _flush_conntrack(ip: str) -> tuple[bool, str]:
    """
    Delete all connection-tracking entries for this IP.

    This is the critical step that makes blocking IMMEDIATE for existing
    sessions.  Without it, TCP connections established before the DROP rule
    was added continue until they timeout naturally (could be minutes).
    With the flush, the OS forgets the connection and the next retransmit
    from either side hits the DROP rule and is discarded.
    """
    if not ip:
        return False, "no IP"
    ok1, _ = _run("conntrack", "-D", "--src", ip, timeout=3)
    ok2, _ = _run("conntrack", "-D", "--dst", ip, timeout=3)
    # conntrack -D returns 1 when no entries found (not an error)
    print(f"[Handler] conntrack: flushed entries for {ip}")
    return True, "flushed"


def _wifi_deauth(mac: str) -> tuple[bool, str]:
    """
    Send a Wi-Fi deauthentication frame to the device via 'iw station del'.

    The device disconnects from the AP for ~1-2 seconds, then reconnects.
    On reconnect, the nft DROP rules are already in place so no internet is
    available.  This gives the user instant visible confirmation the block
    worked.
    """
    if not mac:
        return False, "no MAC"
    # Find the active hotspot interface
    iface = _get_hotspot_iface()
    if not iface:
        return False, "no hotspot interface"
    ok, err = _run("iw", "dev", iface, "station", "del", mac.lower())
    if ok:
        print(f"[Handler] iw: deauth {mac} from {iface}")
        return True, f"deauthed from {iface}"
    return False, err


def _get_hotspot_iface() -> str:
    """Return the Wi-Fi interface currently running as an AP (hotspot)."""
    try:
        r = subprocess.run(
            ["nmcli", "-t", "-f", "DEVICE,TYPE", "connection", "show", "--active"],
            capture_output=True, text=True, timeout=3
        )
        for line in r.stdout.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and "wifi" in parts[1].lower():
                iface = parts[0]
                # Verify it's actually in AP mode
                ap_check = subprocess.run(
                    ["iw", "dev", iface, "info"],
                    capture_output=True, text=True, timeout=3
                )
                if "AP" in ap_check.stdout:
                    return iface
    except Exception:
        pass
    # Fallback: look for any AP-mode wireless interface
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=3)
        current_iface = ""
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                current_iface = line.split()[-1]
            elif "type AP" in line and current_iface:
                return current_iface
    except Exception:
        pass
    return ""


# ── dnsmasq DHCP deny ─────────────────────────────────────────────────────────

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
    return False, "no write permission to dnsmasq-shared.d"


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
    cleared = []
    if _chain_exists():
        ok, _ = _nft("flush", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
        if ok:
            cleared.append("nft:flushed")
            print(f"[Startup] nft: flushed {NFT_CHAIN}")
    try:
        for fname in os.listdir(DNSMASQ_BLOCK_DIR):
            if fname.startswith("block-") and fname.endswith(".conf"):
                path = os.path.join(DNSMASQ_BLOCK_DIR, fname)
                try:
                    os.remove(path)
                    cleared.append(fname)
                except PermissionError:
                    subprocess.run(["sudo", "-n", "rm", path], capture_output=True)
        if any(f.endswith(".conf") for f in cleared):
            subprocess.run(["pkill", "-HUP", "dnsmasq"], capture_output=True, timeout=3)
    except Exception as exc:
        print(f"[Startup] dnsmasq cleanup: {exc}")
    return cleared


def reapply_active_blocks(active_blocks: list[dict]) -> None:
    for blk in active_blocks:
        ip  = blk.get("last_ip")
        mac = blk.get("mac_address") or blk.get("mac")
        dev = blk.get("device_id", "?")
        if ip:
            print(f"[Startup] Re-blocking {dev} IP={ip}")
            _apply_nft_block(ip)
            _flush_conntrack(ip)
        if mac:
            _apply_dnsmasq_block(mac)


# ── Action handlers ───────────────────────────────────────────────────────────

def handle_allow(device_id: str, metadata: dict) -> dict:
    return {"result": "allowed", "device_id": device_id}


def handle_monitor(device_id: str, metadata: dict) -> dict:
    return {"result": "monitoring_enabled", "device_id": device_id}


def handle_require_mfa(device_id: str, metadata: dict) -> dict:
    print(f"[Executor] MFA CHALLENGE → {device_id}")
    return {"result": "mfa_challenge_sent", "device_id": device_id}


def handle_restrict_network(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] RESTRICT NETWORK → {device_id}  ip={ip}")
    nft_ok,  nft_msg  = _apply_nft_block(ip)   if ip  else (False, "no IP")
    conn_ok, conn_msg = _flush_conntrack(ip)    if ip  else (False, "no IP")
    deauth_ok, deauth_msg = _wifi_deauth(mac)   if mac else (False, "no MAC")
    dns_ok,  dns_msg  = _apply_dnsmasq_block(mac) if mac else (False, "no MAC")
    return {"result": "network_restricted", "device_id": device_id,
            "nft": nft_msg, "conntrack": conn_msg,
            "wifi": deauth_msg, "dnsmasq": dns_msg}


def handle_isolate_vlan(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] ISOLATE VLAN → {device_id}  ip={ip}")
    nft_ok, nft_msg   = _apply_nft_block(ip) if ip  else (False, "no IP")
    conn_ok, conn_msg = _flush_conntrack(ip) if ip  else (False, "no IP")
    return {"result": "isolated_vlan", "device_id": device_id,
            "nft": nft_msg, "conntrack": conn_msg}


def handle_lock_account(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] LOCK ACCOUNT → {device_id}  ip={ip}")
    nft_ok,  nft_msg  = _apply_nft_block(ip)     if ip  else (False, "no IP")
    conn_ok, conn_msg = _flush_conntrack(ip)      if ip  else (False, "no IP")
    deauth_ok, deauth_msg = _wifi_deauth(mac)     if mac else (False, "no MAC")
    dns_ok,  dns_msg  = _apply_dnsmasq_block(mac) if mac else (False, "no MAC")
    return {"result": "account_locked", "device_id": device_id,
            "nft": nft_msg, "conntrack": conn_msg,
            "wifi": deauth_msg, "dnsmasq": dns_msg}


def handle_firewall_block(device_id: str, metadata: dict) -> dict:
    ip  = metadata.get("ip")
    mac = metadata.get("mac")
    print(f"[Executor] FIREWALL BLOCK → {device_id}  ip={ip}")
    nft_ok, nft_msg   = _apply_nft_block(ip) if ip  else (False, "no IP")
    conn_ok, conn_msg = _flush_conntrack(ip) if ip  else (False, "no IP")
    return {"result": "firewall_blocked", "device_id": device_id,
            "nft": nft_msg, "conntrack": conn_msg}


def handle_kill_process(device_id: str, metadata: dict) -> dict:
    process = metadata.get("process_name", "unknown")
    print(f"[Executor] KILL PROCESS → {device_id}  process={process}")
    return {"result": "process_killed", "process_name": process, "device_id": device_id}


def handle_block_device(device_id: str, metadata: dict) -> dict:
    """
    Full three-layer block:
      1. nft DROP  — blocks all new forwarded traffic immediately
      2. conntrack flush  — kills existing TCP sessions right away
      3. iw deauth  — kicks device from Wi-Fi (reconnects, but no internet)
      4. dnsmasq deny  — prevents DHCP lease renewal (no new IP on reconnect)
    """
    ip     = metadata.get("ip")
    mac    = metadata.get("mac") or metadata.get("mac_address")
    reason = metadata.get("reason", "Manual SOC block")
    print(f"[Executor] BLOCK DEVICE → {device_id}  ip={ip}  mac={mac}  reason='{reason}'")

    nft_ok,    nft_msg    = _apply_nft_block(ip)     if ip  else (False, "no IP")
    conn_ok,   conn_msg   = _flush_conntrack(ip)      if ip  else (False, "no IP")
    deauth_ok, deauth_msg = _wifi_deauth(mac)          if mac else (False, "no MAC")
    dns_ok,    dns_msg    = _apply_dnsmasq_block(mac)  if mac else (False, "no MAC")

    return {
        "result":    "device_blocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "reason":    reason,
        "nft":       nft_msg,
        "conntrack": conn_msg,
        "wifi":      deauth_msg,
        "dnsmasq":   dns_msg,
    }


def handle_unblock_device(device_id: str, metadata: dict) -> dict:
    """
    Reverse all three enforcement layers.
    The device regains internet within seconds of reconnecting.
    """
    ip  = metadata.get("ip")
    mac = metadata.get("mac") or metadata.get("mac_address")
    print(f"[Executor] UNBLOCK DEVICE → {device_id}  ip={ip}  mac={mac}")

    nft_ok,  nft_msg  = _remove_nft_block(ip)    if ip  else (False, "no IP")
    conn_ok, conn_msg = _flush_conntrack(ip)       if ip  else (False, "no IP")
    dns_ok,  dns_msg  = _remove_dnsmasq_block(mac) if mac else (False, "no MAC")

    return {
        "result":    "device_unblocked",
        "device_id": device_id,
        "ip":        ip,
        "mac":       mac,
        "nft":       nft_msg,
        "conntrack": conn_msg,
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
        print(f"[Executor] WARNING: unknown action '{action}'")
        return {"result": "unhandled", "action": action, "device_id": device_id}
    return handler(device_id, metadata)
