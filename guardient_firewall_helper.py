#!/usr/bin/env python3
"""
Guardient Firewall Helper — runs as root via systemd.
Listens on /run/guardient-fw.sock for block/unblock commands from the API.

Commands (one per connection, newline-terminated):
  block <IP>    → add DROP rules to guardient_blocks chain
  unblock <IP>  → remove DROP rules for that IP
  status        → list all current rules
  flush         → remove all rules (called on startup/shutdown)

Install:  sudo bash poc\ Guardient/install_firewall_helper.sh
"""
import os
import re
import socket
import subprocess
import sys

SOCK_PATH = "/run/guardient-fw.sock"
NFT_TABLE  = "ip"
NFT_FAMILY = "filter"
NFT_CHAIN  = "guardient_blocks"


def nft(*args):
    r = subprocess.run(["nft"] + list(args), capture_output=True, timeout=5)
    return r.returncode == 0, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace").strip()


def ensure_chain():
    ok, out, err = nft("list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    if ok and "hook forward" in out:
        return True
    nft("delete", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    ok, _, err = nft(
        "add", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
        "{", "type", "filter", "hook", "forward",
        "priority", "-10", ";", "policy", "accept", ";", "}"
    )
    if ok:
        print(f"[FW] Created {NFT_CHAIN} chain (priority -10)")
    else:
        print(f"[FW] Chain creation failed: {err}", file=sys.stderr)
    return ok


def get_handles(ip):
    ok, out, _ = nft("-a", "list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    if not ok:
        return []
    return [m.group(1) for line in out.splitlines()
            if ip in line
            for m in [re.search(r'handle\s+(\d+)', line)] if m]


def block(ip):
    ensure_chain()
    if get_handles(ip):
        return f"already_blocked:{ip}"
    ok1, _, e1 = nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                      "ip", "saddr", ip, "counter", "drop")
    ok2, _, e2 = nft("add", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN,
                      "ip", "daddr", ip, "counter", "drop")
    if ok1 and ok2:
        print(f"[FW] Blocked {ip}")
        return f"blocked:{ip}"
    return f"error:{e1 or e2}"


def unblock(ip):
    handles = get_handles(ip)
    if not handles:
        return f"not_blocked:{ip}"
    removed = 0
    for h in handles:
        ok, _, _ = nft("delete", "rule", NFT_TABLE, NFT_FAMILY, NFT_CHAIN, "handle", h)
        if ok:
            removed += 1
    print(f"[FW] Unblocked {ip} (removed {removed} rules)")
    return f"unblocked:{ip}:{removed}"


def flush_all():
    ok, _, _ = nft("flush", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    print("[FW] Flushed all block rules")
    return "flushed"


def status():
    ok, out, _ = nft("list", "chain", NFT_TABLE, NFT_FAMILY, NFT_CHAIN)
    return out if ok else "chain_not_found"


def handle_client(conn):
    try:
        data = conn.recv(256).decode(errors="replace").strip()
        if not data:
            return
        parts = data.split()
        cmd = parts[0].lower() if parts else ""
        ip  = parts[1] if len(parts) > 1 else ""

        # Validate IP to prevent injection
        if ip and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip):
            conn.sendall(b"error:invalid_ip\n")
            return

        if cmd == "block" and ip:
            result = block(ip)
        elif cmd == "unblock" and ip:
            result = unblock(ip)
        elif cmd == "flush":
            result = flush_all()
        elif cmd == "status":
            result = status()
        else:
            result = "error:unknown_command"

        conn.sendall((result + "\n").encode())
    except Exception as exc:
        conn.sendall(f"error:{exc}\n".encode())
    finally:
        conn.close()


def main():
    if os.geteuid() != 0:
        print("Must run as root", file=sys.stderr)
        sys.exit(1)

    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)

    ensure_chain()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCK_PATH)
    os.chmod(SOCK_PATH, 0o777)  # all users can connect; commands are validated
    server.listen(10)
    print(f"[FW] Listening on {SOCK_PATH}")

    try:
        while True:
            conn, _ = server.accept()
            handle_client(conn)
    except KeyboardInterrupt:
        print("[FW] Shutting down")
    finally:
        flush_all()
        server.close()
        if os.path.exists(SOCK_PATH):
            os.unlink(SOCK_PATH)


if __name__ == "__main__":
    main()
