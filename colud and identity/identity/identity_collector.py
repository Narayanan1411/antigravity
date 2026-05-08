"""
Guardient Identity Collector  v2
===================================
Collects real identity & authentication telemetry from the local macOS system.
Polls every 3 seconds. All data is real — zero simulation.

Sources used (macOS):
  psutil              → active logged-in users
  /var/log/system.log → SSH / authentication events (if readable)
  macOS log stream    → unified log (security subsystem) via subprocess
  /etc/passwd         → local user directory
  getent / dscl       → group memberships on macOS

POST → /identity/events  with IDENTITY_KEY
"""

import os
import re
import time
import json
import stat
import subprocess
import pwd
import grp
from datetime import datetime, timezone
from collections import defaultdict
from typing import Optional

import psutil
import requests
from dotenv import load_dotenv

load_dotenv()

# ==============================
# Config
# ==============================

INTERVAL     = 3
API_BASE     = os.getenv("TELEMETRY_API_BASE", "http://localhost:8000")
IDENTITY_KEY = os.getenv("IDENTITY_KEY", "IDN-KEY-7E3B9D2A")

# Running cumulative failure counter per user
_failure_counts: dict = defaultdict(int)
# Watermark: track which log lines we already parsed
_log_watermark: float = time.time() - 30  # start from last 30 s

# ==============================
# Helpers
# ==============================

def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()

def _ts_iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()

# ==============================
# 1. Active logged-in users
#    Source: psutil (real OS sessions)
# ==============================

def get_logged_in_users() -> list:
    users = []
    try:
        for u in psutil.users():
            auth_type = "ssh" if (u.host and u.host not in ("", "localhost", "127.0.0.1")) else "local_tty"
            users.append({
                "user_id":             u.name,
                "login_timestamp":     _ts_iso(u.started),
                "login_source_ip":     u.host if u.host else "local",
                "terminal":            u.terminal,
                "authentication_type": auth_type,
                "mfa_status":          "unknown",  # macOS does not expose this in psutil
                "service_account_activity": u.name in ("root", "daemon", "_www", "_sshd"),
            })
    except Exception as exc:
        users.append({"error": str(exc)})
    return users

# ==============================
# 2. Local user directory
#    Source: /etc/passwd via pwd module (real system users)
# ==============================

def get_local_users() -> list:
    users = []
    try:
        for p in pwd.getpwall():
            # Skip system UIDs below 500 on macOS (system accounts)
            users.append({
                "user_id":     p.pw_name,
                "uid":         p.pw_uid,
                "gid":         p.pw_gid,
                "home":        p.pw_dir,
                "shell":       p.pw_shell,
                "is_service_account": p.pw_uid < 500 or p.pw_shell in ("/usr/bin/false", "/sbin/nologin"),
            })
    except Exception as exc:
        users.append({"error": str(exc)})
    return users

# ==============================
# 3. Group memberships
#    Source: /etc/group via grp module
# ==============================

def get_group_memberships() -> list:
    groups = []
    try:
        for g in grp.getgrall():
            if g.gr_mem:  # only groups that have explicit members
                groups.append({
                    "group_name": g.gr_name,
                    "gid":        g.gr_gid,
                    "members":    list(g.gr_mem),
                    "member_count": len(g.gr_mem),
                    "privileged": g.gr_name in ("admin", "wheel", "sudo", "staff"),
                })
    except Exception as exc:
        groups.append({"error": str(exc)})
    return groups

# ==============================
# 4. Recent auth events
#    Source: macOS Unified Log via `log` command
#    Subsystem: com.apple.security, com.apple.loginwindow, com.openssh
# ==============================

def fetch_auth_events() -> list:
    global _log_watermark

    events = []
    now    = time.time()
    # Only pull events from last INTERVAL + 1 second to avoid duplicates
    since  = datetime.fromtimestamp(_log_watermark, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    try:
        # macOS `log show` — reads the Unified Log from the security subsystem.
        # This is a real OS API, not a simulation.
        result = subprocess.run(
            [
                "log", "show",
                "--style", "json",
                "--start", since,
                "--predicate",
                (
                    'subsystem == "com.apple.security" OR '
                    'subsystem == "com.openssh.sshd" OR '
                    'subsystem == "com.apple.loginwindow" OR '
                    'category == "auth" OR '
                    'category == "authentication" OR '
                    'eventMessage CONTAINS "authentication" OR '
                    'eventMessage CONTAINS "sudo" OR '
                    'eventMessage CONTAINS "login" OR '
                    'eventMessage CONTAINS "logout"'
                ),
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )

        if result.returncode == 0 and result.stdout.strip():
            try:
                raw_entries = json.loads(result.stdout)
            except json.JSONDecodeError:
                raw_entries = []

            for entry in raw_entries:
                msg  = entry.get("eventMessage", "")
                ts   = entry.get("timestamp", _now_iso())
                sub  = entry.get("subsystem", "")
                proc = entry.get("processImagePath", "").split("/")[-1]

                ev = _classify_log_entry(msg, sub, proc, ts)
                if ev:
                    events.append(ev)

    except subprocess.TimeoutExpired:
        events.append({"event_type": "collector_error", "error": "log command timeout",
                        "timestamp": _now_iso()})
    except FileNotFoundError:
        # `log` binary not found — shouldn't happen on macOS but handle gracefully
        events.append({"event_type": "collector_error", "error": "`log` binary not found",
                        "timestamp": _now_iso()})
    except Exception as exc:
        events.append({"event_type": "collector_error", "error": str(exc),
                        "timestamp": _now_iso()})

    _log_watermark = now
    return events

def _classify_log_entry(msg: str, subsystem: str, process: str, timestamp: str) -> Optional[dict]:
    """Parse a macOS unified log entry into a structured identity event."""

    base = {
        "timestamp":               timestamp,
        "collected_at":            _now_iso(),
        "event_type":              None,
        "user_id":                 None,
        "login_source_ip":         None,
        "authentication_type":     None,
        "mfa_status":              "unknown",
        "failure_count":           0,
        "privilege_change_event":  None,
        "group_membership_change": None,
        "service_account_activity": False,
        "token_issuance_event":    None,
        "source_system":           subsystem or process,
        "raw_message":             msg,
    }

    msg_lower = msg.lower()

    # SSH accepted
    m = re.search(r"Accepted (\w+) for (\S+) from ([\d\.]+)", msg)
    if m:
        uid = m.group(2)
        base.update({"event_type": "login_success", "authentication_type": m.group(1),
                     "user_id": uid, "login_source_ip": m.group(3),
                     "service_account_activity": uid in ("root","daemon")})
        return base

    # SSH failed
    m = re.search(r"Failed (\w+) for (\S+) from ([\d\.]+)", msg)
    if m:
        uid = m.group(2)
        _failure_counts[uid] += 1
        base.update({"event_type": "login_failure", "authentication_type": m.group(1),
                     "user_id": uid, "login_source_ip": m.group(3),
                     "failure_count": _failure_counts[uid]})
        return base

    # sudo success
    m = re.search(r"sudo.*?(\S+)\s*:.*?USER=(\S+).*?COMMAND=(.+)", msg)
    if m:
        uid = m.group(1).split()[-1]
        base.update({"event_type": "privilege_escalation", "authentication_type": "sudo",
                     "user_id": uid,
                     "privilege_change_event": {"escalated_to": m.group(2),
                                                "command": m.group(3).strip()}})
        return base

    # sudo bad password
    if "sudo" in msg_lower and "incorrect password" in msg_lower:
        m = re.search(r"for user (\S+)", msg)
        uid = m.group(1) if m else "unknown"
        _failure_counts[uid] += 1
        base.update({"event_type": "sudo_failure", "authentication_type": "sudo",
                     "user_id": uid, "failure_count": _failure_counts[uid]})
        return base

    # macOS loginwindow
    if "loginwindow" in subsystem or "loginwindow" in process:
        if "login" in msg_lower:
            m = re.search(r"user[:\s]+(\S+)", msg, re.IGNORECASE)
            uid = m.group(1) if m else "unknown"
            base.update({"event_type": "gui_login", "authentication_type": "local_gui",
                         "user_id": uid})
            return base
        if "logout" in msg_lower:
            m = re.search(r"user[:\s]+(\S+)", msg, re.IGNORECASE)
            uid = m.group(1) if m else "unknown"
            base.update({"event_type": "gui_logout", "authentication_type": "local_gui",
                         "user_id": uid})
            return base

    # Generic auth failure
    if "authentication failure" in msg_lower or "auth failed" in msg_lower:
        m = re.search(r"user[=:\s]+(\S+)", msg, re.IGNORECASE)
        uid = m.group(1) if m else "unknown"
        _failure_counts[uid] += 1
        base.update({"event_type": "auth_failure", "authentication_type": "pam",
                     "user_id": uid, "failure_count": _failure_counts[uid]})
        return base

    # Token / OAuth mention
    if "token" in msg_lower and ("issued" in msg_lower or "grant" in msg_lower):
        base.update({"event_type": "token_issuance", "token_issuance_event": msg})
        return base

    return None  # unclassified — skip

# ==============================
# 5. Running processes by user
#    Source: psutil (real OS process table)
#    Detects service account interactive activity
# ==============================

def get_user_processes() -> list:
    procs = []
    try:
        for p in psutil.process_iter(["pid","name","username","create_time","status"]):
            info = p.info
            if not info.get("username"):
                continue
            procs.append({
                "pid":          info["pid"],
                "name":         info["name"],
                "user_id":      info["username"],
                "create_time":  _ts_iso(info["create_time"]),
                "status":       info["status"],
                "is_service":   info["username"] in ("root","daemon","_www","_sshd","nobody"),
            })
    except Exception:
        pass
    return procs

# ==============================
# Collect once + push
# ==============================

def collect_once() -> dict:
    now         = _now_iso()
    auth_events = fetch_auth_events()
    logged_in   = get_logged_in_users()
    local_users = get_local_users()
    groups      = get_group_memberships()

    fail_cycle = sum(1 for e in auth_events
                     if e.get("event_type") in ("login_failure","auth_failure","sudo_failure"))
    ok_cycle   = sum(1 for e in auth_events
                     if e.get("event_type") in ("login_success","gui_login"))

    privileged_groups = [g["group_name"] for g in groups if g.get("privileged")]

    return {
        "collected_at":    now,
        "source_system":   "macos_unified_log",
        "collector":       "identity_collector_v2",

        # Required identity fields
        "identity_events": auth_events,       # structured auth events — each has user_id,
                                               # login_source_ip, auth_type, failure_count etc.
        "logged_in_users": logged_in,
        "local_user_directory": local_users,
        "group_memberships":    groups,
        "privileged_groups":    privileged_groups,

        # Summary counts
        "total_events":      len(auth_events),
        "failures_this_cycle": fail_cycle,
        "successes_this_cycle": ok_cycle,
        "cumulative_failures":  dict(_failure_counts),

        # Risk flags
        "risk_flags": {
            "brute_force_detected": any(v >= 5 for v in _failure_counts.values()),
            "root_login_detected":  any(
                e.get("user_id") == "root" and e.get("event_type") == "login_success"
                for e in auth_events),
            "privilege_escalation": any(
                e.get("event_type") == "privilege_escalation" for e in auth_events),
            "service_account_interactive": any(
                e.get("service_account_activity") and e.get("event_type") in
                ("login_success","gui_login") for e in auth_events),
            "token_issuance_detected": any(
                e.get("event_type") == "token_issuance" for e in auth_events),
        },
    }

def push_to_api(data: dict) -> Optional[int]:
    try:
        resp = requests.post(
            f"{API_BASE}/identity/events",
            json=data,
            headers={"x-api-key": IDENTITY_KEY},
            timeout=10,
        )
        return resp.status_code
    except Exception as exc:
        print(f"[PUSH ERROR] {exc}")
        return None

# ==============================
# Entry point
# ==============================

def run():
    print("=" * 55)
    print("  Guardient Identity Collector  v2")
    print("=" * 55)
    print(f"  API Base : {API_BASE}")
    print(f"  Interval : {INTERVAL}s")
    print("  Sources  : macOS Unified Log, psutil, /etc/passwd")
    print("  Data     : 100% real — no simulation")
    print("=" * 55 + "\n")

    while True:
        tick = time.time()
        try:
            data   = collect_once()
            status = push_to_api(data)
            flags  = [k for k, v in data["risk_flags"].items() if v]
            print(
                f"[{data['collected_at']}] "
                f"Events: {data['total_events']} | "
                f"LoggedIn: {len(data['logged_in_users'])} | "
                f"Failures: {data['failures_this_cycle']} | "
                f"API→{status} | "
                f"Flags: {flags or 'none'}"
            )
        except KeyboardInterrupt:
            print("\n[Identity Collector] Stopped.")
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")

        time.sleep(max(0, INTERVAL - (time.time() - tick)))

if __name__ == "__main__":
    run()
