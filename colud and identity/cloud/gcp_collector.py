"""
Guardient GCP Cloud Collector  v4
===================================
Uses ONLY official Google Cloud Python client libraries.
ALL calls are READ-ONLY — zero writes, zero resource creation,
zero billing charges.

APIs used (all free read operations — no running instance required):
  ┌─────────────────────────────────────────────────────────────────┐
  │ google.cloud.logging_v2          Cloud Audit Logs (read)        │
  │ google.cloud.monitoring_v3       CPU / memory / API metrics     │
  │ google.oauth2 + google.auth      Application Default Creds      │
  │ google-api-python-client         IAM, Service Usage, Quotas     │
  └─────────────────────────────────────────────────────────────────┘

No billing API is called — no charges can result.
No gcloud CLI / subprocess is used.
No data is ever simulated or mocked.
No instance / VM data is collected.

Data is:
  1. POSTed to /cloud/events API every 3 seconds
  2. Written locally to gcp_events.jsonl as fallback (even if API is down)

Setup:
  gcloud auth application-default login
  or set GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
"""

from __future__ import annotations

import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Google Cloud Python SDKs
from google.cloud import logging_v2
from google.cloud import monitoring_v3
import googleapiclient.discovery
import google.auth

load_dotenv()

# ==============================
# Configuration
# ==============================

PROJECT_ID   = os.getenv("GCP_PROJECT_ID",  "project-a97c1c37-6647-41e1-a77")
INTERVAL     = 3
API_BASE     = os.getenv("TELEMETRY_API_BASE", "http://localhost:8000")
CLOUD_KEY    = os.getenv("CLOUD_KEY", "CLD-KEY-5C1F4A8E")
OUTPUT_FILE  = os.path.join(os.path.dirname(__file__), "gcp_events.jsonl")

# Watermark: incremental audit log fetch
_last_fetch_time = datetime.now(tz=timezone.utc) - timedelta(hours=24)

# ==============================
# Audit Log helpers
# ==============================

_METHOD_MAP = {
    "compute.instances.insert":                 "instance_start",
    "compute.instances.delete":                 "instance_stop",
    "compute.instances.stop":                   "instance_stop",
    "compute.instances.start":                  "instance_start",
    "compute.firewalls.insert":                 "firewall_rule_created",
    "compute.firewalls.delete":                 "firewall_rule_deleted",
    "compute.firewalls.patch":                  "security_group_change",
    "compute.firewalls.update":                 "security_group_change",
    "storage.buckets.create":                   "storage_bucket_created",
    "storage.buckets.delete":                   "storage_bucket_deleted",
    "storage.objects.get":                      "storage_access_event",
    "storage.objects.create":                   "storage_access_event",
    "iam.serviceAccounts.create":               "service_account_created",
    "iam.serviceAccounts.delete":               "service_account_deleted",
    "google.iam.admin.v1.CreateServiceAccount": "service_account_created",
    "iam.serviceAccounts.actAs":                "service_account_used",
    "SetIamPolicy":                             "iam_policy_change",
    "CreateCryptoKey":                          "key_creation_event",
    "compute.snapshots.insert":                 "snapshot_creation",
    "compute.networks.insert":                  "network_created",
    "ServiceUsage.EnableService":               "api_enabled",
}

_HIGH   = {"key_creation_event","snapshot_creation","iam_policy_change",
           "security_group_change","firewall_rule_deleted"}
_MEDIUM = {"firewall_rule_created","service_account_created",
           "storage_bucket_created","api_enabled"}

def _event_type(method: str) -> str:
    for k, v in _METHOD_MAP.items():
        if k in method:
            return v
    return "api_call"

def _risk_level(ev: str, granted: bool, code: int) -> str:
    if not granted or code not in (0, 9):
        return "high"
    if ev in _HIGH:   return "high"
    if ev in _MEDIUM: return "medium"
    return "low"

def _parse_entry(entry, now: datetime) -> dict:
    payload    = entry.payload or {}
    method     = payload.get("methodName", "unknown")
    service    = payload.get("serviceName", "unknown")
    resource   = payload.get("resourceName", "unknown")
    auth       = payload.get("authenticationInfo", {})
    principal  = auth.get("principalEmail")
    meta       = payload.get("requestMetadata", {})
    caller_ip  = meta.get("callerIp")
    user_agent = meta.get("callerSuppliedUserAgent")
    authz      = payload.get("authorizationInfo", [])
    granted    = all(a.get("granted", True) for a in authz) if authz else True
    perms      = [a.get("permission", "") for a in authz]
    status     = payload.get("status", {})
    code       = status.get("code", 0)
    msg        = status.get("message", "")
    labels     = {}
    if hasattr(entry, "resource") and hasattr(entry.resource, "labels"):
        labels = dict(entry.resource.labels)
    ev   = _event_type(method)
    risk = _risk_level(ev, granted, code)
    return {
        "timestamp":           entry.timestamp.isoformat() if entry.timestamp else None,
        "collected_at":        now.isoformat(),
        "project_id":          labels.get("project_id", PROJECT_ID),
        "instance_id":         labels.get("instance_id"),   # present if event relates to an instance
        "zone":                labels.get("zone"),
        "resource_name":       resource,
        "resource_type":       entry.resource.type if hasattr(entry, "resource") else None,
        "principal_email":     principal,
        "api_source_ip":       caller_ip,
        "user_agent":          user_agent,
        "api_action":          method,
        "event_type":          ev,
        "service_name":        service,
        "permissions_checked": perms,
        "access_granted":      granted,
        "status_code":         code,
        "status_message":      msg,
        "risk_level":          risk,
        "severity":            str(entry.severity),
        "log_name":            entry.log_name,
        "insert_id":           entry.insert_id,
        "security_group_change": ev == "security_group_change",
        "snapshot_creation":     ev == "snapshot_creation",
        "key_creation_event":    ev == "key_creation_event",
        "storage_access_event":  ev == "storage_access_event",
        "instance_start_stop":   ev in ("instance_start", "instance_stop"),
        "risk_flags": {
            "unauthorized_access": not granted,
            "key_created":         ev == "key_creation_event",
            "data_exfil_risk":     ev == "snapshot_creation",
            "lateral_exposure":    ev == "security_group_change",
            "privilege_change":    ev == "iam_policy_change",
            "denied_action":       code != 0,
        },
    }

# ==============================
# Account-level collectors
# ==============================

def fetch_audit_logs() -> list:
    """Cloud Audit Logs — admin activity, data access, system events. Free."""
    global _last_fetch_time
    client = logging_v2.Client(project=PROJECT_ID)
    now    = datetime.now(tz=timezone.utc)
    start  = _last_fetch_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    f = (
        f'(logName="projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Factivity" OR '
        f' logName="projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Fdata_access" OR '
        f' logName="projects/{PROJECT_ID}/logs/cloudaudit.googleapis.com%2Fsystem_event") '
        f'AND timestamp >= "{start}"'
    )
    entries = []
    try:
        for entry in client.list_entries(filter_=f, order_by=logging_v2.DESCENDING, page_size=200):
            try:
                entries.append(_parse_entry(entry, now))
            except Exception as exc:
                entries.append({"parse_error": str(exc), "collected_at": now.isoformat()})
    except Exception as exc:
        entries.append({"fetch_error": str(exc), "collected_at": now.isoformat()})
    _last_fetch_time = now
    return entries

def fetch_monitoring_metrics() -> dict:
    """
    Cloud Monitoring API — pulls real account-level metrics.
    Collects API request rates, error rates, and (if instances exist)
    CPU utilisation and memory usage.
    Cost: FREE — reading built-in metrics is included in the free tier.
    """
    client    = monitoring_v3.MetricServiceClient()
    project   = f"projects/{PROJECT_ID}"
    now_utc   = datetime.now(tz=timezone.utc)
    window    = 60 * 5   # last 5 minutes per sample
    end_time  = now_utc
    start_time = end_time - timedelta(seconds=window)

    interval = monitoring_v3.TimeInterval(
        end_time={"seconds": int(end_time.timestamp())},
        start_time={"seconds": int(start_time.timestamp())},
    )

    def _query(metric_type: str) -> list:
        """Generic helper: list time series for one metric type."""
        results = []
        try:
            req = monitoring_v3.ListTimeSeriesRequest(
                name=project,
                filter=f'metric.type="{metric_type}"',
                interval=interval,
                view=monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            )
            for ts in client.list_time_series(request=req):
                resource_labels = dict(ts.resource.labels)
                for point in ts.points:
                    val = (
                        point.value.double_value
                        or point.value.int64_value
                        or point.value.distribution_value.mean
                        if hasattr(point.value, "distribution_value")
                        else point.value.double_value or point.value.int64_value
                    )
                    results.append({
                        "resource": resource_labels,
                        "start":    point.interval.start_time.isoformat() if point.interval.start_time else None,
                        "end":      point.interval.end_time.isoformat()   if point.interval.end_time   else None,
                        "value":    val,
                    })
        except Exception as exc:
            results.append({"error": str(exc)})
        return results

    # API request counts (e.g. logging, compute, storage API calls made on your project)
    api_requests = _query("serviceruntime.googleapis.com/api/request_count")

    # API error counts
    api_errors = _query("serviceruntime.googleapis.com/api/error_count")

    # CPU utilisation — only populated if Compute Engine instances exist
    cpu_usage = _query("compute.googleapis.com/instance/cpu/utilization")

    # Memory usage (only with agent installed on instances)
    memory_usage = _query("agent.googleapis.com/memory/percent_used")

    # Network sent/received bytes — instance level, empty if no VMs
    network_sent     = _query("compute.googleapis.com/instance/network/sent_bytes_count")
    network_received = _query("compute.googleapis.com/instance/network/received_bytes_count")

    # Summarise CPU for easy risk flagging
    cpu_values  = [p["value"] for p in cpu_usage  if "error" not in p and isinstance(p.get("value"), (int, float))]
    mem_values  = [p["value"] for p in memory_usage if "error" not in p and isinstance(p.get("value"), (int, float))]
    err_values  = [p["value"] for p in api_errors  if "error" not in p and isinstance(p.get("value"), (int, float))]

    return {
        "window_seconds":    window,
        "api_requests":      api_requests,
        "api_errors":        api_errors,
        "cpu_usage":         cpu_usage,
        "memory_usage":      memory_usage,
        "network_sent":      network_sent,
        "network_received":  network_received,
        "summary": {
            "max_cpu_pct":      max(cpu_values, default=None),
            "avg_cpu_pct":      round(sum(cpu_values) / len(cpu_values), 4) if cpu_values else None,
            "max_memory_pct":   max(mem_values, default=None),
            "total_api_errors": sum(err_values) if err_values else 0,
            "cpu_spike":        any(v > 80 for v in cpu_values),
            "memory_spike":     any(v > 85 for v in mem_values),
        },
    }

def fetch_iam_policy() -> dict:
    """Project IAM policy — read-only, no charge."""
    try:
        svc  = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        resp = svc.projects().getIamPolicy(resource=PROJECT_ID, body={}).execute()
        bindings = resp.get("bindings", [])
        high_priv = [b["role"] for b in bindings
                     if any(r in b.get("role","") for r in ["owner","editor","admin"])]
        return {
            "etag":               resp.get("etag"),
            "policy_version":     resp.get("version", 1),
            "total_bindings":     len(bindings),
            "high_privilege_roles": high_priv,
            "bindings": [
                {"role": b.get("role"), "member_count": len(b.get("members",[])),
                 "members": b.get("members",[])}
                for b in bindings
            ],
        }
    except Exception as exc:
        return {"error": str(exc)}

def fetch_enabled_services() -> dict:
    """Enabled APIs — read-only, no charge."""
    try:
        svc  = googleapiclient.discovery.build("serviceusage", "v1", cache_discovery=False)
        resp = svc.services().list(parent=f"projects/{PROJECT_ID}",
                                   filter="state:ENABLED", pageSize=200).execute()
        svcs = resp.get("services", [])
        return {
            "enabled_count": len(svcs),
            "services": [{"name":  s.get("config",{}).get("name"),
                          "title": s.get("config",{}).get("title"),
                          "state": s.get("state")} for s in svcs],
        }
    except Exception as exc:
        return {"error": str(exc)}

def fetch_quota_usage() -> dict:
    """Project quotas — read-only, no charge."""
    try:
        svc  = googleapiclient.discovery.build("compute", "v1", cache_discovery=False)
        proj = svc.projects().get(project=PROJECT_ID).execute()
        raw  = proj.get("quotas", [])
        return {
            "quota_count": len(raw),
            "near_limit": [q["metric"] for q in raw
                           if q.get("limit",0) > 0 and q.get("usage",0)/q["limit"] > 0.80],
            "quotas": [{"metric": q.get("metric"), "limit": q.get("limit"),
                        "usage": q.get("usage"),
                        "usage_pct": round(q["usage"]/q["limit"]*100, 2)
                                     if q.get("limit",0) > 0 else 0}
                       for q in raw],
        }
    except Exception as exc:
        return {"error": str(exc)}

def fetch_project_metadata() -> dict:
    """Project info — always free."""
    try:
        svc  = googleapiclient.discovery.build("cloudresourcemanager", "v1", cache_discovery=False)
        proj = svc.projects().get(projectId=PROJECT_ID).execute()
        return {
            "project_id":      proj.get("projectId"),
            "project_number":  proj.get("projectNumber"),
            "display_name":    proj.get("name"),
            "lifecycle_state": proj.get("lifecycleState"),
            "create_time":     proj.get("createTime"),
            "labels":          proj.get("labels", {}),
        }
    except Exception as exc:
        return {"error": str(exc)}

# ==============================
# Collect + save + push
# ==============================

def collect_once() -> dict:
    now        = datetime.now(tz=timezone.utc)
    audit_logs = fetch_audit_logs()
    monitoring = fetch_monitoring_metrics()
    iam_policy = fetch_iam_policy()
    services   = fetch_enabled_services()
    quotas     = fetch_quota_usage()
    project    = fetch_project_metadata()
    high_risk  = [e for e in audit_logs if e.get("risk_level") == "high"]
    mon_summary = monitoring.get("summary", {})

    return {
        "collected_at":      now.isoformat(),
        "project_id":        PROJECT_ID,
        "collector":         "gcp_collector_v4",
        "source_system":     "gcp_cloud_apis",

        # ── Account-level (always present) ──
        "project_metadata":  project,
        "iam_policy":        iam_policy,
        "enabled_services":  services,
        "quota_usage":       quotas,

        # ── Cloud Monitoring metrics ──
        "monitoring":        monitoring,   # full detail
        "cpu_usage":         monitoring.get("cpu_usage", []),
        "memory_usage":      monitoring.get("memory_usage", []),
        "network_sent":      monitoring.get("network_sent", []),
        "network_received":  monitoring.get("network_received", []),
        "api_request_count": monitoring.get("api_requests", []),
        "cpu_spike":         mon_summary.get("cpu_spike", False),
        "memory_spike":      mon_summary.get("memory_spike", False),
        "max_cpu_pct":       mon_summary.get("max_cpu_pct"),
        "max_memory_pct":    mon_summary.get("max_memory_pct"),

        # ── Audit logs (always present) ──
        "audit_events":      audit_logs,
        "total_events":      len(audit_logs),
        "high_risk_events":  len(high_risk),
        "unique_principals": list({e["principal_email"] for e in audit_logs
                                   if e.get("principal_email")}),

        # ── Aggregate risk flags ──
        "risk_flags": {
            "unauthorized_access":     any(not e.get("access_granted", True) for e in audit_logs),
            "key_creation_detected":   any(e.get("risk_flags", {}).get("key_created") for e in audit_logs),
            "snapshot_created":        any(e.get("risk_flags", {}).get("data_exfil_risk") for e in audit_logs),
            "firewall_modified":       any(e.get("risk_flags", {}).get("lateral_exposure") for e in audit_logs),
            "iam_policy_changed":      any(e.get("event_type") == "iam_policy_change" for e in audit_logs),
            "denied_actions_detected": any(e.get("risk_flags", {}).get("denied_action") for e in audit_logs),
            "quota_near_limit":        bool(quotas.get("near_limit")),
            "high_privilege_roles":    bool(iam_policy.get("high_privilege_roles")),
            "cpu_spike_detected":      mon_summary.get("cpu_spike", False),
            "memory_spike_detected":   mon_summary.get("memory_spike", False),
        },
    }

def push_to_api(data: dict) -> int | None:
    """POST to /cloud/events. Returns status code or None if unreachable."""
    try:
        resp = requests.post(
            f"{API_BASE}/cloud/events",
            json={"cloud_events": [data]},
            headers={"x-api-key": CLOUD_KEY},
            timeout=5,
        )
        return resp.status_code
    except Exception:
        return None   # silently fail — data is saved locally anyway

def save_locally(data: dict):
    """Always write to local JSONL so data is never lost even if API is down."""
    try:
        with open(OUTPUT_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as exc:
        print(f"[LOCAL SAVE ERROR] {exc}")

# ==============================
# Entry point
# ==============================

def run():
    print("=" * 62)
    print("  Guardient GCP Cloud Collector  v4")
    print("=" * 62)
    print(f"  Project  : {PROJECT_ID}")
    print(f"  API Base : {API_BASE}")
    print(f"  Interval : {INTERVAL}s")
    print(f"  Local    : {OUTPUT_FILE}")
    print("  Data     : 100% real GCP APIs — no simulation")
    print("  Cost     : Read-only — no billing charges")
    print("=" * 62)

    try:
        _, detected = google.auth.default()
        print(f"  ADC auth : {detected or '(default)'}")
    except Exception as exc:
        print(f"\n[FATAL] No credentials: {exc}")
        print("  Run: gcloud auth application-default login")
        return

    print("\n[GCP Collector] Running. Press Ctrl+C to stop.\n")

    while True:
        tick = time.time()
        try:
            data   = collect_once()
            status = push_to_api(data)
            save_locally(data)          # always saved locally regardless of API

            flags = [k for k, v in data["risk_flags"].items() if v]
            api_indicator = f"API→{status}" if status else "API→offline (saved locally)"
            print(
                f"[{data['collected_at']}] "
                f"Events: {data['total_events']} | "
                f"HighRisk: {data['high_risk_events']} | "
                f"Services: {data['enabled_services'].get('enabled_count','?')} | "
                f"CPU: {data['max_cpu_pct']}% | "
                f"Mem: {data['max_memory_pct']}% | "
                f"{api_indicator} | "
                f"Flags: {flags or 'none'}"
            )
        except KeyboardInterrupt:
            print("\n[GCP Collector] Stopped.")
            break
        except Exception as exc:
            print(f"[ERROR] {exc}")

        time.sleep(max(0, INTERVAL - (time.time() - tick)))

if __name__ == "__main__":
    run()
