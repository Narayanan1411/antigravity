# Guardient — Security Monitoring Platform

## Overview

Guardient is a **real-time security monitoring platform** with four components that collect telemetry across host, identity, and cloud layers.

| Component | What It Monitors | Output |
|---|---|---|
| `system-monitor.py` | CPU, memory, disk, Docker, network | REST API `:8091` |
| `system_monitor_kafka.py` | Same as above + Kafka streaming | REST API + Kafka topic |
| `identity_collector.py` | PAM auth logs + LDAP user directory | `identity_events.jsonl` |
| `gcp_collector.py` | GCP audit logs + VM inventory | `gcp_events.jsonl` |

---

## 🖥️ System Monitor (`system_monitor_kafka.py`)

### What It Does

Collects **host-level system metrics** every 3 seconds and streams them to Kafka + exposes a REST API.

### Data Fields

| Field | Example |
|---|---|
| `hostname` | `suresh` |
| `cpu_percent` | `23.5` |
| `memory_percent` | `67.2` |
| `disk_percent` | `45.0` |
| `network_bytes_sent` | `524288` |
| `network_bytes_recv` | `1048576` |
| `load_average` | `[1.2, 0.8, 0.5]` |
| `process_count` | `245` |
| `docker_containers` | Name, status, CPU, memory, ports, mounts |
| `active_connections` | Local/remote address, status, PID |

### API Endpoints

```
GET http://localhost:8091/           → Status check
GET http://localhost:8091/telemetry  → Full system telemetry
GET http://localhost:8091/health     → Health + Kafka connection status
```

### Kafka Topic

- Topic: `telemetry`
- Consumer group: `guardient-consumer`
- Bootstrap: `localhost:9092`

---

## 🔐 Identity Collector (`identity_collector.py`)

### What It Does

Monitors **who is doing what** by combining three sources:

```
/var/log/auth.log ──→ ┐
                      ├──→ Identity Collector ──→ identity_events.jsonl
psutil sessions ────→ ┤    (polls every 3s)
                      │
OpenLDAP server ────→ ┘
```

**1. Parses Linux PAM auth log** — catches every SSH login, failed password, sudo command, and session change.

**2. Tracks live sessions** — who is currently logged in, from where, on which terminal.

**3. Polls LDAP directory** — live inventory of all known users and service accounts.

### What It Detects

| Detection | How | Status |
|---|---|---|
| **Brute force attacks** | ≥5 cumulative failed logins per user | ✅ Tested & working |
| **Privilege escalation** | sudo commands with target user + command | ✅ Tested & working |
| **Service account abuse** | Service account gets interactive login | ✅ Monitoring |
| **Root login** | Root SSH login attempts | ✅ Monitoring |
| **Account changes** | useradd, groupmod, usermod commands | ✅ Monitoring |

### Data Fields

**Per Logged-In User:**

| Field | What It Tells You | Example |
|---|---|---|
| `user_id` | Who is logged in | `aswin` |
| `login_timestamp` | When they logged in | `2026-02-28T07:15:40Z` |
| `login_source_ip` | Where from | `localhost` / `192.168.1.5` |
| `terminal` | Which session | `pts/5` / `tty2` |
| `authentication_type` | How they authenticated | `ssh` / `local_tty` |
| `mfa_status` | MFA state | `not_configured` |
| `service_account_activity` | Service account? | `true` / `false` |

**Per Auth Event:**

| Field | What It Tells You | Example |
|---|---|---|
| `event_type` | What happened | `login_success` / `login_failure` / `privilege_escalation` / `session_open` / `account_change` |
| `user_id` | Who did it | `aswin` / `root` |
| `source_ip` | From where | `192.168.1.5` |
| `authentication_type` | Auth method | `ssh` / `pam` / `sudo` |
| `failure_count` | Cumulative failures | `12` |
| `privilege_change_event` | Escalation details | `{"escalated_to": "root", "command": "..."}` |
| `group_membership_change` | Group change details | raw log line |
| `service_account_activity` | Service account flag | `true` / `false` |

**Per LDAP User:**

| Field | What It Tells You | Example |
|---|---|---|
| `user_id` | Username | `aswin` |
| `cn` | Full name | `Aswin` |
| `mail` | Email | `aswin@guardient.local` |
| `uid_number` | Unix UID | `2001` |
| `login_shell` | Shell type | `/bin/bash` / `/bin/false` |
| `service_account` | Service account? | `true` (if shell is `/bin/false`) |

**Risk Flags (per cycle):**

| Flag | Trigger |
|---|---|
| `brute_force_detected` | Any user has ≥5 cumulative failures |
| `root_login_detected` | Root logs in via SSH |
| `service_account_interactive_login` | Service account gets interactive shell |
| `privilege_escalation_detected` | Any sudo command this cycle |

---

## ☁️ GCP Cloud Collector (`gcp_collector.py`)

### What It Does

Monitors **cloud infrastructure activity** from Google Cloud Platform:

```
GCP Cloud Audit Logs ──→ ┐
(cloudaudit.googleapis    ├──→ GCP Collector ──→ gcp_events.jsonl
 .com/activity)           │    (polls every 3s)
                          │
gcloud VM inventory ────→ ┘
```

**1. Pulls GCP audit logs** — every API call (VM creation, IAM changes, firewall mods) with who did it, from which IP, and whether it was allowed.

**2. Tracks VM inventory** — real-time status of all VMs.

### What It Detects

| Detection | How | Status |
|---|---|---|
| **IAM policy changes** | `SetIamPolicy` audit events | ✅ Detected |
| **Denied access attempts** | Non-zero status codes | ✅ Detected |
| **Firewall modifications** | Firewall insert/patch/delete | ✅ Monitoring |
| **Snapshot creation** | `compute.snapshots.insert` (data theft) | ✅ Monitoring |
| **Key creation** | `CreateCryptoKey` / SA key creation | ✅ Monitoring |
| **Service account creation** | New service account events | ✅ Monitoring |
| **VM lifecycle** | Instance start/stop/delete | ✅ Monitoring |
| **OAuth token tracking** | Principal's token per action | ✅ Working |

### Data Fields

**Per Audit Event:**

| Field | What It Tells You | Example |
|---|---|---|
| `timestamp` | When it happened | `2026-02-28T19:14:19Z` |
| `api_action` | API called | `google.iam.admin.v1.CreateServiceAccountKey` |
| `event_type` | Classified action | `instance_start` / `iam_policy_change` / `security_group_change` |
| `principal_email` | Who did it | `aswinsuresh.gt@gmail.com` |
| `api_source_ip` | From which IP | `2401:4900:1c29:716d:...` |
| `user_agent` | Tool/browser | `Firefox/148.0` |
| `token_issuance_event` | OAuth token tracked | `OAuth token used by ...` |
| `service_name` | GCP service | `iam.googleapis.com` / `compute.googleapis.com` |
| `instance_id` | VM ID | `5447168761000788989` |
| `project_id` | GCP project | `project-a97c1c37-...` |
| `zone` | Location | `us-central1-a` |
| `permissions_checked` | Permissions tested | `['iam.serviceAccountKeys.create']` |
| `access_granted` | Was it allowed? | `true` / `false` |
| `status_code` | Result | `0` (success) / `9` (denied) |
| `status_message` | Error detail | `"Key creation is not allowed..."` |
| `risk_level` | Computed risk | `low` / `medium` / `high` |

**Per VM Instance:**

| Field | What It Tells You | Example |
|---|---|---|
| `instance_id` | VM ID | `5447168761000788989` |
| `name` | VM name | `guardient-vm-1` |
| `status` | Current state | `RUNNING` / `STOPPED` |
| `machine_type` | VM size | `e2-micro` |
| `zone` | Location | `us-central1-a` |
| `internal_ip` | Private IP | `10.128.0.2` |
| `external_ip` | Public IP | `34.134.89.213` |

**Risk Flags (per cycle):**

| Flag | Trigger |
|---|---|
| `unauthorized_access_attempt` | Any API call denied |
| `key_creation_detected` | Crypto/SA key created |
| `snapshot_created` | VM snapshot taken |
| `firewall_modified` | Firewall rule changed |
| `iam_policy_changed` | IAM policy modified |
| `denied_actions_detected` | Any non-zero status code |

---

## Real Results

| Metric | System Monitor | Identity | GCP Cloud |
|---|---|---|---|
| **Data source** | psutil + Docker | PAM + LDAP | Cloud Audit API |
| **Events captured** | Continuous metrics | 244+ auth events | 46 audit events |
| **Users/principals** | — | 3 LDAP users | 2 GCP principals |
| **VMs** | — | — | 1 (guardient-vm-1) |
| **Detections fired** | — | Brute force ✅ | IAM change + denied ✅ |
| **Total fields** | 15+ | 30+ | 30+ |

---

## 🚀 How to Run the Whole Project

The Guardient platform consists of a backend API, Kafka streaming, microservice pipelines, a Next.js SOC frontend, and telemetry collector agents.

### 1. Prerequisite Setup

```bash
# Navigate to the project root directory
cd "/Users/kselvanarayanan/Desktop/poc Guardient"

# Setup Python Virtual Environment
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt

# Export SMTP credentials for real-time Response Engine alerts (optional)
export SMTP_USER="your_email@gmail.com"
export SMTP_PASS="your_app_password"
```

### 2. Start Infrastructure & Initialize

```bash
# Start Kafka and PostgreSQL containers in the background
docker-compose up -d

# Initialize Kafka Topics & Database Schema
python3 -m pipeline.topics
python3 -m db.db
```

### 3. Start Core Backend & Pipeline

You need to run the ingestion API and launch the stream-processing pipelines.

```bash
# Window 1: Start the Main FastAPI server (Runs on port 8000)
python3 -m uvicorn api.main:app --port 8000 --reload

# Window 2: Launch all 7 pipeline services in the background
# (This keeps them running persistently and logs to logs/pipeline/)
bash run_background.sh

# Window 3: Start the Network sniffer (requires sudo for packet capture)
sudo python3 network/network_data.py
```

### 4. Start the SOC Dashboard (Frontend)

```bash
# Window 3: Start the Next.js Dashboard (Runs on port 3000)
cd "techgium frontend"
npm install    # If not already installed
npm run dev
```

### 5. Run Telemetry Collectors (Agents)

These agents collect **real** telemetry from your macOS system — no simulation. Run them from the project root (`poc Guardient/`):

```bash
# 🖥️ Hardware metrics (MAC address, VM UUID, ARP table, CPU burst)
# Sends real hardware fingerprint to /hardware/profile → enriches device DGID
python3 "colud and identity/hardware_collector.py"

# 🔐 Identity Collector (real macOS auth events, SSH logins, sudo events)
# Reads /var/log/system.log and macOS unified log — no OpenLDAP required
python3 "colud and identity/identity/identity_collector.py"

# ☁️ GCP Cloud Collector (requires active gcloud auth login)
# Read-only: pulls Cloud Audit Logs, IAM, firewall rules etc.
# Run: gcloud auth application-default login  (once, before starting)
python3 "colud and identity/cloud/gcp_collector.py"
```

> **Note:** The `hardware_collector.py` is the most useful to run first — it sends your Mac's hostname, MAC addresses, and machine ID to the Device Resolver, ensuring all network interfaces are correctly clustered into a single DGID.

---

## File Inventory

```
~/Guardient/
├── requirements.txt            # All Python dependencies
├── README.md                   # This document
├── KAFKA_SETUP.md              # Kafka configuration notes
│
├── system-monitor.py           # Standalone system monitor (REST API)
├── system_monitor_kafka.py     # System monitor + Kafka integration
├── kafka_producer.py           # Kafka producer (testing)
├── kafka_consumer.py           # Kafka consumer (testing)
│
├── identity_collector.py       # Identity collector (PAM + LDAP)
├── structure.ldif              # LDAP OU structure
├── users.ldif                  # LDAP user entries
│
├── gcp_collector.py            # GCP cloud collector
│
├── identity_events.jsonl       # Identity output (generated)
├── gcp_events.jsonl            # GCP output (generated)
│
└── myenv/                      # Python virtual environment
```
