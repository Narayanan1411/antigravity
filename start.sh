#!/usr/bin/env bash
# ============================================================
# Guardient — Single-command startup
#
# Starts and validates the entire stack in order:
#   1. Docker daemon
#   2. Kafka + PostgreSQL containers
#   3. DB schema init + Kafka topic bootstrap
#   4. All 11 pipeline microservices
#   5. FastAPI backend  (port 8000)
#   6. Next.js frontend (port 3000)
#   7. Post-start health validation
#
# Usage:  bash start.sh [--restart]
#   --restart   kill any already-running Guardient processes first
#
# Logs:  logs/pipeline/<service>.log
# PIDs:  pids/<service>.pid
# ============================================================

set -uo pipefail        # -e intentionally omitted: one bad service must not abort the rest

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON=".venv/bin/python3"
LOG_DIR="logs/pipeline"
PID_DIR="pids"
KAFKA_CONTAINER="guardient-kafka"
POSTGRES_CONTAINER="guardient-db"
KAFKA_BIN="/opt/kafka/bin/kafka-topics.sh"

# ── Active network interface detection ────────────────────
# Reads the kernel routing table to find the interface that carries the
# default route — works for Wi-Fi, USB tethering, Ethernet, VPN, etc.
detect_active_iface() {
    ip route show default 2>/dev/null | awk '/^default/{print $5; exit}'
}
ACTIVE_IFACE=$(detect_active_iface)
if [[ -n "$ACTIVE_IFACE" ]]; then
    export NETWORK_INTERFACE="$ACTIVE_IFACE"
fi

# ── Colour helpers ─────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
step()  { echo -e "\n${CYAN}${BOLD}[$((++STEP_N))/${TOTAL_STEPS}] $*${RESET}"; }
ok()    { echo -e "    ${GREEN}✔${RESET}  $*"; }
warn()  { echo -e "    ${YELLOW}⚠${RESET}  $*"; }
fail()  { echo -e "    ${RED}✘${RESET}  $*"; }
info()  { echo -e "    ${DIM}→${RESET}  $*"; }
STEP_N=0; TOTAL_STEPS=7

# ── Prerequisite guard ─────────────────────────────────────
need() {
    command -v "$1" &>/dev/null || { fail "Required tool not found: $1"; exit 1; }
}
need docker; need curl; need nc; need "$PYTHON"

# ── Restart flag ───────────────────────────────────────────
FORCE_RESTART=false
[[ "${1:-}" == "--restart" ]] && FORCE_RESTART=true

# ── Launch a background service ────────────────────────────
#   launch <name> <command …>
#   Writes PID to pids/<name>.pid, stdout+stderr to logs/pipeline/<name>.log
launch() {
    local name="$1"; shift
    local logfile="$LOG_DIR/${name}.log"
    local pidfile="$PID_DIR/${name}.pid"

    # Skip if already running and --restart not requested
    if [[ -f "$pidfile" ]]; then
        local old_pid; old_pid=$(cat "$pidfile" 2>/dev/null)
        if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
            if ! $FORCE_RESTART; then
                ok "$name already running (PID $old_pid) — skipping"
                return 0
            fi
            kill "$old_pid" 2>/dev/null; sleep 0.5
        fi
    fi

    nohup "$@" > "$logfile" 2>&1 &
    local pid=$!
    echo "$pid" > "$pidfile"
    info "$name → PID $pid  (log: $logfile)"
}

# ── Wait for a TCP port to accept connections ──────────────
wait_port() {
    local host="$1" port="$2" label="$3" timeout="${4:-30}"
    local elapsed=0
    while ! nc -z "$host" "$port" 2>/dev/null; do
        (( elapsed++ ))
        [[ $elapsed -ge $timeout ]] && { fail "$label did not open port $port after ${timeout}s"; return 1; }
        sleep 1
    done
    ok "$label is accepting connections on :$port"
}

# ── Wait for an HTTP endpoint to return 2xx ───────────────
wait_http() {
    local url="$1" label="$2" timeout="${3:-60}"
    local elapsed=0
    while true; do
        local code; code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || true)
        [[ "$code" =~ ^2 ]] && { ok "$label responded HTTP $code"; return 0; }
        (( elapsed++ ))
        [[ $elapsed -ge $timeout ]] && { fail "$label not ready after ${timeout}s (last HTTP $code)"; return 1; }
        sleep 1
    done
}

# ── Banner ─────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║          GUARDIENT  —  FULL STACK STARTUP            ║"
echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

mkdir -p "$LOG_DIR" "$PID_DIR"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Docker daemon
# ─────────────────────────────────────────────────────────────────────────────
step "Docker daemon"

if ! docker info &>/dev/null; then
    warn "Docker is not running — attempting to start..."
    # Try systemd first, then snap, then Docker Desktop socket
    if command -v systemctl &>/dev/null && systemctl --user start docker 2>/dev/null; then
        sleep 3
    elif command -v snap &>/dev/null && snap start docker 2>/dev/null; then
        sleep 5
    else
        fail "Cannot start Docker automatically. Please start Docker and re-run this script."
        exit 1
    fi
    docker info &>/dev/null || { fail "Docker still not running after start attempt."; exit 1; }
fi
ok "Docker daemon is running"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Kafka + PostgreSQL containers
# ─────────────────────────────────────────────────────────────────────────────
step "Infrastructure containers (Kafka + PostgreSQL)"

info "Active network interface: ${ACTIVE_IFACE:-unknown}"

# Classify each container: running / stopped (exists but not up) / missing
container_state() {
    local name="$1"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${name}$"; then
        echo "running"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${name}$"; then
        echo "stopped"
    else
        echo "missing"
    fi
}

# Quick host-side port probe — both ports must respond within 2 s.
# Fails when Docker Desktop's port-forwarding breaks after a network-interface
# change (containers stay "Up" in docker ps but are unreachable from the host).
ports_accessible() {
    nc -z -w 2 localhost 9092 2>/dev/null && nc -z -w 2 localhost 5432 2>/dev/null
}

# Tear down and recreate containers + network from scratch.
# Used whenever the Docker bridge may be stale (interface switch, stopped state).
compose_recreate() {
    local reason="$1"
    warn "$reason — recreating containers for a clean network state..."
    docker compose down --remove-orphans 2>&1 | sed 's/^/    /' || true
    sleep 1
    docker compose up -d 2>&1 | sed 's/^/    /' \
        || { fail "docker compose up -d failed — see output above"; exit 1; }
    ok "Containers recreated"
}

KAFKA_STATE=$(container_state "$KAFKA_CONTAINER")
PG_STATE=$(container_state "$POSTGRES_CONTAINER")
info "Container states — kafka: $KAFKA_STATE  postgres: $PG_STATE"

if [[ "$KAFKA_STATE" == "running" && "$PG_STATE" == "running" ]]; then
    if ports_accessible; then
        ok "Both containers running and accessible"
    else
        # Containers are up but ports are unreachable.
        # This happens when Docker Desktop's port-forwarding breaks after
        # switching network interfaces (Wi-Fi → USB tethering, etc.).
        compose_recreate "Containers running but ports unreachable (network interface changed?)"
    fi

elif [[ "$KAFKA_STATE" == "stopped" || "$PG_STATE" == "stopped" ]]; then
    # 'docker compose start' reattaches to the existing (potentially stale)
    # bridge network.  After an interface switch, down+up is the only way to
    # get a clean bridge and working port-forwarding.
    compose_recreate "Containers stopped"

else
    # Containers missing entirely — check for foreign port squatters first.
    port_free() {
        local port="$1" label="$2"
        if nc -z localhost "$port" 2>/dev/null; then
            fail "Port $port ($label) is already bound by another process."
            fail "Stop it first, then re-run start.sh  (e.g. sudo ss -tlnp | grep $port)"
            return 1
        fi
        return 0
    }
    port_free 5432 "PostgreSQL" || exit 1
    port_free 9092 "Kafka"      || exit 1

    info "Creating and starting containers..."
    docker compose up -d 2>&1 | sed 's/^/    /' \
        || { fail "docker compose up -d failed — see output above"; exit 1; }
    ok "Containers created and started"
fi

# Verify both containers actually reached 'running' state.
for container in "$KAFKA_CONTAINER" "$POSTGRES_CONTAINER"; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        fail "Container did not reach running state: $container"
        fail "Inspect with: docker logs $container"
        exit 1
    fi
done

# Wait for Kafka to be truly ready (can list topics, not just open port).
info "Waiting for Kafka to be ready..."
elapsed=0
until docker exec "$KAFKA_CONTAINER" \
        "$KAFKA_BIN" --bootstrap-server localhost:9092 --list &>/dev/null; do
    (( elapsed++ ))
    if [[ $elapsed -ge 60 ]]; then
        fail "Kafka not ready after 60s"
        fail "Last 20 lines of Kafka logs:"
        docker logs --tail 20 "$KAFKA_CONTAINER" 2>&1 | sed 's/^/    /'
        exit 1
    fi
    sleep 1
done
ok "Kafka is ready (:9092)"

# Wait for Postgres to accept connections.
info "Waiting for PostgreSQL to be ready..."
elapsed=0
until docker exec "$POSTGRES_CONTAINER" pg_isready -U guardient -q 2>/dev/null; do
    (( elapsed++ ))
    if [[ $elapsed -ge 30 ]]; then
        fail "PostgreSQL not ready after 30s"
        fail "Last 20 lines of Postgres logs:"
        docker logs --tail 20 "$POSTGRES_CONTAINER" 2>&1 | sed 's/^/    /'
        exit 1
    fi
    sleep 1
done
ok "PostgreSQL is ready (:5432)"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — DB schema + Kafka topics (idempotent)
# ─────────────────────────────────────────────────────────────────────────────
step "Schema & topic bootstrap"

info "Initialising PostgreSQL schema..."
if $PYTHON -c "from db.db import init_schema; init_schema()" >> "$LOG_DIR/bootstrap.log" 2>&1; then
    ok "DB schema ready"
else
    fail "DB schema init failed — see $LOG_DIR/bootstrap.log"; exit 1
fi

info "Creating Kafka topics..."
if $PYTHON -m pipeline.topics >> "$LOG_DIR/bootstrap.log" 2>&1; then
    ok "Kafka topics ready"
else
    fail "Kafka topic creation failed — see $LOG_DIR/bootstrap.log"; exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Pipeline microservices (in data-flow order)
# ─────────────────────────────────────────────────────────────────────────────
step "Pipeline microservices"

if $FORCE_RESTART; then
    info "Stopping existing services (--restart)..."
    pkill -f "\.venv/bin/python3.*services/" 2>/dev/null || true
    sleep 1
fi

# Data-flow order: each service consumes the topic produced by the previous one
launch enrichment_service   "$PYTHON" -u services/enrichment_service.py
launch feature_engine       "$PYTHON" -u services/feature_engine.py
launch ml_monitor           "$PYTHON" -u services/ml_monitor.py
launch risk_engine          "$PYTHON" -u services/risk_engine.py
launch graph_correlator     "$PYTHON" -u services/graph_correlator.py
launch trust_engine         "$PYTHON" -u services/trust_engine.py
launch decision_engine      "$PYTHON" -u services/decision_engine.py
launch response_engine      "$PYTHON" -u services/response_engine.py
launch simulation_controller "$PYTHON" -u services/simulation_controller.py
launch network_discovery    "$PYTHON" -u services/network_discovery_service.py
launch hardware_monitoring  "$PYTHON" -u services/hardware_monitoring_service.py

ok "11 microservices launched"

# Allow Kafka consumer groups to register before the API starts
sleep 2

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — FastAPI backend (port 8000)
# ─────────────────────────────────────────────────────────────────────────────
step "FastAPI backend (port 8000)"

# Use -sTCP:LISTEN so we only match the process actually bound to the port,
# not client processes that merely have open connections to it.
server_pid=$(lsof -ti:8000 -sTCP:LISTEN 2>/dev/null | head -1 || true)
if [[ -n "$server_pid" ]]; then
    saved_pid=$(cat "$PID_DIR/api.pid" 2>/dev/null || true)
    if [[ "$saved_pid" == "$server_pid" ]] && ! $FORCE_RESTART; then
        ok "API already running (PID $server_pid) — skipping"
        server_pid=""
    fi
    if [[ -n "$server_pid" ]]; then
        info "Stopping existing API server (PID $server_pid)"
        kill "$server_pid" 2>/dev/null; sleep 1
    fi
fi

launch api "$PYTHON" -m uvicorn api.main:app \
    --host 0.0.0.0 --port 8000 \
    --reload --log-level warning

wait_http "http://localhost:8000/api/v1/entities/" "FastAPI API" 30

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Next.js frontend (port 3000)
# ─────────────────────────────────────────────────────────────────────────────
step "Next.js frontend (port 3000)"

FRONTEND_DIR="techgium frontend"

# Use -sTCP:LISTEN to only match the process bound to the port (not clients).
# Kill only the saved PID (the npm process we launched), never by process group —
# a PGID kill would take out all nohup'd pipeline services sharing the same group.
server_pid=$(lsof -ti:3000 -sTCP:LISTEN 2>/dev/null | head -1 || true)
if [[ -n "$server_pid" ]]; then
    saved_pid=$(cat "$PID_DIR/frontend.pid" 2>/dev/null || true)
    if [[ -n "$saved_pid" ]] && ! $FORCE_RESTART; then
        if kill -0 "$saved_pid" 2>/dev/null; then
            ok "Frontend already running (PID $saved_pid) — skipping"
            server_pid=""
        fi
    fi
    if [[ -n "$server_pid" ]]; then
        info "Stopping existing frontend (PID $saved_pid → listener $server_pid)"
        # Kill only the saved npm pid; do NOT use kill -PGID (would kill all services)
        [[ -n "$saved_pid" ]] && kill "$saved_pid" 2>/dev/null || true
        kill "$server_pid" 2>/dev/null || true
        sleep 1
    fi
fi

# Install deps if node_modules is missing or package.json changed
if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    info "node_modules missing — running npm install..."
    npm --prefix "$FRONTEND_DIR" install --silent >> "$LOG_DIR/frontend.log" 2>&1 || \
        { fail "npm install failed — see $LOG_DIR/frontend.log"; exit 1; }
    ok "npm install complete"
fi

(
    cd "$FRONTEND_DIR"
    nohup npm run dev >> "../$LOG_DIR/frontend.log" 2>&1 &
    echo $! > "../$PID_DIR/frontend.pid"
    info "frontend → PID $!  (log: $LOG_DIR/frontend.log)"
)

wait_http "http://localhost:3000" "Next.js frontend" 60

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Health validation
# ─────────────────────────────────────────────────────────────────────────────
step "Health validation"

FAILURES=0

# API entities endpoint
code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/api/v1/entities/ 2>/dev/null || true)
[[ "$code" =~ ^2 ]] && ok "GET /api/v1/entities/  →  HTTP $code" || { fail "GET /api/v1/entities/ → HTTP $code"; (( FAILURES++ )) || true; }

# Kafka consumer group count (must have at least 8 active groups)
cg_count=$(docker exec "$KAFKA_CONTAINER" \
    /opt/kafka/bin/kafka-consumer-groups.sh \
    --bootstrap-server localhost:9092 --list 2>/dev/null | wc -l || echo 0)
if [[ $cg_count -ge 8 ]]; then
    ok "Kafka consumer groups active: $cg_count"
else
    warn "Kafka consumer groups: $cg_count (expected ≥8 — services may still be connecting)"
fi

# Postgres table count
tbl_count=$(docker exec "$POSTGRES_CONTAINER" \
    psql -U guardient -d guardient -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';" 2>/dev/null || echo 0)
[[ "$tbl_count" -ge 17 ]] && \
    ok "PostgreSQL tables: $tbl_count" || \
    { fail "PostgreSQL tables: $tbl_count (expected ≥17)"; (( FAILURES++ )) || true; }

# Pipeline PIDs alive
dead_services=()
for pidfile in "$PID_DIR"/*.pid; do
    [[ -f "$pidfile" ]] || continue
    svc=$(basename "$pidfile" .pid)
    pid=$(cat "$pidfile" 2>/dev/null)
    kill -0 "$pid" 2>/dev/null || dead_services+=("$svc")
done
if [[ ${#dead_services[@]} -eq 0 ]]; then
    ok "All service PIDs alive"
else
    for svc in "${dead_services[@]}"; do
        fail "Service crashed immediately: $svc — check $LOG_DIR/${svc}.log"
        (( FAILURES++ )) || true
    done
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗"
    echo -e "║            GUARDIENT IS READY  ✔                    ║"
    echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
else
    echo -e "${YELLOW}${BOLD}╔══════════════════════════════════════════════════════╗"
    echo -e "║     GUARDIENT STARTED WITH ${FAILURES} FAILURE(S)  ⚠         ║"
    echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
fi

echo ""
printf "  %-28s %s\n" "SOC Dashboard"    "http://localhost:3000"
printf "  %-28s %s\n" "REST API"         "http://localhost:8000/api/v1/"
printf "  %-28s %s\n" "Simulation ctrl"  "http://localhost:8001"
printf "  %-28s %s\n" "API docs"         "http://localhost:8000/docs"
echo ""
printf "  %-28s %s\n" "Pipeline logs"    "logs/pipeline/<service>.log"
printf "  %-28s %s\n" "PID files"        "pids/<service>.pid"
echo ""
echo "  To stop all services:  pkill -f '\.venv/bin/python3.*services/' && pkill -f 'uvicorn api\.main'"
echo "  To hard reset state:   bash hard_reset.sh"
echo ""
