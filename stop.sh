#!/usr/bin/env bash
# ============================================================
# Guardient — Full stack shutdown
#
# Stops everything that start.sh launched, in reverse order:
#   1. Next.js frontend       (port 3000)
#   2. FastAPI backend        (port 8000)
#   3. Simulation controller  (port 8001)
#   4. All 11 pipeline microservices
#   5. Kafka + PostgreSQL Docker containers  (optional, see --keep-docker)
#
# Usage:
#   bash stop.sh               # stop all services + pause Docker containers
#   bash stop.sh --keep-docker # stop services but leave Docker running
#
# PID files in pids/ are removed on successful stop.
# ============================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PID_DIR="pids"
KAFKA_CONTAINER="guardient-kafka"
POSTGRES_CONTAINER="guardient-db"

KEEP_DOCKER=false
[[ "${1:-}" == "--keep-docker" ]] && KEEP_DOCKER=true

# ── Colour helpers ─────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
ok()   { echo -e "    ${GREEN}✔${RESET}  $*"; }
warn() { echo -e "    ${YELLOW}⚠${RESET}  $*"; }
fail() { echo -e "    ${RED}✘${RESET}  $*"; }
info() { echo -e "    ${DIM}→${RESET}  $*"; }

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║          GUARDIENT  —  FULL STACK SHUTDOWN           ║"
echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
echo ""

# ── Helper: stop a process by PID file ────────────────────
stop_pid() {
    local name="$1"
    local pidfile="$PID_DIR/${name}.pid"

    if [[ ! -f "$pidfile" ]]; then
        warn "$name — no PID file found (already stopped?)"
        return 0
    fi

    local pid; pid=$(cat "$pidfile" 2>/dev/null)
    if [[ -z "$pid" ]]; then
        warn "$name — PID file is empty"
        rm -f "$pidfile"
        return 0
    fi

    if kill -0 "$pid" 2>/dev/null; then
        # Send SIGTERM first; give the process up to 5 s to exit cleanly
        kill -TERM "$pid" 2>/dev/null
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [[ $waited -lt 5 ]]; do
            sleep 0.5; (( waited++ )) || true
        done
        # Force-kill if still alive after SIGTERM window
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL "$pid" 2>/dev/null
            sleep 0.3
        fi
        ok "$name stopped (PID $pid)"
    else
        warn "$name (PID $pid) was not running"
    fi

    rm -f "$pidfile"
}

# ── Helper: kill anything still listening on a port ───────
kill_port() {
    local port="$1"
    local pids; pids=$(lsof -ti:"$port" -sTCP:LISTEN 2>/dev/null || true)
    if [[ -n "$pids" ]]; then
        echo "$pids" | xargs -r kill -TERM 2>/dev/null || true
        sleep 1
        echo "$pids" | xargs -r kill -KILL 2>/dev/null || true
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Next.js frontend
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}[1/4] Next.js frontend${RESET}"
stop_pid "frontend"
# Also kill any orphaned next-server process listening on :3000 or :3001
kill_port 3000
kill_port 3001

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — FastAPI backend + simulation controller
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}[2/4] FastAPI backend + simulation controller${RESET}"
stop_pid "api"
stop_pid "simulation_controller"
kill_port 8000
kill_port 8001

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Pipeline microservices (reverse data-flow order)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}[3/4] Pipeline microservices${RESET}"

for svc in \
    hardware_monitoring \
    network_discovery \
    response_engine \
    decision_engine \
    trust_engine \
    graph_correlator \
    risk_engine \
    ml_monitor \
    feature_engine \
    enrichment_service
do
    stop_pid "$svc"
done

# Belt-and-suspenders: catch any venv python service that slipped through
remaining=$(pgrep -f "\.venv/bin/python3.*services/" 2>/dev/null || true)
if [[ -n "$remaining" ]]; then
    warn "Sending SIGTERM to remaining venv service processes..."
    echo "$remaining" | xargs -r kill -TERM 2>/dev/null || true
    sleep 1
    # Force-kill any survivors
    remaining=$(pgrep -f "\.venv/bin/python3.*services/" 2>/dev/null || true)
    [[ -n "$remaining" ]] && echo "$remaining" | xargs -r kill -KILL 2>/dev/null || true
fi
ok "All pipeline services stopped"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Docker containers (Kafka + PostgreSQL)
# ─────────────────────────────────────────────────────────────────────────────
echo -e "\n${CYAN}${BOLD}[4/4] Infrastructure containers (Kafka + PostgreSQL)${RESET}"

if $KEEP_DOCKER; then
    info "Skipping Docker shutdown (--keep-docker)"
else
    if docker info &>/dev/null 2>&1; then
        docker compose stop 2>&1 | sed 's/^/    /' || true
        ok "Docker containers stopped (data preserved — use 'docker compose up -d' to restart)"
    else
        warn "Docker daemon not reachable — skipping container shutdown"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Clean up any leftover empty PID files
# ─────────────────────────────────────────────────────────────────────────────
find "$PID_DIR" -name "*.pid" -empty -delete 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║            GUARDIENT STOPPED  ✔                     ║"
echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "  To start again:      bash start.sh"
echo "  To wipe all state:   bash hard_reset.sh"
echo ""
