#!/usr/bin/env bash
# ============================================================
# Guardient — Hard Reset
# Wipes ALL persisted state and restores a clean first-install
# state without touching code, dependencies, or infrastructure.
#
# What this touches:
#   • All PostgreSQL tables (TRUNCATE + RESTART IDENTITY CASCADE)
#   • All Kafka topics (delete + recreate)
#   • SQLite fallback DB (response_executor/response_engine.db)
#   • Trained ML model files (models/*.pt, models/*.pkl)
#   • All log files and JSONL telemetry records
#   • All PID files
#   • Python __pycache__ trees
#   • Next.js build cache (.next/)
#
# What this does NOT touch:
#   • Docker containers (Kafka + Postgres stay running)
#   • .venv, node_modules, source code, config files
#   • Docker volumes (Postgres data persists in Docker —
#     tables are truncated via SQL, not volume-deleted)
#
# Usage:
#   bash hard_reset.sh [--yes]   # --yes skips the confirmation prompt
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON=".venv/bin/python3"
PSQL_CMD="docker exec -i guardient-db psql -U guardient -d guardient"

# ── Colour helpers ────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

step()  { echo -e "\n${CYAN}${BOLD}▶ $*${RESET}"; }
ok()    { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn()  { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
die()   { echo -e "\n${RED}✘ $*${RESET}" >&2; exit 1; }

# ── Confirmation gate ────────────────────────────────────
if [[ "${1:-}" != "--yes" ]]; then
    echo ""
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════╗"
    echo -e "║          GUARDIENT HARD RESET — DESTRUCTIVE          ║"
    echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo "This will permanently delete:"
    echo "  • All device records, trust scores, and behavioral history"
    echo "  • All audit logs, alerts, and response records"
    echo "  • All ML baselines, model weights, and learning history"
    echo "  • All Kafka topic contents (messages purged)"
    echo "  • All log files and JSONL telemetry records"
    echo ""
    echo -e "${YELLOW}Kafka and PostgreSQL containers will remain running.${RESET}"
    echo -e "${YELLOW}Source code, dependencies, and config are untouched.${RESET}"
    echo ""
    read -rp "Type RESET to confirm: " confirm
    [[ "$confirm" == "RESET" ]] || { echo "Aborted."; exit 0; }
fi

echo ""
echo -e "${BOLD}Starting hard reset...${RESET}"

# ── Step 1: Stop all pipeline services ───────────────────
step "Stopping all Guardient pipeline services"

stop_pid_file() {
    local pidfile="$1"
    if [[ -f "$pidfile" ]]; then
        local pid; pid=$(cat "$pidfile" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null && ok "Stopped PID $pid ($pidfile)" || true
        fi
        rm -f "$pidfile"
    fi
}

# Kill by pattern first (catches services started outside of pid files)
pkill -f "\.venv/bin/python3.*services/"      2>/dev/null || true
pkill -f "python3.*services/.*\.py"           2>/dev/null || true
pkill -f "uvicorn api\.main"                  2>/dev/null || true
pkill -f "next.*dev"                          2>/dev/null || true
pkill -f "node.*next"                         2>/dev/null || true

sleep 1  # allow graceful shutdown

# Clean up any pid files
stop_pid_file "api.pid"
stop_pid_file "frontend.pid"
stop_pid_file "network_discovery_service.pid"
for f in pids/*.pid; do stop_pid_file "$f"; done

ok "All services stopped"

# ── Step 2: Truncate all PostgreSQL tables ────────────────
step "Truncating all PostgreSQL tables"

# Check Postgres is reachable
if ! docker exec guardient-db pg_isready -U guardient -q 2>/dev/null; then
    die "PostgreSQL container (guardient-db) is not reachable. Start it with: docker compose up -d"
fi

$PSQL_CMD <<'EOSQL'
-- Disable FK checks during truncation
SET session_replication_role = replica;

TRUNCATE TABLE
    device_aliases,
    events,
    features,
    ml_scores,
    device_baselines,
    risk_scores,
    graph_correlation_events,
    trust_scores,
    trust_states,
    alerts,
    feedback_labels,
    feedback_weights,
    simulation_runs,
    response_actions,
    response_executions,
    device_blocks,
    devices
RESTART IDENTITY CASCADE;

-- Re-enable FK checks
SET session_replication_role = DEFAULT;
EOSQL

ok "All tables truncated (RESTART IDENTITY CASCADE)"

# ── Step 3: Purge and recreate Kafka topics ───────────────
step "Purging and recreating Kafka topics"

if ! nc -z localhost 9092 2>/dev/null; then
    warn "Kafka not reachable on :9092 — skipping topic purge (start docker compose first)"
else
    TOPICS=(
        raw_events
        enriched_events
        feature_stream
        ml_scores
        risk_scores
        graph_scores
        trust_scores
        alerts
        security_actions
        feedback_events
        simulation_events
        response_actions
        response_executions
    )

    KAFKA_CONTAINER="guardient-kafka"

    for topic in "${TOPICS[@]}"; do
        docker exec "$KAFKA_CONTAINER" \
            /opt/kafka/bin/kafka-topics.sh \
            --bootstrap-server localhost:9092 \
            --delete --topic "$topic" 2>/dev/null || true
    done

    sleep 2  # let deletions propagate

    # Recreate via Python helper (handles TopicAlreadyExistsError safely)
    $PYTHON -c "
from pipeline.topics import create_all_topics
create_all_topics(partitions=3, replication=1)
print('[Topics] All topics recreated.')
"
    ok "Kafka topics purged and recreated"
fi

# ── Step 4: Delete SQLite fallback database ───────────────
step "Removing SQLite fallback database"

if [[ -f "response_executor/response_engine.db" ]]; then
    rm -f "response_executor/response_engine.db"
    ok "response_executor/response_engine.db removed"
else
    ok "No SQLite DB found (already clean)"
fi

# ── Step 5: Delete trained ML models ─────────────────────
step "Removing trained ML model files"

model_count=0
while IFS= read -r -d '' f; do
    rm -f "$f"
    ok "Deleted: $f"
    (( model_count++ )) || true
done < <(find models/ -type f \( -name "*.pt" -o -name "*.pkl" -o -name "*.h5" -o -name "*.npy" -o -name "*.npz" \) -print0 2>/dev/null)

if [[ -d "new_work" ]]; then
    while IFS= read -r -d '' f; do
        rm -f "$f"
        ok "Deleted: $f"
        (( model_count++ )) || true
    done < <(find new_work/ -type f \( -name "*.pt" -o -name "*.pkl" -o -name "*.h5" -o -name "*.npy" -o -name "*.npz" \) -not -path "*/.*" -print0 2>/dev/null)
fi

[[ $model_count -eq 0 ]] && ok "No model files found (already clean)" || ok "$model_count model file(s) deleted"

# ── Step 6: Delete all log files ─────────────────────────
step "Removing log files and JSONL telemetry records"

# Root-level logs
rm -f api.log frontend.log network_discovery_service.log

# Structured log directories
find logs/ -type f \( -name "*.log" -o -name "*.jsonl" \) -delete 2>/dev/null || true

ok "All logs and JSONL records cleared"

# ── Step 7: Delete PID files ─────────────────────────────
step "Removing stale PID files"

rm -f api.pid frontend.pid network_discovery_service.pid
find pids/ -name "*.pid" -delete 2>/dev/null || true
# Zero-byte "=X.Y.Z" pip marker files (benign, but clean them up too)
find . -maxdepth 1 -name "=*" -type f -delete 2>/dev/null || true

ok "PID files cleared"

# ── Step 8: Remove Python caches ─────────────────────────
step "Removing Python __pycache__ trees"

find . -type d -name "__pycache__" \
    -not -path "./.venv/*" \
    -not -path "./node_modules/*" \
    -exec rm -rf {} + 2>/dev/null || true

find . -name "*.pyc" -o -name "*.pyo" \
    -not -path "./.venv/*" \
    -delete 2>/dev/null || true

ok "Python caches removed"

# ── Step 9: Remove Next.js build cache ───────────────────
step "Removing Next.js build cache"

if [[ -d "techgium frontend/.next" ]]; then
    rm -rf "techgium frontend/.next"
    ok "techgium frontend/.next removed"
else
    ok "No .next cache found (already clean)"
fi

# ── Step 10: Reinitialise DB schema ──────────────────────
step "Reinitialising PostgreSQL schema"

$PYTHON -c "
from db.db import init_schema
init_schema()
"
ok "Schema reinitialised (all tables recreated)"

# ── Done ─────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════╗"
echo -e "║              HARD RESET COMPLETE ✔                  ║"
echo -e "╚══════════════════════════════════════════════════════╝${RESET}"
echo ""
echo "What was reset:"
echo "  ✔  PostgreSQL — all tables truncated, schema reinitialised"
echo "  ✔  Kafka      — all topics deleted and recreated"
echo "  ✔  ML models  — all .pt / .pkl / .h5 files deleted"
echo "  ✔  SQLite DB  — response_executor fallback removed"
echo "  ✔  Logs       — all .log and .jsonl files cleared"
echo "  ✔  PID files  — all stale PID files removed"
echo "  ✔  Caches     — __pycache__ and .next cleared"
echo ""
echo "To restart the application:"
echo "  1. bash run_background.sh          # pipeline services"
echo "  2. python3 -m uvicorn api.main:app --port 8000 --reload"
echo "  3. cd 'techgium frontend' && npm run dev"
echo ""
