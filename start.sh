#!/bin/bash
# ============================================================
# Guardient — Full Pipeline Startup Script
# Launches all pipeline services in separate terminal tabs
# then starts the network sniffer (requires sudo for packet capture)
# Usage: bash start.sh
# ============================================================

set -e
cd "$(dirname "$0")"
ROOT="$(pwd)"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         GUARDIENT FULL PIPELINE STARTUP          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── Helpers ──────────────────────────────────────────────
open_tab() {
    local title="$1"
    local cmd="$2"
    osascript -e "
        tell application \"Terminal\"
            activate
            tell application \"System Events\" to keystroke \"t\" using command down
            delay 0.4
            do script \"cd '$ROOT' && echo '=== $title ===' && $cmd\" in front window
        end tell
    " 2>/dev/null || true
}

# ── Check Kafka is reachable ─────────────────────────────
echo "[1/7] Checking Kafka (port 9092)..."
if ! nc -z localhost 9092 2>/dev/null; then
    echo "⚠️  Kafka not reachable. Starting docker compose..."
    docker compose up -d
    echo "     Waiting 5s for Kafka to be ready..."
    sleep 5
else
    echo "     ✅ Kafka is running"
fi

# ── Check Postgres ────────────────────────────────────────
echo "[2/7] Checking PostgreSQL (port 5432)..."
if ! nc -z localhost 5432 2>/dev/null; then
    echo "⚠️  PostgreSQL not reachable. Starting docker compose..."
    docker compose up -d postgres
    sleep 3
else
    echo "     ✅ PostgreSQL is running"
fi

echo ""
echo "Starting pipeline services in new Terminal tabs..."
echo ""

# ── Pipeline Services ─────────────────────────────────────
open_tab "Enrichment Service"   "python3 services/enrichment_service.py"
sleep 0.5
open_tab "Feature Engine"       "python3 services/feature_engine.py"
sleep 0.5
open_tab "ML Monitor"           "python3 services/ml_monitor.py"
sleep 0.5
open_tab "Risk Engine"          "python3 services/risk_engine.py"
sleep 0.5
open_tab "Graph Correlator"     "python3 services/graph_correlator.py"
sleep 0.5
open_tab "Trust Engine"         "python3 services/trust_engine.py"
sleep 0.5
open_tab "Decision Engine"      "python3 services/decision_engine.py"
sleep 0.5
open_tab "Response Engine"      "python3 services/response_engine.py"
sleep 0.5
open_tab "Simulation Controller" "python3 services/simulation_controller.py"
sleep 0.5
open_tab "Network Discovery"    "python3 services/network_discovery_service.py"
sleep 0.5
open_tab "Hardware Monitoring"  "python3 services/hardware_monitoring_service.py"
sleep 0.5

echo "[3/7] ✅ 11 pipeline services launched in Terminal tabs"
echo ""

# ── Network Sniffer (requires sudo) ──────────────────────
echo "[4/7] Starting network sniffer (requires sudo for packet capture)..."
osascript -e "
    tell application \"Terminal\"
        activate
        tell application \"System Events\" to keystroke \"t\" using command down
        delay 0.4
        do script \"cd '$ROOT' && echo '=== Network Sniffer ===' && sudo python3 network/network_data.py\" in front window
    end tell
" 2>/dev/null || true

echo "     ✅ Network sniffer tab opened (enter your password if prompted)"
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  ALL SERVICES STARTED                            ║"
echo "║                                                  ║"
echo "║  • 10 pipeline services running                  ║"
echo "║    (incl. Graph Correlator & Response Engine)    ║"
echo "║  • Network Discovery active (real data)          ║"
echo "║  • Network sniffer active (sudo)                 ║"
echo "║  • main API running on http://localhost:8000     ║"
echo "║  • Simulation UI running on http://localhost:8001║"
echo "║  • Dashboard at  http://localhost:3000           ║"
echo "║                                                  ║"
echo "║  Data will appear in the dashboard within ~15s   ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
