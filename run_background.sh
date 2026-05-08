#!/bin/bash
# ============================================================
# Guardient — Background Pipeline Runner
# Launches all pipeline services in the background and saves logs
# ============================================================

set -e
cd "$(dirname "$0")"

echo "Creating log directory..."
mkdir -p logs/pipeline

echo "Stopping any existing pipeline services..."
pkill -f "python3 services/enrichment_service.py" || true
pkill -f "python3 services/feature_engine.py" || true
pkill -f "python3 services/ml_monitor.py" || true
pkill -f "python3 services/risk_engine.py" || true
pkill -f "python3 services/trust_engine.py" || true
pkill -f "python3 services/decision_engine.py" || true
pkill -f "python3 services/graph_correlator.py" || true
sleep 2

echo "Starting pipeline services in background..."

nohup python3 services/enrichment_service.py > logs/pipeline/enrichment.log 2>&1 &
nohup python3 services/feature_engine.py > logs/pipeline/feature.log 2>&1 &
nohup python3 services/ml_monitor.py > logs/pipeline/ml.log 2>&1 &
nohup python3 services/risk_engine.py > logs/pipeline/risk.log 2>&1 &
nohup python3 services/trust_engine.py > logs/pipeline/trust.log 2>&1 &
nohup python3 services/decision_engine.py > logs/pipeline/decision.log 2>&1 &
nohup python3 services/graph_correlator.py > logs/pipeline/graph.log 2>&1 &

# Also start the network sniffer without sudo (will throw warning but might get some local traffic, user should run it with sudo though)
echo "Pipeline services started! Check logs in logs/pipeline/"
echo "Run 'ps aux | grep python3' to verify."
