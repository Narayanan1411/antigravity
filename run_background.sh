#!/bin/bash
# ============================================================
# Guardient — Background Pipeline Runner
# Launches all pipeline services in the background and saves logs
# ============================================================

cd "$(dirname "$0")"

echo "Creating log directory..."
mkdir -p logs/pipeline

echo "Stopping any existing pipeline services..."
pkill -f "python.*services/.*\.py" || true
pkill -f "python.*hardware/.*\.py" || true
sleep 2

echo "Starting pipeline services in background..."

nohup .venv/bin/python3 -u services/enrichment_service.py > logs/pipeline/enrichment.log 2>&1 &
nohup .venv/bin/python3 -u services/feature_engine.py > logs/pipeline/feature.log 2>&1 &
nohup .venv/bin/python3 -u services/ml_monitor.py > logs/pipeline/ml.log 2>&1 &
nohup .venv/bin/python3 -u services/risk_engine.py > logs/pipeline/risk.log 2>&1 &
nohup .venv/bin/python3 -u services/trust_engine.py > logs/pipeline/trust.log 2>&1 &
nohup .venv/bin/python3 -u services/decision_engine.py > logs/pipeline/decision.log 2>&1 &
nohup .venv/bin/python3 -u services/graph_correlator.py > logs/pipeline/graph.log 2>&1 &
nohup .venv/bin/python3 -u services/response_engine.py > logs/pipeline/response.log 2>&1 &
nohup .venv/bin/python3 -u services/simulation_controller.py > logs/pipeline/simulation.log 2>&1 &
nohup .venv/bin/python3 -u services/network_discovery_service.py > logs/pipeline/network_discovery.log 2>&1 &
nohup .venv/bin/python3 -u services/hardware_monitoring_service.py > logs/pipeline/hardware_monitoring.log 2>&1 &
# Also start the network sniffer without sudo (will throw warning but might get some local traffic, user should run it with sudo though)
echo "Pipeline services started! Check logs in logs/pipeline/"
echo "Run 'ps aux | grep python3' to verify."
