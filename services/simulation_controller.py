"""
Guardient Simulation Controller
===============================
FastAPI microservice for orchestration of attack simulations.
Runs on port 8001 to avoid conflicting with the main API on 8000.
"""

from __future__ import annotations
import sys
import uuid
import uvicorn
from pathlib import Path
from pydantic import BaseModel

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from db.db import init_schema, insert_simulation_run, get_simulation_runs, execute
from services.sandbox_executor import execute_simulation

app = FastAPI(title="Guardient Simulation Controller")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SimulationRequest(BaseModel):
    device_id: str
    attack_type: str
    rounds: int = 5
    interval_sec: int = 3


@app.post("/simulate")
def start_simulation(req: SimulationRequest):
    """Start an attack simulation against a device."""
    valid_attacks = {"c2_beaconing", "credential_abuse", "lateral_movement", "ransomware_activity"}
    if req.attack_type not in valid_attacks:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Expected one of: {valid_attacks}")

    run_id = f"SIM-RUN-{uuid.uuid4().hex[:8]}"
    
    # 1. Record the run in DB
    try:
        insert_simulation_run(
            run_id=run_id,
            device_id=req.device_id,
            attack_type=req.attack_type,
            status="running",
            parameters={"rounds": req.rounds, "interval_sec": req.interval_sec}
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB Error: {exc}")

    # 2. Spawn the executor thread
    execute_simulation(
        run_id=run_id,
        device_id=req.device_id,
        attack_type=req.attack_type,
        rounds=req.rounds,
        interval_sec=req.interval_sec
    )

    return {
        "status": "started",
        "run_id": run_id,
        "device_id": req.device_id,
        "attack_type": req.attack_type,
    }


@app.delete("/simulation/device/{device_id}")
def reset_device(device_id: str):
    """
    Stop active simulation logic and clear the trust_states for a device,
    bringing its trust score back to 100.
    """
    
    # 1. Update any running sim status down to "stopped"
    execute("UPDATE simulation_runs SET status = 'stopped', ended_at = NOW() WHERE device_id = %s AND status = 'running'", (device_id,))
    
    # 2. Reset the device's trust state directly in PostgreSQL
    # Zeroing out I,C,V,N arrays means adjusted_risk goes back to 0 -> trust=100
    execute("""
        UPDATE trust_states 
        SET state = '{"I": 0.0, "C": 0.0, "V": 0.0, "N": 0.0, "AR_prev": 0.0, "last_timestamp": 0.0}'::jsonb,
            updated_at = NOW()
        WHERE device_id = %s
    """, (device_id,))
    
    return {"status": "success", "device_id": device_id, "message": "Trust state reset to 100"}


@app.get("/simulation/runs")
def list_simulation_runs():
    """List recent simulation runs."""
    return get_simulation_runs()


if __name__ == "__main__":
    init_schema()
    print("=" * 60)
    print("  Guardient Simulation Controller is up on port 8001")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8001)

