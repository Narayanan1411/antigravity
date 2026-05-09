from fastapi import FastAPI

from prometheus_client import (
    generate_latest
)

from fastapi.responses import Response

from app.models.request_models import (
    ExecuteRequest
)

from app.orchestrator.orchestrator import (
    ActionOrchestrator
)

from app.services.logger_service import (
    LoggerService
)


app = FastAPI()

orchestrator = ActionOrchestrator()

logger = LoggerService()


@app.get("/")
def root():

    return {
        "message": "Response Engine Running"
    }


@app.post("/execute")
def execute_action(
    request: ExecuteRequest
):

    result = orchestrator.execute_action(
        action=request.action,
        target_id=request.target_id
    )

    return {
        "status": "success",
        "result": result
    }


@app.get("/logs")
def get_logs():

    logs = logger.get_logs()

    response = []

    for log in logs:

        response.append({
            "id": log.id,
            "action": log.action,
            "target": log.target,
            "status": log.status,
            "message": log.message,
            "timestamp": log.timestamp
        })

    return response


@app.get("/metrics")
def metrics():

    return Response(
        generate_latest(),
        media_type="text/plain"
    )