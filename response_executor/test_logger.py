from app.services.logger_service import LoggerService

logger = LoggerService()

logger.log_event(
    action="block_device",
    target="10.42.0.165",
    status="SUCCESS",
    message="Device blocked successfully"
)

print("Log inserted")
