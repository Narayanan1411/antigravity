from app.controllers.network_controller import (
    NetworkController
)

# from app.controllers.container_controller import (
#     ContainerController
# )

# from app.services.email_service import (
#     EmailService
# )

from app.services.logger_service import (
    LoggerService
)

from app.services.metrics_service import (
    REQUEST_COUNT,
    SUCCESS_COUNT,
    FAILURE_COUNT
)


class ActionOrchestrator:

    def __init__(self):

        self.network = NetworkController()

        # self.container = ContainerController()

        # self.email = EmailService()

        self.logger = LoggerService()

    def execute_action(
        self,
        action,
        target_id
    ):

        REQUEST_COUNT.inc()

        try:

            if action == "block_device":

                result = self.network.block_device(
                    target_id
                )

            elif action == "unblock_device":

                result = self.network.unblock_device(
                    target_id
                )

            elif action == "shutdown_container":

                result = self.container.stop_container(
                    target_id
                )

            else:

                raise Exception(
                    "Unsupported action"
                )

            SUCCESS_COUNT.inc()

            self.logger.log_event(
                action=action,
                target=target_id,
                status="SUCCESS",
                message=str(result)
            )

            self.email.send_alert(
                subject=f"{action} executed",
                body=(
                    f"Action: {action}\n"
                    f"Target: {target_id}\n"
                    f"Result: {result}"
                )
            )

            return result

        except Exception as e:

            FAILURE_COUNT.inc()

            self.logger.log_event(
                action=action,
                target=target_id,
                status="FAIL",
                message=str(e)
            )

            raise e