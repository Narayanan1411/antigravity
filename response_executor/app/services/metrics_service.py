from prometheus_client import Counter


REQUEST_COUNT = Counter(
    "response_engine_requests_total",
    "Total API Requests"
)

SUCCESS_COUNT = Counter(
    "response_engine_success_total",
    "Successful Executions"
)

FAILURE_COUNT = Counter(
    "response_engine_failure_total",
    "Failed Executions"
)