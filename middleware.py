from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from security_monitor import monitor

def get_client_ip(request: Request):
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0]
    return request.client.host

class ErrorTrackingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        client_ip = get_client_ip(request)
        if 400 <= response.status_code < 600:
            monitor.record_request(client_ip, response.status_code)
            if monitor.is_error_burst(client_ip):
                response.headers["X-Error-Burst-Detected"] = "true"
        return response