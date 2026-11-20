"""ASGI correlation and safe request summaries, including pre-routing failures."""

import asyncio
import logging
import time
import uuid

from app.infrastructure.logging import context, event


class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        correlation_id = str(uuid.uuid4())
        token = context.set({"correlation_id": correlation_id})
        started = time.perf_counter()
        status = 499

        async def observed_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                message = dict(message)
                message["headers"] = [
                    *message.get("headers", []),
                    (b"x-correlation-id", correlation_id.encode("ascii")),
                ]
            await send(message)

        try:
            await self.app(scope, receive, observed_send)
        except asyncio.CancelledError:
            event("request_cancelled", level=logging.WARNING, stage="http")
            raise
        except Exception:
            status = 500
            event("request_failed", level=logging.ERROR, stage="http", error_code="UNHANDLED_ERROR")
            raise
        finally:
            route = getattr(scope.get("route"), "path", scope.get("path", "UNMATCHED"))
            if route not in {"/health/live", "/health/ready"} and not scope.get("state", {}).get(
                "ingress_rejected"
            ):
                event(
                    "request_rejected" if status in {401, 429} else "request_completed",
                    route=route,
                    method=scope["method"],
                    http_status=status,
                    duration_ms=round((time.perf_counter() - started) * 1000, 3),
                    limited=status in {401, 429},
                )
            context.reset(token)
