"""Fail-fast HTTP admission *before* request-body buffering and validation.

This is per ASGI application worker. The Uvicorn limit supplies the outer
connection/task boundary; the existing prompt admission remains independent.
"""

from __future__ import annotations

import logging

from app.api.admission import InFlightAdmission
from app.api.errors import error_response
from app.infrastructure.logging import event


class HTTPIngressLimitMiddleware:
    def __init__(self, app, admission: InFlightAdmission, operations=None):
        self.app = app
        self.admission = admission
        self.operations = operations

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        # Dedicated bounded management lane; liveness performs no dependency work.
        if self.operations is not None and scope["method"] == "GET":
            if scope.get("path") == "/health/live":
                return await self.app(scope, receive, send)
            admission = (
                self.operations
                if scope.get("path") in {"/health/ready", "/metrics"}
                else self.admission
            )
        else:
            admission = self.admission
        if not admission.try_enter():
            scope.setdefault("state", {})["ingress_rejected"] = True
            event(
                "http_ingress_rejected",
                level=logging.WARNING,
                limited=True,
                error_code="HTTP_INGRESS_CAPACITY_EXCEEDED",
                stage="http_ingress",
                http_status=503,
                method=scope["method"],
                route=scope.get("path", "UNMATCHED"),
            )
            return await error_response(
                503,
                "HTTP_INGRESS_CAPACITY_EXCEEDED",
                status="OVERLOADED",
                headers={"Retry-After": "1"},
            )(scope, receive, send)
        try:
            await self.app(scope, receive, send)
        finally:
            admission.leave()
