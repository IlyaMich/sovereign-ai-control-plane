"""Fail-fast HTTP admission *before* request-body buffering and validation.

This is per ASGI application worker. The Uvicorn limit supplies the outer
connection/task boundary; the existing prompt admission remains independent.
"""

from __future__ import annotations

import logging

from starlette.responses import JSONResponse

from app.api.admission import InFlightAdmission
from app.infrastructure.logging import event


class HTTPIngressLimitMiddleware:
    def __init__(self, app, admission: InFlightAdmission):
        self.app = app
        self.admission = admission

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if not self.admission.try_enter():
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
            return await JSONResponse(
                status_code=503,
                headers={"Retry-After": "1", "Cache-Control": "no-store"},
                content={
                    "status": "OVERLOADED",
                    "reason_codes": ["HTTP_INGRESS_CAPACITY_EXCEEDED"],
                },
            )(scope, receive, send)
        try:
            await self.app(scope, receive, send)
        finally:
            self.admission.leave()
