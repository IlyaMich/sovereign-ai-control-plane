"""Fail-fast HTTP admission *before* request-body buffering and validation.

This is per ASGI application worker. The Uvicorn limit supplies the outer
connection/task boundary; the existing prompt admission remains independent.
"""

from __future__ import annotations

from starlette.responses import JSONResponse

from app.api.admission import InFlightAdmission


class HTTPIngressLimitMiddleware:
    def __init__(self, app, admission: InFlightAdmission):
        self.app = app
        self.admission = admission

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if not self.admission.try_enter():
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
