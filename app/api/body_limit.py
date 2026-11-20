"""ASGI request-body limiter, including chunked bodies without Content-Length."""

import asyncio
import math

from app.api.errors import error_response
from app.infrastructure.config import IngressLimits, RequestLimits


class RequestBodyLimitMiddleware:
    def __init__(
        self,
        app,
        max_bytes: int = RequestLimits.max_request_body_bytes,
        body_read_timeout_seconds: float = IngressLimits.body_read_timeout_seconds,
    ):
        if (
            isinstance(body_read_timeout_seconds, bool)
            or not isinstance(body_read_timeout_seconds, (int, float))
            or not math.isfinite(body_read_timeout_seconds)
            or body_read_timeout_seconds <= 0
        ):
            raise ValueError("body_read_timeout_seconds must be finite and positive")
        self.app = app
        self.max_bytes = max_bytes
        self.body_read_timeout_seconds = body_read_timeout_seconds

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes or int(length) < 0:
                    return await error_response(413)(scope, receive, send)
            except ValueError:
                return await error_response(400, "INVALID_CONTENT_LENGTH")(scope, receive, send)

        # Read at most the configured limit before invoking FastAPI. FastAPI can
        # otherwise turn receive-time limiter exceptions into a generic HTTP 400.
        body = bytearray()
        oversized = False
        # One total deadline across all chunks: trickling bytes cannot extend it.
        # Keep application processing and response writes outside this deadline.
        deadline = asyncio.timeout(self.body_read_timeout_seconds)
        try:
            async with deadline:
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    chunk = message.get("body", b"")
                    if len(body) + len(chunk) > self.max_bytes:
                        oversized = True
                        break
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            if not deadline.expired():
                raise
            # Unread HTTP/1.x body bytes must not be reused as another request.
            headers = (
                {"Connection": "close"}
                if scope.get("http_version", "1.1") in {"1.0", "1.1"}
                else {}
            )
            return await error_response(408, headers=headers)(scope, receive, send)

        if oversized:
            return await error_response(413)(scope, receive, send)

        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, buffered_receive, send)
