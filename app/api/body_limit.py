"""ASGI request-body limiter, including chunked bodies without Content-Length."""

from starlette.responses import JSONResponse

from app.infrastructure.config import RequestLimits


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int = RequestLimits.max_request_body_bytes):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in ("POST", "PUT", "PATCH"):
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        length = headers.get(b"content-length")
        if length is not None:
            try:
                if int(length) > self.max_bytes or int(length) < 0:
                    return await JSONResponse({"detail": "Request too large"}, status_code=413)(
                        scope, receive, send
                    )
            except ValueError:
                return await JSONResponse({"detail": "Invalid content length"}, status_code=400)(
                    scope, receive, send
                )

        # Read at most the configured limit before invoking FastAPI. FastAPI can
        # otherwise turn receive-time limiter exceptions into a generic HTTP 400.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > self.max_bytes:
                return await JSONResponse({"detail": "Request too large"}, status_code=413)(
                    scope, receive, send
                )
            body.extend(chunk)
            if not message.get("more_body", False):
                break

        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.app(scope, buffered_receive, send)
