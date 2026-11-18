"""ASGI request-body limiter, including chunked bodies without Content-Length."""
from starlette.responses import JSONResponse


class BodyTooLarge(Exception):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int = 16384):
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
                    return await JSONResponse({"detail": "Request too large"}, status_code=413)(scope, receive, send)
            except ValueError:
                return await JSONResponse({"detail": "Invalid content length"}, status_code=400)(scope, receive, send)

        total = 0

        async def limited_receive():
            nonlocal total
            message = await receive()
            if message["type"] == "http.request":
                total += len(message.get("body", b""))
                if total > self.max_bytes:
                    raise BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except BodyTooLarge:
            return await JSONResponse({"detail": "Request too large"}, status_code=413)(scope, receive, send)
