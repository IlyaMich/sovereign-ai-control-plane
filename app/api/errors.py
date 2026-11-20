"""One privacy-safe transport error contract, also usable before routing."""

from collections.abc import Mapping
from http import HTTPStatus

from fastapi.responses import JSONResponse

from app.infrastructure.logging import context

ERROR_CODES = {
    400: "BAD_REQUEST",
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    408: "REQUEST_BODY_TIMEOUT",
    409: "CONFLICT",
    413: "REQUEST_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "INVALID_BODY",
    429: "CAPACITY_EXCEEDED",
    500: "INTERNAL_ERROR",
    502: "MODEL_UNAVAILABLE",
    503: "SERVICE_UNAVAILABLE",
}


def error_response(
    status_code: int,
    code: str | None = None,
    *,
    detail: str | None = None,
    status: str = "ERROR",
    request_id: str | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """Never pass exception text, submitted values, or arbitrary URLs here."""
    body = {
        "status": status,
        "reason_codes": [code or ERROR_CODES.get(status_code, "HTTP_ERROR")],
        "detail": detail or HTTPStatus(status_code).phrase,
        "correlation_id": (context.get() or {}).get("correlation_id"),
    }
    if request_id is not None:
        body["request_id"] = request_id
    return JSONResponse(
        status_code=status_code,
        content=body,
        headers={"Cache-Control": "no-store", **(headers or {})},
    )
