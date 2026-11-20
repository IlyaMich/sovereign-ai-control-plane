"""Allowlisted operational events; never serialize messages, bodies or exceptions."""

from __future__ import annotations

import atexit
import json
import logging
import math
import os
import queue
import re
import sys
import threading
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import QueueHandler, QueueListener
from typing import Any, TextIO

context: ContextVar[dict[str, str] | None] = ContextVar("log_context", default=None)
_FIELDS = {
    "correlation_id",
    "request_id",
    "stage",
    "error_code",
    "route",
    "method",
    "http_status",
    "duration_ms",
    "queue_wait_ms",
    "processing_ms",
    "event_type",
    "sequence",
    "effect",
    "execution_status",
    "transformed",
    "destination_id",
    "release_id",
    "policy_digest",
    "detector_digest",
    "state",
    "suppressed",
    "attempt",
}
_ROUTES = {
    "/v1/prompts",
    "/v1/requests/{request_id}",
    "/v1/idempotency/status",
    "/v1/diagnostics/concurrency",
    "/v1/diagnostics/dlp",
    "/health/live",
    "/health/ready",
    "/metrics",
}
_lock = threading.Lock()
_listener: QueueListener | None = None
_dropped = 0
_output_errors = 0
_limits: dict[str, tuple[float, int]] = {}


def _safe(fields: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in fields.items():
        if key not in _FIELDS or type(value) not in {str, int, float, bool}:
            continue
        if key in {"correlation_id", "request_id"}:
            if not isinstance(value, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value
            ):
                continue
        elif key in {"release_id", "policy_digest", "detector_digest"}:
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                continue
        elif key == "route":
            value = value if value in _ROUTES else "UNMATCHED"
        elif key == "destination_id":
            value = value if value in {"sovereign-model", "external-simulator"} else "UNREGISTERED"
        elif key == "method":
            value = (
                value
                if value in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
                else "OTHER"
            )
        elif isinstance(value, str):
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", value):
                continue
        elif type(value) not in {int, float, bool}:
            continue
        if isinstance(value, float) and not math.isfinite(value):
            continue
        result[key] = value
    return result


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Ignore getMessage(), exc_info, stack_info and arbitrary extra fields.
        fields = _safe(getattr(record, "fields", {}))
        if not record.name.startswith("sovereign."):
            source = record.name.split(".", 1)[0]
            fields["stage"] = (
                ("presidio" if source == "presidio-analyzer" else source)
                if source in {"uvicorn", "httpx", "httpcore", "spacy", "presidio-analyzer"}
                else "dependency"
            )
        event = getattr(record, "event", "runtime_message")
        if not isinstance(event, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,79}", event):
            event = "runtime_message"
        return json.dumps(
            {
                "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
                "level": record.levelname,
                "service": "control-plane",
                "event": event,
                **fields,
            },
            allow_nan=False,
            separators=(",", ":"),
        )


def _rate_limit(name: str) -> int | None:
    """Return suppressed count when emitting; None while the fixed event is limited."""
    now = time.monotonic()
    with _lock:
        last, count = _limits.get(name, (float("-inf"), 0))
        if now - last < 10:
            _limits[name] = (last, count + 1)
            return None
        _limits[name] = (now, 0)
    return count


class SafeQueueHandler(QueueHandler):
    def emit(self, record: logging.LogRecord) -> None:
        # Match a fixed server message without formatting arbitrary arguments.
        # This rejection happens before ASGI and has no request correlation ID.
        if (
            record.name == "uvicorn.error"
            and record.msg == "Exceeded concurrency limit."
            and not record.args
        ):
            suppressed = _rate_limit("server_capacity_exceeded")
            if suppressed is None:
                return
            record = logging.makeLogRecord(record.__dict__.copy())
            record.event = "server_capacity_exceeded"
            record.fields = {
                "stage": "uvicorn",
                "error_code": "UVICORN_CAPACITY_EXCEEDED",
                "http_status": 503,
                "suppressed": suppressed,
            }
        super().emit(record)

    def prepare(self, record: logging.LogRecord) -> logging.LogRecord:
        # Only the sanitized JSON crosses the queue boundary.
        clean = logging.LogRecord(record.name, record.levelno, "", 0, self.format(record), (), None)
        return clean

    def enqueue(self, record: logging.LogRecord) -> None:
        global _dropped
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            with _lock:
                _dropped += 1

    def handleError(self, record: logging.LogRecord) -> None:
        global _dropped
        with _lock:
            _dropped += 1


class SafeStreamHandler(logging.StreamHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        global _output_errors
        with _lock:
            _output_errors += 1


def shutdown_logging() -> None:
    global _listener
    listener, _listener = _listener, None
    if listener is not None:
        # Never wait indefinitely for a blocked output stream at process exit.
        try:
            listener.enqueue_sentinel()
        except queue.Full:
            return
        thread = listener._thread
        if thread is not None:
            thread.join(timeout=1)


def configure_logging(*, stream: TextIO | None = None) -> None:
    global _listener
    if _listener is not None:
        return
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    if level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ValueError("LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR or CRITICAL")
    handler = SafeQueueHandler(queue.Queue(maxsize=2048))
    handler.setFormatter(JSONFormatter())
    sink = SafeStreamHandler(sys.stdout if stream is None else stream)
    _listener = QueueListener(handler.queue, sink)
    _listener.start()
    logger = logging.getLogger("sovereign")
    logger.handlers = [handler]
    logger.setLevel(level)
    logger.propagate = False
    # Uvicorn tracebacks and dependency messages may contain raw exception text.
    # These records use the same safe envelope, without free-form messages.
    for name in (
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "httpx",
        "httpcore",
        "presidio-analyzer",
        "spacy",
    ):
        dependency = logging.getLogger(name)
        dependency.handlers = [handler]
        dependency.setLevel(logging.WARNING)
        dependency.propagate = False
    atexit.register(shutdown_logging)


def logging_snapshot() -> dict[str, int]:
    with _lock:
        return {"dropped_events": _dropped, "output_errors": _output_errors}


def event(name: str, *, level: int = logging.INFO, limited: bool = False, **fields: Any) -> None:
    """Call with constant event names/codes and explicitly selected metadata only."""
    try:
        if limited:
            count = _rate_limit(name)
            if count is None:
                return
            fields["suppressed"] = count
        safe = _safe({**(context.get() or {}), **fields})
        logging.getLogger("sovereign.events").log(level, "", extra={"event": name, "fields": safe})
    except Exception:
        # Operational logging cannot change an authorization or audit outcome.
        global _dropped
        with _lock:
            _dropped += 1


def failure_code(exc: Exception, prefix: str) -> str:
    """Classify without copying exception messages, URLs or response content."""
    import httpx

    from app.infrastructure.resilience import circuit_unavailable_code

    circuit_code = circuit_unavailable_code(exc, prefix)
    if circuit_code is not None:
        return circuit_code
    if isinstance(exc, (httpx.TimeoutException, TimeoutError)):
        return prefix + "_TIMEOUT"
    if isinstance(exc, httpx.HTTPStatusError):
        return prefix + "_HTTP_ERROR"
    if isinstance(exc, httpx.RequestError):
        return prefix + "_CONNECTION_ERROR"
    return prefix + "_INVALID_RESPONSE"
