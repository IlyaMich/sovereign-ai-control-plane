"""Validated, configurable Uvicorn entrypoint for the approved control-plane image."""

from __future__ import annotations

import uvicorn

from app.infrastructure.config import positive_int
from app.infrastructure.logging import configure_logging


def server_limits() -> tuple[int, int]:
    concurrency = positive_int("UVICORN_LIMIT_CONCURRENCY", 96)
    keepalive = positive_int("UVICORN_KEEPALIVE_SECONDS", 5)
    if concurrency > 100000 or keepalive > 3600:
        raise ValueError("Uvicorn limits exceed supported bounds")
    return concurrency, keepalive


def main() -> None:
    configure_logging()
    concurrency, keepalive = server_limits()
    uvicorn.run(
        "app.api.main:create_app",
        factory=True,
        log_config=None,
        host="0.0.0.0",
        port=8000,
        access_log=False,
        proxy_headers=False,
        limit_concurrency=concurrency,
        timeout_keep_alive=keepalive,
    )


if __name__ == "__main__":
    main()
