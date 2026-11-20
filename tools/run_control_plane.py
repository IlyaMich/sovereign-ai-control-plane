"""Validated, configurable Uvicorn entrypoint for the approved control-plane image."""

from __future__ import annotations

import os
from ipaddress import ip_address

import uvicorn

from app.infrastructure.config import positive_int
from app.infrastructure.logging import configure_logging


def server_host() -> str:
    try:
        return str(ip_address(os.environ.get("CONTROL_PLANE_LISTEN_HOST", "127.0.0.1")))
    except ValueError as exc:
        raise ValueError("CONTROL_PLANE_LISTEN_HOST must be a literal IP address") from exc


def server_limits() -> tuple[int, int]:
    concurrency = positive_int("UVICORN_LIMIT_CONCURRENCY", 96)
    keepalive = positive_int("UVICORN_KEEPALIVE_SECONDS", 5)
    if concurrency > 100000 or keepalive > 3600:
        raise ValueError("Uvicorn limits exceed supported bounds")
    return concurrency, keepalive


def main() -> None:
    configure_logging()
    concurrency, keepalive = server_limits()
    # Local startup is loopback-only; containers opt into their network interface.
    uvicorn.run(
        "app.api.main:create_app",
        factory=True,
        log_config=None,
        host=server_host(),
        port=8000,
        access_log=False,
        proxy_headers=False,
        limit_concurrency=concurrency,
        timeout_keep_alive=keepalive,
    )


if __name__ == "__main__":
    main()
