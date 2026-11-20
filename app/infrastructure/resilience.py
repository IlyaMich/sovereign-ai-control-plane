"""Per-dependency circuit breaking; retry only explicitly safe health probes."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import TYPE_CHECKING

import httpx

from app.infrastructure.config import APIOperations
from app.infrastructure.logging import event, failure_code

if TYPE_CHECKING:
    from app.infrastructure.api_metrics import APIMetrics


class CircuitOpen(httpx.RequestError):
    pass


def circuit_unavailable_code(exc: BaseException, prefix: str) -> str | None:
    """Recognize local circuit rejection through adapter causes, without message text."""
    current: BaseException | None = exc
    for _ in range(3):
        if isinstance(current, CircuitOpen):
            return prefix + "_CIRCUIT_OPEN"
        current = current.__cause__ if current is not None else None
    return None


class CircuitBreaker:
    """Owned by one event loop. Ignore completions from an older circuit generation."""

    def __init__(self, threshold: int, reset_seconds: float, *, dependency: str = "dependency"):
        self.dependency = dependency if dependency in {"opa", "model"} else "dependency"
        self.threshold = threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_at: float | None = None
        self.probing = False
        self.generation = 0

    @property
    def is_open(self) -> bool:
        return self.opened_at is not None

    def enter(self) -> int:
        if self.opened_at is not None:
            if self.probing or time.monotonic() - self.opened_at < self.reset_seconds:
                raise CircuitOpen("Dependency circuit open")
            self.probing = True
            event("dependency_circuit_half_open", stage=self.dependency, state="HALF_OPEN")
        return self.generation

    def finish(self, generation: int, failed: bool) -> None:
        if generation != self.generation:
            return
        if not failed:
            was_open = self.is_open
            self.failures = 0
            self.opened_at = None
            self.probing = False
            if was_open:
                event("dependency_circuit_closed", stage=self.dependency, state="CLOSED")
            return
        self.failures += 1
        if self.probing or self.failures >= self.threshold:
            self.opened_at = time.monotonic()
            self.probing = False
            self.generation += 1
            event(
                "dependency_circuit_opened",
                level=logging.WARNING,
                stage=self.dependency,
                state="OPEN",
                error_code="DEPENDENCY_CIRCUIT_OPEN",
            )


class ResilientHTTP:
    def __init__(self, settings: APIOperations, metrics: APIMetrics | None = None):
        self.settings = settings
        self.metrics = metrics
        self.circuits = {
            name: CircuitBreaker(
                settings.circuit_failure_threshold, settings.circuit_reset_seconds, dependency=name
            )
            for name in ("opa", "model")
        }

    async def request(
        self,
        client: httpx.AsyncClient,
        dependency: str,
        method: str,
        url: str,
        *,
        probe: bool = False,
        **kwargs,
    ) -> httpx.Response:
        # Callers supply only these fixed dependency names; never label URLs or model IDs.
        circuit = self.circuits[dependency]
        try:
            generation = circuit.enter()
        except CircuitOpen:
            if self.metrics is not None:
                self.metrics.circuit_rejections.labels(dependency).inc()
            raise
        attempts = self.settings.probe_attempts if probe else 1
        try:
            for attempt in range(attempts):
                try:
                    response = await client.request(method, url, **kwargs)
                    response.raise_for_status()
                except httpx.HTTPError as exc:
                    if self.metrics is not None:
                        self.metrics.dependency_failures.labels(dependency).inc()
                    transient = isinstance(exc, httpx.TransportError) or (
                        isinstance(exc, httpx.HTTPStatusError)
                        and exc.response.status_code in {502, 503, 504}
                    )
                    if attempt + 1 == attempts or not transient:
                        raise
                    event(
                        "dependency_probe_retry",
                        level=logging.DEBUG,
                        stage=dependency,
                        attempt=attempt + 2,
                        error_code=failure_code(exc, dependency.upper()),
                        http_status=exc.response.status_code
                        if isinstance(exc, httpx.HTTPStatusError)
                        else None,
                    )
                    delay = min(5.0, self.settings.probe_backoff_seconds * 2**attempt)
                    await asyncio.sleep(delay * random.SystemRandom().uniform(0.5, 1.0))
                else:
                    circuit.finish(generation, False)
                    return response
        except BaseException:
            # Cancellation cannot leave the half-open gate permanently occupied.
            circuit.finish(generation, True)
            raise
        raise AssertionError("No HTTP attempt made")
