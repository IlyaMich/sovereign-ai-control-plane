"""Coalesce and briefly cache the whole readiness operation, not request checks."""

from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from typing import Awaitable, Callable

ProbeResult = tuple[int, dict]


class ReadinessProbe:
    def __init__(self, cache_seconds: float):
        self.cache_seconds = cache_seconds
        self.completed_at = float("-inf")
        self._result: ProbeResult | None = None
        self._task: asyncio.Task[ProbeResult] | None = None

    async def run(self, operation: Callable[[], Awaitable[ProbeResult]]) -> ProbeResult:
        if self._task is not None:
            return await asyncio.shield(self._task)
        if self._result is not None and time.monotonic() - self.completed_at < self.cache_seconds:
            return self._result

        async def execute() -> ProbeResult:
            try:
                self._result = await operation()
                self.completed_at = time.monotonic()
                return self._result
            finally:
                self._task = None

        self._task = asyncio.create_task(execute(), name="readiness-probe")
        # Retrieve unexpected failures even if every HTTP waiter disconnects.
        # Active waiters still receive the original exception.
        self._task.add_done_callback(lambda task: None if task.cancelled() else task.exception())
        return await asyncio.shield(self._task)

    async def aclose(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
