"""Bounded, process-local concurrency diagnostics; never records request data."""

from __future__ import annotations

import asyncio
import math
from collections import Counter, deque
from contextlib import suppress


def _distribution(samples: deque[float]) -> dict[str, float | int | None]:
    if not samples:
        return {"samples": 0, "p50_ms": None, "p95_ms": None, "max_ms": None}
    ordered = sorted(samples)

    def percentile(p: float) -> float:
        index = max(0, math.ceil(p * len(ordered)) - 1)
        return round(ordered[index], 3)

    return {
        "samples": len(ordered),
        "p50_ms": percentile(0.5),
        "p95_ms": percentile(0.95),
        "max_ms": round(ordered[-1], 3),
    }


class ExecutorMetrics:
    """Update only on the owning event loop, including future-completion callbacks."""

    def __init__(self, capacity: int, sample_window: int = 512) -> None:
        if type(capacity) is not int or capacity < 1:
            raise ValueError("Invalid executor capacity")
        if type(sample_window) is not int or not 1 <= sample_window <= 4096:
            raise ValueError("Invalid metrics sample window")
        self.capacity = capacity
        self.waiting = 0
        self.active = 0
        self.peak_active = 0
        self.submitted = 0
        self.completed = 0
        self.failed = 0
        self.rejected = 0
        self.submitted_by_kind: Counter[str] = Counter()
        self._waits: deque[float] = deque(maxlen=sample_window)
        self._processing: deque[float] = deque(maxlen=sample_window)

    def begin_wait(self) -> None:
        self.waiting += 1

    def end_wait(self) -> None:
        self.waiting -= 1

    def refuse(self) -> None:
        self.rejected += 1

    def submit(self, kind: str = "job") -> None:
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)
        self.submitted += 1
        self.submitted_by_kind[kind] += 1

    def finish(self, wait_ms: float, processing_ms: float, failed: bool) -> None:
        self.active -= 1
        self.completed += 1
        self.failed += int(failed)
        self._waits.append(max(0.0, wait_ms))
        self._processing.append(max(0.0, processing_ms))

    def snapshot(self) -> dict:
        return {
            "capacity": self.capacity,
            "active_jobs": self.active,
            "waiting_for_capacity": self.waiting,
            "peak_active_jobs": self.peak_active,
            "submitted": self.submitted,
            "completed": self.completed,
            "failed": self.failed,
            "capacity_rejections": self.rejected,
            "submitted_by_kind": dict(sorted(self.submitted_by_kind.items())),
            "queue_wait": _distribution(self._waits),
            "processing": _distribution(self._processing),
        }


class LoopLagMonitor:
    """Observe scheduling delay on the FastAPI event loop without additional threads."""

    def __init__(self, interval_seconds: float = 0.25, sample_window: int = 512) -> None:
        if not math.isfinite(interval_seconds) or interval_seconds <= 0:
            raise ValueError("Invalid loop lag interval")
        if type(sample_window) is not int or not 1 <= sample_window <= 4096:
            raise ValueError("Invalid metrics sample window")
        self.interval_seconds = interval_seconds
        self._samples: deque[float] = deque(maxlen=sample_window)
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            raise RuntimeError("Loop monitor already started")
        self._task = asyncio.create_task(self._run(), name="sovereign-loop-lag")

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        while True:
            due = loop.time() + self.interval_seconds
            await asyncio.sleep(self.interval_seconds)
            self._samples.append(max(0.0, 1000.0 * (loop.time() - due)))

    def snapshot(self) -> dict:
        return {"sample_interval_seconds": self.interval_seconds, **_distribution(self._samples)}

    async def aclose(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task
            self._task = None
