"""Bounded off-loop integrity verification, with independently coalesced readiness.

No result caching: every request performs the same filesystem and signature checks
as before M7.7. Only *overlapping* readiness calls share one full live-artifact
scan; the next readiness call runs a new scan. No prompts are retained here.
"""

from __future__ import annotations

import asyncio
import math
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable, TypeVar, cast

T = TypeVar("T")


class IntegrityCapacityExceeded(RuntimeError):
    """The integrity verification lane is saturated; fail closed."""


class IntegrityExecutorClosed(RuntimeError):
    """Verification was requested after shutdown started; fail closed."""


class BoundedIntegrityExecutor:
    """One per FastAPI app/event loop; threads only read verified artifacts.

    Ordinary verifications have bounded submitted work and bounded waiters.
    Readiness has an independent single thread to avoid blocking request checks.
    Cancellation of an awaiting caller never cancels already submitted work.
    """

    def __init__(
        self,
        *,
        max_jobs: int = 8,
        max_waiters: int = 8,
        queue_wait_seconds: float = 1.0,
        worker_threads: int = 2,
    ) -> None:
        if type(max_jobs) is not int or not 1 <= max_jobs <= 1024:
            raise ValueError("max_jobs must be an integer from 1 to 1024")
        if type(max_waiters) is not int or not 0 <= max_waiters <= 1024:
            raise ValueError("max_waiters must be an integer from 0 to 1024")
        if type(worker_threads) is not int or not 1 <= worker_threads <= max_jobs:
            raise ValueError("worker_threads must be between 1 and max_jobs")
        if (
            isinstance(queue_wait_seconds, bool)
            or not isinstance(queue_wait_seconds, (int, float))
            or not math.isfinite(queue_wait_seconds)
            or queue_wait_seconds <= 0
        ):
            raise ValueError("queue_wait_seconds must be finite and positive")
        self._slots = asyncio.Semaphore(max_jobs)
        self._pool = ThreadPoolExecutor(
            max_workers=worker_threads, thread_name_prefix="sovereign-integrity"
        )
        self._readiness_pool = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="sovereign-integrity-readiness"
        )
        self._max_jobs = max_jobs
        self._max_waiters = max_waiters
        self._queue_wait_seconds = float(queue_wait_seconds)
        self._active = 0
        self._waiting = 0
        self._rejected = 0
        self._completed = 0
        self._failed = 0
        self._closed = False
        self._readiness_future: Future[Any] | None = None
        self._readiness_scans = 0
        self._readiness_coalesced = 0

    async def run(self, operation: Callable[[], T]) -> T:
        """Perform fresh verification on a worker; never cache an approval."""
        if self._closed:
            raise IntegrityExecutorClosed("Integrity executor is shutting down")
        # This check and increment are on the owning event loop, without await.
        if self._active + self._waiting >= self._max_jobs + self._max_waiters:
            self._rejected += 1
            raise IntegrityCapacityExceeded("Integrity verification capacity exhausted")
        self._waiting += 1
        try:
            try:
                await asyncio.wait_for(self._slots.acquire(), timeout=self._queue_wait_seconds)
            except TimeoutError as exc:
                self._rejected += 1
                raise IntegrityCapacityExceeded(
                    "Integrity verification capacity exhausted"
                ) from exc
        finally:
            self._waiting -= 1
        if self._closed:
            self._slots.release()
            raise IntegrityExecutorClosed("Integrity executor is shutting down")
        try:
            submitted: Future[T] = self._pool.submit(operation)
        except RuntimeError as exc:
            self._slots.release()
            raise IntegrityExecutorClosed("Integrity executor is shutting down") from exc
        except BaseException:
            self._slots.release()
            raise
        self._active += 1
        loop = asyncio.get_running_loop()

        def completed(future: Future[T]) -> None:
            def finalize() -> None:
                self._active -= 1
                self._completed += 1
                self._failed += int(future.cancelled() or future.exception() is not None)
                self._slots.release()

            try:
                loop.call_soon_threadsafe(finalize)
            except RuntimeError:
                # Event loop is gone; no further admissions are possible.
                pass

        submitted.add_done_callback(completed)
        # shield prevents cancellation propagating into the concurrent future.
        return await asyncio.shield(asyncio.wrap_future(submitted))

    async def check_readiness(self, operation: Callable[[], T]) -> T:
        """Run full live-byte verification; overlap shares work, never cached."""
        if self._closed:
            raise IntegrityExecutorClosed("Integrity executor is shutting down")
        future = self._readiness_future
        if future is None or future.done():
            try:
                future = self._readiness_pool.submit(operation)
            except RuntimeError as exc:
                raise IntegrityExecutorClosed("Integrity executor is shutting down") from exc
            self._readiness_future = future
            self._readiness_scans += 1
        else:
            self._readiness_coalesced += 1
        # Caller cancellation cannot stop the ongoing model-file hash scan.
        return cast(T, await asyncio.shield(asyncio.wrap_future(future)))

    def snapshot(self) -> dict[str, int | bool]:
        return {
            "capacity": self._max_jobs,
            "max_waiters": self._max_waiters,
            "active_jobs": self._active,
            "waiting_for_capacity": self._waiting,
            "rejected": self._rejected,
            "completed": self._completed,
            "failed": self._failed,
            "readiness_running": self._readiness_future is not None
            and not self._readiness_future.done(),
            "readiness_scans": self._readiness_scans,
            "readiness_coalesced": self._readiness_coalesced,
        }

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Both pools drain submitted work. Shutdown does not block the loop.
        await asyncio.gather(
            asyncio.to_thread(self._pool.shutdown, wait=True, cancel_futures=False),
            asyncio.to_thread(self._readiness_pool.shutdown, wait=True, cancel_futures=False),
        )
