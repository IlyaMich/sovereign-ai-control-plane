"""Bounded, nonblocking adapter around the existing synchronous audit store.

Single worker preserves in-process writer order; SQLite BEGIN IMMEDIATE remains
responsible for serialization across independent processes. Submitted operations
are shielded from request cancellation, so cancellation cannot cancel a queued
precommit or release capacity before the actual database operation finishes.

A cancelled caller will *not* invoke the model. Its decision may still commit,
creating a decision without an outcome; reconciliation belongs to M7.4.
"""

from __future__ import annotations

import asyncio
import math
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, Protocol, TypeVar

from app.audit.sqlite_store import AuditUnavailable
from app.domain.contracts import AuditReceipt
from app.infrastructure.runtime_metrics import ExecutorMetrics

T = TypeVar("T")


class SynchronousAuditBackend(Protocol):
    def commit(
        self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]
    ) -> AuditReceipt: ...

    def get_events(self, request_id: str, tenant_id: str) -> list[dict[str, Any]]: ...

    def check_writable(self) -> None: ...


class AuditCapacityExceeded(AuditUnavailable):
    """No audit executor capacity was available before the configured deadline."""


class AuditExecutorClosed(AuditUnavailable):
    """Audit executor is draining and no longer admits operations."""


class BoundedAuditExecutor:
    """One nonblocking audit execution lane, with bounded running + pending work.

    Each instance belongs to one FastAPI process/event loop. The queue bound is
    independent of M7.1 request admission and the M7.2 detector queue.
    """

    def __init__(
        self,
        store: SynchronousAuditBackend,
        *,
        max_jobs: int = 16,
        queue_wait_seconds: float = 1.0,
        sample_window: int = 512,
    ) -> None:
        if type(max_jobs) is not int or not 1 <= max_jobs <= 1024:
            raise ValueError("max_jobs must be an integer between 1 and 1024")
        if (
            isinstance(queue_wait_seconds, bool)
            or not isinstance(queue_wait_seconds, (int, float))
            or not math.isfinite(queue_wait_seconds)
            or queue_wait_seconds <= 0
        ):
            raise ValueError("queue_wait_seconds must be a finite positive number")
        self._store = store
        self._slots = asyncio.Semaphore(max_jobs)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sovereign-audit")
        self._queue_wait_seconds = float(queue_wait_seconds)
        self._closed = False
        self.metrics = ExecutorMetrics(max_jobs, sample_window)

    async def _execute(self, operation: Callable[[], T], *, kind: str = "aux") -> T:
        if self._closed:
            raise AuditExecutorClosed("Audit executor is shutting down")
        requested_at = time.perf_counter()
        self.metrics.begin_wait()
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=self._queue_wait_seconds)
        except TimeoutError as exc:
            self.metrics.refuse()
            raise AuditCapacityExceeded("Audit executor capacity exhausted") from exc
        finally:
            self.metrics.end_wait()
        if self._closed:
            self._slots.release()
            raise AuditExecutorClosed("Audit executor is shutting down")
        started_at: list[float | None] = [None]
        stopped_at: list[float | None] = [None]

        def timed_operation() -> T:
            started_at[0] = time.perf_counter()
            try:
                return operation()
            finally:
                stopped_at[0] = time.perf_counter()

        try:
            submitted: Future[T] = self._executor.submit(timed_operation)
        except RuntimeError as exc:
            self._slots.release()
            raise AuditExecutorClosed("Audit executor is shutting down") from exc
        except BaseException:
            self._slots.release()
            raise

        self.metrics.submit(kind)
        loop = asyncio.get_running_loop()

        def after_real_completion(_: Future[T]) -> None:
            # Release only when the *thread-pool* future actually completes. An
            # asyncio caller may already have been cancelled at this point.
            def finalize() -> None:
                now = time.perf_counter()
                began = started_at[0] if started_at[0] is not None else now
                ended = stopped_at[0] if stopped_at[0] is not None else now
                self.metrics.finish(
                    (began - requested_at) * 1000,
                    (ended - began) * 1000,
                    submitted.cancelled() or submitted.exception() is not None,
                )
                self._slots.release()

            try:
                loop.call_soon_threadsafe(finalize)
            except RuntimeError:
                # No more requests can enter after a closed event loop.
                pass

        submitted.add_done_callback(after_real_completion)
        # shield is crucial: cancellation of an awaiting request must NOT cancel
        # the queued concurrent.futures.Future (or forge an audit success).
        return await asyncio.shield(asyncio.wrap_future(submitted))

    async def run(self, operation: Callable[[], T]) -> T:
        """Run internal auxiliary SQLite operations in the existing bounded lane."""
        return await self._execute(operation, kind="aux")

    async def commit(
        self, request_id: str, tenant_id: str, event_type: str, payload: dict[str, Any]
    ) -> AuditReceipt:
        return await self._execute(
            partial(self._store.commit, request_id, tenant_id, event_type, payload),
            kind="commit_" + event_type.lower(),
        )

    async def get_events(self, request_id: str, tenant_id: str) -> list[dict[str, Any]]:
        return await self._execute(
            partial(self._store.get_events, request_id, tenant_id), kind="read"
        )

    async def check_writable(self) -> None:
        await self._execute(self._store.check_writable, kind="probe")

    async def aclose(self) -> None:
        """Stop accepting new work and drain all submitted operations."""
        if self._closed:
            return
        self._closed = True
        await asyncio.to_thread(self._executor.shutdown, wait=True, cancel_futures=False)
