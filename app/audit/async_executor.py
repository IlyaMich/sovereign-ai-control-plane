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
import logging
import math
import time
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, Protocol, TypeVar

from app.audit.sqlite_store import AuditUnavailable
from app.domain.contracts import AuditReceipt
from app.infrastructure.logging import context, event
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
        max_waiters: int = 8,
        max_auxiliary_jobs: int = 4,
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
        for name, count in (
            ("max_waiters", max_waiters),
            ("max_auxiliary_jobs", max_auxiliary_jobs),
        ):
            if type(count) is not int or not 1 <= count <= 1024:
                raise ValueError(f"{name} must be an integer between 1 and 1024")
        self._max_waiters = max_waiters
        # When multiple submissions are possible, reserve at least one
        # job slot for DECISION/OUTCOME writes against auxiliary saturation.
        self._max_auxiliary_jobs = min(max_auxiliary_jobs, max(1, max_jobs - 1))
        self._slot_waiters = 0
        self._auxiliary_inflight = 0
        self._store = store
        self._slots = asyncio.Semaphore(max_jobs)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sovereign-audit")
        self._queue_wait_seconds = float(queue_wait_seconds)
        self._closed = False
        self.metrics = ExecutorMetrics(max_jobs, sample_window)

    def capacity_snapshot(self) -> dict[str, int]:
        """Process-local capacity limits; no request or tenant identifiers."""
        return {
            "maximum_waiters": self._max_waiters,
            "waiting_for_slot": self._slot_waiters,
            "maximum_auxiliary_jobs": self._max_auxiliary_jobs,
            "auxiliary_inflight": self._auxiliary_inflight,
        }

    def _refuse_capacity(self, reason: str) -> None:
        self.metrics.refuse()
        event(
            "audit_capacity_exceeded",
            level=logging.WARNING,
            limited=True,
            error_code="AUDIT_CAPACITY_EXCEEDED",
            stage=reason,
        )
        raise AuditCapacityExceeded("Audit executor capacity exhausted")

    async def _execute(self, operation: Callable[[], T], *, kind: str = "aux") -> T:
        if self._closed:
            raise AuditExecutorClosed("Audit executor is shutting down")

        # Reserve auxiliary capacity before any await. Holding this reservation
        # until the *real* thread future completes also covers cancelled callers.
        auxiliary = kind in {"aux", "read", "probe"}
        if auxiliary:
            if self._auxiliary_inflight >= self._max_auxiliary_jobs:
                self._refuse_capacity("auxiliary")
            self._auxiliary_inflight += 1

        acquired = False
        handed_off = False
        try:
            # A coroutine may enter wait_for before the Semaphore's internal
            # acquire task executes. Count those callers explicitly rather than
            # using semaphore.locked() as an optimistic capacity test.
            if self.metrics.active + self._slot_waiters >= (
                self.metrics.capacity + self._max_waiters
            ):
                self._refuse_capacity("waiters")
            requested_at = time.perf_counter()
            self._slot_waiters += 1
            self.metrics.begin_wait()
            try:
                try:
                    await asyncio.wait_for(self._slots.acquire(), timeout=self._queue_wait_seconds)
                    acquired = True
                except TimeoutError as exc:
                    self.metrics.refuse()
                    event(
                        "audit_capacity_exceeded",
                        level=logging.WARNING,
                        limited=True,
                        error_code="AUDIT_CAPACITY_EXCEEDED",
                        stage="timeout",
                    )
                    raise AuditCapacityExceeded("Audit executor capacity exhausted") from exc
            finally:
                self._slot_waiters -= 1
                self.metrics.end_wait()

            if self._closed:
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
                raise AuditExecutorClosed("Audit executor is shutting down") from exc

            handed_off = True
            self.metrics.submit(kind)
            loop = asyncio.get_running_loop()
            captured_context = dict(context.get() or {})
            caller_cancelled = False

            def after_real_completion(_: Future[T]) -> None:
                def finalize() -> None:
                    now = time.perf_counter()
                    began = started_at[0] if started_at[0] is not None else now
                    ended = stopped_at[0] if stopped_at[0] is not None else now
                    failed = submitted.cancelled() or submitted.exception() is not None
                    self.metrics.finish(
                        (began - requested_at) * 1000,
                        (ended - began) * 1000,
                        failed,
                    )
                    self._slots.release()
                    if auxiliary:
                        self._auxiliary_inflight -= 1
                    event(
                        "audit_operation_finished",
                        level=logging.ERROR if failed else logging.DEBUG,
                        correlation_id=captured_context.get("correlation_id"),
                        request_id=captured_context.get("request_id"),
                        event_type=kind,
                        error_code="AUDIT_OPERATION_FAILED" if failed else "NONE",
                        state="CALLER_CANCELLED" if caller_cancelled else "CALLER_WAITING",
                        queue_wait_ms=round((began - requested_at) * 1000, 3),
                        processing_ms=round((ended - began) * 1000, 3),
                    )

                try:
                    loop.call_soon_threadsafe(finalize)
                except RuntimeError:
                    # Closed loop cannot admit further work, so no reusable slot.
                    pass

            submitted.add_done_callback(after_real_completion)
            # Do not cancel an already-submitted SQLite operation on HTTP disconnect.
            try:
                return await asyncio.shield(asyncio.wrap_future(submitted))
            except asyncio.CancelledError:
                caller_cancelled = True
                event(
                    "audit_wait_cancelled",
                    level=logging.WARNING,
                    correlation_id=captured_context.get("correlation_id"),
                    request_id=captured_context.get("request_id"),
                    stage="audit",
                )
                raise
        finally:
            if not handed_off:
                if acquired:
                    self._slots.release()
                if auxiliary:
                    self._auxiliary_inflight -= 1

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
