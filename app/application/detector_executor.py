"""Bounded nonblocking adapter for the existing synchronous Detector port.

One worker per adapter serializes use of the shared Presidio/spaCy analyzer.
The permit counts *submitted* jobs, not request coroutines: cancellation of an
awaiting request never frees a permit while its thread is still working.
"""

from __future__ import annotations

import asyncio
import math
import time
from concurrent.futures import Future, ThreadPoolExecutor

from app.domain.contracts import DetectionResult, Detector
from app.infrastructure.runtime_metrics import ExecutorMetrics


class DetectorCapacityExceeded(RuntimeError):
    """No executor job slot became available within the configured wait."""


class DetectorExecutorClosed(RuntimeError):
    """Detection was requested after shutdown began."""


class BoundedDetectorExecutor:
    """Offload one shared detector to one thread; bound running + queued work.

    Must be created and used on one application's event loop. Exactly one
    worker avoids relying on Presidio/spaCy analyzer thread safety. This is
    not a CPU-parallelism improvement; it improves event-loop responsiveness.
    """

    def __init__(
        self,
        detector: Detector,
        *,
        max_jobs: int = 8,
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
        self._detector = detector
        self._slots = asyncio.Semaphore(max_jobs)
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="sovereign-detector")
        self._queue_wait_seconds = float(queue_wait_seconds)
        self._closed = False
        self.metrics = ExecutorMetrics(max_jobs, sample_window)

    async def detect(self, prompt: str) -> DetectionResult:
        if self._closed:
            raise DetectorExecutorClosed("Detector executor is shutting down")
        requested_at = time.perf_counter()
        self.metrics.begin_wait()
        try:
            await asyncio.wait_for(self._slots.acquire(), timeout=self._queue_wait_seconds)
        except TimeoutError as exc:
            self.metrics.refuse()
            raise DetectorCapacityExceeded("Detector executor capacity exhausted") from exc
        finally:
            self.metrics.end_wait()

        # No await between checking closed state and submitting the job.
        if self._closed:
            self._slots.release()
            raise DetectorExecutorClosed("Detector executor is shutting down")
        started_at: list[float | None] = [None]
        stopped_at: list[float | None] = [None]

        def timed_detection() -> DetectionResult:
            started_at[0] = time.perf_counter()
            try:
                return self._detector.detect(prompt)
            finally:
                stopped_at[0] = time.perf_counter()

        try:
            submitted: Future[DetectionResult] = self._executor.submit(timed_detection)
        except BaseException:
            self._slots.release()
            raise

        self.metrics.submit("detect")
        loop = asyncio.get_running_loop()

        def after_real_completion(_: Future[DetectionResult]) -> None:
            # Completion is the *concurrent.futures* Future, not the cancelled
            # asyncio wrapper. A running thread may outlive its awaiting request.
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
        return await asyncio.wrap_future(submitted)

    async def aclose(self) -> None:
        """Stop admission and drain real detector jobs without blocking the loop."""
        if self._closed:
            return
        self._closed = True
        await asyncio.to_thread(self._executor.shutdown, wait=True, cancel_futures=False)
