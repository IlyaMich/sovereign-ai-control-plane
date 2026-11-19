"""Reject-fast, per-event-loop bounded admission for prompt processing.

One instance is created per FastAPI app/worker. Calls must be made on that
app's event-loop thread (without an intervening await between check and increment).
This does NOT bound request-body parsing, cross-process load or CPU thread pools.
"""

from dataclasses import dataclass


@dataclass(slots=True)
class InFlightAdmission:
    limit: int
    active: int = 0
    peak_active: int = 0
    rejected: int = 0

    def __post_init__(self) -> None:
        if type(self.limit) is not int or not 1 <= self.limit <= 1024:
            raise ValueError("Admission capacity must be between 1 and 1024")

    def try_enter(self) -> bool:
        """Acquire immediately or reject; no async wait queue can grow here."""
        if self.active >= self.limit:
            self.rejected += 1
            return False
        self.active += 1
        self.peak_active = max(self.peak_active, self.active)
        return True

    def leave(self) -> None:
        if self.active <= 0:
            raise RuntimeError("Unbalanced admission release")
        self.active -= 1
