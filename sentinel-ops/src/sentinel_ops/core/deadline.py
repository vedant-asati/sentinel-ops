import time
from typing import Optional


class RunDeadlineExceeded(Exception):
    """Raised when the investigation run-wide deadline budget is exhausted."""
    pass


class DeadlineTracker:
    """Tracks run-wide latency budget and enforces per-call boundaries."""

    def __init__(self, deadline_seconds: float = 25.0):
        self.deadline_seconds = deadline_seconds
        self.start_time = time.monotonic()

    @property
    def elapsed(self) -> float:
        """Returns elapsed seconds since tracker initialization."""
        return time.monotonic() - self.start_time

    @property
    def remaining(self) -> float:
        """Returns remaining seconds before hard deadline is hit."""
        rem = self.deadline_seconds - self.elapsed
        return max(0.0, rem)

    def is_expired(self) -> bool:
        """True if the hard deadline has passed."""
        return self.remaining <= 0.0

    def check_deadline(self, step_name: str = "step") -> None:
        """Raises RunDeadlineExceeded if the deadline is expired."""
        if self.is_expired():
            raise RunDeadlineExceeded(
                f"Investigation deadline of {self.deadline_seconds}s exceeded during '{step_name}' "
                f"(elapsed: {self.elapsed:.2f}s)"
            )

    def bounded_timeout(self, desired_timeout: float) -> float:
        """Caps a desired timeout by the remaining total budget.
        Raises RunDeadlineExceeded if the deadline is already expired.
        Guarantees a strictly positive timeout for active sockets.
        """
        if self.is_expired() or self.remaining <= 0.0:
            raise RunDeadlineExceeded(
                f"Investigation deadline of {self.deadline_seconds}s exceeded before socket operation "
                f"(elapsed: {self.elapsed:.2f}s)"
            )
        return max(0.001, min(desired_timeout, self.remaining))
