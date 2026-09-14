"""
backoff.py -- generic exponential backoff for recovery/retry actions.

Built standalone (no engine imports) so it's reusable outside the health manager
too -- e.g. a future retrofit into scripts/scheduler.py's own currently-zero
retry logic (see that file: fire-and-forget subprocess.Popen, no backoff at all
today). Schedule matches My_way_forward.txt's own worked example: 1st attempt
immediate, then 30s/2min/10min, then stop and require a human.
"""
import time
from typing import List, Optional


class RecoveryBackoff:
    """Tracks attempts for ONE recoverable condition (e.g. one component's
    UNHEALTHY streak). Not thread-safe by itself -- callers (HealthManager) own
    one instance per component and only ever touch it from their own single
    check-loop thread, so no lock is needed here."""

    SCHEDULE: List[float] = [0.0, 30.0, 120.0, 600.0]

    def __init__(self, max_attempts: int = 5):
        self.max_attempts = max_attempts
        self._attempt_count = 0
        self._last_attempt_at: Optional[float] = None

    def attempt_allowed(self, now: Optional[float] = None) -> bool:
        """True if enough time has passed since the last attempt (per SCHEDULE)
        AND max_attempts hasn't been exhausted yet."""
        if self.exhausted():
            return False
        if self._last_attempt_at is None:
            return True
        now = now if now is not None else time.time()
        # SCHEDULE[0] is the wait before the 1st attempt (0, immediate);
        # SCHEDULE[N] is the wait before the (N+1)-th attempt. After
        # _attempt_count attempts have already been recorded, the wait required
        # before the NEXT one is SCHEDULE[_attempt_count] -- NOT
        # SCHEDULE[_attempt_count - 1], which would (and did, before this fix)
        # reuse the wait for the attempt that already happened, making every
        # subsequent attempt immediately allowed instead of backing off.
        idx = min(self._attempt_count, len(self.SCHEDULE) - 1)
        required_wait = self.SCHEDULE[idx]
        return (now - self._last_attempt_at) >= required_wait

    def record_attempt(self, now: Optional[float] = None) -> None:
        self._attempt_count += 1
        self._last_attempt_at = now if now is not None else time.time()

    def exhausted(self) -> bool:
        return self._attempt_count >= self.max_attempts

    def reset(self) -> None:
        self._attempt_count = 0
        self._last_attempt_at = None

    @property
    def attempt_count(self) -> int:
        return self._attempt_count
