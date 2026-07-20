"""Circuit breaker for adapters (scanners, audit sinks).

Three-state model: CLOSED → OPEN → HALF_OPEN.

CLOSED:    normal operation. Failures increment counter.
           When counter reaches failure_threshold → transition to OPEN.

OPEN:      adapter is skipped entirely. No calls made.
           After recovery_timeout seconds → transition to HALF_OPEN.

HALF_OPEN: one probe call is allowed.
           Success → CLOSED (counter reset).
           Failure → OPEN with doubled timeout (capped at max_recovery_timeout).

Thread/task safety: uses time.monotonic() for timekeeping; no locks needed
because Python's GIL protects the counter updates and state transitions
are idempotent. Safe for concurrent asyncio tasks in the same event loop.
"""
from __future__ import annotations

import logging
import time
from enum import StrEnum

log = logging.getLogger(__name__)

_DEFAULT_FAILURE_THRESHOLD   = 5
_DEFAULT_RECOVERY_TIMEOUT    = 60.0   # seconds
_MAX_RECOVERY_TIMEOUT        = 300.0  # 5 minutes cap


class CircuitState(StrEnum):
    CLOSED    = "closed"
    OPEN      = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Per-adapter circuit breaker.

    Usage in _scan.py::

        breaker = CircuitBreaker(name="injection_scan")

        if breaker.is_open:
            # skip this scanner entirely
            ...
        else:
            try:
                result = await scanner.scan(text, ctx)
                breaker.record_success()
            except Exception:
                breaker.record_failure()
    """

    def __init__(
        self,
        name: str,
        failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD,
        recovery_timeout: float = _DEFAULT_RECOVERY_TIMEOUT,
        max_recovery_timeout: float = _MAX_RECOVERY_TIMEOUT,
    ) -> None:
        self.name                 = name
        self._failure_threshold   = failure_threshold
        self._base_recovery       = recovery_timeout
        self._max_recovery        = max_recovery_timeout
        self._state               = CircuitState.CLOSED
        self._failure_count       = 0
        self._current_recovery    = recovery_timeout
        self._opened_at: float    = 0.0       # monotonic timestamp
        self._logged_open         = False      # log once per OPEN transition

    @property
    def state(self) -> CircuitState:
        """Current state, accounting for recovery timeout expiry."""
        if self._state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self._current_recovery:
                self._state = CircuitState.HALF_OPEN
        return self._state

    @property
    def is_open(self) -> bool:
        """True when the adapter should be skipped (OPEN state only)."""
        return self.state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """True when exactly one probe call is allowed."""
        return self.state == CircuitState.HALF_OPEN

    def record_success(self) -> None:
        """Called after a successful adapter call."""
        if self._state in (CircuitState.HALF_OPEN, CircuitState.OPEN):
            log.info("circuit breaker closed — adapter recovered",
                     extra={"adapter": self.name})
        self._state            = CircuitState.CLOSED
        self._failure_count    = 0
        self._current_recovery = self._base_recovery
        self._logged_open      = False

    def record_failure(self) -> None:
        """Called after a failed adapter call."""
        self._failure_count += 1

        if self._state == CircuitState.HALF_OPEN:
            # Probe failed — back to OPEN with doubled timeout (floor = base)
            self._current_recovery = min(
                max(self._current_recovery * 2, self._base_recovery),
                self._max_recovery,
            )
            self._transition_to_open()
            return

        if self._failure_count >= self._failure_threshold:
            self._transition_to_open()

    def _transition_to_open(self) -> None:
        self._state     = CircuitState.OPEN
        self._opened_at = time.monotonic()
        if not self._logged_open:
            log.warning(
                "circuit breaker open — adapter skipped",
                extra={
                    "adapter": self.name,
                    "failure_count": self._failure_count,
                    "recovery_timeout": self._current_recovery,
                },
            )
            self._logged_open = True

    def reset(self) -> None:
        """Force-reset to CLOSED. Used in tests and at shutdown."""
        self._state            = CircuitState.CLOSED
        self._failure_count    = 0
        self._current_recovery = self._base_recovery
        self._opened_open      = False
