"""RateLimiter — per-agent tool call rate limiting.

Mitigates T4 (Resource Overload) and T2 (Tool Misuse / flooding).

Two independent sliding-window counters per agent:
  - global:   total tool calls across all tools in the window
  - per-tool: calls to the same tool in the window

Both limits must be satisfied for a call to proceed.
Counters are maintained in memory using deques of timestamps.
Keys expire after the window elapses with no activity to prevent unbounded growth.

Not a Scanner — called directly by check_tool_call before the gate runs.
Returns (allowed: bool, reason: str | None).
"""
from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Sliding-window rate limiter for tool calls.

    Thread-safe via per-bucket locks.
    Deque entries are (timestamp_seconds, ).
    Old entries are pruned on every check — O(1) amortised.
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_calls_per_window: int = 60,
        max_calls_per_tool: int = 20,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_calls_per_window <= 0 or max_calls_per_tool <= 0:
            raise ValueError("rate limits must be positive")

        self._window   = window_seconds
        self._global   = max_calls_per_window
        self._per_tool = max_calls_per_tool

        # {agent_id: deque[float]}         — global call timestamps
        self._global_buckets: dict[str, deque] = {}
        # {(agent_id, tool_name): deque[float]} — per-tool timestamps
        self._tool_buckets: dict[tuple, deque] = {}
        self._lock = threading.Lock()

    def check(self, agent_id: str, tool_name: str) -> tuple[bool, str | None]:
        """Check and record a tool call attempt.

        Returns (allowed, deny_reason).
        deny_reason is None when allowed=True.
        Must be called before the gate — records the attempt even on deny.
        """
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            # ── Global bucket ──────────────────────────────────────────────
            if agent_id not in self._global_buckets:
                self._global_buckets[agent_id] = deque()
            gbucket = self._global_buckets[agent_id]
            self._prune(gbucket, cutoff)

            if len(gbucket) >= self._global:
                return False, (
                    f"rate limit exceeded: {len(gbucket)} calls in last "
                    f"{self._window:.0f}s (max {self._global})"
                )

            # ── Per-tool bucket ────────────────────────────────────────────
            key = (agent_id, tool_name)
            if key not in self._tool_buckets:
                self._tool_buckets[key] = deque()
            tbucket = self._tool_buckets[key]
            self._prune(tbucket, cutoff)

            if len(tbucket) >= self._per_tool:
                return False, (
                    f"rate limit exceeded: tool '{tool_name}' called "
                    f"{len(tbucket)} times in last {self._window:.0f}s "
                    f"(max {self._per_tool})"
                )

            # ── Record the call ────────────────────────────────────────────
            gbucket.append(now)
            tbucket.append(now)
            return True, None

    def reset(self, agent_id: str) -> None:
        """Clear all buckets for an agent. Used in tests and agent deregistration."""
        with self._lock:
            self._global_buckets.pop(agent_id, None)
            keys = [k for k in self._tool_buckets if k[0] == agent_id]
            for k in keys:
                del self._tool_buckets[k]

    @staticmethod
    def _prune(bucket: deque, cutoff: float) -> None:
        """Remove timestamps older than cutoff from the left of the deque."""
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
