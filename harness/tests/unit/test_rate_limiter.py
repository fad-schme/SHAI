"""Unit tests for RateLimiter (R1)."""
from __future__ import annotations

import asyncio
import time

import pytest

from harness.adapters.scanners.rate_limiter import RateLimiter


def test_allows_first_call():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=5, max_calls_per_tool=3)
    allowed, reason = rl.check("agent1", "search_docs")
    assert allowed is True
    assert reason is None


def test_global_limit_enforced():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=3, max_calls_per_tool=10)
    for _ in range(3):
        allowed, _ = rl.check("agent1", "search_docs")
        assert allowed
    allowed, reason = rl.check("agent1", "search_docs")
    assert allowed is False
    assert "60" in reason  # window mentioned
    assert "3" in reason   # limit mentioned


def test_per_tool_limit_enforced():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=100, max_calls_per_tool=2)
    rl.check("agent1", "send_email")
    rl.check("agent1", "send_email")
    allowed, reason = rl.check("agent1", "send_email")
    assert allowed is False
    assert "send_email" in reason


def test_per_tool_limit_does_not_affect_other_tools():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=100, max_calls_per_tool=1)
    rl.check("agent1", "send_email")
    rl.check("agent1", "send_email")  # exceeded
    # different tool should still be allowed
    allowed, _ = rl.check("agent1", "search_docs")
    assert allowed is True


def test_agents_are_isolated():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=1, max_calls_per_tool=10)
    rl.check("agent1", "search_docs")
    # agent1 is at limit — agent2 should be unaffected
    allowed, _ = rl.check("agent2", "search_docs")
    assert allowed is True


def test_reset_clears_agent_state():
    rl = RateLimiter(window_seconds=60, max_calls_per_window=1, max_calls_per_tool=1)
    rl.check("agent1", "search_docs")
    allowed, _ = rl.check("agent1", "search_docs")
    assert allowed is False
    rl.reset("agent1")
    allowed, _ = rl.check("agent1", "search_docs")
    assert allowed is True


def test_window_expiry():
    rl = RateLimiter(window_seconds=0.05, max_calls_per_window=1, max_calls_per_tool=10)
    rl.check("agent1", "search_docs")
    allowed, _ = rl.check("agent1", "search_docs")
    assert allowed is False
    time.sleep(0.06)
    allowed, _ = rl.check("agent1", "search_docs")
    assert allowed is True


def test_invalid_config():
    with pytest.raises(ValueError):
        RateLimiter(window_seconds=0)
    with pytest.raises(ValueError):
        RateLimiter(max_calls_per_window=0)
    with pytest.raises(ValueError):
        RateLimiter(max_calls_per_tool=0)


def test_concurrent_safety():
    """Multiple threads checking the same agent must not corrupt state."""
    import threading
    rl = RateLimiter(window_seconds=60, max_calls_per_window=50, max_calls_per_tool=50)
    results = []
    lock = threading.Lock()

    def call():
        allowed, _ = rl.check("agent1", "search_docs")
        with lock:
            results.append(allowed)

    threads = [threading.Thread(target=call) for _ in range(60)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed_count = sum(1 for r in results if r)
    assert allowed_count == 50  # exactly 50 allowed, 10 denied
