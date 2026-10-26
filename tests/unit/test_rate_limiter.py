"""Unit tests for RateLimiter (R1)."""
from __future__ import annotations

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


# ── Reclaiming empty buckets ──────────────────────────────────────────────

def _key_count(rl: RateLimiter) -> int:
    return len(rl._global_buckets) + len(rl._tool_buckets)


def test_empty_buckets_are_removed_after_the_window(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    rl = RateLimiter(window_seconds=10, max_calls_per_window=5, max_calls_per_tool=5)
    rl.check("agent1", "a")
    rl.check("agent2", "b")
    assert _key_count(rl) == 4
    now[0] += 11
    rl.check("agent3", "c")
    assert set(rl._global_buckets) == {"agent3"}
    assert set(rl._tool_buckets) == {("agent3", "c")}


def test_bucket_with_live_timestamps_is_kept_across_a_sweep(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    rl = RateLimiter(window_seconds=10, max_calls_per_window=5, max_calls_per_tool=5)
    rl.check("agent1", "a")
    now[0] += 6
    rl.check("agent2", "b")
    now[0] += 6   # agent1's call is 12s old, agent2's is 6s old; a sweep runs
    rl.check("agent3", "c")
    assert "agent1" not in rl._global_buckets
    assert "agent2" in rl._global_buckets
    assert ("agent2", "b") in rl._tool_buckets


def test_limits_still_apply_across_a_prune_boundary(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    rl = RateLimiter(window_seconds=10, max_calls_per_window=2, max_calls_per_tool=2)
    assert rl.check("agent1", "a")[0]
    now[0] += 5
    assert rl.check("agent1", "a")[0]
    assert not rl.check("agent1", "a")[0]
    now[0] += 6   # first call aged out, second still live
    assert rl.check("agent1", "a")[0]
    assert not rl.check("agent1", "a")[0]


def test_invented_tool_names_across_windows_do_not_accumulate(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    rl = RateLimiter(window_seconds=10, max_calls_per_window=60, max_calls_per_tool=20)
    for window in range(40):
        for i in range(50):
            rl.check("agent1", f"invented-{window}-{i}")
        now[0] += 11
    rl.check("agent1", "real")
    assert _key_count(rl) <= 4
