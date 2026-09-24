"""Tests for SessionBudget — DoS / Unbounded Consumption enforcement."""
from __future__ import annotations

import pytest

from harness.adapters.state_store.memory_store import InMemoryStore
from harness.boundaries.session_budget import ExecutionLimits, SessionBudget

# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def budget():
    return SessionBudget(InMemoryStore())


def _limits(**kwargs) -> ExecutionLimits:
    return ExecutionLimits(**kwargs)


# ── Step counter ──────────────────────────────────────────────────────────

async def test_step_counter_allows_under_limit(budget):
    limits = _limits(max_steps=3)
    for i in range(3):
        allowed, reason = await budget.check("agent1", "sess1", "search", {}, limits)
        assert allowed, f"call {i+1} should be allowed"


async def test_step_counter_blocks_at_limit(budget):
    limits = _limits(max_steps=2)
    await budget.check("agent1", "sess1", "search", {}, limits)
    await budget.check("agent1", "sess1", "search", {}, limits)
    allowed, reason = await budget.check("agent1", "sess1", "search", {}, limits)
    assert not allowed
    assert "max_steps=2" in reason


async def test_step_counter_per_session_isolation(budget):
    limits = _limits(max_steps=1)
    await budget.check("agent1", "sess_a", "search", {}, limits)
    # sess_b should have its own counter
    allowed, reason = await budget.check("agent1", "sess_b", "search", {}, limits)
    assert allowed


async def test_step_counter_per_agent_isolation(budget):
    limits = _limits(max_steps=1)
    await budget.check("agent1", "sess1", "search", {}, limits)
    # different agent — own counter
    allowed, _ = await budget.check("agent2", "sess1", "search", {}, limits)
    assert allowed


# ── Per-prompt fan-out ────────────────────────────────────────────────────

async def test_fanout_allows_under_limit(budget):
    limits = _limits(max_tool_calls_per_prompt=3)
    for _ in range(3):
        allowed, _ = await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
        assert allowed


async def test_fanout_blocks_at_limit(budget):
    limits = _limits(max_tool_calls_per_prompt=2)
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    allowed, reason = await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    assert not allowed
    assert "max_tool_calls_per_prompt=2" in reason


async def test_fanout_resets_on_new_prompt(budget):
    limits = _limits(max_tool_calls_per_prompt=2)
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    # new prompt — counter resets
    allowed, _ = await budget.check("a", "s", "tool", {}, limits, prompt_id="p2")
    assert allowed


async def test_fanout_skipped_without_prompt_id(budget):
    limits = _limits(max_tool_calls_per_prompt=1)
    for _ in range(5):
        allowed, _ = await budget.check("a", "s", "tool", {}, limits, prompt_id=None)
        assert allowed  # fan-out disabled when prompt_id is None


# ── Loop detection ────────────────────────────────────────────────────────

async def test_loop_detection_blocks_exact_duplicate(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    await budget.check("a", "s", "search", {"q": "cats"}, limits)
    allowed, reason = await budget.check("a", "s", "search", {"q": "cats"}, limits)
    assert not allowed
    assert "loop detected" in reason


async def test_loop_detection_allows_different_args(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    await budget.check("a", "s", "search", {"q": "cats"}, limits)
    allowed, _ = await budget.check("a", "s", "search", {"q": "dogs"}, limits)
    assert allowed


async def test_loop_detection_window_expires(budget):
    limits = _limits(loop_detection_window=2, loop_similarity_threshold=0.95)
    # Fill window with different calls
    await budget.check("a", "s", "search", {"q": "cats"}, limits)
    await budget.check("a", "s", "other",  {"x": "1"},    limits)
    await budget.check("a", "s", "other2", {"x": "2"},    limits)
    # "cats" call is now outside the window of 2
    allowed, _ = await budget.check("a", "s", "search", {"q": "cats"}, limits)
    assert allowed


async def test_loop_detection_disabled_when_window_zero(budget):
    limits = _limits(loop_detection_window=0)
    for _ in range(10):
        allowed, _ = await budget.check("a", "s", "search", {"q": "same"}, limits)
        assert allowed


# ── Reset ─────────────────────────────────────────────────────────────────

async def test_reset_session_clears_state(budget):
    limits = _limits(max_steps=1)
    await budget.check("a", "s", "tool", {}, limits)
    await budget.reset("a", "s")
    allowed, _ = await budget.check("a", "s", "tool", {}, limits)
    assert allowed


async def test_reset_agent_clears_all_sessions(budget):
    limits = _limits(max_steps=1)
    await budget.check("a", "s1", "tool", {}, limits)
    await budget.check("a", "s2", "tool", {}, limits)
    await budget.reset("a")
    for sid in ("s1", "s2"):
        allowed, _ = await budget.check("a", sid, "tool", {}, limits)
        assert allowed


# ── Snapshot ──────────────────────────────────────────────────────────────

async def test_snapshot_returns_zero_for_new_session(budget):
    snap = await budget.snapshot("a", "new_session")
    assert snap == {"steps": 0, "prompt_calls": 0}


async def test_snapshot_reflects_consumed_budget(budget):
    limits = _limits(max_steps=10)
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    await budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    snap = await budget.snapshot("a", "s")
    assert snap["steps"] == 2
    assert snap["prompt_calls"] == 2


# ── No-op when limits are all None ────────────────────────────────────────

async def test_noop_when_no_limits(budget):
    limits = _limits()  # all None
    for _ in range(100):
        allowed, _ = await budget.check("a", "s", "tool", {}, limits)
        assert allowed


# ── Sessions never share state ────────────────────────────────────────────

async def test_same_call_in_two_sessions_is_not_a_loop(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    first, _ = await budget.check("a", "s1", "search", {"q": "cats"}, limits)
    second, reason = await budget.check("a", "s2", "search", {"q": "cats"}, limits)
    assert first and second, reason


async def test_same_call_by_two_agents_is_not_a_loop(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    await budget.check("a", "s", "search", {"q": "cats"}, limits)
    allowed, reason = await budget.check("b", "s", "search", {"q": "cats"}, limits)
    assert allowed, reason


def test_each_session_starts_from_its_own_state():
    from harness.boundaries.session_budget import _new_state
    a, b = _new_state(), _new_state()
    a["recent_fingerprints"].append(["x"])
    assert b["recent_fingerprints"] == []
