"""Tests for SessionBudget — DoS / Unbounded Consumption enforcement."""
from __future__ import annotations

import pytest

from harness.boundaries.session_budget import ExecutionLimits, SessionBudget


# ── Fixtures ──────────────────────────────────────────────────────────────

@pytest.fixture
def budget():
    return SessionBudget()


def _limits(**kwargs) -> ExecutionLimits:
    return ExecutionLimits(**kwargs)


# ── Step counter ──────────────────────────────────────────────────────────

def test_step_counter_allows_under_limit(budget):
    limits = _limits(max_steps=3)
    for i in range(3):
        allowed, reason = budget.check("agent1", "sess1", "search", {}, limits)
        assert allowed, f"call {i+1} should be allowed"


def test_step_counter_blocks_at_limit(budget):
    limits = _limits(max_steps=2)
    budget.check("agent1", "sess1", "search", {}, limits)
    budget.check("agent1", "sess1", "search", {}, limits)
    allowed, reason = budget.check("agent1", "sess1", "search", {}, limits)
    assert not allowed
    assert "max_steps=2" in reason


def test_step_counter_per_session_isolation(budget):
    limits = _limits(max_steps=1)
    budget.check("agent1", "sess_a", "search", {}, limits)
    # sess_b should have its own counter
    allowed, reason = budget.check("agent1", "sess_b", "search", {}, limits)
    assert allowed


def test_step_counter_per_agent_isolation(budget):
    limits = _limits(max_steps=1)
    budget.check("agent1", "sess1", "search", {}, limits)
    # different agent — own counter
    allowed, _ = budget.check("agent2", "sess1", "search", {}, limits)
    assert allowed


# ── Token burn-down ───────────────────────────────────────────────────────

def test_token_budget_allows_under_limit(budget):
    limits = _limits(max_tokens_per_session=100)
    allowed, _ = budget.check("a", "s", "search", {}, limits, tokens_consumed=50)
    assert allowed
    allowed, _ = budget.check("a", "s", "search", {}, limits, tokens_consumed=49)
    assert allowed


def test_token_budget_blocks_when_exceeded(budget):
    limits = _limits(max_tokens_per_session=100)
    budget.check("a", "s", "search", {}, limits, tokens_consumed=80)
    allowed, reason = budget.check("a", "s", "search", {}, limits, tokens_consumed=30)
    assert not allowed
    assert "max_tokens_per_session=100" in reason


def test_token_budget_cost_weights(budget):
    limits = _limits(
        max_tokens_per_session=100,
        tool_cost_weights={"web_search": 3},
    )
    # 1 token × weight 3 = 3 effective tokens
    for _ in range(33):
        allowed, _ = budget.check("a", "s", "web_search", {}, limits, tokens_consumed=1)
        assert allowed
    # next call: 33*3=99 used, 1*3=3 more would exceed 100
    allowed, reason = budget.check("a", "s", "web_search", {}, limits, tokens_consumed=1)
    assert not allowed


# ── Per-prompt fan-out ────────────────────────────────────────────────────

def test_fanout_allows_under_limit(budget):
    limits = _limits(max_tool_calls_per_prompt=3)
    for _ in range(3):
        allowed, _ = budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
        assert allowed


def test_fanout_blocks_at_limit(budget):
    limits = _limits(max_tool_calls_per_prompt=2)
    budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    allowed, reason = budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    assert not allowed
    assert "max_tool_calls_per_prompt=2" in reason


def test_fanout_resets_on_new_prompt(budget):
    limits = _limits(max_tool_calls_per_prompt=2)
    budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    # new prompt — counter resets
    allowed, _ = budget.check("a", "s", "tool", {}, limits, prompt_id="p2")
    assert allowed


def test_fanout_skipped_without_prompt_id(budget):
    limits = _limits(max_tool_calls_per_prompt=1)
    for _ in range(5):
        allowed, _ = budget.check("a", "s", "tool", {}, limits, prompt_id=None)
        assert allowed  # fan-out disabled when prompt_id is None


def test_new_prompt_method_resets_fanout(budget):
    limits = _limits(max_tool_calls_per_prompt=1)
    budget.check("a", "s", "tool", {}, limits, prompt_id="p1")
    budget.new_prompt("a", "s", "p2")
    allowed, _ = budget.check("a", "s", "tool", {}, limits, prompt_id="p2")
    assert allowed


# ── Loop detection ────────────────────────────────────────────────────────

def test_loop_detection_blocks_exact_duplicate(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    budget.check("a", "s", "search", {"q": "cats"}, limits)
    allowed, reason = budget.check("a", "s", "search", {"q": "cats"}, limits)
    assert not allowed
    assert "loop detected" in reason


def test_loop_detection_allows_different_args(budget):
    limits = _limits(loop_detection_window=5, loop_similarity_threshold=0.95)
    budget.check("a", "s", "search", {"q": "cats"}, limits)
    allowed, _ = budget.check("a", "s", "search", {"q": "dogs"}, limits)
    assert allowed


def test_loop_detection_window_expires(budget):
    limits = _limits(loop_detection_window=2, loop_similarity_threshold=0.95)
    # Fill window with different calls
    budget.check("a", "s", "search", {"q": "cats"}, limits)
    budget.check("a", "s", "other",  {"x": "1"},    limits)
    budget.check("a", "s", "other2", {"x": "2"},    limits)
    # "cats" call is now outside the window of 2
    allowed, _ = budget.check("a", "s", "search", {"q": "cats"}, limits)
    assert allowed


def test_loop_detection_disabled_when_window_zero(budget):
    limits = _limits(loop_detection_window=0)
    for _ in range(10):
        allowed, _ = budget.check("a", "s", "search", {"q": "same"}, limits)
        assert allowed


# ── Reset ─────────────────────────────────────────────────────────────────

def test_reset_session_clears_state(budget):
    limits = _limits(max_steps=1)
    budget.check("a", "s", "tool", {}, limits)
    budget.reset("a", "s")
    allowed, _ = budget.check("a", "s", "tool", {}, limits)
    assert allowed


def test_reset_agent_clears_all_sessions(budget):
    limits = _limits(max_steps=1)
    budget.check("a", "s1", "tool", {}, limits)
    budget.check("a", "s2", "tool", {}, limits)
    budget.reset("a")
    for sid in ("s1", "s2"):
        allowed, _ = budget.check("a", sid, "tool", {}, limits)
        assert allowed


# ── Snapshot ──────────────────────────────────────────────────────────────

def test_snapshot_returns_zero_for_new_session(budget):
    snap = budget.snapshot("a", "new_session")
    assert snap == {"steps": 0, "tokens": 0, "prompt_calls": 0}


def test_snapshot_reflects_consumed_budget(budget):
    limits = _limits(max_steps=10, max_tokens_per_session=100)
    budget.check("a", "s", "tool", {}, limits, tokens_consumed=20, prompt_id="p1")
    budget.check("a", "s", "tool", {}, limits, tokens_consumed=15, prompt_id="p1")
    snap = budget.snapshot("a", "s")
    assert snap["steps"] == 2
    assert snap["tokens"] == 35
    assert snap["prompt_calls"] == 2


# ── No-op when limits are all None ────────────────────────────────────────

def test_noop_when_no_limits(budget):
    limits = _limits()  # all None
    for _ in range(100):
        allowed, _ = budget.check("a", "s", "tool", {}, limits)
        assert allowed
