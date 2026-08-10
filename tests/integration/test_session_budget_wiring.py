"""Integration tests — SessionBudget wired through the real SHAI facade.

`test_session_budget.py` exercises SessionBudget.check() directly, passing
session_id and prompt_id by hand. Those tests passed for the entire time three
of the four controls were unreachable in production, because the facade never
supplied either value. These tests drive `SHAI.check_tool_call` instead, which
is the only path that proves the controls are actually connected.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.tools.tool import Tool

AGENT    = "budget_agent"
SUBAGENT = "budget_sub"


async def _harness(tmp_path: Path, **limits) -> SHAI:
    """Real SHAI with one agent carrying the given execution limits."""
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    limit_lines = "".join(f"  {k}: {v}\n" for k, v in limits.items())
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"id: {AGENT}\n"
        f"allowed_tool_names:\n  - search_docs\n  - list_inbox\n"
        f"allowed_tags:\n  - read\n  - internal\n"
        f"policy_rules: []\n"
        f"limits:\n{limit_lines}"
        f"sub_agents:\n"
        f"  - id: {SUBAGENT}\n"
        f"    allowed_tool_names:\n      - search_docs\n"
        f"    allowed_tags:\n      - read\n      - internal\n"
        f"    policy_rules: []\n"
    )
    h = await SHAI.from_yaml(cfg)
    await h.load_agent(agent)
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"], transport=Transport.LOCAL),
    ])
    return h


# ── Per-prompt fan-out ────────────────────────────────────────────────────

async def test_fanout_limit_fires_within_a_turn(tmp_path: Path):
    """max_tool_calls_per_prompt enforces once scan_input has opened a turn."""
    h   = await _harness(tmp_path, max_tool_calls_per_prompt=2)
    ctx = AgentContext(agent_id=AGENT, conversation_id="c1")
    await h.scan_input("hello", ctx)          # opens the turn

    assert (await h.check_tool_call("search_docs", {}, ctx)).allowed
    assert (await h.check_tool_call("search_docs", {}, ctx)).allowed
    third = await h.check_tool_call("search_docs", {}, ctx)
    assert not third.allowed
    assert "max_tool_calls_per_prompt" in third.deny_reason


async def test_fanout_counter_resets_on_next_turn(tmp_path: Path):
    """A fresh scan_input is a new turn, so the fan-out budget starts over."""
    h   = await _harness(tmp_path, max_tool_calls_per_prompt=1)
    ctx = AgentContext(agent_id=AGENT, conversation_id="c1")

    await h.scan_input("first", ctx)
    assert (await h.check_tool_call("search_docs", {}, ctx)).allowed
    assert not (await h.check_tool_call("search_docs", {}, ctx)).allowed

    await h.scan_output("reply", ctx)
    await h.scan_input("second", ctx)         # new turn
    assert (await h.check_tool_call("search_docs", {}, ctx)).allowed


# ── Session scoping ───────────────────────────────────────────────────────

async def test_budgets_are_scoped_per_conversation(tmp_path: Path):
    """Two conversations for one agent hold independent budgets.

    Before the fix every conversation collapsed onto the agent_id key, so one
    conversation could exhaust the budget for all of them.
    """
    h    = await _harness(tmp_path, max_steps=2)
    one  = AgentContext(agent_id=AGENT, conversation_id="c1")
    two  = AgentContext(agent_id=AGENT, conversation_id="c2")

    assert (await h.check_tool_call("search_docs", {}, one)).allowed
    assert (await h.check_tool_call("search_docs", {}, one)).allowed
    assert not (await h.check_tool_call("search_docs", {}, one)).allowed

    # c2 is untouched by c1 exhausting its steps
    assert (await h.check_tool_call("search_docs", {}, two)).allowed
    assert (await h.check_tool_call("search_docs", {}, two)).allowed
    assert not (await h.check_tool_call("search_docs", {}, two)).allowed


async def test_subagent_shares_the_parent_session_budget(tmp_path: Path):
    """Delegation must not hand out a fresh step budget.

    scope_subagent() has to carry conversation_id through, or the subagent
    keys on (agent_id, agent_id) while the parent keys on the conversation —
    two buckets, and an agent that exhausts max_steps can simply delegate.
    """
    h      = await _harness(tmp_path, max_steps=2)
    parent = AgentContext(agent_id=AGENT, conversation_id="c1")

    assert (await h.check_tool_call("search_docs", {}, parent)).allowed
    assert (await h.check_tool_call("search_docs", {}, parent)).allowed
    assert not (await h.check_tool_call("search_docs", {}, parent)).allowed

    sub = h.scope_context_for_subagent(parent, SUBAGENT)
    assert sub.conversation_id == parent.conversation_id
    denied = await h.check_tool_call("search_docs", {}, sub)
    assert not denied.allowed
    assert "max_steps" in denied.deny_reason


# ── Invalid limits fail closed ────────────────────────────────────────────

def _bare_harness_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    return cfg


async def test_invalid_agent_limits_raise_rather_than_falling_back(tmp_path: Path):
    """An unusable limits: block must not silently disarm the agent.

    Falling back to global defaults would discard the agent's valid max_steps
    along with the bad key, leaving it unbounded when the global budget sets
    no ceiling. harness.yaml already fails closed on the same error.
    """
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"id: {AGENT}\n"
        f"allowed_tool_names:\n  - search_docs\n"
        f"allowed_tags:\n  - read\n  - internal\n"
        f"policy_rules: []\n"
        f"limits:\n  max_steps: 2\n  no_such_limit: 1000\n"
    )
    h = await SHAI.from_yaml(_bare_harness_yaml(tmp_path))
    with pytest.raises(ConfigError, match="invalid limits"):
        await h.load_agent(agent)


async def test_failed_load_leaves_no_half_registered_agent(tmp_path: Path):
    """Raising is not enough — the agent must not remain usable.

    The budget check is skipped entirely when `_agent_limits` has no entry, so
    an agent left registered by a partial load would run with no ceiling at
    all: the same failure the raise exists to prevent, reached another way.
    """
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"id: {AGENT}\n"
        f"allowed_tool_names:\n  - search_docs\n"
        f"allowed_tags:\n  - read\n  - internal\n"
        f"policy_rules: []\n"
        f"limits:\n  max_steps: 2\n  no_such_limit: 1000\n"
    )
    h = await SHAI.from_yaml(_bare_harness_yaml(tmp_path))
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    ])

    with pytest.raises(ConfigError):
        await h.load_agent(agent)

    assert AGENT not in [a.id for a in h.maintenance.registered_agents()]
    assert AGENT not in h._agent_limits
    assert AGENT not in h._agent_tools


async def test_failed_reload_keeps_the_previous_definition(tmp_path: Path):
    """A rejected reload must leave the running agent exactly as it was.

    Registry, resolved tools, and limits have to move together — a reload that
    swapped the config but kept the old limits would run new tools under stale
    ceilings.
    """
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        f"id: {AGENT}\n"
        f"allowed_tool_names:\n  - search_docs\n"
        f"allowed_tags:\n  - read\n  - internal\n"
        f"policy_rules: []\n"
        f"limits:\n  max_steps: 1\n"
    )
    h = await SHAI.from_yaml(_bare_harness_yaml(tmp_path))
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    ])
    await h.load_agent(agent)

    agent.write_text(
        f"id: {AGENT}\n"
        f"allowed_tool_names:\n  - search_docs\n"
        f"allowed_tags:\n  - read\n  - internal\n"
        f"policy_rules: []\n"
        f"limits:\n  max_steps: 99\n  no_such_limit: 1000\n"
    )
    with pytest.raises(ConfigError):
        await h.maintenance.reload_agent(agent)

    assert h._agent_limits[AGENT].max_steps == 1
    assert h._agent_registry.get(AGENT).limits == {"max_steps": 1}

    # And the old ceiling is still enforced end to end.
    ctx = AgentContext(agent_id=AGENT, conversation_id="c1")
    assert (await h.check_tool_call("search_docs", {}, ctx)).allowed
    assert not (await h.check_tool_call("search_docs", {}, ctx)).allowed


# ── Loop detection reachability ───────────────────────────────────────────

async def test_loop_detection_only_config_is_reachable(tmp_path: Path):
    """Loop detection with no numeric limit set must still reach the enforcer.

    any_enabled() gates the whole call; omitting loop_detection_window from it
    left this configuration silently unenforced.
    """
    h   = await _harness(tmp_path, loop_detection_window=5)
    ctx = AgentContext(agent_id=AGENT, conversation_id="c1")
    await h.scan_input("hello", ctx)

    args = {"query": "same thing"}
    assert (await h.check_tool_call("search_docs", args, ctx)).allowed
    dup = await h.check_tool_call("search_docs", args, ctx)
    assert not dup.allowed
    assert "loop detected" in dup.deny_reason
