"""Tests for SHAI facade — phases 1–3."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.errors import AgentNotRegisteredError, ConfigError, SubAgentNotDeclaredError
from harness.core.harness import SHAI


@pytest.fixture
async def harness(tmp_path: Path) -> SHAI:
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    return await SHAI.from_yaml(cfg)


async def test_load_and_list_agents(harness, orchestrator_yaml, research_yaml):
    await harness.load_agent(orchestrator_yaml)
    await harness.load_agent(research_yaml)
    agents = await harness.list_agents()
    ids = {a.id for a in agents}
    assert ids == {"orchestrator_agent", "research_agent"}


async def test_reload_agent(harness, orchestrator_yaml, tmp_path):
    await harness.load_agent(orchestrator_yaml)
    updated = tmp_path / "upd.yaml"
    updated.write_text(
        "id: orchestrator_agent\n"
        "display_name: Updated\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read]\n"
    )
    agent = await harness.reload_agent(updated)
    # reload_agent returns AgentContext — verify via registry that config updated
    assert agent.agent_id == "orchestrator_agent"
    cfg = harness._agent_registry.get("orchestrator_agent")
    assert cfg.display_name == "Updated"


async def test_deregister_agent(harness, orchestrator_yaml):
    await harness.load_agent(orchestrator_yaml)
    await harness.deregister_agent("orchestrator_agent")
    agents = await harness.list_agents()
    assert not any(a.id == "orchestrator_agent" for a in agents)


async def test_scope_context_for_subagent(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)
    assert agent.agent_id == "orchestrator_agent"   # load_agent returns AgentContext

    child = harness.scope_context_for_subagent(agent, sub_agent_id="research_sub")
    assert child.agent_id     == "orchestrator_agent"
    assert child.sub_agent_id == "research_sub"
    assert set(child.allowed_tags) == {"read", "internal"}

    # Also works via agent.scope_subagent() directly
    child2 = agent.scope_subagent(
        "research_sub",
        allowed_tags=list(child.allowed_tags),
    )
    assert child2.sub_agent_id == "research_sub"


async def test_scope_context_unknown_subagent(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)
    with pytest.raises(SubAgentNotDeclaredError):
        harness.scope_context_for_subagent(agent, sub_agent_id="nonexistent_sub")


async def test_scope_context_unregistered_agent(harness):
    ctx = AgentContext(
        agent_id="nobody")
    with pytest.raises(AgentNotRegisteredError):
        harness.scope_context_for_subagent(ctx, sub_agent_id="sub")


async def test_scope_context_child_tags_are_subset(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)

    # research_sub has read + internal (subset of parent's read + internal + external_write)
    child = harness.scope_context_for_subagent(agent, sub_agent_id="research_sub")
    assert "external_write" not in child.allowed_tags

    # email_sub has all three
    child2 = harness.scope_context_for_subagent(agent, sub_agent_id="email_sub")
    assert "external_write" in child2.allowed_tags


async def test_boundaries_are_wired_in_phase5(harness):
    """All boundary methods are wired and never raise on unknown agents —
    they return deny-with-audit instead (pre-gate guarantee).
    """
    ctx = AgentContext(agent_id="a1")
    # scan_input disabled in fixture → allow verdict, no error
    verdict = await harness.scan_input("hello", ctx)
    assert not verdict.blocked
    # check_tool_call on unregistered agent → GateDecision deny, no exception
    gate = await harness.check_tool_call("search_docs", {}, ctx)
    assert gate.allowed is False
    assert gate.deny_reason is not None

async def test_from_yaml_missing_file():
    with pytest.raises(ConfigError):
        await SHAI.from_yaml("/nonexistent/path/harness.yaml")