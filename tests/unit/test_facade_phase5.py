"""Facade unit tests — Phase 5 (boundaries wired)."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def harness(tmp_path: Path) -> SHAI:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    return SHAI.from_yaml(cfg)


@pytest.fixture
async def wired_harness(harness: SHAI) -> SHAI:
    await harness.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])
    return harness


# ── Tools resolved at load_agent time ────────────────────────────────────

async def test_agent_tools_resolved_at_load(wired_harness: SHAI):
    tools = wired_harness._agent_tools.get("orchestrator_agent", {})
    assert "search_docs" in tools
    assert "list_inbox"  in tools


async def test_agent_tools_filtered_by_allowed_tool_names(wired_harness: SHAI):
    """Only tools whose name is in allowed_tool_names are resolved.
    Tag filtering happens at gate time, not at resolution time.
    """
    tools = wired_harness._agent_tools.get("orchestrator_agent", {})
    cfg   = wired_harness._agent_registry.get("orchestrator_agent")
    # Every resolved tool must be in allowed_tool_names
    for name in tools:
        assert name in cfg.allowed_tool_names
    # send_email is in allowed_tool_names and must be resolved even though
    # it carries the 'sensitive' tag (a scanner hint, not a capability gate)
    assert "send_email" in tools


# ── scan_input ────────────────────────────────────────────────────────────

async def test_scan_input_disabled_returns_allow(wired_harness: SHAI):
    agent = AgentContext(agent_id="orchestrator_agent")
    verdict = await wired_harness.scan_input("hello", agent)
    assert not verdict.blocked  # boundary disabled in fixture config


async def test_scan_output_disabled_returns_allow(wired_harness: SHAI):
    agent = AgentContext(agent_id="orchestrator_agent")
    verdict = await wired_harness.scan_output("hello", agent)
    assert not verdict.blocked


# ── check_tool_call ───────────────────────────────────────────────────────

async def test_check_tool_call_allow(wired_harness: SHAI):
    ctx = AgentContext(agent_id="orchestrator_agent")
    gate = await wired_harness.check_tool_call("search_docs", {"query": "test"}, ctx)
    assert gate.allowed


async def test_check_tool_call_deny_policy(wired_harness: SHAI):
    """send_email has a deny rule in orchestrator_agent.yaml by default."""
    ctx = AgentContext(agent_id="orchestrator_agent")
    # The orchestrator policy denies external_write by default
    gate = await wired_harness.check_tool_call(
        "send_email", {"to": "x@y.com", "subject": "hi", "body": "hello"}, ctx
    )
    # Expected: denied by policy rule deny_external_write_default
    assert not gate.allowed


async def test_check_tool_call_unregistered_agent_denied(harness: SHAI):
    from harness.core.errors import AgentNotRegisteredError
    ctx = AgentContext(agent_id="nobody")
    with pytest.raises(AgentNotRegisteredError):
        await harness.check_tool_call("search_docs", {}, ctx)


# ── Subagent isolation ────────────────────────────────────────────────────

async def test_subagent_scope_restricts_tags(wired_harness: SHAI):
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")
    assert child_ctx.sub_agent_id == "research_sub"
    assert "external_write" not in child_ctx.allowed_tags


async def test_subagent_send_email_denied(wired_harness: SHAI):
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")
    gate = await wired_harness.check_tool_call("send_email", {}, child_ctx)
    assert not gate.allowed


async def test_subagent_ctx_is_distinct_from_parent(wired_harness: SHAI):
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")
    assert child_ctx.sub_agent_id == "research_sub"
    assert child_ctx.allowed_tags == ["read", "internal"]
    assert parent_ctx.sub_agent_id is None

