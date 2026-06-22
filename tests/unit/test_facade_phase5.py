"""Facade unit tests — Phase 5 (boundaries wired)."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import RuntimeContext
from harness.core.harness import Harness
from harness.core.types import Transport
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    return Harness.from_yaml(cfg)


@pytest.fixture
async def wired_harness(harness: Harness) -> Harness:
    await harness.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])
    return harness


# ── load_sources / unload_sources ─────────────────────────────────────────

async def test_load_sources_returns_tool_list(wired_harness: Harness):
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    tools = await wired_harness.load_sources(ctx)
    assert isinstance(tools, list)
    await wired_harness.unload_sources(ctx)


async def test_unload_sources_is_idempotent(wired_harness: Harness):
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    await wired_harness.load_sources(ctx)
    await wired_harness.unload_sources(ctx)
    await wired_harness.unload_sources(ctx)  # must not raise


# ── scan_input ────────────────────────────────────────────────────────────

async def test_scan_input_disabled_returns_allow(wired_harness: Harness):
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    verdict = await wired_harness.scan_input("hello", ctx)
    assert not verdict.blocked  # boundary disabled in fixture config


async def test_scan_output_disabled_returns_allow(wired_harness: Harness):
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    verdict = await wired_harness.scan_output("hello", ctx)
    assert not verdict.blocked


# ── check_tool_call ───────────────────────────────────────────────────────

async def test_check_tool_call_allow(wired_harness: Harness):
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    await wired_harness.load_sources(ctx)
    gate = await wired_harness.check_tool_call("search_docs", {"query": "test"}, ctx)
    assert gate.allowed
    await wired_harness.unload_sources(ctx)


async def test_check_tool_call_deny_policy(wired_harness: Harness):
    """send_email has a deny rule in orchestrator_agent.yaml by default."""
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    await wired_harness.load_sources(ctx)
    # The orchestrator policy denies external_write by default
    gate = await wired_harness.check_tool_call(
        "send_email", {"to": "x@y.com", "subject": "hi", "body": "hello"}, ctx
    )
    # Expected: denied by policy rule deny_external_write_default
    assert not gate.allowed
    await wired_harness.unload_sources(ctx)


async def test_check_tool_call_unregistered_agent_denied(harness: Harness):
    ctx = RuntimeContext(
        agent_id="nobody")
    gate = await harness.check_tool_call("search_docs", {}, ctx)
    assert not gate.allowed
    assert "not registered" in gate.deny_reason


# ── Subagent isolation ────────────────────────────────────────────────────

async def test_subagent_scope_restricts_tags(wired_harness: Harness):
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")
    assert child_ctx.sub_agent_id == "research_sub"
    assert "external_write" not in child_ctx.allowed_tags


async def test_subagent_send_email_denied(wired_harness: Harness):
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")
    await wired_harness.load_sources(child_ctx)
    gate = await wired_harness.check_tool_call("send_email", {}, child_ctx)
    assert not gate.allowed
    await wired_harness.unload_sources(child_ctx)


async def test_parent_and_child_views_isolated(wired_harness: Harness):
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = wired_harness.scope_context_for_subagent(parent_ctx, "research_sub")

    await wired_harness.load_sources(parent_ctx)
    await wired_harness.load_sources(child_ctx)

    # Keys are distinct because ctx objects are distinct (id-based keying)
    assert id(parent_ctx) != id(child_ctx)
    assert wired_harness._views.get(id(parent_ctx)) is not None
    assert wired_harness._views.get(id(child_ctx)) is not None

    await wired_harness.unload_sources(parent_ctx)
    await wired_harness.unload_sources(child_ctx)
