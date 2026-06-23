"""Concurrent agent isolation tests.

Proves that one SHAI instance safely serves multiple concurrent agents
and parent/child subagent pairs with no cross-contamination.

Tools are resolved once at load_agent() time.
No per-turn view state — concurrent turns are naturally isolated.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.harness import SHAI
from harness.core.types import BoundaryName, Transport
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


class RecordingSink:
    name = "recording"
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
    async def emit(self, event: AuditEvent) -> None:
        self.events.append(event)
    async def close(self) -> None:
        pass


def _recording_sink(h: SHAI) -> RecordingSink:
    return next(s for s in h._emitter._sinks if isinstance(s, RecordingSink))


async def _build_harness(tmp_path: Path) -> SHAI:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h = await SHAI.from_yaml(cfg)
    h._emitter._sinks.append(RecordingSink())
    await h.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])
    return h


# ── 10 concurrent top-level agents ───────────────────────────────────────

async def test_10_concurrent_agents_all_succeed(tmp_path: Path):
    """10 concurrent turns must all gate correctly and independently."""
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    results = await asyncio.gather(
        *[h.check_tool_call("search_docs", {"query": f"turn_{i}"}, ctx)
          for i in range(10)],
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors
    assert all(r.allowed for r in results)


async def test_concurrent_tools_resolved_once(tmp_path: Path):
    """Tools for an agent are resolved once at load_agent() — verify the dict."""
    h = await _build_harness(tmp_path)
    tools = h._agent_tools.get("orchestrator_agent", {})
    assert "search_docs" in tools
    assert "list_inbox" in tools
    # send_email has external_write — it's in allowed_tool_names and allowed_tags
    assert "send_email" in tools


async def test_concurrent_audit_events_carry_correct_ids(tmp_path: Path):
    """Every audit event must carry the agent_id of the turn that emitted it."""
    h   = await _build_harness(tmp_path)
    rec = _recording_sink(h)
    ctx = AgentContext(agent_id="orchestrator_agent")

    await asyncio.gather(*[h.check_tool_call("search_docs", {}, ctx) for _ in range(10)])

    gate_events = [e for e in rec.events if e.boundary == BoundaryName.TOOL_CALL_GATE]
    assert len(gate_events) == 10
    for e in gate_events:
        assert e.agent_id == "orchestrator_agent"
        assert e.sub_agent_id is None


# ── Parent + subagent concurrent ──────────────────────────────────────────

async def test_parent_and_subagent_concurrent(tmp_path: Path):
    """Parent and child run concurrently — correct allow/deny on each."""
    h          = await _build_harness(tmp_path)
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    async def parent_turn():
        allow = await h.check_tool_call("search_docs", {}, parent_ctx)
        deny  = await h.check_tool_call("send_email",  {}, parent_ctx)
        return allow.allowed, deny.allowed

    async def child_turn():
        allow = await h.check_tool_call("search_docs", {}, child_ctx)
        deny  = await h.check_tool_call("send_email",  {}, child_ctx)
        return allow.allowed, deny.allowed

    (p_allow, p_deny), (c_allow, c_deny) = await asyncio.gather(
        parent_turn(), child_turn()
    )

    assert p_allow is True,  "parent: search_docs should be allowed"
    assert p_deny  is False, "parent: send_email denied by policy"
    assert c_allow is True,  "child: search_docs should be allowed"
    assert c_deny  is False, "child: send_email not in allowlist"


async def test_subagent_audit_events_carry_sub_agent_id(tmp_path: Path):
    """Audit events from subagent turns must carry sub_agent_id."""
    h          = await _build_harness(tmp_path)
    rec        = _recording_sink(h)
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    await h.check_tool_call("search_docs", {}, child_ctx)
    await h.check_tool_call("send_email",  {}, child_ctx)

    gate_events = [e for e in rec.events if e.boundary == BoundaryName.TOOL_CALL_GATE]
    assert len(gate_events) == 2
    for e in gate_events:
        assert e.sub_agent_id == "research_sub"
        assert e.agent_id     == "orchestrator_agent"


async def test_parent_and_subagent_tool_sets_distinct(tmp_path: Path):
    """Parent's resolved tool set includes all declared tools.
    Subagent capability narrowing happens at gate time via ctx.allowed_tags.
    """
    h          = await _build_harness(tmp_path)
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    # Parent tool set is resolved at load_agent time — shared for all turns
    tools = h._agent_tools["orchestrator_agent"]
    assert "search_docs" in tools
    assert "send_email"  in tools  # in parent's allowed set

    # research_sub is gated by ctx.allowed_tags at check_tool_call time
    assert child_ctx.allowed_tags == ["read", "internal"]
    gate = await h.check_tool_call("send_email", {}, child_ctx)
    assert not gate.allowed  # denied by subagent tag gate


# ── Cross-turn isolation ──────────────────────────────────────────────────

async def test_concurrent_turns_same_agent_no_interference(tmp_path: Path):
    """10 concurrent turns for the same agent — no state shared between turns."""
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    async def one_turn(i: int) -> bool:
        await asyncio.sleep(0)  # yield to interleave
        gate = await h.check_tool_call("search_docs", {"query": f"q{i}"}, ctx)
        await asyncio.sleep(0)
        return gate.allowed

    results = await asyncio.gather(*[one_turn(i) for i in range(10)])
    assert all(results)


async def test_deny_does_not_affect_subsequent_allow(tmp_path: Path):
    """A deny on one turn must not affect the next turn's allow."""
    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    deny  = await h.check_tool_call("send_email", {"to": "x"}, ctx)
    allow = await h.check_tool_call("search_docs", {}, ctx)

    assert not deny.allowed
    assert allow.allowed
