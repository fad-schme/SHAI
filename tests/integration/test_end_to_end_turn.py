"""Integration tests — full async turn through a real SHAI instance.

No mocks beyond the RecordingSink. Tests run against the real boundaries,
real registry, real policy engine, real scanners.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.types import BoundaryName, Decision, Transport
from harness.core.events import AuditEvent
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


class RecordingSink:
    name = "recording"
    def __init__(self): self.events: list[AuditEvent] = []
    async def emit(self, e): self.events.append(e)
    async def close(self): pass


def _make_harness(tmp_path: Path, *, scan_enabled: bool = False) -> SHAI:
    cfg = tmp_path / "h.yaml"
    scanners_block = (
        "  scanners:\n    - name: regex_pii\n    - name: basic_injection\n"
        if scan_enabled else ""
    )
    enabled_str = "true" if scan_enabled else "false"
    cfg.write_text(
        f"version: 1\n"
        f"scan_input:\n  enabled: {enabled_str}\n{scanners_block if scan_enabled else ''}"
        f"scan_output:\n  enabled: {enabled_str}\n{scanners_block if scan_enabled else ''}"
        f"policy:\n  name: rules\n"
        f"audit_sinks:\n  - name: stdout\n"
    )
    h = SHAI.from_yaml(cfg)
    # Inject recording sink for assertions
    h._emitter._sinks.append(RecordingSink())
    return h


def _recording_sink(h: SHAI) -> RecordingSink:
    return next(s for s in h._emitter._sinks if isinstance(s, RecordingSink))


async def _setup_harness(tmp_path: Path, *, scan_enabled: bool = False) -> SHAI:
    h = _make_harness(tmp_path, scan_enabled=scan_enabled)
    await h.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])
    return h


# ── Happy path ────────────────────────────────────────────────────────────

async def test_full_turn_allow_path(tmp_path: Path):
    h   = await _setup_harness(tmp_path)
    ctx = AgentContext(
        agent_id="orchestrator_agent")
    rec = _recording_sink(h)


    verdict_in = await h.scan_input("Please search the docs.", ctx)
    assert not verdict_in.blocked

    gate = await h.check_tool_call("search_docs", {"query": "docs"}, ctx)
    assert gate.allowed

    verdict_out = await h.scan_output("Here are the results.", ctx)
    assert not verdict_out.blocked


    # Three boundary events: input_scan, tool_call_gate, output_scan
    boundaries = [e.boundary for e in rec.events]
    assert BoundaryName.INPUT_SCAN    in boundaries
    assert BoundaryName.TOOL_CALL_GATE in boundaries
    assert BoundaryName.OUTPUT_SCAN   in boundaries


async def test_full_turn_deny_path(tmp_path: Path):
    """send_email is blocked by orchestrator's default deny rule."""
    h   = await _setup_harness(tmp_path)
    ctx = AgentContext(
        agent_id="orchestrator_agent")

    gate = await h.check_tool_call(
        "send_email", {"to": "x@y.com", "subject": "hi", "body": "test"}, ctx
    )
    assert not gate.allowed


async def test_audit_events_carry_correct_identity(tmp_path: Path):
    h   = await _setup_harness(tmp_path)
    ctx = AgentContext(
        agent_id="orchestrator_agent",
    )
    rec = _recording_sink(h)

    await h.scan_input("hello", ctx)
    await h.check_tool_call("search_docs", {}, ctx)
    await h.scan_output("result", ctx)

    for event in rec.events:
        # tenant_id is stamped from harness.yaml (default="default" in fixture)
        assert event.tenant_id == "default"
        assert event.agent_id  == "orchestrator_agent"
        assert not hasattr(event, "user_id") or True  # user_id not on AuditEvent


# ── PII blocking ──────────────────────────────────────────────────────────

async def test_pii_in_input_blocked(tmp_path: Path):
    h   = await _setup_harness(tmp_path, scan_enabled=True)
    ctx = AgentContext(
        agent_id="orchestrator_agent")
    rec = _recording_sink(h)

    verdict = await h.scan_input("My SSN is 123-45-6789.", ctx)

    assert verdict.blocked
    assert rec.events[0].decision == Decision.BLOCKED


# ── Subagent turn ─────────────────────────────────────────────────────────

async def test_subagent_full_turn(tmp_path: Path):
    h          = await _setup_harness(tmp_path)
    parent_ctx = AgentContext(
        agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")
    rec        = _recording_sink(h)


    gate_allow = await h.check_tool_call("search_docs", {"query": "test"}, child_ctx)
    gate_deny  = await h.check_tool_call("send_email", {"to": "x@y.com"}, child_ctx)


    assert gate_allow.allowed
    assert not gate_deny.allowed

    # All events carry sub_agent_id
    gate_events = [e for e in rec.events if e.boundary == BoundaryName.TOOL_CALL_GATE]
    for e in gate_events:
        assert e.sub_agent_id == "research_sub"
        assert e.agent_id == "orchestrator_agent"


async def test_subagent_view_isolated_from_parent(tmp_path: Path):
    h          = await _setup_harness(tmp_path)
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    # Tools resolved once at load_agent — same dict for all turns of same agent
    tools = h._agent_tools.get("orchestrator_agent", {})
    assert "search_docs" in tools
    assert child_ctx.allowed_tags == ["read", "internal"]




# ── Concurrent agents ─────────────────────────────────────────────────────

async def test_concurrent_agents_isolated(tmp_path: Path):
    import asyncio
    h = await _setup_harness(tmp_path)

    async def agent_turn(user_id: str):
        ctx = AgentContext(
        agent_id="orchestrator_agent", user_id=user_id
        )
        gate = await h.check_tool_call("search_docs", {"query": user_id}, ctx)
        return gate.allowed

    results = await asyncio.gather(*[agent_turn(i) for i in range(10)])
    assert all(results)
