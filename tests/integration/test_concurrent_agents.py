"""Concurrent agent isolation tests.

Proves that one Harness instance safely serves multiple concurrent agents
and parent/child subagent pairs with no cross-contamination.

All tests use asyncio.gather to run turns truly concurrently within the
single-threaded event loop, which surfaces any shared-state bugs in
view keying, registry access, or audit emission.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.core.context import RuntimeContext
from harness.core.events import AuditEvent
from harness.core.harness import Harness
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


def _recording_sink(h: Harness) -> RecordingSink:
    return next(s for s in h._emitter._sinks if isinstance(s, RecordingSink))


async def _build_harness(tmp_path: Path) -> Harness:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h = Harness.from_yaml(cfg)
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
    """10 concurrent turns on the same agent must all succeed independently."""
    h = await _build_harness(tmp_path)

    async def one_turn(i: int) -> bool:
        ctx = RuntimeContext(
        agent_id="orchestrator_agent",
        )
        tools = await h.load_sources(ctx)
        gate  = await h.check_tool_call("search_docs", {"query": f"turn_{i}"}, ctx)
        await h.unload_sources(ctx)
        return gate.allowed

    results = await asyncio.gather(*[one_turn(i) for i in range(10)])
    assert all(results), f"Some turns failed: {results}"


async def test_10_concurrent_agents_views_isolated(tmp_path: Path):
    """Each concurrent turn must get its own ScopedRegistryView."""
    h = await _build_harness(tmp_path)
    views_seen: list[int] = []

    # Keep strong references to each ctx AND each view so CPython cannot
    # reuse the same memory address across concurrent turns.
    contexts = [RuntimeContext(agent_id="orchestrator_agent") for _ in range(10)]
    views_held: list = []  # strong refs prevent id() reuse

    async def one_turn(ctx: RuntimeContext) -> object:
        await h.load_sources(ctx)
        view = h._views.get(id(ctx))
        assert view is not None, "no view stored"
        views_held.append(view)   # hold strong ref before unload
        await h.unload_sources(ctx)
        return view               # return object, not id

    returned_views = await asyncio.gather(*[one_turn(ctx) for ctx in contexts])
    # All view objects must be distinct — no two turns shared a view
    assert len(set(id(v) for v in returned_views)) == 10, "Some turns shared a view object"


async def test_concurrent_audit_events_carry_correct_ids(tmp_path: Path):
    """Every audit event must carry the agent_id of the turn that emitted it."""
    h   = await _build_harness(tmp_path)
    rec = _recording_sink(h)

    async def one_turn(i: int) -> None:
        ctx = RuntimeContext(
        agent_id="orchestrator_agent",
        )
        await h.load_sources(ctx)
        await h.check_tool_call("search_docs", {}, ctx)
        await h.unload_sources(ctx)

    await asyncio.gather(*[one_turn(i) for i in range(10)])

    gate_events = [e for e in rec.events if e.boundary == BoundaryName.TOOL_CALL_GATE]
    assert len(gate_events) == 10
    for e in gate_events:
        assert e.agent_id == "orchestrator_agent"
        assert e.sub_agent_id is None


# ── Parent + subagent concurrent ──────────────────────────────────────────

async def test_parent_and_subagent_concurrent(tmp_path: Path):
    """Parent (orchestrator) and child (research_sub) run concurrently.
    Each gets its own view; child is denied send_email; parent is denied
    by policy; neither bleeds into the other.
    """
    h          = await _build_harness(tmp_path)
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    async def parent_turn():
        tools = await h.load_sources(parent_ctx)
        allow = await h.check_tool_call("search_docs", {}, parent_ctx)
        # send_email is denied by the orchestrator's default policy
        deny  = await h.check_tool_call("send_email", {}, parent_ctx)
        await h.unload_sources(parent_ctx)
        return allow.allowed, deny.allowed

    async def child_turn():
        tools = await h.load_sources(child_ctx)
        allow = await h.check_tool_call("search_docs", {}, child_ctx)
        # send_email not in research_sub's allowed_tool_names → L1b deny
        deny  = await h.check_tool_call("send_email", {}, child_ctx)
        await h.unload_sources(child_ctx)
        return allow.allowed, deny.allowed

    (p_allow, p_deny), (c_allow, c_deny) = await asyncio.gather(
        parent_turn(), child_turn()
    )

    assert p_allow is True,  "parent: search_docs should be allowed"
    assert p_deny  is False, "parent: send_email should be denied by policy"
    assert c_allow is True,  "child: search_docs should be allowed"
    assert c_deny  is False, "child: send_email should be denied (not in allowlist)"


async def test_parent_and_subagent_views_distinct(tmp_path: Path):
    """Parent and child must have distinct, non-None views after load_sources."""
    h          = await _build_harness(tmp_path)
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    await asyncio.gather(
        h.load_sources(parent_ctx),
        h.load_sources(child_ctx),
    )

    parent_view = h._views.get(id(parent_ctx))
    child_view  = h._views.get(id(child_ctx))

    assert parent_view is not None
    assert child_view  is not None
    assert parent_view is not child_view

    await asyncio.gather(
        h.unload_sources(parent_ctx),
        h.unload_sources(child_ctx),
    )


async def test_subagent_audit_events_carry_sub_agent_id(tmp_path: Path):
    """Audit events from subagent turns must carry sub_agent_id."""
    h         = await _build_harness(tmp_path)
    rec       = _recording_sink(h)
    parent_ctx = RuntimeContext(
        agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")

    await h.load_sources(child_ctx)
    await h.check_tool_call("search_docs", {}, child_ctx)
    await h.check_tool_call("send_email",  {}, child_ctx)
    await h.unload_sources(child_ctx)

    gate_events = [e for e in rec.events if e.boundary == BoundaryName.TOOL_CALL_GATE]
    assert len(gate_events) == 2
    for e in gate_events:
        assert e.sub_agent_id == "research_sub"
        assert e.agent_id     == "orchestrator_agent"


# ── Overlapping load / unload ─────────────────────────────────────────────

async def test_overlapping_load_unload_no_errors(tmp_path: Path):
    """10 agents load and unload in overlapping windows — no KeyError or
    stale-view access must occur.
    """
    h = await _build_harness(tmp_path)

    async def one_turn(i: int) -> None:
        ctx = RuntimeContext(
        agent_id="orchestrator_agent",
        )
        await h.load_sources(ctx)
        # Deliberately interleave by yielding before unload
        await asyncio.sleep(0)
        await h.check_tool_call("search_docs", {}, ctx)
        await asyncio.sleep(0)
        await h.unload_sources(ctx)

    await asyncio.gather(*[one_turn(i) for i in range(10)])
    # If we reach here with no exception, the test passes


async def test_unload_after_unload_is_noop(tmp_path: Path):
    """Double-unload must be a silent no-op, not a KeyError."""
    h   = await _build_harness(tmp_path)
    ctx = RuntimeContext(
        agent_id="orchestrator_agent")

    await h.load_sources(ctx)
    await h.unload_sources(ctx)
    await h.unload_sources(ctx)   # must not raise


# ── Cross-contamination proof ─────────────────────────────────────────────

async def test_tool_loaded_for_one_agent_invisible_to_another(tmp_path: Path):
    """A tool added to agent A's view must not appear in agent B's view."""
    h = await _build_harness(tmp_path)

    ctx_a = RuntimeContext(
        agent_id="orchestrator_agent"
    )
    ctx_b = RuntimeContext(
        agent_id="orchestrator_agent"
    )

    await h.load_sources(ctx_a)
    await h.load_sources(ctx_b)

    # Add an extra tool directly to ctx_a's overlay only
    extra = Tool(name="secret_tool_a", tags=["read"], transport=Transport.LOCAL)
    view_a = h._views.get(id(ctx_a))
    view_b = h._views.get(id(ctx_b))
    assert view_a is not view_b

    await view_a.add(extra)

    # extra_tool appears in A's view
    result_a = await view_a.get("secret_tool_a")
    assert result_a.name == "secret_tool_a"

    # extra_tool does NOT appear in B's view
    from harness.core.errors import ToolNotRegisteredError
    with pytest.raises(ToolNotRegisteredError):
        await view_b.get("secret_tool_a")

    await h.unload_sources(ctx_a)
    await h.unload_sources(ctx_b)
