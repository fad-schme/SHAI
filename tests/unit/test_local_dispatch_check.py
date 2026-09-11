"""SHAI.verify_tool_dispatch — the dispatch-token check a local tool runs first.

The gate mints a token for every allowed call. For an MCP tool ShaiTransport
checks it; a local tool has no transport, so it asks SHAI directly. These tests
drive the check through the public API only: execute_gated_tool_call puts the
token in scope, and anything else finds none.
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from harness.connectivity.token import (
    _SIGNED_FIELDS,
    current_dispatch_token,
    encode_token,
    sign_token,
)
from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.signing import claims_of, sign
from harness.core.types import BoundaryName, Decision, Transport
from harness.integrations.base import execute_gated_tool_call
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

FIXTURES   = Path(__file__).parent.parent / "fixtures"
AGENT_YAML = FIXTURES / "agents" / "orchestrator_agent.yaml"

_CFG = """\
version: 1
connectivity:
  token_secret: test-connectivity-secret
scan_input:
  enabled: true
  scanners:
    - name: injection_scan
scan_output:
  enabled: true
  scanners:
    - name: injection_scan
scan_tool_result:
  enabled: true
  scanners:
    - name: injection_scan
scan_file:
  enabled: true
  scanners:
    - name: injection_scan
audit_sinks:
  - name: stdout
"""

TOOLS = [
    Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    Tool(name="list_inbox", tags=["read", "internal"], transport=Transport.LOCAL),
]


async def _harness(tmp_path: Path) -> tuple[SHAI, RecordingSink]:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(_CFG)
    h = await SHAI.from_yaml(cfg)
    sink = RecordingSink()
    h._emitter._sinks = [sink]
    await h.load_agent(AGENT_YAML)
    await h.register_tools(TOOLS)
    sink.events.clear()
    return h, sink


def _events(sink: RecordingSink, boundary: BoundaryName) -> list[Any]:
    return [e for e in sink.events if getattr(e, "boundary", None) == boundary]


def _signed(h: SHAI, **overrides: Any) -> str:
    fields = dict(
        agent_id="orchestrator_agent", sub_agent_id=None, tenant_id=h._tenant_id,
        tool_name="search_docs", source_name="local", purpose="tool_call",
        allowed_urls=[], allowed_methods=[], secret=h._connectivity_secret,
    )
    fields.update(overrides)
    return encode_token(sign_token(**fields))


async def _check_with(h: SHAI, token: str | None, ctx: AgentContext,
                      tool: str = "search_docs"):
    scope = current_dispatch_token.set(token)
    try:
        return await h.verify_tool_dispatch(tool, ctx)
    finally:
        current_dispatch_token.reset(scope)


# ── Happy path through the integration wrapper ────────────────────────────

async def test_wrapped_call_passes_and_joins_gate_check_and_result(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    seen: list[Any] = []

    async def tool(args: dict) -> str:
        seen.append(await h.verify_tool_dispatch("search_docs", ctx))
        return "benign result"

    call = await execute_gated_tool_call(
        harness=h, ctx=ctx, tool_name="search_docs",
        tool_args={"query": "q"}, invoke=tool,
    )

    assert call.status == "allowed"
    assert seen[0].allowed
    [gate]   = _events(sink, BoundaryName.TOOL_CALL_GATE)
    [check]  = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    [result] = _events(sink, BoundaryName.TOOL_RESULT_SCAN)
    assert check.decision == Decision.ALLOW
    assert gate.token_id is not None
    assert check.token_id == gate.token_id == result.token_id


async def test_token_is_single_use(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    seen: list[Any] = []

    async def tool(args: dict) -> str:
        seen.append(await h.verify_tool_dispatch("search_docs", ctx))
        seen.append(await h.verify_tool_dispatch("search_docs", ctx))
        return "ok"

    await execute_gated_tool_call(
        harness=h, ctx=ctx, tool_name="search_docs",
        tool_args={"query": "q"}, invoke=tool,
    )

    assert seen[0].allowed
    assert not seen[1].allowed
    assert "already been used" in seen[1].deny_reason
    assert len(_events(sink, BoundaryName.TOOL_DISPATCH_CHECK)) == 2


async def test_gate_deny_never_reaches_the_tool(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    ran: list[bool] = []

    async def tool(args: dict) -> str:
        ran.append(True)
        return "ok"

    call = await execute_gated_tool_call(
        harness=h, ctx=ctx, tool_name="not_a_registered_tool",
        tool_args={}, invoke=tool,
    )

    assert call.status == "denied"
    assert not ran
    assert _events(sink, BoundaryName.TOOL_DISPATCH_CHECK) == []


# ── Refusals — each emits exactly one event with a reason ─────────────────

def _expired(h: SHAI) -> str:
    tok = sign_token(
        agent_id="orchestrator_agent", sub_agent_id=None, tenant_id=h._tenant_id,
        tool_name="search_docs", source_name="local", purpose="tool_call",
        allowed_urls=[], allowed_methods=[], secret=h._connectivity_secret,
    )
    aged = dataclasses.replace(
        tok, expires_at=datetime.now(UTC) - timedelta(seconds=60), signature="",
    )
    aged = dataclasses.replace(
        aged, signature=sign(claims_of(aged, _SIGNED_FIELDS), h._connectivity_secret),
    )
    return encode_token(aged)


def _tampered(h: SHAI) -> str:
    good = _signed(h)
    return good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB")


@pytest.mark.parametrize("case, make_token, ctx_agent, tool, reason", [
    ("direct call, no token", lambda h: None, "orchestrator_agent",
     "search_docs", "no dispatch token"),
    ("malformed", lambda h: "not-a-token", "orchestrator_agent",
     "search_docs", "invalid dispatch token"),
    ("expired", _expired, "orchestrator_agent", "search_docs", "expired"),
    ("tampered", _tampered, "orchestrator_agent", "search_docs",
     "invalid dispatch token"),
    ("other tool", lambda h: _signed(h, tool_name="list_inbox"),
     "orchestrator_agent", "search_docs", "tool"),
    ("other agent", lambda h: _signed(h, agent_id="someone_else"),
     "orchestrator_agent", "search_docs", "agent"),
    ("mcp source", lambda h: _signed(h, source_name="slack_mcp",
                                     allowed_urls=["https://slack.com/*"]),
     "orchestrator_agent", "search_docs", "source"),
    ("connect token", lambda h: _signed(h, purpose="connect", tool_name=None),
     "orchestrator_agent", "search_docs", "purpose"),
])
async def test_refused_with_one_event(tmp_path: Path, case, make_token,
                                      ctx_agent, tool, reason):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id=ctx_agent)

    decision = await _check_with(h, make_token(h), ctx, tool)

    assert not decision.allowed, case
    assert reason in decision.deny_reason, case
    [event] = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    assert event.decision == Decision.DENY
    assert event.deny_reason == decision.deny_reason
    assert len(sink.events) == 1


async def test_a_tool_outside_the_agents_set_is_refused(tmp_path: Path):
    """A valid, correctly bound token still does not run a tool the agent was
    never given — the check resolves the tool the way the gate does."""
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    decision = await _check_with(h, _signed(h, tool_name="unknown_tool"), ctx,
                                 tool="unknown_tool")

    assert not decision.allowed
    assert len(_events(sink, BoundaryName.TOOL_DISPATCH_CHECK)) == 1
