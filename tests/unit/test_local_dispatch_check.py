"""SHAI.verify_tool_dispatch — the dispatch-token check a local tool runs first.

The gate mints a token for every allowed call. For an MCP tool ShaiTransport
checks it; a local tool has no transport, so it asks SHAI directly. The check
is sync and raises DispatchRefused; dispatch_scope puts the token in scope and
emits one event per check; execute_gated_tool_call renders a refusal as the
standard denial.
"""
from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from harness.connectivity.token import _SIGNED_FIELDS, encode_token, sign_token
from harness.core.context import AgentContext
from harness.core.errors import DispatchRefused
from harness.core.harness import SHAI
from harness.core.signing import claims_of, sign
from harness.core.types import BoundaryName, Decision, Transport
from harness.core.verdicts import GateDecision
from harness.integrations.base import execute_gated_tool_call, invoke_tool
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


async def _gated(h: SHAI, ctx: AgentContext, invoke: Any, tool: str = "search_docs"):
    return await execute_gated_tool_call(
        harness=h, ctx=ctx, tool_name=tool, tool_args={"query": "q"}, invoke=invoke,
    )


# ── Through the integration wrapper ───────────────────────────────────────

async def test_wrapped_call_passes_and_joins_gate_check_and_result(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    async def tool(args: dict) -> str:
        h.verify_tool_dispatch("search_docs")
        return "benign result"

    call = await _gated(h, ctx, tool)

    assert call.status == "allowed"
    [gate]   = _events(sink, BoundaryName.TOOL_CALL_GATE)
    [check]  = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    [result] = _events(sink, BoundaryName.TOOL_RESULT_SCAN)
    assert check.decision == Decision.ALLOW
    assert gate.token_id is not None
    assert check.token_id == gate.token_id == result.token_id


async def test_sync_tool_on_a_worker_thread_is_checked(tmp_path: Path):
    """The check is sync: a plain-def tool run by invoke_tool on a worker
    thread calls it directly, and the scope still records the check."""
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    def search_docs(query: str) -> str:
        h.verify_tool_dispatch("search_docs")
        return "benign result"

    call = await _gated(h, ctx, lambda args: invoke_tool(search_docs, args))

    assert call.status == "allowed"
    [check] = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    assert check.decision == Decision.ALLOW


async def test_refusal_is_rendered_as_the_standard_denial(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    ran: list[bool] = []

    async def tool(args: dict) -> str:
        h.verify_tool_dispatch("list_inbox")   # not the tool the gate allowed
        ran.append(True)
        return "should not run"

    call = await _gated(h, ctx, tool)

    assert call.status == "denied"
    assert not ran
    assert call.message.startswith("Tool call denied: token was issued for another tool")
    [check] = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    assert check.decision == Decision.DENY
    assert check.deny_reason in call.message
    assert _events(sink, BoundaryName.TOOL_RESULT_SCAN) == []


async def test_token_is_single_use(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    async def tool(args: dict) -> str:
        h.verify_tool_dispatch("search_docs")
        h.verify_tool_dispatch("search_docs")
        return "ok"

    call = await _gated(h, ctx, tool)

    assert call.status == "denied"
    assert "already been used" in call.message
    decisions = [e.decision for e in _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)]
    assert decisions == [Decision.ALLOW, Decision.DENY]


async def test_gate_deny_never_reaches_the_tool(tmp_path: Path):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")
    ran: list[bool] = []

    async def tool(args: dict) -> str:
        ran.append(True)
        return "ok"

    call = await _gated(h, ctx, tool, tool="not_a_registered_tool")

    assert call.status == "denied"
    assert not ran
    assert _events(sink, BoundaryName.TOOL_DISPATCH_CHECK) == []


# ── Refusals inside a scope — each raises and emits exactly one event ─────

@pytest.mark.parametrize("case, make_token, tool, reason", [
    ("gate allowed nothing", lambda h: None, "search_docs", "no dispatch token"),
    ("malformed", lambda h: "not-a-token", "search_docs", "invalid dispatch token"),
    ("expired", _expired, "search_docs", "expired"),
    ("tampered", _tampered, "search_docs", "invalid dispatch token"),
    ("other tool", lambda h: _signed(h, tool_name="list_inbox"), "search_docs",
     "another tool"),
    ("other agent", lambda h: _signed(h, agent_id="someone_else"), "search_docs",
     "another agent"),
    ("mcp source", lambda h: _signed(h, source_name="slack_mcp",
                                     allowed_urls=["https://slack.com/*"]),
     "search_docs", "source"),
    ("connect token", lambda h: _signed(h, purpose="connect", tool_name=None),
     "search_docs", "purpose"),
    ("tool outside the agent's set", lambda h: _signed(h, tool_name="unknown_tool"),
     "unknown_tool", "source"),
])
async def test_refused_with_one_event(tmp_path: Path, case, make_token, tool, reason):
    h, sink = await _harness(tmp_path)
    ctx  = AgentContext(agent_id="orchestrator_agent")
    gate = GateDecision(allowed=True, dispatch_token=make_token(h))

    with pytest.raises(DispatchRefused, match=reason):
        async with h.dispatch_scope(ctx, gate):
            h.verify_tool_dispatch(tool)

    [event] = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    assert event.decision == Decision.DENY, case
    assert reason in event.deny_reason, case
    assert len(sink.events) == 1


async def test_a_defect_in_the_check_refuses(tmp_path: Path, monkeypatch):
    h, sink = await _harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    def broken(*_: Any) -> str | None:
        raise RuntimeError("store exploded")

    monkeypatch.setattr(h._dispatch_nonces, "consume", broken)

    async def tool(args: dict) -> str:
        h.verify_tool_dispatch("search_docs")
        return "should not run"

    call = await _gated(h, ctx, tool)

    assert call.status == "denied"
    assert "dispatch check failed: RuntimeError" in call.message
    [event] = _events(sink, BoundaryName.TOOL_DISPATCH_CHECK)
    assert event.decision == Decision.DENY


def test_no_scope_raises(tmp_path: Path):
    h = SHAI.__new__(SHAI)
    h._tenant_id = "t"
    with pytest.raises(DispatchRefused, match="no dispatch token in scope"):
        h.verify_tool_dispatch("search_docs")
