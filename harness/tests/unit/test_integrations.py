"""Unit tests for framework integrations.

All tests run WITHOUT requiring the actual framework packages installed.
They test the harness gating logic by using minimal stubs.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.core.verdicts import GateDecision
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ── Shared setup ──────────────────────────────────────────────────────────

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
    await h.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
    ])
    return h


# ── anthropic_sdk integration ─────────────────────────────────────────────

async def test_gated_dispatch_allow(tmp_path: Path):
    from harness.integrations.anthropic_sdk import gated_dispatch

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    dispatched = []

    async def dispatch(name: str, args: dict) -> str:
        dispatched.append((name, args))
        return "result"

    result = await gated_dispatch("search_docs", {"query": "test"}, ctx,
                                   harness=h, dispatch=dispatch)

    assert result == "result"
    assert dispatched == [("search_docs", {"query": "test"})]


async def test_gated_dispatch_deny(tmp_path: Path):
    """send_email is denied by orchestrator default policy."""
    from harness.integrations.anthropic_sdk import gated_dispatch

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    dispatched = []

    async def dispatch(name: str, args: dict) -> str:
        dispatched.append(name)
        return "should not reach"

    result = await gated_dispatch("send_email", {"to": "x@y.com"}, ctx,
                                   harness=h, dispatch=dispatch)

    assert isinstance(result, GateDecision)
    assert not result.allowed
    assert not dispatched


async def test_make_tool_result_from_denial(tmp_path: Path):
    from harness.integrations.anthropic_sdk import make_tool_result_from_denial

    gate = GateDecision(allowed=False, deny_reason="policy denied")
    result = make_tool_result_from_denial(gate, "tool_use_123")

    assert result["type"] == "tool_result"
    assert result["tool_use_id"] == "tool_use_123"
    assert result["is_error"] is True
    assert "policy denied" in result["content"]


async def test_run_turn_allow(tmp_path: Path):
    from harness.integrations.anthropic_sdk import run_turn

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    async def llm_fn(text, tools, ctx):
        return f"Response to: {text}"

    result = await run_turn("hello", ctx, harness=h, llm_fn=llm_fn)
    assert result == "Response to: hello"


async def test_run_turn_input_blocked(tmp_path: Path):
    """When scan_input blocks, run_turn returns a ScanVerdict."""
    from harness.integrations.anthropic_sdk import run_turn
    from harness.core.verdicts import ScanVerdict

    # Enable scanning with a very low block threshold for this test
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: true\n  block_at: info\n"
        "  scanners:\n    - name: regex_pii\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    h = await SHAI.from_yaml(cfg)
    await h.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await h.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    ])

    ctx = AgentContext(agent_id="orchestrator_agent")

    async def llm_fn(text, tools, ctx):
        return "should not reach"

    result = await run_turn("My email is test@example.com", ctx, harness=h, llm_fn=llm_fn)
    assert isinstance(result, ScanVerdict)
    assert result.blocked


# ── langgraph integration ─────────────────────────────────────────────────

async def test_harness_tool_node_allow(tmp_path: Path):
    from harness.integrations.langgraph import HarnessToolNode

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    calls: list[str] = []

    class _Tool:
        name = "search_docs"
        async def ainvoke(self, args): calls.append("search_docs"); return "docs"

    class _AIMsg:
        tool_calls = [{"name": "search_docs", "args": {"query": "q"}, "id": "1"}]

    import sys, unittest.mock as mock
    FakeTM = mock.MagicMock()
    FakeTM.side_effect = lambda **kw: type("TM", (), kw)()

    with mock.patch.dict(sys.modules, {
        "langchain_core": mock.MagicMock(),
        "langchain_core.messages": mock.MagicMock(AIMessage=_AIMsg, ToolMessage=FakeTM),
    }):
        import importlib, harness.integrations.langgraph as m
        importlib.reload(m)
        node = m.HarnessToolNode(tools=[_Tool()], harness=h, ctx=ctx)
        result = await node({"messages": [_AIMsg()]})

    assert calls == ["search_docs"]


async def test_harness_tool_node_deny(tmp_path: Path):
    """send_email must be denied — ToolMessage with error status returned."""
    from harness.integrations.langgraph import HarnessToolNode

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    calls: list[str] = []

    class _EmailTool:
        name = "send_email"
        async def ainvoke(self, args): calls.append("send_email"); return "sent"

    class _AIMsg:
        tool_calls = [{"name": "send_email", "args": {"to": "x@y.com"}, "id": "2"}]

    import sys, unittest.mock as mock
    tool_msgs = []
    def fake_tm(**kw):
        tool_msgs.append(kw)
        return kw
    with mock.patch.dict(sys.modules, {
        "langchain_core": mock.MagicMock(),
        "langchain_core.messages": mock.MagicMock(AIMessage=_AIMsg, ToolMessage=fake_tm),
    }):
        import importlib, harness.integrations.langgraph as m
        importlib.reload(m)
        node = m.HarnessToolNode(tools=[_EmailTool()], harness=h, ctx=ctx)
        await node({"messages": [_AIMsg()]})

    assert not calls, "send_email should not have been dispatched"
    assert tool_msgs and tool_msgs[0].get("status") == "error"


# ── pydantic_ai integration ───────────────────────────────────────────────

async def test_harness_tool_decorator_allow(tmp_path: Path):
    from harness.integrations.pydantic_ai import harness_tool

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    @harness_tool(harness=h, ctx=ctx)
    async def search_docs(query: str) -> str:
        return f"results for {query}"

    result = await search_docs(query="test")
    assert result == "results for test"


async def test_harness_tool_decorator_deny(tmp_path: Path):
    from harness.integrations.pydantic_ai import harness_tool

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    @harness_tool(harness=h, ctx=ctx)
    async def send_email(to: str, subject: str, body: str) -> str:
        return "sent"

    result = await send_email(to="x@y.com", subject="hi", body="hello")
    assert "denied" in result.lower()


# ── openai_agents integration ─────────────────────────────────────────────

async def test_make_before_tool_hook_allow(tmp_path: Path):
    from harness.integrations.openai_agents import make_before_tool_hook

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    hook = make_before_tool_hook(harness=h, ctx=ctx)

    class _Tool:
        name = "search_docs"

    result = await hook(_Tool(), {"query": "test"})
    # None means proceed — search_docs is allowed
    assert result is None


async def test_make_before_tool_hook_deny(tmp_path: Path):
    from harness.integrations.openai_agents import make_before_tool_hook

    h   = await _build_harness(tmp_path)
    ctx = AgentContext(agent_id="orchestrator_agent")

    hook = make_before_tool_hook(harness=h, ctx=ctx)

    class _Tool:
        name = "send_email"

    result = await hook(_Tool(), {"to": "x@y.com"})
    assert "denied" in str(result).lower()


# ── Subagent handoff — integration-level ─────────────────────────────────

async def test_gated_dispatch_subagent_cannot_send_email(tmp_path: Path):
    """research_sub is not allowed to call send_email (not in its allowed_tool_names)."""
    from harness.integrations.anthropic_sdk import gated_dispatch

    h          = await _build_harness(tmp_path)
    parent_ctx = AgentContext(agent_id="orchestrator_agent")
    child_ctx  = h.scope_context_for_subagent(parent_ctx, "research_sub")


    dispatched = []
    async def dispatch(name, args): dispatched.append(name); return "ok"

    result = await gated_dispatch("send_email", {"to": "x@y.com"}, child_ctx,
                                   harness=h, dispatch=dispatch)

    assert isinstance(result, GateDecision)
    assert not result.allowed
    assert not dispatched
