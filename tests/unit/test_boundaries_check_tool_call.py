"""Unit tests for check_tool_call boundary.

Tests the boundary directly with pre-resolved agent_config and tools dict
— no registry lookup on the hot path.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.tools.registry import ToolRegistry
from harness.agents.agent_config import AgentConfig, RuleConfig, RuleMatchConfig, SubAgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.types import Decision, Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool

FIXTURES = Path(__file__).parent.parent / "fixtures"


class RecordingSink:
    name = "recording"
    def __init__(self): self.events: list[AuditEvent] = []
    async def emit(self, e): self.events.append(e)
    async def close(self): pass


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


def make_agent(
    agent_id: str = "test_agent",
    allowed_tool_names: list[str] | None = None,
    allowed_tags: list[str] | None = None,
    policy_rules: list | None = None,
    sub_agents: list | None = None,
) -> AgentConfig:
    return AgentConfig(
        id=agent_id,
        allowed_tool_names=allowed_tool_names or ["search_docs"],
        allowed_tags=allowed_tags or ["read", "internal"],
        policy_rules=policy_rules or [],
        sub_agents=sub_agents or [],
    )


def setup() -> tuple[dict[str, Tool], RecordingSink, AuditEmitter, RuleBasedPolicy]:
    tools  = {"search_docs": make_tool("search_docs"),
               "send_email":  make_tool("send_email", ["external_write", "sensitive"])}
    sink    = RecordingSink()
    emitter = AuditEmitter([sink])
    policy  = RuleBasedPolicy()
    return tools, sink, emitter, policy


async def _run(name, args, ctx, *, agent_config, tools, policy=None, emitter=None, sink=None):
    if policy is None:
        policy = RuleBasedPolicy()
    if emitter is None:
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
    return await check_tool_call.run(
        name, args, ctx,
        agent_config=agent_config,
        tools=tools,
        policy=policy,
        arg_scanners=[],
        emitter=emitter,
        tenant_id="test",
    ), sink


# ── L1: allowed_tool_names ────────────────────────────────────────────────

async def test_tool_not_in_allowed_tool_names_denied():
    agent = make_agent(allowed_tool_names=["search_docs"],
                       allowed_tags=["read", "internal", "external_write"])
    tools, sink, emitter, policy = setup()
    ctx  = AgentContext(agent_id="test_agent")

    gate, _ = await _run("send_email", {}, ctx,
                         agent_config=agent, tools=tools, policy=policy, emitter=emitter, sink=sink)
    assert not gate.allowed
    assert "allowed_tool_names" in gate.deny_reason
    assert sink.events[0].decision == Decision.DENY


async def test_unregistered_tool_denied():
    agent = make_agent(allowed_tool_names=["phantom_tool"],
                       allowed_tags=["read"])
    tools = {}  # phantom_tool not in tools dict
    ctx   = AgentContext(agent_id="test_agent")
    gate, sink = await _run("phantom_tool", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
    assert "not registered" in gate.deny_reason


# ── L2: allowed_tags subagent gate ────────────────────────────────────────

async def test_subagent_tag_gate_denies_external_write():
    sub = SubAgentConfig(
        id="read_sub",
        allowed_tool_names=["search_docs", "send_email"],
        allowed_tags=["read", "internal"],  # no external_write
    )
    agent = make_agent(
        allowed_tool_names=["search_docs", "send_email"],
        allowed_tags=["read", "internal", "external_write"],
        sub_agents=[sub],
    )
    tools = {"search_docs": make_tool("search_docs"),
             "send_email":  make_tool("send_email", ["external_write"])}
    ctx   = AgentContext(agent_id="test_agent", sub_agent_id="read_sub",
                         allowed_tags=["read", "internal"])

    gate, _ = await _run("send_email", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
    assert "capability set" in gate.deny_reason


# ── L3: policy deny ───────────────────────────────────────────────────────

async def test_policy_deny_rule_fires():
    rule = RuleConfig(
        id="deny_email",
        match=RuleMatchConfig(tool_names=["send_email"]),
        action="deny",
        reason="email not allowed",
    )
    agent = make_agent(
        allowed_tool_names=["send_email"],
        allowed_tags=["read", "internal", "external_write"],
        policy_rules=[rule],
    )
    tools = {"send_email": make_tool("send_email", ["external_write"])}
    ctx   = AgentContext(agent_id="test_agent")

    gate, _ = await _run("send_email", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
    assert "email not allowed" in gate.deny_reason


# ── Allow path ────────────────────────────────────────────────────────────

async def test_allow_path_emits_allow_event():
    agent = make_agent()
    tools = {"search_docs": make_tool("search_docs")}
    ctx   = AgentContext(agent_id="test_agent")
    sink  = RecordingSink()
    emitter = AuditEmitter([sink])

    gate, _ = await _run("search_docs", {"query": "test"}, ctx,
                         agent_config=agent, tools=tools, emitter=emitter, sink=sink)
    assert gate.allowed
    assert sink.events[0].decision == Decision.ALLOW


# ── Exactly one audit event ───────────────────────────────────────────────

async def test_exactly_one_event_on_deny():
    agent = make_agent(allowed_tool_names=["missing"])
    tools = {}
    ctx   = AgentContext(agent_id="test_agent")
    gate, sink = await _run("missing", {}, ctx, agent_config=agent, tools=tools)
    assert len(sink.events) == 1


async def test_exactly_one_event_on_allow():
    agent = make_agent()
    tools = {"search_docs": make_tool("search_docs")}
    ctx   = AgentContext(agent_id="test_agent")
    gate, sink = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert len(sink.events) == 1


# ── Subagent resolution ───────────────────────────────────────────────────

async def test_unknown_subagent_denied():
    agent = make_agent(sub_agents=[])  # no subagents declared
    tools = {"search_docs": make_tool("search_docs")}
    ctx   = AgentContext(agent_id="test_agent", sub_agent_id="ghost_sub",
                         allowed_tags=["read"])
    gate, _ = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
