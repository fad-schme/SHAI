"""Unit tests for check_tool_call boundary."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.adapters.tool_registry.memory import InMemoryRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import RuntimeContext
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


async def _setup():
    """Return (registry, view, policy, emitter, sink) pre-populated with test tools."""
    reg = InMemoryRegistry()
    await reg.register_many([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])
    sink    = RecordingSink()
    emitter = AuditEmitter([sink])
    policy  = RuleBasedPolicy()
    return reg, sink, emitter, policy


async def _load_agent_registry(path: Path):
    from harness.agents.registry import AgentRegistry
    r = AgentRegistry()
    await r.load(path)
    return r


# ── L1a: agent not registered ─────────────────────────────────────────────

async def test_unregistered_agent_denied():
    from harness.agents.registry import AgentRegistry
    reg, sink, emitter, policy = await _setup()
    view = reg.scoped_view(RuntimeContext(tenant_id="t1", agent_id="nobody"))
    ctx  = RuntimeContext(tenant_id="t1", agent_id="nobody")

    gate = await check_tool_call.run(
        "search_docs", {}, ctx,
        agent_registry=AgentRegistry(),
        registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert not gate.allowed
    assert "not registered" in gate.deny_reason
    assert sink.events[0].decision == Decision.DENY


# ── L1b: allowed_tool_names ────────────────────────────────────────────────

async def test_tool_not_in_allowed_tool_names_denied(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search_docs]\n"  # send_email NOT allowed
        "allowed_tags: [read, internal, external_write]\n"
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="test_agent")
    view = reg.scoped_view(ctx)

    gate = await check_tool_call.run(
        "send_email", {"to": "x@y.com"}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert not gate.allowed
    assert "allowed_tool_names" in gate.deny_reason
    assert sink.events[0].decision == Decision.DENY


# ── L1c: allowed_tags ─────────────────────────────────────────────────────

async def test_subagent_tag_gate_denies_external_write(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search_docs, send_email]\n"
        "allowed_tags: [read, internal, external_write]\n"
        "sub_agents:\n"
        "  - id: read_sub\n"
        "    allowed_tool_names: [search_docs, send_email]\n"
        "    allowed_tags: [read, internal]\n"  # no external_write
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()
    ctx = RuntimeContext(
        tenant_id="t1", agent_id="test_agent",
        sub_agent_id="read_sub", allowed_tags=["read", "internal"],
    )
    view = reg.scoped_view(ctx)

    gate = await check_tool_call.run(
        "send_email", {"to": "x@y.com"}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert not gate.allowed
    assert "capability set" in gate.deny_reason


# ── L2: policy deny ───────────────────────────────────────────────────────

async def test_policy_deny_rule_fires(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [send_email]\n"
        "allowed_tags: [read, internal, external_write]\n"
        "policy_rules:\n"
        "  - id: deny_email\n"
        "    match:\n"
        "      tool_names: [send_email]\n"
        "    action: deny\n"
        "    reason: email not allowed\n"
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="test_agent")
    view = reg.scoped_view(ctx)

    gate = await check_tool_call.run(
        "send_email", {}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert not gate.allowed
    assert "email not allowed" in gate.deny_reason


# ── Allow path ────────────────────────────────────────────────────────────

async def test_allow_path_emits_allow_event(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read, internal]\n"
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="test_agent")
    view = reg.scoped_view(ctx)
    await view.add(Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL))

    gate = await check_tool_call.run(
        "search_docs", {"query": "test"}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert gate.allowed
    assert sink.events[0].decision == Decision.ALLOW


# ── Exactly one audit event every path ───────────────────────────────────

async def test_exactly_one_event_on_deny():
    from harness.agents.registry import AgentRegistry
    reg, sink, emitter, policy = await _setup()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="nobody")
    view = reg.scoped_view(ctx)

    await check_tool_call.run(
        "search_docs", {}, ctx,
        agent_registry=AgentRegistry(),
        registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert len(sink.events) == 1


async def test_exactly_one_event_on_allow(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read, internal]\n"
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="test_agent")
    view = reg.scoped_view(ctx)
    await view.add(Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL))

    await check_tool_call.run(
        "search_docs", {}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert len(sink.events) == 1


# ── Tool not in registry ──────────────────────────────────────────────────

async def test_unknown_tool_denied(tmp_path):
    agent_yaml = tmp_path / "a.yaml"
    agent_yaml.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [phantom_tool]\n"
        "allowed_tags: [read]\n"
    )
    agent_reg = await _load_agent_registry(agent_yaml)
    reg, sink, emitter, policy = await _setup()  # phantom_tool not registered
    ctx  = RuntimeContext(tenant_id="t1", agent_id="test_agent")
    view = reg.scoped_view(ctx)

    gate = await check_tool_call.run(
        "phantom_tool", {}, ctx,
        agent_registry=agent_reg, registry_view=view, policy=policy,
        arg_scanners=[], emitter=emitter,
    )
    assert not gate.allowed
    assert "not found in registry" in gate.deny_reason
