"""Unit tests for check_tool_call boundary.

Tests the boundary directly with pre-resolved agent_config and tools dict
— no registry lookup on the hot path.
"""
from __future__ import annotations

from pathlib import Path

from harness.agents.agent_config import AgentConfig, RuleConfig, RuleMatchConfig, SubAgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import AgentContext
from harness.core.types import Decision, Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

FIXTURES = Path(__file__).parent.parent / "fixtures"


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


# ── L4: parent capability gate (SHAI-011) ────────────────────────────────
#
# allowed_tags used to bind subagents only: L4 read ctx.allowed_tags, which is
# None on a parent turn, so a top-level agent declaring `allowed_tags: [read]`
# got no gate enforcement from it at all. It now binds both, intersected — a
# hand-built AgentContext cannot widen the config, and a deliberately narrowed
# one is not ignored.

async def test_parent_allowed_tags_denies_uncovered_tag():
    """A parent's own declaration gates its own calls."""
    tools, sink, emitter, policy = setup()
    agent = make_agent(allowed_tags=["read"])          # tool carries read+internal
    ctx   = AgentContext(agent_id="test_agent")        # no ctx.allowed_tags

    gate, sink = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
    assert "internal" in gate.deny_reason
    assert "agent capability set" in gate.deny_reason
    assert len(sink.events) == 1
    assert sink.events[0].decision == Decision.DENY


async def test_parent_allowed_tags_allows_full_cover():
    """Declaring every tag the tool carries lets it through."""
    tools, sink, emitter, policy = setup()
    agent = make_agent(allowed_tags=["read", "internal"])
    ctx   = AgentContext(agent_id="test_agent")

    gate, _ = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert gate.allowed


async def test_context_cannot_widen_the_configured_capability_set():
    """A hand-built context claiming more tags than the config does not win.

    ctx.allowed_tags is caller-supplied. Preferring it over the config would
    make L4 bypassable by constructing an AgentContext directly.
    """
    tools, sink, emitter, policy = setup()
    agent = make_agent(allowed_tags=["read"])
    ctx   = AgentContext(agent_id="test_agent",
                         allowed_tags=["read", "internal", "external_write"])

    gate, _ = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed, "context widened the agent's configured capability set"


async def test_context_can_still_narrow():
    """A narrower context is honoured — intersection, not replacement."""
    tools, sink, emitter, policy = setup()
    agent = make_agent(allowed_tags=["read", "internal"])
    ctx   = AgentContext(agent_id="test_agent", allowed_tags=["read"])

    gate, _ = await _run("search_docs", {}, ctx, agent_config=agent, tools=tools)
    assert not gate.allowed
    assert "internal" in gate.deny_reason


# ── L7: per-scanner action ────────────────────────────────────────────────
#
# Layer 7 resolves each scanner's declared action exactly as every other
# boundary does. It previously took bare scanner instances and hard-denied on
# any HIGH finding, so `action: redact` on a check_tool_call scanner loaded
# without complaint and did nothing.

from harness.adapters.scanners.base import ConfiguredScanner  # noqa: E402
from harness.adapters.scanners.regex_pii import RegexPIIScanner  # noqa: E402
from harness.core.types import ScanAction  # noqa: E402

_CREDENTIAL_ARGS = {"api_key": "sk-live-9f8a7b6c5d4e3f2a1b0c"}


async def _run_with_arg_scanner(action, args=None):
    agent = make_agent(allowed_tool_names=["send_email"],
                       allowed_tags=["read", "internal", "external_write", "sensitive"])
    tools, sink, emitter, policy = setup()
    ctx = AgentContext(agent_id="test_agent")
    gate = await check_tool_call.run(
        "send_email", args if args is not None else dict(_CREDENTIAL_ARGS), ctx,
        agent_config=agent,
        tools=tools,
        policy=policy,
        arg_scanners=[ConfiguredScanner(scanner=RegexPIIScanner(), action=action)],
        emitter=emitter,
        tenant_id="test",
        scan_args_for_tags=frozenset({"sensitive"}),
    )
    return gate, sink


async def test_l7_undeclared_action_still_blocks():
    """The gate has no boundary action to inherit, so the default stays block."""
    gate, sink = await _run_with_arg_scanner(None)
    assert gate.allowed is False
    assert "arg scan blocked" in gate.deny_reason
    assert "sk-live" not in gate.deny_reason


async def test_l7_alert_passes_through():
    gate, _ = await _run_with_arg_scanner(ScanAction.ALERT)
    assert gate.allowed is True
    assert gate.redacted_args is None


async def test_l7_redact_substitutes_into_the_argument():
    """Redaction lands on the key that produced it, without the scan framing."""
    gate, _ = await _run_with_arg_scanner(ScanAction.REDACT)
    assert gate.allowed is True
    assert gate.redacted_args is not None
    redacted = gate.redacted_args["api_key"]
    assert "sk-live-9f8a7b6c5d4e3f2a1b0c" not in redacted
    # The `key: ` framing added for detection must not survive into the value.
    assert not redacted.startswith("api_key: ")


async def test_l7_scans_with_key_context():
    """regex_pii matches `api_key: <value>` and finds nothing in the value alone.

    Scanning bare values would silently stop detecting credentials at the gate,
    so the key stays in the scanned text.
    """
    gate, _ = await _run_with_arg_scanner(None, args={"api_key": "sk-live-9f8a7b6c5d4e3f2a1b0c"})
    assert gate.allowed is False

    bare = await RegexPIIScanner().scan("sk-live-9f8a7b6c5d4e3f2a1b0c", AgentContext(agent_id="t"))
    assert bare.findings == []


async def test_l7_benign_arguments_are_untouched():
    gate, _ = await _run_with_arg_scanner(None, args={"recipient": "team@example.com"})
    assert gate.allowed is True
    assert gate.redacted_args is None
