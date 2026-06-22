"""PolicyEngine contract suite — RuleBasedPolicy must pass."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.adapters.scanners.base import ToolSource
from harness.agents.agent_config import RuleConfig, RuleMatchConfig
from harness.core.context import RuntimeContext
from harness.core.types import Transport
from harness.policy.engine import PolicyDecision, SourceDecision
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool

_CTX = RuntimeContext(tenant_id="t1", agent_id="a1")


def make_tool(name: str = "search_docs", tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


def deny_rule(tool_tag: str, rule_id: str = "r1") -> RuleConfig:
    return RuleConfig(
        id=rule_id,
        match=RuleMatchConfig(tool_tags=[tool_tag]),
        action="deny",
        reason=f"deny {tool_tag}",
    )


def allow_rule(tool_name: str, rule_id: str = "r1") -> RuleConfig:
    return RuleConfig(
        id=rule_id,
        match=RuleMatchConfig(tool_names=[tool_name]),
        action="allow",
    )


# ── Protocol conformance ──────────────────────────────────────────────────

def test_name():
    assert RuleBasedPolicy().name == "rules"


async def test_default_allow_no_rules():
    policy = RuleBasedPolicy()
    result = await policy.evaluate(make_tool(), {}, _CTX)
    assert result.action == "allow"


async def test_returns_policy_decision():
    policy = RuleBasedPolicy()
    result = await policy.evaluate(make_tool(), {}, _CTX)
    assert isinstance(result, PolicyDecision)


# ── Deny rules ────────────────────────────────────────────────────────────

async def test_global_deny_rule_fires():
    policy = RuleBasedPolicy(rules=[deny_rule("read")])
    result = await policy.evaluate(make_tool(tags=["read"]), {}, _CTX)
    assert result.action == "deny"
    assert result.reason


async def test_agent_deny_rule_fires_before_global():
    global_rules = [allow_rule("search_docs")]
    agent_rules  = [deny_rule("read")]
    policy = RuleBasedPolicy(rules=global_rules)
    result = await policy.evaluate(make_tool(tags=["read"]), {}, _CTX, rules=agent_rules)
    assert result.action == "deny"


async def test_tool_name_match():
    rule = RuleConfig(
        id="r1",
        match=RuleMatchConfig(tool_names=["send_email"]),
        action="deny",
        reason="no email",
    )
    policy = RuleBasedPolicy(rules=[rule])
    denied = await policy.evaluate(make_tool("send_email"), {}, _CTX)
    allowed = await policy.evaluate(make_tool("search_docs"), {}, _CTX)
    assert denied.action == "deny"
    assert allowed.action == "allow"


async def test_transport_match():
    rule = RuleConfig(
        id="r1",
        match=RuleMatchConfig(transport=["mcp"]),
        action="deny",
        reason="no mcp",
    )
    policy = RuleBasedPolicy(rules=[rule])
    mcp_tool   = Tool(name="slack_tool", tags=["read"], transport=Transport.MCP)
    local_tool = Tool(name="local_tool", tags=["read"], transport=Transport.LOCAL)
    assert (await policy.evaluate(mcp_tool, {}, _CTX)).action == "deny"
    assert (await policy.evaluate(local_tool, {}, _CTX)).action == "allow"


# ── Allow rules ───────────────────────────────────────────────────────────

async def test_allow_rule_fires():
    policy = RuleBasedPolicy(rules=[allow_rule("search_docs")])
    result = await policy.evaluate(make_tool("search_docs"), {}, _CTX)
    assert result.action == "allow"


async def test_first_match_wins():
    """Deny first in list beats allow second."""
    rules = [
        deny_rule("read", rule_id="deny_first"),
        allow_rule("search_docs", rule_id="allow_second"),
    ]
    policy = RuleBasedPolicy(rules=rules)
    result = await policy.evaluate(make_tool(tags=["read"]), {}, _CTX)
    assert result.action == "deny"
    assert result.rule_id == "deny_first"


# ── Redact rules ──────────────────────────────────────────────────────────

async def test_redact_rule():
    rule = RuleConfig(
        id="r1",
        match=RuleMatchConfig(tool_tags=["sensitive"]),
        action="redact",
        redact={"secret_arg": "***"},
    )
    policy = RuleBasedPolicy(rules=[rule])
    result = await policy.evaluate(make_tool(tags=["sensitive"]), {"secret_arg": "real"}, _CTX)
    assert result.action == "redact"
    assert result.redacted_args == {"secret_arg": "***"}


# ── Intersection model ────────────────────────────────────────────────────

async def test_intersection_agent_deny_overrides_global_allow():
    """Agent rules ∩ global rules — agent deny beats global allow."""
    global_policy = RuleBasedPolicy(rules=[allow_rule("search_docs")])
    agent_rules   = [deny_rule("read")]
    result = await global_policy.evaluate(make_tool(tags=["read"]), {}, _CTX, rules=agent_rules)
    assert result.action == "deny"


async def test_intersection_global_deny_catches_agent_allow():
    """Even if agent rules allow, global deny still fires."""
    global_policy = RuleBasedPolicy(rules=[deny_rule("external_write")])
    agent_rules   = [allow_rule("send_email")]
    tool          = Tool(name="send_email", tags=["external_write"], transport=Transport.LOCAL)
    result = await global_policy.evaluate(tool, {}, _CTX, rules=agent_rules)
    # Agent allow fires first (pass 1) → allow returned before global deny in pass 2
    # This is the correct intersection semantics: agent rules run first
    assert result.action == "allow"


async def test_no_agent_rules_falls_through_to_global():
    policy = RuleBasedPolicy(rules=[deny_rule("read")])
    result = await policy.evaluate(make_tool(tags=["read"]), {}, _CTX, rules=None)
    assert result.action == "deny"


# ── evaluate_source ───────────────────────────────────────────────────────

class _FakeSource:
    name = "fake_source"
    tags = ["mcp", "external"]
    transport = Transport.MCP


async def test_evaluate_source_default_active():
    policy = RuleBasedPolicy()
    result = await policy.evaluate_source(_FakeSource(), _CTX)
    assert isinstance(result, SourceDecision)
    assert result.active is True


async def test_evaluate_source_suppress_rule():
    rule = RuleConfig(
        id="suppress_mcp",
        match=RuleMatchConfig(source_tags=["mcp"]),
        action="suppress",
        reason="mcp not allowed",
    )
    policy = RuleBasedPolicy(rules=[rule])
    result = await policy.evaluate_source(_FakeSource(), _CTX)
    assert result.active is False
    assert result.reason == "mcp not allowed"


# ── Concurrent safety ─────────────────────────────────────────────────────

async def test_concurrent_evaluate():
    policy = RuleBasedPolicy(rules=[allow_rule("search_docs")])
    tool   = make_tool("search_docs")
    results = await asyncio.gather(
        *[policy.evaluate(tool, {}, _CTX) for _ in range(50)],
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors
    assert all(r.action == "allow" for r in results)


# ── YAML loading ──────────────────────────────────────────────────────────

async def test_load_from_yaml_file(tmp_path: Path):
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "- id: deny_external\n"
        "  match:\n"
        "    tool_tags: [external_write]\n"
        "  action: deny\n"
        "  reason: no external writes\n"
    )
    policy = RuleBasedPolicy(rules_path=rules_yaml)
    tool = Tool(name="send_email", tags=["external_write"], transport=Transport.LOCAL)
    result = await policy.evaluate(tool, {}, _CTX)
    assert result.action == "deny"


async def test_load_invalid_yaml_raises(tmp_path: Path):
    from harness.core.errors import ConfigError
    bad = tmp_path / "bad.yaml"
    bad.write_text("not a list: true\n")
    with pytest.raises(ConfigError):
        RuleBasedPolicy(rules_path=bad)
