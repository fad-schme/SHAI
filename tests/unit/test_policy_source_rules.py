"""Global policy carries source-activation rules only.

`policy.rules` — the per-tool-call deny/allow/redact list evaluated at layer 5
after the agent's own rules — is gone. What survives under `policy:` is
`source_rules`, which decide which sources activate, and
`forbidden_tag_combinations`, which constrains what an agent may declare.
Both are about the harness's own composition rather than arbitrating one
agent's tool call.

`_match_source` honours every field a source rule is allowed to carry. A field
it cannot honour is rejected at parse — silently ignoring one turns a narrowing
rule into a blanket one.
"""
from __future__ import annotations

import pytest

from harness.agents.agent_config import AgentConfig, RuleConfig, RuleMatchConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.config.loader import load_dict
from harness.config.schema import PolicyConfig
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

_CTX = AgentContext(agent_id="a")


class _Source:
    def __init__(self, name: str, tags: list[str], transport: Transport) -> None:
        self.name, self.tags, self.transport = name, tags, transport


def _suppress(**match: object) -> RuleConfig:
    return RuleConfig(
        id="s", match=RuleMatchConfig(**match), action="suppress", reason="off"
    )


# ── _match_source honours transport ───────────────────────────────────────

async def test_transport_scoped_suppress_leaves_other_transports_active():
    """The bug this replaces: `transport` was dropped, so a rule narrowed to
    MCP suppressed local sources too."""
    policy = RuleBasedPolicy([_suppress(transport=["mcp"])])
    mcp   = _Source("slack_mcp", ["external_mcp"], Transport.MCP)
    local = _Source("local_fs",  ["local"],        Transport.LOCAL)

    assert (await policy.evaluate_source(mcp, _CTX)).active is False
    assert (await policy.evaluate_source(local, _CTX)).active is True


async def test_source_tags_still_match():
    policy = RuleBasedPolicy([_suppress(source_tags=["external_mcp"])])
    assert (await policy.evaluate_source(
        _Source("slack_mcp", ["external_mcp"], Transport.MCP), _CTX)).active is False
    assert (await policy.evaluate_source(
        _Source("local_fs", ["local"], Transport.LOCAL), _CTX)).active is True


async def test_transport_and_source_tags_must_both_match():
    policy = RuleBasedPolicy([_suppress(transport=["mcp"], source_tags=["messaging"])])
    assert (await policy.evaluate_source(
        _Source("slack", ["messaging"], Transport.MCP), _CTX)).active is False
    # right transport, wrong tag
    assert (await policy.evaluate_source(
        _Source("other", ["files"], Transport.MCP), _CTX)).active is True


async def test_no_rules_leaves_every_source_active():
    policy = RuleBasedPolicy()
    assert (await policy.evaluate_source(
        _Source("any", ["x"], Transport.LOCAL), _CTX)).active is True


# ── fields a source rule cannot honour are rejected ───────────────────────

@pytest.mark.parametrize("bad", [
    {"tool_names": ["send"]},
    {"tool_tags": ["destructive"]},
    {"any": [{"tool_tags": ["read"]}]},
    {"all": [{"tool_tags": ["read"]}]},
])
def test_source_rule_with_a_tool_scoped_field_is_rejected(bad):
    with pytest.raises(ValueError, match="source_rules"):
        PolicyConfig(source_rules=[{
            "id": "s", "match": bad, "action": "suppress", "reason": "off",
        }])


def test_source_rule_must_be_suppress():
    with pytest.raises(ValueError, match="suppress"):
        PolicyConfig(source_rules=[{
            "id": "s", "match": {"source_tags": ["x"]},
            "action": "deny", "reason": "no",
        }])


def test_valid_source_rule_parses():
    cfg = PolicyConfig(source_rules=[{
        "id": "s", "match": {"transport": ["mcp"], "agent_ids": ["a"]},
        "action": "suppress", "reason": "off",
    }])
    assert len(cfg.parsed_source_rules()) == 1


# ── policy.rules is gone ──────────────────────────────────────────────────

def test_policy_rules_key_is_rejected():
    """A stale config must fail loudly, not be silently ignored."""
    with pytest.raises(ConfigError):
        load_dict({
            "scan_input":  {"enabled": False},
            "scan_output": {"enabled": False},
            "audit_sinks": [{"name": "stdout"}],
            "policy": {"rules": [
                {"id": "x", "match": {"tool_tags": ["mcp"]},
                 "action": "deny", "reason": "no"},
            ]},
        })


# ── agent-scoped rules still work at layer 5 ──────────────────────────────

async def _gate(tool: Tool, args: dict, agent: AgentConfig):
    sink = RecordingSink()
    decision = await check_tool_call.run(
        tool.name, args, _CTX,
        agent_config=agent, tools={tool.name: tool},
        policy=RuleBasedPolicy(), arg_scanners=[],
        emitter=AuditEmitter([sink]), tenant_id="t",
    )
    return decision, sink


async def test_agent_deny_rule_still_fires_with_no_global_rules():
    tool  = Tool(name="drop_db", tags=["destructive"], transport=Transport.LOCAL)
    agent = AgentConfig(
        id="a", allowed_tool_names=["drop_db"], allowed_tags=["destructive"],
        policy_rules=[RuleConfig(
            id="no_drop", match=RuleMatchConfig(tool_names=["drop_db"]),
            action="deny", reason="not allowed",
        )],
    )
    decision, sink = await _gate(tool, {}, agent)
    assert not decision.allowed
    assert decision.deny_reason == "not allowed"
    assert len(sink.events) == 1


async def test_agent_redact_rule_still_fires_with_no_global_rules():
    tool  = Tool(name="send", tags=["external_write"], transport=Transport.LOCAL)
    agent = AgentConfig(
        id="a", allowed_tool_names=["send"], allowed_tags=["external_write"],
        policy_rules=[RuleConfig(
            id="mask", match=RuleMatchConfig(tool_names=["send"]),
            action="redact", redact={"body": "[GONE]"},
        )],
    )
    decision, _ = await _gate(tool, {"body": "secret", "to": "x"}, agent)
    assert decision.allowed
    # merge, not replace — the unnamed argument survives
    assert decision.redacted_args == {"body": "[GONE]", "to": "x"}


async def test_no_rules_anywhere_defaults_to_allow():
    tool  = Tool(name="safe", tags=["read"], transport=Transport.LOCAL)
    agent = AgentConfig(id="a", allowed_tool_names=["safe"], allowed_tags=["read"])
    decision, _ = await _gate(tool, {}, agent)
    assert decision.allowed


def test_malformed_source_rule_names_the_field():
    """A rule missing `id` is rejected at config load naming the field, not
    flattened into an opaque construction failure."""
    with pytest.raises(ValueError, match="id"):
        PolicyConfig(source_rules=[{
            "match": {"source_tags": ["x"]}, "action": "suppress",
        }])
