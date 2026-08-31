"""The manifest's per-tool `action` is enforced.

`action: block` compiles to a deny rule the gate evaluates ahead of the
agent's own rules; `action: allow` compiles to nothing at all, so an agent
rule denying the same tool still denies. The manifest adds denials, never
removes them.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.agents.agent_config import (
    AgentConfig,
    RuleConfig,
    RuleMatchConfig,
    SubAgentConfig,
)
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.types import Decision, Transport
from harness.mcp.discovery import compile_manifest_rules
from harness.mcp.manifest import load_manifest_file
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

_MANIFEST = """\
id: svc
display_name: "Service"
url: "https://mcp.example.test/sse"
tools:
  - name: search
    description: "Search the corpus."
    action: allow
  - name: delete_repo
    description: "Delete a repo — irreversible, destroys history."
    action: block
"""


def _manifest(tmp_path: Path, body: str = _MANIFEST):
    path = tmp_path / "svc.yaml"
    path.write_text(body, encoding="utf-8")
    return load_manifest_file(path), path


def _tools() -> dict[str, Tool]:
    return {
        "search":      Tool(name="search", tags=["mcp"], transport=Transport.MCP,
                            source_name="svc"),
        "delete_repo": Tool(name="delete_repo", tags=["mcp"], transport=Transport.MCP,
                            source_name="svc"),
    }


def _agent(policy_rules: list[RuleConfig] | None = None) -> AgentConfig:
    return AgentConfig(
        id="agent",
        allowed_tool_names=["search", "delete_repo"],
        allowed_tags=["mcp"],
        policy_rules=policy_rules or [],
    )


async def _gate(name, *, agent, manifest_rules):
    sink    = RecordingSink()
    emitter = AuditEmitter([sink])
    decision = await check_tool_call.run(
        name, {}, AgentContext(agent_id="agent"),
        agent_config=agent,
        tools=_tools(),
        policy=RuleBasedPolicy(),
        arg_scanners=[],
        emitter=emitter,
        tenant_id="test",
        manifest_rules=manifest_rules,
    )
    return decision, sink


# ── Compilation ───────────────────────────────────────────────────────────

def test_block_compiles_to_a_deny_rule_and_allow_compiles_to_nothing(tmp_path: Path):
    manifest, _ = _manifest(tmp_path)
    rules = compile_manifest_rules(manifest)

    assert [r.match.tool_names for r in rules] == [["delete_repo"]]
    assert rules[0].action == "deny"
    assert rules[0].id == "mcp:svc:delete_repo"


def test_alert_is_rejected_at_parse_naming_the_field_and_file(tmp_path: Path):
    body = _MANIFEST.replace("action: block", "action: alert")
    with pytest.raises(ConfigError) as exc:
        _manifest(tmp_path, body)
    message = str(exc.value)
    assert "tools.1.action" in message
    assert str(tmp_path / "svc.yaml") in message


# ── Enforcement at the gate ───────────────────────────────────────────────

async def test_manifest_block_denies_the_call(tmp_path: Path):
    manifest, _ = _manifest(tmp_path)
    decision, sink = await _gate(
        "delete_repo", agent=_agent(), manifest_rules=compile_manifest_rules(manifest),
    )
    assert not decision.allowed
    assert "delete_repo" in decision.deny_reason
    assert "action: block" in decision.deny_reason
    # Invariant 1: exactly one audit event on the deny path.
    assert len(sink.events) == 1
    assert sink.events[0].decision == Decision.DENY
    # Invariant 3: the reason names the tool and the declared action — never
    # the manifest's description text.
    assert "irreversible" not in decision.deny_reason.lower()


async def test_manifest_allow_passes(tmp_path: Path):
    manifest, _ = _manifest(tmp_path)
    decision, _ = await _gate(
        "search", agent=_agent(), manifest_rules=compile_manifest_rules(manifest),
    )
    assert decision.allowed


async def test_operator_deny_over_manifest_allow_still_denies(tmp_path: Path):
    """`action: allow` is the absence of a restriction, not a grant."""
    manifest, _ = _manifest(tmp_path)
    agent = _agent([RuleConfig(
        id="no_search",
        match=RuleMatchConfig(tool_names=["search"]),
        action="deny",
        reason="operator policy",
    )])
    decision, _ = await _gate(
        "search", agent=agent, manifest_rules=compile_manifest_rules(manifest),
    )
    assert not decision.allowed
    assert "operator policy" in decision.deny_reason


async def test_agent_allow_does_not_override_manifest_block(tmp_path: Path):
    manifest, _ = _manifest(tmp_path)
    agent = _agent([RuleConfig(
        id="allow_delete",
        match=RuleMatchConfig(tool_names=["delete_repo"]),
        action="allow",
    )])
    decision, _ = await _gate(
        "delete_repo", agent=agent, manifest_rules=compile_manifest_rules(manifest),
    )
    assert not decision.allowed
    assert "action: block" in decision.deny_reason


async def test_subagent_allow_rule_does_not_override_manifest_block(tmp_path: Path):
    """The manifest deny leads the combined list for a subagent context too —
    where the order is manifest → subagent rules → parent rules.
    """
    manifest, _ = _manifest(tmp_path)
    sub = SubAgentConfig(
        id="deleter",
        allowed_tool_names=["delete_repo"],
        allowed_tags=["mcp"],
        policy_rules=[RuleConfig(
            id="sub_allows_delete",
            match=RuleMatchConfig(tool_names=["delete_repo"]),
            action="allow",
        )],
    )
    agent = AgentConfig(
        id="agent",
        allowed_tool_names=["search", "delete_repo"],
        allowed_tags=["mcp"],
        sub_agents=[sub],
    )
    sink    = RecordingSink()
    emitter = AuditEmitter([sink])
    decision = await check_tool_call.run(
        "delete_repo", {},
        AgentContext(agent_id="agent", sub_agent_id="deleter", allowed_tags=["mcp"]),
        agent_config=agent,
        tools=_tools(),
        policy=RuleBasedPolicy(),
        arg_scanners=[],
        emitter=emitter,
        tenant_id="test",
        manifest_rules=compile_manifest_rules(manifest),
    )
    assert not decision.allowed
    assert "action: block" in decision.deny_reason
    assert len(sink.events) == 1
