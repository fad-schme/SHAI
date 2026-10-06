"""Tests for agents/agent_config.py."""
import pytest
from pydantic import ValidationError

from harness.agents.agent_config import AgentConfig
from harness.core.errors import SubAgentNotDeclaredError


def _minimal(**kw) -> dict:
    base = {
        "id": "test_agent",
        "allowed_tool_names": ["search_docs"],
        "allowed_tags": ["read", "internal"],
    }
    base.update(kw)
    return base


def test_minimal_valid():
    a = AgentConfig.model_validate(_minimal())
    assert a.id == "test_agent"
    assert a.sub_agents == []
    assert a.log_level == "INFO"


def test_id_uppercase_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(id="TestAgent"))


def test_id_spaces_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(id="test agent"))


def test_id_digits_first_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(id="1agent"))


def test_id_snake_case_ok():
    a = AgentConfig.model_validate(_minimal(id="my_email_agent_v2"))
    assert a.id == "my_email_agent_v2"


def test_empty_allowed_tool_names_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(allowed_tool_names=[]))


def test_empty_allowed_tags_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(allowed_tags=[]))


def test_invalid_log_level_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(log_level="VERBOSE"))


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(surprise_key="oops"))


def test_subagent_tool_names_must_be_subset():
    data = _minimal(
        allowed_tool_names=["search_docs"],
        sub_agents=[{
            "id": "sub",
            "allowed_tool_names": ["search_docs", "send_email"],
            "allowed_tags": ["read"],
        }],
    )
    with pytest.raises(ValidationError, match="send_email"):
        AgentConfig.model_validate(data)


def test_subagent_tags_must_be_subset():
    data = _minimal(
        allowed_tags=["read"],
        sub_agents=[{
            "id": "sub",
            "allowed_tool_names": ["search_docs"],
            "allowed_tags": ["read", "external_write"],
        }],
    )
    with pytest.raises(ValidationError, match="external_write"):
        AgentConfig.model_validate(data)


def test_duplicate_sub_agent_ids_rejected():
    sub = {"id": "sub", "allowed_tool_names": ["search_docs"], "allowed_tags": ["read"]}
    data = _minimal(sub_agents=[sub, sub])
    with pytest.raises(ValidationError, match="duplicate"):
        AgentConfig.model_validate(data)


def test_get_sub_agent_found():
    data = _minimal(sub_agents=[{
        "id": "research_sub",
        "allowed_tool_names": ["search_docs"],
        "allowed_tags": ["read"],
    }])
    a = AgentConfig.model_validate(data)
    sub = a.get_sub_agent("research_sub")
    assert sub.id == "research_sub"
    assert sub.allowed_tags == ["read"]


def test_get_sub_agent_not_found():
    a = AgentConfig.model_validate(_minimal())
    with pytest.raises(SubAgentNotDeclaredError):
        a.get_sub_agent("nonexistent")


def test_subagent_sources_independent_of_parent():
    """Subagent sources are NOT required to be a subset of parent sources."""
    data = _minimal(
        sources=["docs_skill"],
        sub_agents=[{
            "id": "sub",
            "allowed_tool_names": ["search_docs"],
            "allowed_tags": ["read"],
            "sources": ["outlook_mcp"],  # not in parent — this is correct behaviour
        }],
    )
    a = AgentConfig.model_validate(data)
    assert a.sub_agents[0].sources == ["outlook_mcp"]


def test_rule_deny_requires_reason():
    data = _minimal(policy_rules=[{
        "id": "r1",
        "match": {},
        "action": "deny",
    }])
    with pytest.raises(ValidationError, match="reason"):
        AgentConfig.model_validate(data)


def test_rule_deny_with_reason_ok():
    data = _minimal(policy_rules=[{
        "id": "r1",
        "match": {"tool_tags": ["external_write"]},
        "action": "deny",
        "reason": "not allowed",
    }])
    a = AgentConfig.model_validate(data)
    assert a.policy_rules[0].reason == "not allowed"


# ── A tool rule cannot name a source-scoped field ────────────────────────
#
# _match_tool never reads source_tags, so a rule whose match names only it has
# nothing to compare and matches every tool call. Rejected at load, the mirror
# of PolicyConfig rejecting tool-scoped fields on a source rule.

_DENY_BY_SOURCE = {"source_tags": ["external"]}


def _rule(match: dict) -> dict:
    return {"id": "by_source", "match": match, "action": "deny", "reason": "no"}


@pytest.mark.parametrize("match", [
    _DENY_BY_SOURCE,
    {"tool_names": ["search_docs"], "source_tags": ["external"]},
    {"any": [{"source_tags": ["external"]}]},
    {"all": [{"tool_tags": ["read"]}, {"source_tags": ["external"]}]},
    {"not": {"source_tags": ["external"]}},
    {"any": [{"not": {"source_tags": ["external"]}}]},
    {"not_": {"source_tags": ["external"]}},
    {"any": [{"not_": {"source_tags": ["external"]}}]},
    {"all": [{"tool_tags": ["read"]}, {"not_": {"source_tags": ["external"]}}]},
], ids=["top-level", "with-tool-field", "any", "all", "not", "nested",
        "not_-top-level", "not_-in-any", "not_-in-all"])
def test_agent_rule_naming_source_tags_is_rejected(match):
    with pytest.raises(ValidationError, match="by_source.*source_tags"):
        AgentConfig.model_validate(_minimal(policy_rules=[_rule(match)]))


def test_sub_agent_rule_naming_source_tags_is_rejected():
    sub = {"id": "child", "allowed_tool_names": ["search_docs"], "allowed_tags": ["read"],
           "policy_rules": [_rule(_DENY_BY_SOURCE)]}
    with pytest.raises(ValidationError, match="child.*by_source.*source_tags"):
        AgentConfig.model_validate(_minimal(sub_agents=[sub]))


def test_agent_rules_using_only_tool_fields_still_load():
    match = {"tool_names": ["search_docs"], "tool_tags": ["read"], "transport": ["local"],
             "agent_ids": ["test_agent"], "sub_agent_ids": ["child"]}
    a = AgentConfig.model_validate(_minimal(policy_rules=[_rule(match)]))
    assert a.policy_rules[0].id == "by_source"


# ── NHI profile: optional metadata, never enforced ────────────────────────

_PROFILE = {
    "description": "Answers support tickets",
    "owners": ["alice@example.com"],
    "sponsors": ["bob@example.com"],
    "environment": "production",
    "review_due": "2026-12-01",
    "delegation_mode": "on_behalf_of_user",
    "credential_refs": [
        {"name": "slack_bot_token", "expires_at": "2027-01-15", "rotated_at": "2026-07-01"},
        {"name": "db_password"},
    ],
}


def test_profile_defaults_when_absent():
    a = AgentConfig.model_validate(_minimal())
    assert a.description is None and a.environment is None
    assert a.review_due is None and a.delegation_mode is None
    assert a.owners == [] and a.sponsors == [] and a.credential_refs == []


def test_profile_fields_parse():
    a = AgentConfig.model_validate(_minimal(**_PROFILE))
    assert a.owners == ["alice@example.com"]
    assert a.review_due.isoformat() == "2026-12-01"
    assert a.delegation_mode == "on_behalf_of_user"
    assert [c.name for c in a.credential_refs] == ["slack_bot_token", "db_password"]
    assert a.credential_refs[0].expires_at.isoformat() == "2027-01-15"
    assert a.credential_refs[1].expires_at is None


@pytest.mark.parametrize("bad", [
    {"owners": "alice@example.com"},
    {"sponsors": "bob"},
    {"review_due": "next quarter"},
    {"delegation_mode": "semi_autonomous"},
    {"credential_refs": [{"expires_at": "2027-01-15"}]},
    {"credential_refs": [{"name": ""}]},
    {"credential_refs": [{"name": "t", "expires_at": "soon"}]},
    {"credential_refs": [{"name": "t", "secret": "hunter2"}]},
    {"unknown_profile_key": "x"},
])
def test_malformed_profile_rejected(bad):
    with pytest.raises(ValidationError):
        AgentConfig.model_validate(_minimal(**bad))
