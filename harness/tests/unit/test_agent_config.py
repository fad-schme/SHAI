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
