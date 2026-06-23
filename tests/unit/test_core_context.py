"""Tests for core/context.py — AgentContext."""
import pytest
from pydantic import ValidationError

from harness.core.context import AgentContext


def test_basic_construction():
    ctx = AgentContext(agent_id="a1")
    assert ctx.agent_id == "a1"
    assert ctx.sub_agent_id is None
    assert ctx.allowed_tags is None


def test_to_log_fields():
    ctx = AgentContext(agent_id="a1", sub_agent_id="sub1")
    fields = ctx.to_log_fields()
    assert fields["agent_id"] == "a1"
    assert fields["sub_agent_id"] == "sub1"


def test_to_log_fields_no_tenant_or_user():
    """AgentContext carries only agent identity — no tenant_id or user_id."""
    ctx = AgentContext(agent_id="a1")
    fields = ctx.to_log_fields()
    assert "tenant_id" not in fields
    assert "user_id" not in fields
    assert "session_id" not in fields


def test_empty_agent_id_rejected():
    with pytest.raises(ValidationError):
        AgentContext(agent_id="")


def test_whitespace_agent_id_rejected():
    with pytest.raises(ValidationError):
        AgentContext(agent_id="   ")


def test_frozen():
    ctx = AgentContext(agent_id="a1")
    with pytest.raises(Exception):
        ctx.agent_id = "changed"  # type: ignore


def test_no_tenant_id_field():
    """tenant_id is on HarnessConfig, not AgentContext."""
    ctx = AgentContext(agent_id="a1")
    assert not hasattr(ctx, "tenant_id")


def test_no_user_id_field():
    """user_id is not on AgentContext — use audit_tags on AgentConfig."""
    ctx = AgentContext(agent_id="a1")
    assert not hasattr(ctx, "user_id")


def test_scope_subagent_returns_child():
    ctx   = AgentContext(agent_id="orchestrator")
    child = ctx.scope_subagent("research_sub", allowed_tags=["read", "internal"])
    assert child.agent_id     == "orchestrator"
    assert child.sub_agent_id == "research_sub"
    assert child.allowed_tags == ["read", "internal"]


def test_scope_subagent_parent_unchanged():
    ctx   = AgentContext(agent_id="orchestrator")
    child = ctx.scope_subagent("research_sub", allowed_tags=["read"])
    assert ctx.sub_agent_id is None   # parent not mutated