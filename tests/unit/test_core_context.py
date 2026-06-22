"""Tests for core/context.py."""
import pytest
from pydantic import ValidationError

from harness.core.context import RuntimeContext


def test_basic_construction():
    ctx = RuntimeContext(agent_id="a1")
    assert ctx.agent_id == "a1"
    assert ctx.sub_agent_id is None
    assert ctx.allowed_tags is None


def test_agent_key_top_level():
    ctx = RuntimeContext(agent_id="a1")
    assert ctx.agent_key() == ("a1", "")


def test_agent_key_subagent():
    ctx = RuntimeContext(agent_id="a1", sub_agent_id="s1")
    assert ctx.agent_key() == ("a1", "s1")


def test_to_log_fields():
    ctx = RuntimeContext(agent_id="a1", sub_agent_id="sub1")
    fields = ctx.to_log_fields()
    assert fields["agent_id"] == "a1"
    assert fields["sub_agent_id"] == "sub1"


def test_to_log_fields_no_tenant_or_user():
    """RuntimeContext carries only agent identity — no tenant_id or user_id."""
    ctx = RuntimeContext(agent_id="a1")
    fields = ctx.to_log_fields()
    assert "tenant_id" not in fields
    assert "user_id" not in fields
    assert "session_id" not in fields


def test_empty_agent_id_rejected():
    with pytest.raises(ValidationError):
        RuntimeContext(agent_id="")


def test_whitespace_agent_id_rejected():
    with pytest.raises(ValidationError):
        RuntimeContext(agent_id="   ")


def test_frozen():
    ctx = RuntimeContext(agent_id="a1")
    with pytest.raises(Exception):
        ctx.agent_id = "changed"  # type: ignore


def test_no_tenant_id_field():
    """tenant_id is on HarnessConfig, not RuntimeContext."""
    ctx = RuntimeContext(agent_id="a1")
    assert not hasattr(ctx, "tenant_id")


def test_no_user_id_field():
    """user_id is not on RuntimeContext — use audit_tags on AgentConfig."""
    ctx = RuntimeContext(agent_id="a1")
    assert not hasattr(ctx, "user_id")
