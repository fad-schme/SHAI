"""Tests for core/context.py."""
import pytest
from pydantic import ValidationError

from harness.core.context import RuntimeContext


def test_basic_construction():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    assert ctx.tenant_id == "t1"
    assert ctx.agent_id == "a1"
    assert ctx.sub_agent_id is None
    assert ctx.user_id is None
    assert ctx.session_id is None


def test_agent_key_top_level():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    assert ctx.agent_key() == ("a1", "")


def test_agent_key_subagent():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1", sub_agent_id="s1")
    assert ctx.agent_key() == ("a1", "s1")


def test_to_log_fields_all_present():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1", user_id="u1")
    fields = ctx.to_log_fields()
    assert fields["tenant_id"] == "t1"
    assert fields["agent_id"] == "a1"
    assert fields["user_id"] == "u1"
    assert fields["sub_agent_id"] is None
    assert fields["session_id"] is None


def test_empty_tenant_id_rejected():
    with pytest.raises(ValidationError):
        RuntimeContext(tenant_id="", agent_id="a1")


def test_whitespace_tenant_id_rejected():
    with pytest.raises(ValidationError):
        RuntimeContext(tenant_id="   ", agent_id="a1")


def test_empty_agent_id_rejected():
    with pytest.raises(ValidationError):
        RuntimeContext(tenant_id="t1", agent_id="")


def test_frozen():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    with pytest.raises(Exception):
        ctx.agent_id = "changed"  # type: ignore


def test_user_id_session_id_are_optional():
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1", user_id="u1", session_id="s1")
    assert ctx.user_id == "u1"
    assert ctx.session_id == "s1"
    # These are audit-only — verify they don't affect agent_key
    assert ctx.agent_key() == ("a1", "")
