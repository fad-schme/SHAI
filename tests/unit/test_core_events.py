"""Tests for core/events.py."""
import pytest
from pydantic import ValidationError

from harness.core.context import RuntimeContext
from harness.core.events import AuditEvent
from harness.core.types import BoundaryName, Decision, Severity


def _ctx(**kw) -> RuntimeContext:
    return RuntimeContext(tenant_id="t1", agent_id="a1", **kw)


def _build(**kw) -> AuditEvent:
    defaults = dict(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=_ctx(),
        duration_ms=5,
    )
    defaults.update(kw)
    return AuditEvent.build(**defaults)


def test_build_allow_defaults():
    e = _build()
    assert e.decision == Decision.ALLOW
    assert e.tenant_id == "t1"
    assert e.agent_id == "a1"
    assert e.finding_count == 0
    assert e.disabled is False
    assert e.sub_agent_id is None


def test_build_deny_requires_reason():
    with pytest.raises(ValidationError):
        _build(boundary=BoundaryName.TOOL_CALL_GATE, decision=Decision.DENY)


def test_build_deny_with_reason():
    e = _build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.DENY,
        deny_reason="policy denied",
    )
    assert e.deny_reason == "policy denied"


def test_disabled_boundary_event():
    e = _build(disabled=True)
    assert e.disabled is True
    assert e.decision == Decision.ALLOW
    assert e.finding_count == 0


def test_disabled_with_nonzero_findings_rejected():
    with pytest.raises(ValidationError):
        _build(disabled=True, finding_count=1)


def test_blocked_on_gate_rejected():
    with pytest.raises(ValidationError):
        _build(boundary=BoundaryName.TOOL_CALL_GATE, decision=Decision.BLOCKED)


def test_sub_agent_id_carried():
    ctx = _ctx(sub_agent_id="research_sub")
    e = AuditEvent.build(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=ctx,
        duration_ms=1,
    )
    assert e.sub_agent_id == "research_sub"


def test_audit_tags_carried():
    e = _build(audit_tags={"team": "platform"})
    assert e.audit_tags == {"team": "platform"}


def test_user_id_session_id_are_audit_only():
    ctx = _ctx(user_id="u99", session_id="s99")
    e = AuditEvent.build(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=ctx,
        duration_ms=1,
    )
    assert e.user_id == "u99"
    assert e.session_id == "s99"
    # They are on the event for audit trail — verify they're present and correct
    assert e.tenant_id == "t1"
    assert e.agent_id == "a1"
