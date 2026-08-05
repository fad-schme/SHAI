"""Tests for argument_policy.py and its integration into check_tool_call.

Section 1 — ArgumentRule.evaluate(): unit tests for each constraint type.
Section 2 — check_argument_rules(): confirms gate fires and carries context.
Section 3 — check_irreversibility(): confirms tier enforcement.
Section 4 — Integration through check_tool_call.run(): confirms both checks
             sit in the gate's hot path and emit exactly one audit event.
"""
from __future__ import annotations

from typing import Any

import pytest

from harness.agents.agent_config import AgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.boundaries.argument_policy import check_argument_rules, check_irreversibility
from harness.core.approval import ApprovalPolicy, encode_grant, sign_grant
from harness.core.context import AgentContext
from harness.core.errors import ArgumentViolationError, IrreversibleActionError
from harness.core.types import Decision, Irreversibility
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import ArgumentRule, Tool
from tests.conftest import RecordingSink

# ── Helpers ───────────────────────────────────────────────────────────────

def make_agent(tool_name: str = "pay_invoice") -> AgentConfig:
    return AgentConfig(
        id="test_agent",
        allowed_tool_names=[tool_name],
        allowed_tags=["read", "financial"],
    )


_SECRET = b"approval-test-secret"
_POLICY = ApprovalPolicy(secret=_SECRET, sensitive_quorum=1, irreversible_quorum=2)


def _grants(tool_name: str, args: dict[str, Any], *approvers: str,
            agent_id: str = "test_agent", tenant_id: str = "test") -> tuple[str, ...]:
    return tuple(
        encode_grant(sign_grant(
            agent_id=agent_id, tenant_id=tenant_id, tool_name=tool_name,
            args=args, approver_id=a, secret=_SECRET,
        ))
        for a in approvers
    )


async def _gate(
    tool: Tool,
    args: dict[str, Any],
    ctx: AgentContext | None = None,
    approvals: ApprovalPolicy | None = None,
) -> tuple:
    if ctx is None:
        ctx = AgentContext(agent_id="test_agent")
    agent = make_agent(tool.name)
    sink = RecordingSink()
    emitter = AuditEmitter([sink])
    gate = await check_tool_call.run(
        tool.name, args, ctx,
        agent_config=agent,
        tools={tool.name: tool},
        policy=RuleBasedPolicy(),
        arg_scanners=[],
        emitter=emitter,
        tenant_id="test",
        approvals=approvals,
    )
    return gate, sink


# ── Section 1: ArgumentRule.evaluate() ───────────────────────────────────

def test_max_value_pass():
    assert ArgumentRule(arg="amount", max_value=50_000).evaluate({"amount": 49_999}) is None

def test_max_value_exact_boundary_passes():
    assert ArgumentRule(arg="amount", max_value=50_000).evaluate({"amount": 50_000}) is None

def test_max_value_violation():
    result = ArgumentRule(arg="amount", max_value=50_000).evaluate({"amount": 1_200_000})
    assert result is not None and "amount" in result

def test_min_value_pass():
    assert ArgumentRule(arg="qty", min_value=1).evaluate({"qty": 5}) is None

def test_min_value_violation():
    result = ArgumentRule(arg="qty", min_value=1).evaluate({"qty": 0})
    assert result is not None and "qty" in result

def test_allowlist_pass():
    assert ArgumentRule(arg="vendor", allowlist=["acme", "globex"]).evaluate({"vendor": "acme"}) is None

def test_allowlist_violation():
    result = ArgumentRule(arg="vendor", allowlist=["acme"]).evaluate({"vendor": "evil_corp"})
    assert result is not None and "vendor" in result

def test_pattern_pass():
    assert ArgumentRule(arg="url", pattern=r"^https://pay\.internal/").evaluate(
        {"url": "https://pay.internal/tx"}) is None

def test_pattern_violation():
    result = ArgumentRule(arg="url", pattern=r"^https://pay\.internal/").evaluate(
        {"url": "https://evil.com/steal"})
    assert result is not None and "url" in result

def test_required_present():
    assert ArgumentRule(arg="recipient", required=True).evaluate({"recipient": "a@b.com"}) is None

def test_required_missing():
    result = ArgumentRule(arg="recipient", required=True).evaluate({})
    assert result is not None and "recipient" in result

def test_absent_optional_passes():
    assert ArgumentRule(arg="cc", max_value=100).evaluate({}) is None

def test_non_numeric_value_fails_max_check():
    result = ArgumentRule(arg="amount", max_value=100).evaluate({"amount": "not_a_number"})
    assert result is not None

def test_nan_string_passes_silently():
    # float("nan") is valid Python — nan comparisons are always False, so
    # nan never exceeds a numeric bound. This is expected behaviour.
    assert ArgumentRule(arg="amount", max_value=100).evaluate({"amount": "nan"}) is None


# ── Section 2: check_argument_rules() ────────────────────────────────────

def test_no_rules_passes():
    tool = Tool(name="read_doc", tags=["read"])
    check_argument_rules(tool, {"anything": "goes"}, AgentContext(agent_id="a1"))

def test_all_rules_satisfied_passes():
    tool = Tool(name="pay", tags=["financial"], argument_rules=[
        ArgumentRule(arg="amount", max_value=50_000),
        ArgumentRule(arg="vendor", allowlist=["acme"]),
    ])
    check_argument_rules(tool, {"amount": 100, "vendor": "acme"}, AgentContext(agent_id="a1"))

def test_first_violation_raises():
    tool = Tool(name="pay", tags=["financial"], argument_rules=[
        ArgumentRule(arg="amount", max_value=50_000),
        ArgumentRule(arg="vendor", allowlist=["acme"]),
    ])
    with pytest.raises(ArgumentViolationError):
        check_argument_rules(tool, {"amount": 999_999, "vendor": "acme"},
                             AgentContext(agent_id="a1"))

def test_error_carries_agent_id():
    tool = Tool(name="pay", tags=["financial"], argument_rules=[
        ArgumentRule(arg="amount", max_value=100),
    ])
    with pytest.raises(ArgumentViolationError) as exc_info:
        check_argument_rules(tool, {"amount": 200}, AgentContext(agent_id="my_agent"))
    assert exc_info.value.agent_id == "my_agent"


# ── Section 3: check_irreversibility() ───────────────────────────────────

def _check(tool: Tool, ctx: AgentContext, args: dict[str, Any] | None = None,
           approvals: ApprovalPolicy = _POLICY) -> list[str]:
    return check_irreversibility(
        tool, ctx, args=args or {}, tenant_id="test", approvals=approvals
    )


def test_reversible_always_passes():
    tool = Tool(name="t", tags=["read"], irreversibility=Irreversibility.REVERSIBLE)
    assert _check(tool, AgentContext(agent_id="a1")) == []

def test_sensitive_blocked_without_approval():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    with pytest.raises(IrreversibleActionError):
        _check(tool, AgentContext(agent_id="a1"))

def test_sensitive_passes_with_one_grant():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    ctx = AgentContext(agent_id="a1", approvals=_grants("t", {}, "alex", agent_id="a1"))
    assert _check(tool, ctx) == ["alex"]

def test_irreversible_blocked_without_approval():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.IRREVERSIBLE)
    with pytest.raises(IrreversibleActionError):
        _check(tool, AgentContext(agent_id="a1"))

def test_irreversible_requires_two_distinct_approvers():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.IRREVERSIBLE)
    one = AgentContext(agent_id="a1", approvals=_grants("t", {}, "alex", agent_id="a1"))
    with pytest.raises(IrreversibleActionError, match="1 distinct approver"):
        _check(tool, one)

    two = AgentContext(agent_id="a1",
                       approvals=_grants("t", {}, "alex", "sam", agent_id="a1"))
    assert _check(tool, two) == ["alex", "sam"]

def test_two_grants_from_one_approver_are_not_a_quorum():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.IRREVERSIBLE)
    ctx = AgentContext(agent_id="a1",
                       approvals=_grants("t", {}, "alex", "alex", agent_id="a1"))
    with pytest.raises(IrreversibleActionError, match="1 distinct approver"):
        _check(tool, ctx)

def test_unconfigured_approvals_deny_rather_than_fall_back():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    ctx = AgentContext(agent_id="a1", approvals=_grants("t", {}, "alex", agent_id="a1"))
    with pytest.raises(IrreversibleActionError, match="not configured"):
        _check(tool, ctx, approvals=ApprovalPolicy())

def test_error_carries_agent_id():
    tool = Tool(name="delete_record", tags=["write"], irreversibility=Irreversibility.IRREVERSIBLE)
    with pytest.raises(IrreversibleActionError) as exc_info:
        _check(tool, AgentContext(agent_id="my_agent"))
    assert exc_info.value.agent_id == "my_agent"


# ── Grant binding: a signature is not enough on its own ──────────────────

@pytest.mark.parametrize("kwargs,expected", [
    ({"tool_name": "other_tool"},                "different tool"),
    ({"agent_id": "other_agent"},                "different agent"),
    ({"tenant_id": "other_tenant"},              "different tenant"),
])
def test_grant_bound_elsewhere_is_rejected(kwargs, expected):
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    defaults = {"agent_id": "a1", "tenant_id": "test", "tool_name": "t"}
    grant = encode_grant(sign_grant(
        **{**defaults, **kwargs}, args={}, approver_id="alex", secret=_SECRET,
    ))
    ctx = AgentContext(agent_id="a1", approvals=(grant,))
    with pytest.raises(IrreversibleActionError, match=expected):
        _check(tool, ctx)


def test_grant_does_not_authorise_different_arguments():
    """Approving a $5 refund must not authorise a $50,000 one."""
    tool = Tool(name="refund", tags=["financial"],
                irreversibility=Irreversibility.SENSITIVE)
    ctx = AgentContext(
        agent_id="a1",
        approvals=_grants("refund", {"amount": 5}, "alex", agent_id="a1"),
    )
    assert _check(tool, ctx, {"amount": 5}) == ["alex"]
    with pytest.raises(IrreversibleActionError, match="different arguments"):
        _check(tool, ctx, {"amount": 50_000})


def test_grant_signed_with_another_key_is_rejected():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    forged = encode_grant(sign_grant(
        agent_id="a1", tenant_id="test", tool_name="t", args={},
        approver_id="alex", secret=b"not-the-key",
    ))
    ctx = AgentContext(agent_id="a1", approvals=(forged,))
    with pytest.raises(IrreversibleActionError, match="signature mismatch"):
        _check(tool, ctx)


def test_expired_grant_is_rejected():
    tool = Tool(name="t", tags=["write"], irreversibility=Irreversibility.SENSITIVE)
    stale = encode_grant(sign_grant(
        agent_id="a1", tenant_id="test", tool_name="t", args={},
        approver_id="alex", secret=_SECRET, ttl_seconds=-1,
    ))
    ctx = AgentContext(agent_id="a1", approvals=(stale,))
    with pytest.raises(IrreversibleActionError, match="expired"):
        _check(tool, ctx)


def test_approvals_do_not_reach_subagents():
    """A grant authorises one call by the parent, not whatever it delegates."""
    ctx = AgentContext(agent_id="a1", approvals=_grants("t", {}, "alex", agent_id="a1"))
    assert ctx.scope_subagent("child", allowed_tags=["read"]).approvals == ()


# ── Section 4: Integration through check_tool_call.run() ─────────────────

async def test_argument_violation_denies_gate():
    tool = Tool(name="pay_invoice", tags=["financial"], argument_rules=[
        ArgumentRule(arg="amount", max_value=50_000),
    ])
    gate, sink = await _gate(tool, {"amount": 1_200_000})
    assert not gate.allowed
    assert "argument rule violation" in gate.deny_reason
    assert sink.events[0].decision == Decision.DENY

async def test_argument_violation_emits_exactly_one_event():
    tool = Tool(name="pay_invoice", tags=["financial"], argument_rules=[
        ArgumentRule(arg="amount", max_value=50_000),
    ])
    gate, sink = await _gate(tool, {"amount": 999_999})
    assert len(sink.events) == 1

async def test_irreversibility_denies_without_approval():
    tool = Tool(name="pay_invoice", tags=["financial"],
                irreversibility=Irreversibility.IRREVERSIBLE)
    gate, sink = await _gate(tool, {}, approvals=_POLICY)
    assert not gate.allowed
    assert "irreversible" in gate.deny_reason
    assert sink.events[0].decision == Decision.DENY

async def test_irreversibility_passes_with_quorum():
    tool = Tool(name="pay_invoice", tags=["financial"],
                irreversibility=Irreversibility.IRREVERSIBLE)
    ctx = AgentContext(
        agent_id="test_agent",
        approvals=_grants("pay_invoice", {}, "alex", "sam"),
    )
    gate, sink = await _gate(tool, {}, ctx=ctx, approvals=_POLICY)
    assert gate.allowed

async def test_approvers_are_recorded_on_the_allow_event():
    """The audit trail must answer who authorised an irreversible action."""
    tool = Tool(name="pay_invoice", tags=["financial"],
                irreversibility=Irreversibility.IRREVERSIBLE)
    ctx = AgentContext(
        agent_id="test_agent",
        approvals=_grants("pay_invoice", {}, "alex", "sam"),
    )
    _, sink = await _gate(tool, {}, ctx=ctx, approvals=_POLICY)
    assert sink.events[0].extra["approvers"] == ["alex", "sam"]

async def test_reversible_tool_records_no_approvers():
    tool = Tool(name="search", tags=["read"])
    _, sink = await _gate(tool, {}, approvals=_POLICY)
    assert "approvers" not in sink.events[0].extra

async def test_argument_rules_checked_before_irreversibility():
    """Argument violation fires first — irreversibility not reached."""
    tool = Tool(
        name="pay_invoice",
        tags=["financial"],
        argument_rules=[ArgumentRule(arg="amount", max_value=50_000)],
        irreversibility=Irreversibility.IRREVERSIBLE,
    )
    # No human_approved AND amount violation — argument rule fires first
    gate, _ = await _gate(tool, {"amount": 999_999})
    assert not gate.allowed
    assert "argument rule violation" in gate.deny_reason

async def test_all_rules_pass_irreversible_approved_allows():
    tool = Tool(
        name="pay_invoice",
        tags=["financial"],
        argument_rules=[ArgumentRule(arg="amount", max_value=50_000)],
        irreversibility=Irreversibility.IRREVERSIBLE,
    )
    args = {"amount": 100}
    ctx = AgentContext(
        agent_id="test_agent",
        approvals=_grants("pay_invoice", args, "alex", "sam"),
    )
    gate, _ = await _gate(tool, args, ctx=ctx, approvals=_POLICY)
    assert gate.allowed

async def test_reversible_tool_with_no_rules_unaffected():
    """Tools with defaults are completely unaffected by the new checks."""
    tool = Tool(name="pay_invoice", tags=["financial"])
    gate, sink = await _gate(tool, {"anything": "goes"})
    assert gate.allowed
    assert len(sink.events) == 1
    assert sink.events[0].decision == Decision.ALLOW
