"""Tests for argument_policy.py and its integration into check_tool_call.

Section 1 — ArgumentRule.evaluate(): unit tests for each constraint type.
Section 2 — check_argument_rules(): confirms gate fires and carries context.
Section 3 — check_irreversibility(): confirms tier enforcement.
Section 4 — Integration through check_tool_call.run(): confirms both checks
             sit in the gate's hot path and emit exactly one audit event.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from harness.adapters.state_store.memory_store import InMemoryStore
from harness.agents.agent_config import AgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.boundaries.argument_policy import check_argument_rules, check_irreversibility
from harness.core.approval import ApprovalPolicy, encode_grant, sign_grant
from harness.core.context import AgentContext
from harness.core.errors import ArgumentViolationError, IrreversibleActionError
from harness.core.types import Decision, Irreversibility
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import ArgumentRule, ScopeRulePolicy, Tool
from tests.conftest import RecordingSink

# ── Helpers ───────────────────────────────────────────────────────────────

def make_agent(tool_name: str = "pay_invoice") -> AgentConfig:
    return AgentConfig(
        id="test_agent",
        allowed_tool_names=[tool_name],
        allowed_tags=["read", "financial"],
    )


_SECRET = b"approval-test-secret"
_POLICY = ApprovalPolicy(
    secret=_SECRET, sensitive_quorum=1, irreversible_quorum=2, store=InMemoryStore().kv,
)


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


# ── scope_policy: ArgumentRule wiring (matching logic itself is tested in
# test_scope.py, which owns connectivity.scope.check_scope_policy) ─────────

_DOMAIN_POLICY = ScopeRulePolicy(allowed_domains=["example.test"], allow_subdomains=True)


def test_scope_policy_pass_returns_none():
    rule = ArgumentRule(arg="url", scope_policy=_DOMAIN_POLICY)
    assert rule.evaluate({"url": "https://api.example.test/hook"}) is None


def test_scope_policy_violation_names_the_argument():
    rule = ArgumentRule(arg="url", scope_policy=_DOMAIN_POLICY)
    result = rule.evaluate({"url": "https://evil.test/hook"})
    assert result is not None and "url" in result


def test_scope_policy_absent_leaves_other_fields_unaffected():
    rule = ArgumentRule(arg="vendor", allowlist=["acme"])
    assert rule.evaluate({"vendor": "acme"}) is None


def test_scope_policy_violation_message_carries_no_raw_url():
    """Unlike allowlist/pattern, the scope_policy violation message must not
    embed the raw argument value — it can reach a signed audit field."""
    rule = ArgumentRule(arg="url", scope_policy=_DOMAIN_POLICY)
    result = rule.evaluate({"url": "https://secret-token-abc123@evil.test/hook"})
    assert result is not None
    assert "secret-token-abc123" not in result
    assert "evil.test" not in result


def test_scope_policy_ip_in_allowed_hosts_does_not_bypass_default_deny():
    """Regression: an IP literal in allowed_hosts must not skip
    is_ip_in_scope's private-range default-deny (see test_scope.py for the
    full corpus) — confirms the ArgumentRule path carries the same posture."""
    rule = ArgumentRule(
        arg="url", scope_policy=ScopeRulePolicy(allowed_hosts=["127.0.0.1"])
    )
    result = rule.evaluate({"url": "http://127.0.0.1/hook"})
    assert result is not None


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


# ── Section 5: a grant authorises one call ───────────────────────────────

_SPENT = "approval_grant:"


def _policy(store=None, **kwargs) -> ApprovalPolicy:
    return ApprovalPolicy(
        secret=_SECRET, sensitive_quorum=1, irreversible_quorum=2,
        store=store if store is not None else InMemoryStore().kv, **kwargs,
    )


def _pay(irreversibility=Irreversibility.SENSITIVE, tags=("financial",)) -> Tool:
    return Tool(name="pay_invoice", tags=list(tags), irreversibility=irreversibility)


async def test_a_grant_allows_one_call_and_denies_the_next():
    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    first, _ = await _gate(_pay(), {}, ctx=ctx, approvals=policy)
    second, sink = await _gate(_pay(), {}, ctx=ctx, approvals=policy)
    assert first.allowed
    assert not second.allowed
    assert "already been used" in second.deny_reason
    assert len(sink.events) == 1 and sink.events[0].decision == Decision.DENY


async def test_a_grant_spent_through_one_policy_is_refused_through_another_on_the_store():
    kv = InMemoryStore().kv
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    first, _ = await _gate(_pay(), {}, ctx=ctx, approvals=_policy(kv))
    second, _ = await _gate(_pay(), {}, ctx=ctx, approvals=_policy(kv))
    assert first.allowed and not second.allowed


async def test_every_grant_of_a_quorum_is_spent_by_one_allowed_call():
    policy = _policy()
    grants = _grants("pay_invoice", {}, "alex", "sam")
    tool = _pay(Irreversibility.IRREVERSIBLE)
    first, _ = await _gate(tool, {}, ctx=AgentContext(agent_id="test_agent", approvals=grants),
                           approvals=policy)
    assert first.allowed
    assert len(await policy.store.list(_SPENT)) == 2
    for single in grants:
        again, _ = await _gate(
            tool, {}, ctx=AgentContext(agent_id="test_agent", approvals=(single,)),
            approvals=_policy(policy.store, ),
        )
        assert not again.allowed


async def test_a_call_denied_after_layer_3_leaves_its_grant_unspent():
    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    # "write" is outside the agent's capability set: layer 4 refuses after layer 3 verified.
    denied, _ = await _gate(_pay(tags=("financial", "write")), {}, ctx=ctx, approvals=policy)
    assert not denied.allowed
    assert await policy.store.list(_SPENT) == []
    allowed, _ = await _gate(_pay(), {}, ctx=ctx, approvals=policy)
    assert allowed.allowed


async def test_concurrent_calls_with_one_grant_allow_exactly_one():
    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    results = await asyncio.gather(
        *[_gate(_pay(), {}, ctx=ctx, approvals=policy) for _ in range(15)]
    )
    assert sum(gate.allowed for gate, _ in results) == 1
    assert all(len(sink.events) == 1 for _, sink in results)


async def test_a_reversible_tool_does_not_spend_the_grants_on_the_context():
    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    gate, _ = await _gate(_pay(Irreversibility.REVERSIBLE), {}, ctx=ctx, approvals=policy)
    assert gate.allowed
    assert await policy.store.list(_SPENT) == []


async def test_approvals_without_a_store_deny_rather_than_skip_the_spend():
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    gate, sink = await _gate(
        _pay(), {}, ctx=ctx, approvals=ApprovalPolicy(secret=_SECRET),
    )
    assert not gate.allowed
    assert "approvals store" in gate.deny_reason
    assert len(sink.events) == 1


class _DeadKV:
    name = "dead"

    async def list(self, prefix):
        raise ConnectionError("store unreachable")

    put_if_absent = get = delete = list


async def test_an_unreachable_store_denies_with_one_event_and_no_exception():
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    gate, sink = await _gate(_pay(), {}, ctx=ctx, approvals=_policy(_DeadKV()))
    assert not gate.allowed
    assert "approvals store" in gate.deny_reason
    assert "unreachable" not in gate.deny_reason
    assert len(sink.events) == 1 and sink.events[0].decision == Decision.DENY


async def test_the_reuse_denial_carries_no_argument_value():
    policy = _policy()
    args = {"note": "AKIAIOSFODNN7EXAMPLE_hunter2"}
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", args, "alex"))
    await _gate(_pay(), args, ctx=ctx, approvals=policy)
    gate, sink = await _gate(_pay(), args, ctx=ctx, approvals=policy)
    assert not gate.allowed
    assert "AKIA" not in gate.deny_reason and "hunter2" not in gate.deny_reason
    assert "AKIA" not in str(sink.events[0].model_dump())


async def test_a_token_mint_failure_denies_with_one_event_and_gives_the_grant_back():
    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))

    def broken_mint():
        raise RuntimeError("token mint failed: secret-detail")

    tool, sink = _pay(), RecordingSink()
    gate = await check_tool_call.run(
        tool.name, {}, ctx, agent_config=make_agent(tool.name), tools={tool.name: tool},
        policy=RuleBasedPolicy(), arg_scanners=[], emitter=AuditEmitter([sink]),
        tenant_id="test", approvals=policy, issue_token=broken_mint,
    )
    assert not gate.allowed
    assert "secret-detail" not in gate.deny_reason
    assert len(sink.events) == 1 and sink.events[0].decision == Decision.DENY
    assert await policy.store.list(_SPENT) == []
    retry, _ = await _gate(tool, {}, ctx=ctx, approvals=policy)
    assert retry.allowed


async def test_a_token_mint_failure_denies_a_call_that_carries_no_grants_too():
    tool, sink = Tool(name="search", tags=["read"]), RecordingSink()

    def broken_mint():
        raise RuntimeError("boom")

    gate = await check_tool_call.run(
        tool.name, {}, AgentContext(agent_id="test_agent"),
        agent_config=make_agent(tool.name), tools={tool.name: tool},
        policy=RuleBasedPolicy(), arg_scanners=[], emitter=AuditEmitter([sink]),
        tenant_id="test", issue_token=broken_mint,
    )
    assert not gate.allowed
    assert len(sink.events) == 1 and sink.events[0].decision == Decision.DENY


async def test_grants_are_released_once_when_the_deny_event_also_cannot_be_written():
    """A second release could delete a claim another call made in between."""
    from harness.core.errors import AuditEmissionError

    kv = InMemoryStore().kv
    deletes: list[str] = []
    real_delete = kv.delete

    async def counting_delete(key):
        deletes.append(key)
        await real_delete(key)

    kv.delete = counting_delete
    policy = _policy(kv)
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))

    def broken_mint():
        raise RuntimeError("boom")

    tool = _pay()
    with pytest.raises(AuditEmissionError):
        await check_tool_call.run(
            tool.name, {}, ctx, agent_config=make_agent(tool.name), tools={tool.name: tool},
            policy=RuleBasedPolicy(), arg_scanners=[], emitter=AuditEmitter([_DeadSink()]),
            tenant_id="test", approvals=policy, issue_token=broken_mint,
        )
    assert len(deletes) == 1


class _DeadSink:
    name = "dead"

    async def emit(self, event):
        raise OSError("sink is down")

    async def close(self):
        pass


async def test_a_total_audit_outage_gives_the_grant_back():
    from harness.core.errors import AuditEmissionError

    policy = _policy()
    ctx = AgentContext(agent_id="test_agent", approvals=_grants("pay_invoice", {}, "alex"))
    tool = _pay()
    with pytest.raises(AuditEmissionError):
        await check_tool_call.run(
            tool.name, {}, ctx, agent_config=make_agent(tool.name), tools={tool.name: tool},
            policy=RuleBasedPolicy(), arg_scanners=[], emitter=AuditEmitter([_DeadSink()]),
            tenant_id="test", approvals=policy,
        )
    assert await policy.store.list(_SPENT) == []


# ── Invariant 3: no violation message may carry the argument value ────────
#
# `evaluate()` returns the text that becomes ArgumentViolationError, which the
# gate passes verbatim to emit_deny and thence to AuditEvent.deny_reason — a
# signed, durable field. The rule scope_policy has always been held to this
# (see test_scope_policy_violation_message_carries_no_raw_url); these extend it
# to the branches that used to interpolate the value.

_ARG_VALUE = "AKIAIOSFODNN7EXAMPLE_hunter2"


def test_allowlist_violation_carries_no_raw_value():
    result = ArgumentRule(arg="vendor", allowlist=["acme"]).evaluate({"vendor": _ARG_VALUE})
    assert result is not None and "vendor" in result
    assert _ARG_VALUE not in result


def test_pattern_violation_carries_no_raw_value():
    """The widest leak: pattern echoed the whole value on any non-match."""
    result = ArgumentRule(arg="body", pattern=r"^SAFE:").evaluate({"body": _ARG_VALUE})
    assert result is not None and "body" in result
    assert _ARG_VALUE not in result


def test_max_value_violation_carries_no_raw_value():
    result = ArgumentRule(arg="amount", max_value=1_000).evaluate({"amount": 999_999.99})
    assert result is not None and "amount" in result
    assert "999999.99" not in result and "999_999.99" not in result


def test_min_value_violation_carries_no_raw_value():
    result = ArgumentRule(arg="qty", min_value=10).evaluate({"qty": -4242})
    assert result is not None and "qty" in result
    assert "-4242" not in result and "4242" not in result


def test_violation_messages_still_distinguish_the_constraint():
    """Stripping the value must not make every violation read the same — an
    operator triages on which constraint fired, not just which argument."""
    arg = "field"
    msgs = [
        ArgumentRule(arg=arg, allowlist=["ok"]).evaluate({arg: "no"}),
        ArgumentRule(arg=arg, pattern=r"^ok$").evaluate({arg: "no"}),
        ArgumentRule(arg=arg, max_value=1).evaluate({arg: 2}),
        ArgumentRule(arg=arg, min_value=5).evaluate({arg: 1}),
    ]
    assert all(m is not None and arg in m for m in msgs)
    assert len(set(msgs)) == len(msgs)
