"""Tests for core/approval.py — grant signing, verification, and binding."""
from __future__ import annotations

import base64
import json

import pytest

from harness.core.approval import (
    ApprovalError,
    args_digest,
    encode_grant,
    sign_grant,
    verify_grant,
    verify_grants,
)

SECRET = b"unit-test-secret"


def _issue(*, approver="alex", agent_id="a1", tenant_id="t1",
           tool_name="pay", args=None, secret=SECRET, ttl=300) -> str:
    return encode_grant(sign_grant(
        agent_id=agent_id, tenant_id=tenant_id, tool_name=tool_name,
        args=args if args is not None else {}, approver_id=approver,
        secret=secret, ttl_seconds=ttl,
    ))


# ── Round trip ────────────────────────────────────────────────────────────

def test_round_trip_preserves_claims():
    grant = verify_grant(_issue(args={"amount": 5}), SECRET)
    assert grant.agent_id == "a1"
    assert grant.tenant_id == "t1"
    assert grant.tool_name == "pay"
    assert grant.approver_id == "alex"
    assert grant.args_digest == args_digest({"amount": 5})
    assert grant.version == 1


def test_args_digest_is_order_independent():
    assert args_digest({"a": 1, "b": 2}) == args_digest({"b": 2, "a": 1})


def test_args_digest_handles_non_json_values():
    class Opaque:
        def __str__(self) -> str:
            return "opaque"

    assert args_digest({"x": Opaque()}) == args_digest({"x": "opaque"})


def test_grant_with_no_approver_is_refused_at_issue():
    with pytest.raises(ApprovalError, match="approver_id is required"):
        sign_grant(agent_id="a1", tenant_id="t1", tool_name="pay",
                   args={}, approver_id="   ", secret=SECRET)


# ── Signature integrity ───────────────────────────────────────────────────

def test_wrong_secret_fails():
    with pytest.raises(ApprovalError, match="signature mismatch"):
        verify_grant(_issue(), b"other-secret")


def test_tampered_claim_fails():
    raw = json.loads(base64.urlsafe_b64decode(_issue().encode() + b"=="))
    raw["approver_id"] = "mallory"
    forged = base64.urlsafe_b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    with pytest.raises(ApprovalError, match="signature mismatch"):
        verify_grant(forged, SECRET)


def test_smuggled_extra_field_fails():
    """Re-encoding what remains, not the expected fields, is what catches this."""
    raw = json.loads(base64.urlsafe_b64decode(_issue().encode() + b"=="))
    raw["quorum_override"] = 99
    smuggled = base64.urlsafe_b64encode(
        json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    with pytest.raises(ApprovalError, match="signature mismatch"):
        verify_grant(smuggled, SECRET)


@pytest.mark.parametrize("bad", ["", "not-base64!!", "e30="])
def test_malformed_input_raises_approval_error(bad):
    with pytest.raises(ApprovalError):
        verify_grant(bad, SECRET)


def test_expired_grant_fails():
    with pytest.raises(ApprovalError, match="expired"):
        verify_grant(_issue(ttl=-1), SECRET)


# ── Binding + quorum ──────────────────────────────────────────────────────

def _verify(encoded, *, quorum=1, args=None, tool_name="pay"):
    return verify_grants(
        encoded, secret=SECRET, agent_id="a1", tenant_id="t1",
        tool_name=tool_name, args=args if args is not None else {}, quorum=quorum,
    )


def test_quorum_counts_distinct_approvers():
    assert _verify((_issue(approver="alex"), _issue(approver="sam")), quorum=2) == ["alex", "sam"]


def test_duplicate_approver_does_not_reach_quorum():
    with pytest.raises(ApprovalError, match="1 distinct approver"):
        _verify((_issue(approver="alex"), _issue(approver="alex")), quorum=2)


def test_no_grants_fails_any_quorum():
    with pytest.raises(ApprovalError, match="0 distinct approver"):
        _verify((), quorum=1)


@pytest.mark.parametrize("kwargs,expected", [
    ({"agent_id": "other"},  "different agent"),
    ({"tenant_id": "other"}, "different tenant"),
    ({"tool_name": "other"}, "different tool"),
])
def test_binding_mismatch_rejected(kwargs, expected):
    with pytest.raises(ApprovalError, match=expected):
        _verify((_issue(**kwargs),))


def test_argument_binding_rejected():
    grant = _issue(args={"amount": 5})
    assert _verify((grant,), args={"amount": 5}) == ["alex"]
    with pytest.raises(ApprovalError, match="different arguments"):
        _verify((grant,), args={"amount": 50_000})


def test_one_bad_grant_fails_the_whole_set():
    """A valid grant alongside an invalid one does not carry the set."""
    with pytest.raises(ApprovalError, match="different tool"):
        _verify((_issue(approver="alex"), _issue(approver="sam", tool_name="other")), quorum=1)
