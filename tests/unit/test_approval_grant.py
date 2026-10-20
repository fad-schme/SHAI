"""Tests for core/approval.py — grant signing, verification, and binding."""
from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from harness.adapters.state_store.memory_store import InMemoryStore
from harness.core.approval import (
    ApprovalError,
    args_digest,
    encode_grant,
    release_grants,
    sign_grant,
    spend_grants,
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


# ── Single use ────────────────────────────────────────────────────────────

_SPENT = "approval_grant:"


async def _spend(store, *encoded):
    await spend_grants(encoded, secret=SECRET, store=store.kv)


async def test_a_spent_grant_is_refused_a_second_time():
    store = InMemoryStore()
    grant = _issue()
    await _spend(store, grant)
    with pytest.raises(ApprovalError, match="already been used"):
        await _spend(store, grant)


async def test_distinct_grants_are_independent():
    store = InMemoryStore()
    await _spend(store, _issue())
    await _spend(store, _issue())


async def test_a_refused_quorum_leaves_the_other_grants_unspent():
    store = InMemoryStore()
    fresh, used = _issue(approver="alex"), _issue(approver="sam")
    await _spend(store, used)
    with pytest.raises(ApprovalError, match="already been used"):
        await _spend(store, fresh, used)
    await _spend(store, fresh)   # still spendable: the failed call released it


async def test_concurrent_spends_of_one_grant_have_one_winner():
    store = InMemoryStore()
    grant = _issue()
    results = await asyncio.gather(
        *[_spend(store, grant) for _ in range(20)], return_exceptions=True
    )
    assert sum(r is None for r in results) == 1
    assert all(isinstance(r, ApprovalError) for r in results if r is not None)


async def test_spent_record_outlives_the_grant_it_names_by_a_grace_period_then_goes():
    store = InMemoryStore()
    long_gone = (datetime.now(UTC) - timedelta(hours=1)).isoformat().encode()
    just_expired = (datetime.now(UTC) - timedelta(seconds=5)).isoformat().encode()
    await store.kv.put(_SPENT + "long-gone", long_gone)
    await store.kv.put(_SPENT + "just-expired", just_expired)
    await _spend(store, _issue())
    keys = set(await store.kv.list(_SPENT))
    assert _SPENT + "long-gone" not in keys
    assert _SPENT + "just-expired" in keys   # clock skew between replicas


async def test_an_unverifiable_grant_is_refused_before_anything_is_recorded():
    store = InMemoryStore()
    with pytest.raises(ApprovalError, match="signature mismatch"):
        await _spend(store, _issue(secret=b"another-key"))
    assert await store.kv.list(_SPENT) == []


async def test_spend_returns_what_it_claimed_and_release_frees_it():
    store = InMemoryStore()
    grant = _issue()
    claimed = await spend_grants((grant,), secret=SECRET, store=store.kv)
    assert len(claimed) == 1
    await release_grants(claimed, store=store.kv)
    await _spend(store, grant)   # usable again


class _FailingDelete:
    """A store whose delete fails for chosen keys."""

    def __init__(self, kv, fail_for):
        self._kv, self._fail_for = kv, fail_for

    def __getattr__(self, name):
        return getattr(self._kv, name)

    async def delete(self, key):
        if any(marker in key for marker in self._fail_for):
            raise ConnectionError("delete failed")
        await self._kv.delete(key)


async def test_a_failed_release_does_not_strand_the_other_claims_or_hide_the_cause():
    store = InMemoryStore()
    g1, g2, g3 = _issue(approver="a"), _issue(approver="b"), _issue(approver="c")
    first_id = verify_grant(g1, SECRET).grant_id
    await _spend(store, g3)                               # g3 is already spent
    flaky = _FailingDelete(store.kv, fail_for=[first_id])
    with pytest.raises(ApprovalError, match="already been used"):   # not ConnectionError
        await spend_grants((g1, g2, g3), secret=SECRET, store=flaky)
    await _spend(store, g2)                               # g2 was released despite g1's failure


async def test_a_record_with_a_timezone_less_timestamp_is_left_alone():
    store = InMemoryStore()
    await store.kv.put(_SPENT + "foreign", b"2020-01-01")
    await _spend(store, _issue())
    assert await store.kv.get(_SPENT + "foreign") == b"2020-01-01"
