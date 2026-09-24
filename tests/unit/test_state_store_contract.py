"""StateStore contract (both adapters) and the hardening found in security review."""
from __future__ import annotations

import json

import pytest

from harness.adapters.state_store.memory_store import InMemoryStore
from harness.adapters.state_store.sqlite_store import SQLiteStore
from harness.boundaries.session_accumulator import ThreatAccumulator
from harness.boundaries.session_budget import ExecutionLimits, SessionBudget
from harness.patterns.store import (
    _sign_row,
    apply_bundle,
    list_rules,
    load_verified_rules,
    verify_all,
)

_SECRET = b"contract-secret"


@pytest.fixture(params=["sqlite", "memory"])
async def store(request, tmp_path):
    s = SQLiteStore(path=str(tmp_path / "c.db")) if request.param == "sqlite" else InMemoryStore()
    yield s
    await s.close()


# ── KVStore contract ──────────────────────────────────────────────────────

async def test_kv_get_put_delete(store):
    assert await store.kv.get("k") is None
    await store.kv.put("k", b"v1")
    await store.kv.put("k", b"v2")
    assert await store.kv.get("k") == b"v2"
    await store.kv.delete("k")
    await store.kv.delete("k")
    assert await store.kv.get("k") is None


async def test_kv_list_prefix_is_literal_and_case_sensitive(store):
    for k in ("a:1", "a:2", "A:3", "ab:4", "a_x", "a%y"):
        await store.kv.put(k, b"x")
    assert sorted(await store.kv.list("a:")) == ["a:1", "a:2"]
    assert await store.kv.list("a_") == ["a_x"]
    assert await store.kv.list("a%") == ["a%y"]
    assert len(await store.kv.list("")) == 6


async def test_kv_batch_put(store):
    await store.kv.batch_put({"x": b"1", "y": b"2"})
    assert await store.kv.get("x") == b"1"
    assert await store.kv.get("y") == b"2"


# ── LogStore contract ─────────────────────────────────────────────────────

async def test_log_tail_is_newest_first_and_bounded(store):
    for i in range(5):
        await store.log.append("s", str(i).encode())
    assert await store.log.tail("s", 3) == [b"4", b"3", b"2"]
    assert await store.log.tail("missing", 3) == []


async def test_log_tail_of_zero_or_less_is_empty(store):
    await store.log.append("s", b"1")
    assert await store.log.tail("s", 0) == []
    assert await store.log.tail("s", -1) == []


async def test_failed_batch_put_leaves_nothing_behind(store):
    with pytest.raises(Exception):  # noqa: B017 — adapter-specific error type
        await store.kv.batch_put({"good": b"1", "bad": {"not": "bytes"}})
    await store.kv.put("other", b"x")   # a later write must not commit the partial batch
    assert await store.kv.get("good") is None


@pytest.mark.parametrize("bad", ["text", None, 7, {"a": 1}])
async def test_non_bytes_values_are_refused_on_every_adapter(store, bad):
    with pytest.raises(TypeError):
        await store.kv.put("k", bad)
    with pytest.raises(TypeError):
        await store.kv.batch_put({"k": bad})
    with pytest.raises(TypeError):
        await store.log.append("k", bad)
    assert await store.kv.get("k") is None


async def test_log_delete_is_per_key(store):
    await store.log.append("a", b"1")
    await store.log.append("b", b"2")
    await store.log.delete("a")
    assert await store.log.tail("a", 5) == []
    assert await store.log.tail("b", 5) == [b"2"]


# ── Adapters that fail ────────────────────────────────────────────────────

class _Boom:
    name = "boom"

    async def _fail(self, *a, **k):
        raise RuntimeError("store is on fire")

    get = put = delete = list = batch_put = append = tail = _fail

    async def close(self):
        pass


class _BoomStore:
    kv = _Boom()
    log = _Boom()

    async def close(self):
        pass


async def test_accumulator_check_fails_closed_by_default():
    acc = ThreatAccumulator(_BoomStore())
    escalated, reason = await acc.check("s")
    assert escalated
    assert "unreachable" in reason


async def test_accumulator_check_fail_open():
    acc = ThreatAccumulator(_BoomStore(), on_error="fail_open")
    assert await acc.check("s") == (False, None)


async def test_accumulator_record_never_raises():
    acc = ThreatAccumulator(_BoomStore())
    await acc.record("s", "text", "block", [])


async def test_accumulator_corrupt_row_is_a_store_failure():
    store = InMemoryStore()
    await store.kv.put("session:s", b"not json")
    escalated, _ = await ThreatAccumulator(store).check("s")
    assert escalated


async def test_accumulator_sweep_is_throttled():
    store = InMemoryStore()
    acc = ThreatAccumulator(store, ttl_hours=0.0)  # everything stale immediately
    await acc.record("old", "t", "allow", [])
    # ttl 0: a second record within the throttle window must not sweep "old"
    await acc.record("new", "t", "allow", [])
    assert await store.kv.get("session:old") is not None


# ── Session budget ────────────────────────────────────────────────────────

async def test_budget_reset_waits_for_in_flight_check():
    store = InMemoryStore()
    b = SessionBudget(store)
    limits = ExecutionLimits(max_steps=5)
    await b.check("a", "s", "t", {}, limits)
    lock = await b._lock_for("a:s")
    async with lock:
        import asyncio
        task = asyncio.ensure_future(b.reset("a", "s"))
        await asyncio.sleep(0)
        assert not task.done(), "reset must take the per-session lock"
    await task
    assert await store.kv.get("a:s") is None


# ── Pattern store: signed row is bound to its key ─────────────────────────

def _entry(rule_id, catalog="injection"):
    payload = json.dumps({"name": rule_id})
    return {"rule_id": rule_id, "catalog": catalog, "payload": payload,
            "signature": _sign_row(rule_id, catalog, payload, _SECRET), "version": 1}


async def _apply(store, tmp_path, *entries):
    f = tmp_path / "b.json"
    f.write_text(json.dumps(list(entries)))
    await apply_bundle(f, store, _SECRET)


async def test_row_rekeyed_to_another_catalog_is_rejected(store, tmp_path):
    await _apply(store, tmp_path, _entry("x", catalog="jailbreak"))
    await store.kv.put("injection:x", await store.kv.get("jailbreak:x"))
    assert await load_verified_rules(store, _SECRET, catalog="injection") == []
    assert await verify_all(store, _SECRET) == (1, 1)


async def test_malformed_row_is_skipped_not_fatal(store, tmp_path):
    await _apply(store, tmp_path, _entry("ok"))
    await store.kv.put("injection:bad", b'{"rule_id": "bad"}')
    assert len(await load_verified_rules(store, _SECRET)) == 1
    assert await verify_all(store, _SECRET) == (1, 1)


async def test_colon_in_catalog_is_refused(store, tmp_path):
    with pytest.raises(ValueError, match="catalog"):
        await _apply(store, tmp_path, _entry("x", catalog="a:b"))


async def test_reading_a_missing_sqlite_file_does_not_create_it(tmp_path):
    path = tmp_path / "nope.db"
    s = SQLiteStore(path=str(path))
    assert await list_rules(s) == []
    assert await load_verified_rules(s, _SECRET) == []
    await s.close()
    assert not path.exists()


# ── Sweep isolation ───────────────────────────────────────────────────────

async def test_malformed_row_does_not_stop_the_sweep():
    import time
    store = InMemoryStore()
    acc = ThreatAccumulator(store, ttl_hours=0.0001)
    await store.kv.put("session:aaa-bad", b"garbage")
    await store.kv.put("session:zzz-stale",
                       json.dumps({"risk_score": 0, "updated_at": 0}).encode())
    await acc._sweep_stale_sessions(time.time())
    assert await store.kv.get("session:zzz-stale") is None


@pytest.mark.parametrize("row", [
    {"updated_at": None}, {"updated_at": "x"}, {"risk_score": 0}, [], "str",
])
async def test_unreadable_row_shapes_do_not_stop_the_sweep(row):
    import time
    store = InMemoryStore()
    acc = ThreatAccumulator(store, ttl_hours=0.0001)
    await store.kv.put("session:aaa-bad", json.dumps(row).encode())
    await store.kv.put("session:zzz-stale",
                       json.dumps({"risk_score": 0, "updated_at": 0}).encode())
    await acc._sweep_stale_sessions(time.time())
    assert await store.kv.get("session:zzz-stale") is None


@pytest.mark.parametrize("row", [{"risk_score": None}, {"risk_score": "x"}, {}, []])
async def test_check_treats_unreadable_score_as_store_failure(row):
    store = InMemoryStore()
    await store.kv.put("session:s", json.dumps(row).encode())
    assert (await ThreatAccumulator(store).check("s"))[0] is True
    assert await ThreatAccumulator(store, on_error="fail_open").check("s") == (False, None)


# ── Failing store: budget and patterns ────────────────────────────────────

async def test_budget_denies_when_store_fails():
    b = SessionBudget(_BoomStore())
    allowed, reason = await b.check("a", "s", "t", {}, ExecutionLimits(max_steps=5))
    assert not allowed and "unreachable" in reason


async def test_budget_fail_open_allows_when_store_fails():
    b = SessionBudget(_BoomStore(), on_error="fail_open")
    assert (await b.check("a", "s", "t", {}, ExecutionLimits(max_steps=5)))[0]


async def test_pattern_load_from_a_failing_store_raises_not_empty():
    with pytest.raises(RuntimeError):
        await load_verified_rules(_BoomStore(), _SECRET)


async def test_mid_bundle_failure_leaves_no_rules(tmp_path):
    store = InMemoryStore()

    async def failing(items):
        raise RuntimeError("disk full")

    store.kv.batch_put = failing
    with pytest.raises(RuntimeError):
        await _apply(store, tmp_path, _entry("r1"), _entry("r2"))
    assert await list_rules(store) == []
