"""Per-session locks are reclaimed when idle and still serialise a session."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from harness.adapters.state_store.memory_store import InMemoryStore
from harness.boundaries._keyed_locks import KeyedLocks
from harness.boundaries.session_budget import ExecutionLimits, SessionBudget


async def test_entry_removed_after_use_and_recreated_for_a_later_call():
    locks = KeyedLocks()
    async with locks.hold("s"):
        assert len(locks) == 1
    assert len(locks) == 0
    async with locks.hold("s"):
        assert len(locks) == 1
    assert len(locks) == 0


async def test_entry_removed_when_the_body_raises():
    locks = KeyedLocks()
    with pytest.raises(RuntimeError):
        async with locks.hold("s"):
            raise RuntimeError("boom")
    assert len(locks) == 0


async def test_same_key_is_serialised_including_when_first_finishes_while_second_waits():
    locks = KeyedLocks()
    value = 0

    async def read_modify_write():
        nonlocal value
        async with locks.hold("s"):
            seen = value
            await asyncio.sleep(0.01)   # interleaving point inside the critical section
            value = seen + 1

    await asyncio.gather(*(read_modify_write() for _ in range(5)))
    assert value == 5
    assert len(locks) == 0


async def test_entry_survives_while_a_waiter_exists():
    locks = KeyedLocks()
    release_first = asyncio.Event()
    first_in = asyncio.Event()
    order: list[str] = []

    async def first():
        async with locks.hold("s"):
            first_in.set()
            await release_first.wait()
            order.append("first")

    async def second():
        await first_in.wait()
        async with locks.hold("s"):
            order.append("second")

    t1, t2 = asyncio.create_task(first()), asyncio.create_task(second())
    await first_in.wait()
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    release_first.set()
    await asyncio.gather(t1, t2)
    assert order == ["first", "second"]
    assert len(locks) == 0


async def test_different_keys_do_not_block_each_other():
    locks = KeyedLocks()
    async with locks.hold("a"):
        async with asyncio.timeout(1):
            async with locks.hold("b"):
                assert len(locks) == 2
    assert len(locks) == 0


async def test_budget_lock_table_empty_after_many_conversations():
    budget = SessionBudget(InMemoryStore())
    limits = ExecutionLimits(max_steps=5)
    for i in range(1000):
        allowed, _ = await budget.check("agent", f"conv-{i}", "tool", {}, limits)
        assert allowed
    assert len(budget._locks) == 0


async def test_budget_concurrent_calls_on_one_session_lose_no_update():
    budget = SessionBudget(InMemoryStore())
    limits = ExecutionLimits(max_steps=100)
    await asyncio.gather(*(
        budget.check("agent", "s", "tool", {"n": i}, limits) for i in range(20)
    ))
    assert (await budget.snapshot("agent", "s"))["steps"] == 20
    assert len(budget._locks) == 0


async def test_budget_reset_leaves_no_locks_and_session_reusable():
    budget = SessionBudget(InMemoryStore())
    limits = ExecutionLimits(max_steps=1)
    await budget.check("agent", "s", "tool", {}, limits)
    await budget.reset("agent")
    assert len(budget._locks) == 0
    allowed, _ = await budget.check("agent", "s", "tool", {}, limits)
    assert allowed


async def test_accumulator_lock_table_empty_after_many_sessions(tmp_path: Path):
    pytest.importorskip("aiosqlite")
    from harness.adapters.state_store.sqlite_store import SQLiteStore
    from harness.boundaries.session_accumulator import ThreatAccumulator

    acc = ThreatAccumulator(SQLiteStore(path=str(tmp_path / "acc.db")))
    for i in range(200):
        await acc.record(f"s{i}", "hello", "allow", [])
        await acc.check(f"s{i}")
    assert len(acc._session_locks) == 0
    await acc.close()
