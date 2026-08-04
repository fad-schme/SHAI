"""Unit tests for AuditEmitter.collect_events subscriber bookkeeping.

The contract these guard: each block collects only the events emitted inside
it, and exiting one block never disturbs another. That held only by accident
while every bucket was distinct in content — buckets are compared by identity
now, because two that have collected the same events (most commonly two empty
ones) are equal, and equality-based removal unsubscribed the wrong one.
"""
from __future__ import annotations

import asyncio

import pytest

from harness.audit.emitter import AuditEmitter
from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.types import BoundaryName, Decision
from tests.conftest import RecordingSink

CTX = AgentContext(agent_id="a1")


def _event(decision: Decision = Decision.ALLOW) -> AuditEvent:
    # deny_reason is required when decision=deny; supply one so the helper is
    # usable for either decision without tripping the AuditEvent validator.
    return AuditEvent.build(
        boundary=BoundaryName.INPUT_SCAN,
        decision=decision,
        ctx=CTX,
        tenant_id="test",
        duration_ms=1,
        disabled=False,
        deny_reason="test denial" if decision is Decision.DENY else None,
    )


def _emitter() -> AuditEmitter:
    return AuditEmitter([RecordingSink()])


# ── Subscriber bookkeeping ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_two_empty_collectors_both_exit_cleanly():
    """The regression: two empty buckets are equal, so equality-based removal
    dropped the first and left the second attached — then raised on its exit."""
    emitter = _emitter()
    with emitter.collect_events() as outer:
        with emitter.collect_events() as inner:
            pass
        # Inner exited; outer must still be subscribed and still collecting.
        await emitter.emit(_event())
    assert inner == []
    assert len(outer) == 1


@pytest.mark.asyncio
async def test_exiting_a_collector_leaves_no_subscriber_behind():
    emitter = _emitter()
    with emitter.collect_events():
        pass
    with emitter.collect_events():
        pass
    assert emitter._subscribers == []


@pytest.mark.asyncio
async def test_concurrent_collectors_each_see_only_their_own_events():
    """Overlapping blocks in separate tasks must not cross-contaminate."""
    emitter = _emitter()
    started = asyncio.Event()

    async def first() -> list:
        with emitter.collect_events() as bucket:
            started.set()
            await asyncio.sleep(0.02)
            return list(bucket)

    async def second() -> list:
        await started.wait()
        with emitter.collect_events() as bucket:
            await emitter.emit(_event(Decision.DENY))
            return list(bucket)

    first_events, second_events = await asyncio.gather(first(), second())
    # The event was emitted while both were open, so both saw it once.
    assert len(second_events) == 1
    assert len(first_events) == 1
    assert emitter._subscribers == []


@pytest.mark.asyncio
async def test_many_overlapping_collectors_all_unsubscribe():
    """Eight empty buckets: under equality removal this raised ValueError."""
    emitter = _emitter()

    async def collect() -> None:
        with emitter.collect_events():
            await asyncio.sleep(0)

    await asyncio.gather(*[collect() for _ in range(8)])
    assert emitter._subscribers == []


@pytest.mark.asyncio
async def test_exception_inside_the_block_still_unsubscribes():
    """The finally must not mask the caller's exception, nor leak the bucket."""
    emitter = _emitter()
    with pytest.raises(RuntimeError, match="boom"), emitter.collect_events():
        raise RuntimeError("boom")
    assert emitter._subscribers == []


@pytest.mark.asyncio
async def test_collectors_do_not_suppress_configured_sinks():
    sink = RecordingSink()
    emitter = AuditEmitter([sink])
    with emitter.collect_events() as bucket:
        await emitter.emit(_event())
    assert len(bucket) == 1
    assert len(sink.events) == 1
