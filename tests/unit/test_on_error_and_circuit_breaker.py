"""Tests for on_error degradation modes and circuit breaker in _scan.py.

Covers:
  - fail_closed: scanner failure → BLOCK
  - fail_open:   scanner failure → empty findings, pipeline continues
  - degrade:     scanner failure → WARN, degraded=True in audit event
  - circuit breaker: repeated failures trip the breaker; scanner skipped
  - circuit breaker recovery: HALF_OPEN → success → CLOSED
  - system events: scanner failure emits SYSTEM/DEGRADED audit event
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from harness.adapters.circuit_breaker import CircuitBreaker, CircuitState
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import ScanState, run_scan
from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.types import (
    BoundaryName,
    Decision,
    OnError,
    ScanAction,
    ScanStatus,
    Severity,
)

CTX = AgentContext(agent_id="test_agent")


class RecordingSink:
    name = "recording"
    def __init__(self): self.events: list[AuditEvent] = []
    async def emit(self, event): self.events.append(event)
    async def close(self): pass


@pytest.fixture
def sink():
    return RecordingSink()


@pytest.fixture
def emitter(sink):
    return AuditEmitter([sink])


@pytest.fixture
def state():
    """Fresh ScanState per test — no cross-test breaker leakage."""
    return ScanState()


def _bad_scanner(name: str = "bad") -> MagicMock:
    """Scanner that always raises."""
    s = MagicMock()
    s.name = name
    s.scan = AsyncMock(side_effect=RuntimeError("exploded"))
    return s


# ── on_error=fail_closed (default) ──────────────────────────────────────

async def test_fail_closed_scanner_failure_blocks(emitter, sink, state):
    """Scanner failure with fail_closed returns BLOCK immediately."""
    bad = _bad_scanner()
    verdict = await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad, RegexPIIScanner()],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.FAIL_CLOSED,
        state=state,
    )
    assert verdict.blocked
    assert verdict.status == ScanStatus.BLOCK


async def test_fail_closed_emits_blocked_event(emitter, sink, state):
    """fail_closed emits a BLOCKED audit event with deny_reason."""
    bad = _bad_scanner()
    await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.FAIL_CLOSED,
        state=state,
    )
    # Should have the boundary BLOCKED event + a SYSTEM/DEGRADED event
    boundary_events = [e for e in sink.events if e.boundary == BoundaryName.INPUT_SCAN]
    system_events   = [e for e in sink.events if e.boundary == BoundaryName.SYSTEM]
    assert len(boundary_events) == 1
    assert boundary_events[0].decision == Decision.BLOCKED
    assert "fail_closed" in boundary_events[0].deny_reason
    assert len(system_events) == 1
    assert system_events[0].decision == Decision.DEGRADED


# ── on_error=fail_open ──────────────────────────────────────────────────

async def test_fail_open_scanner_failure_allows(emitter, sink, state):
    """Scanner failure with fail_open is treated as empty findings."""
    bad = _bad_scanner()
    verdict = await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad, RegexPIIScanner()],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.FAIL_OPEN,
        state=state,
    )
    assert not verdict.blocked
    assert verdict.status == ScanStatus.ALLOW


async def test_fail_open_remaining_scanners_still_run(emitter, sink, state):
    """With fail_open, the second scanner still runs and can find things."""
    bad = _bad_scanner()
    verdict = await run_scan(
        "My SSN is 123-45-6789.", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad, RegexPIIScanner()],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.FAIL_OPEN,
        state=state,
    )
    # PII scanner should catch the SSN even though bad scanner failed
    assert verdict.blocked


# ── on_error=degrade ────────────────────────────────────────────────────

async def test_degrade_scanner_failure_warns(emitter, sink, state):
    """Scanner failure with degrade returns WARN, not BLOCK."""
    bad = _bad_scanner()
    verdict = await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad, RegexPIIScanner()],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.DEGRADE,
        state=state,
    )
    assert verdict.warned
    assert verdict.status == ScanStatus.WARN


async def test_degrade_audit_event_carries_degraded_flag(emitter, sink, state):
    """degrade mode sets degraded=True in the audit event extra field."""
    bad = _bad_scanner()
    await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        on_error=OnError.DEGRADE,
        state=state,
    )
    boundary_events = [e for e in sink.events if e.boundary == BoundaryName.INPUT_SCAN]
    assert len(boundary_events) == 1
    assert boundary_events[0].extra.get("degraded") is True


# ── Circuit breaker ─────────────────────────────────────────────────────

class TestCircuitBreaker:
    """Unit tests for the CircuitBreaker class itself."""

    def test_starts_closed(self):
        cb = CircuitBreaker(name="test")
        assert cb.state == CircuitState.CLOSED
        assert not cb.is_open

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(name="test", failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.is_open

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(name="test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert not cb.is_open

    def test_success_resets_count(self):
        cb = CircuitBreaker(name="test", failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        cb.record_failure()
        assert not cb.is_open  # 2 failures, not 3

    def test_half_open_success_closes(self):
        cb = CircuitBreaker(name="test", failure_threshold=1, recovery_timeout=0.0)
        cb.record_failure()  # → OPEN
        # With recovery_timeout=0, state check immediately transitions to HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_failure_reopens_with_backoff(self):
        cb = CircuitBreaker(
            name="test", failure_threshold=1,
            recovery_timeout=1.0, max_recovery_timeout=10.0,
        )
        cb.record_failure()  # → OPEN
        # Force HALF_OPEN by setting opened_at far in the past
        cb._opened_at = cb._opened_at - 2.0
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()  # → back to OPEN with doubled timeout
        assert cb._state == CircuitState.OPEN
        assert cb._current_recovery == 2.0  # doubled from 1.0


# ── Circuit breaker integration with run_scan ────────────────────────────

async def test_circuit_breaker_trips_after_repeated_failures(emitter, sink, state):
    """Scanner breaker opens after repeated failures on the same state."""
    bad = _bad_scanner("flaky")
    # Default threshold is 5 — this many failures should trip the breaker
    for _ in range(5):
        await run_scan(
            "text", CTX,
            boundary=BoundaryName.INPUT_SCAN,
            scanners=[bad],
            scanner_actions=[], scanner_redact_withs=[],
            boundary_action=ScanAction.BLOCK,
            emitter=emitter, tenant_id="test",
            enabled=True, block_at=Severity.HIGH,
            on_error=OnError.FAIL_OPEN,  # don't short-circuit — let failures accumulate
            state=state,
        )
    breaker = state.get_breaker(bad)
    assert breaker.is_open


# ── Default on_error ─────────────────────────────────────────────────────

async def test_default_on_error_is_fail_closed(emitter, sink, state):
    """run_scan defaults to fail_closed when on_error is not specified."""
    bad = _bad_scanner()
    verdict = await run_scan(
        "clean text", CTX,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=[bad],
        scanner_actions=[], scanner_redact_withs=[],
        boundary_action=ScanAction.BLOCK,
        emitter=emitter, tenant_id="test",
        enabled=True, block_at=Severity.HIGH,
        # on_error not passed — should default to FAIL_CLOSED
        state=state,
    )
    assert verdict.blocked
