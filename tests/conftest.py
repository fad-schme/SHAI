"""Shared pytest fixtures and test doubles.

The doubles here are real implementations of the protocols they stand for,
not mocks. A MagicMock satisfies any attribute access, so it keeps passing
when a protocol gains a required member — which is how a broken audit
serializer survived the suite. Real classes fail the way production fails.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.adapters.scanners.base import ScanResult
from harness.config.schema import AdapterRef, BoundaryConfig, ToolResultScanConfig
from harness.core.context import AgentContext
from harness.core.events import AnyAuditEvent
from harness.core.types import OnError, ScanAction, Severity

FIXTURES = Path(__file__).parent / "fixtures"
AGENTS   = FIXTURES / "agents"


class RecordingSink:
    """Canonical AuditSink double — a real sink implementation, not a mock.

    Collects emitted events for inspection while the real AuditEmitter still
    runs truncation, signing and fan-out. Mocking the emitter or the sink
    instead is what let network events fail serialization unnoticed.

    Use `StdoutSink(stream=io.StringIO())` when the assertion is about the
    serialized line rather than the event object — only that exercises the
    serializer.
    """

    name = "recording"

    def __init__(self) -> None:
        self.events: list[AnyAuditEvent] = []

    async def emit(self, event: AnyAuditEvent) -> None:
        self.events.append(event)

    async def close(self) -> None:
        pass


@pytest.fixture
def recording_sink() -> RecordingSink:
    return RecordingSink()


class FailingScanner:
    """Scanner that always raises — for on_error and circuit-breaker tests.

    Declares method_family because the Scanner protocol requires it: a
    MagicMock would satisfy that attribute with a mock object and keep
    passing even if TurnSignals corroboration started reading it for real.
    """

    method_family = "unknown"

    def __init__(self, name: str = "bad", error: str = "exploded") -> None:
        self.name   = name
        self._error = error

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        raise RuntimeError(self._error)


def boundary_config(*, cls: type = BoundaryConfig, **overrides) -> BoundaryConfig:
    """Build a BoundaryConfig (or ToolResultScanConfig via cls=) for tests that

    call run_scan()/run_tool_result_scan() directly. Defaults match what most
    such tests want: enabled, block, HIGH, fail-closed. run_scan reads
    scanners as its own separate argument, not from config.scanners — the
    dummy AdapterRef here exists only to satisfy the config's own "enabled
    needs scanners" validator.
    """
    defaults: dict = dict(
        enabled=True,
        block_at=Severity.HIGH,
        action=ScanAction.BLOCK,
        on_error=OnError.FAIL_CLOSED,
    )
    defaults.update(overrides)
    if defaults["enabled"] and "scanners" not in defaults:
        defaults["scanners"] = [AdapterRef(name="dummy")]
    return cls(**defaults)


def tool_result_scan_config(**overrides) -> ToolResultScanConfig:
    return boundary_config(cls=ToolResultScanConfig, **overrides)


def resolved_tool_names(h, agent_id: str) -> frozenset[str]:
    """Tool names resolved for an agent at load_agent() time — the raw

    allowed_tool_names ∩ registry intersection, before the gate's per-call L4
    tag narrowing. tools_for() applies that narrowing and is what production
    code should use; some tests specifically assert on resolution *before*
    it (tag filtering happens at gate time, not at resolution time), which
    only SHAI._agent_tools can answer. Test-only: not a product surface.
    """
    return frozenset(h._agent_tools.get(agent_id, {}))


@pytest.fixture
def ctx() -> AgentContext:
    return AgentContext(
        agent_id="orchestrator_agent",
    )


@pytest.fixture
def sub_ctx() -> AgentContext:
    return AgentContext(
        agent_id="orchestrator_agent",
        sub_agent_id="research_sub",
        allowed_tags=["read", "internal"],
    )


@pytest.fixture
def orchestrator_yaml() -> Path:
    return AGENTS / "orchestrator_agent.yaml"


@pytest.fixture
def research_yaml() -> Path:
    return AGENTS / "research_agent.yaml"


@pytest.fixture
def harness_yaml() -> Path:
    return FIXTURES / "harness.yaml"
