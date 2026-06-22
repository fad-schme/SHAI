"""Shared fixtures for contract test suites."""
from __future__ import annotations

import pytest

from harness.core.context import RuntimeContext
from harness.core.types import Severity
from harness.core.verdicts import Finding
from harness.core.events import AuditEvent
from harness.core.types import BoundaryName, Decision


@pytest.fixture
def ctx() -> RuntimeContext:
    return RuntimeContext(tenant_id="t1", agent_id="test_agent")


@pytest.fixture
def sub_ctx() -> RuntimeContext:
    return RuntimeContext(
        tenant_id="t1",
        agent_id="test_agent",
        sub_agent_id="test_sub",
        allowed_tags=["read"],
    )


def make_event(**kwargs) -> AuditEvent:
    defaults = dict(
        boundary=BoundaryName.INPUT_SCAN,
        decision=Decision.ALLOW,
        ctx=RuntimeContext(tenant_id="t1", agent_id="a1"),
        duration_ms=1,
    )
    defaults.update(kwargs)
    return AuditEvent.build(**defaults)
