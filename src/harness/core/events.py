"""AuditEvent — the structured event every boundary emits exactly once per call.

No raw user input, LLM output, tool args, or scanner matches in any field.

tenant_id is stamped by the Harness instance from harness.yaml — not supplied
by the agent. user_id is not on AuditEvent; operators use audit_tags for that.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, model_validator

from harness.core.context import RuntimeContext
from harness.core.types import BoundaryName, Decision, Severity


class AuditEvent(BaseModel, frozen=True):
    # When + boundary
    timestamp:   datetime
    boundary:    BoundaryName
    decision:    Decision
    disabled:    bool = False
    duration_ms: int

    # Identity — tenant_id from HarnessConfig, agent fields from RuntimeContext
    tenant_id:    str
    agent_id:     str
    sub_agent_id: str | None = None

    # Tool call gate fields
    tool_name:  str | None = None
    transport:  str | None = None

    # Scan results
    adapters:      list[str] = []
    finding_count: int = 0
    max_severity:  Severity | None = None
    deny_reason:   str | None = None

    # Agent context
    audit_tags: dict[str, str] = {}
    extra:      dict[str, Any] = {}

    @model_validator(mode="after")
    def _cross_field_constraints(self) -> "AuditEvent":
        if self.decision == Decision.DENY and not self.deny_reason:
            raise ValueError("deny_reason required when decision=deny")
        if (self.decision == Decision.BLOCKED
                and self.boundary == BoundaryName.TOOL_CALL_GATE):
            raise ValueError("tool_call_gate uses deny, not blocked")
        if self.disabled:
            if self.decision != Decision.ALLOW:
                raise ValueError("disabled boundary must have decision=allow")
            if self.finding_count != 0:
                raise ValueError("disabled boundary must have finding_count=0")
        return self

    @classmethod
    def build(
        cls,
        *,
        boundary: BoundaryName,
        decision: Decision,
        ctx: RuntimeContext,
        tenant_id: str,
        duration_ms: int,
        adapters: list[str] | None = None,
        finding_count: int = 0,
        max_severity: Severity | None = None,
        deny_reason: str | None = None,
        tool_name: str | None = None,
        transport: str | None = None,
        disabled: bool = False,
        audit_tags: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> "AuditEvent":
        """Canonical builder. Boundaries always use this, never construct directly.

        tenant_id is passed explicitly from the Harness instance — not read
        from ctx (which no longer carries it).
        """
        return cls(
            timestamp=datetime.now(timezone.utc),
            boundary=boundary,
            decision=decision,
            disabled=disabled,
            duration_ms=duration_ms,
            tenant_id=tenant_id,
            agent_id=ctx.agent_id,
            sub_agent_id=ctx.sub_agent_id,
            tool_name=tool_name,
            transport=transport,
            adapters=adapters or [],
            finding_count=finding_count,
            max_severity=max_severity,
            deny_reason=deny_reason,
            audit_tags=audit_tags or {},
            extra=extra or {},
        )


def now_ms() -> int:
    """Current monotonic time in milliseconds — used to measure boundary duration."""
    return int(time.monotonic() * 1000)
