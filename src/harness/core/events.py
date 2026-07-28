"""Audit events — the structured records SHAI writes to its sinks.

AuditEvent:        emitted exactly once per boundary call.
NetworkAuditEvent: emitted per outbound HTTP request by ShaiTransport.
AnyAuditEvent:     what an AuditSink accepts.

No raw user input, LLM output, tool args, or scanner matches in any field.

tenant_id is stamped by the Harness instance from harness.yaml — not supplied
by the agent. user_id is not on AuditEvent; operators use audit_tags for that.
"""
from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, model_validator

from harness.core.context import AgentContext
from harness.core.types import BoundaryName, Decision, Severity


class AuditEvent(BaseModel, frozen=True):
    # When + boundary
    timestamp:   datetime
    boundary:    BoundaryName
    decision:    Decision
    disabled:    bool = False
    duration_ms: int

    # Identity — tenant_id from HarnessConfig, agent fields from AgentContext
    tenant_id:    str
    agent_id:     str
    sub_agent_id: str | None = None

    # Tool call gate fields
    tool_name:  str | None = None
    transport:  str | None = None
    token_id:   str | None = None   # DispatchToken.token_id — join key for NetworkAuditEvent

    # Scan results
    adapters:      list[str] = []
    finding_count: int = 0
    max_severity:  Severity | None = None
    deny_reason:   str | None = None

    # Agent context
    audit_tags: dict[str, str] = {}
    extra:      dict[str, Any] = {}
    signature:  str | None = None  # HMAC-SHA256, stamped by AuditEmitter when configured

    @model_validator(mode="after")
    def _cross_field_constraints(self) -> AuditEvent:
        if self.decision == Decision.DENY and not self.deny_reason:
            raise ValueError("deny_reason required when decision=deny")
        if self.decision == Decision.DEGRADED and not self.deny_reason:
            raise ValueError("deny_reason required when decision=degraded")
        if self.decision in (Decision.BLOCKED, Decision.WARN) \
                and self.boundary == BoundaryName.TOOL_CALL_GATE:
            raise ValueError("tool_call_gate uses deny/allow, not blocked/warn")
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
        ctx: AgentContext,
        tenant_id: str,
        duration_ms: int,
        adapters: list[str] | None = None,
        finding_count: int = 0,
        max_severity: Severity | None = None,
        deny_reason: str | None = None,
        tool_name: str | None = None,
        transport: str | None = None,
        token_id: str | None = None,
        disabled: bool = False,
        audit_tags: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Canonical builder. Boundaries always use this, never construct directly.

        tenant_id is passed explicitly from the Harness instance — not read
        from ctx (which no longer carries it).
        """
        return cls(
            timestamp=datetime.now(UTC),
            boundary=boundary,
            decision=decision,
            disabled=disabled,
            duration_ms=duration_ms,
            tenant_id=tenant_id,
            agent_id=ctx.agent_id,
            sub_agent_id=ctx.sub_agent_id,
            tool_name=tool_name,
            transport=transport,
            token_id=token_id,
            adapters=adapters or [],
            finding_count=finding_count,
            max_severity=max_severity,
            deny_reason=deny_reason,
            audit_tags=audit_tags or {},
            extra=extra or {},
        )


class NetworkAuditEvent(BaseModel, frozen=True):
    """Audit event emitted per outbound HTTP request from an MCP source.

    event_type="network_egress" distinguishes these from boundary AuditEvents.
    token_id is the join key with the gate AuditEvent in the SIEM:

        SELECT gate.*, net.*
        FROM audit_events gate
        JOIN network_audit_events net ON gate.token_id = net.token_id
        WHERE gate.agent_id = 'orchestrator_agent'

    Written to the same AuditEmitter sinks as AuditEvent (file, stdout, etc.).
    """
    timestamp:    datetime
    event_type:   str           # always "network_egress"
    token_id:     str | None    # DispatchToken.token_id — join key with AuditEvent
    source_name:  str           # MCPSource.name
    agent_id:     str
    sub_agent_id: str | None
    tenant_id:    str
    tool_name:    str | None    # None for SSE/init requests
    destination:  str           # full URL
    method:       str
    status:       str           # "allowed" | "denied"
    deny_reason:  str | None
    bytes_sent:   int
    bytes_recv:   int
    duration_ms:  int
    signature:    str | None = None  # HMAC-SHA256, stamped by AuditEmitter when configured


# What an AuditSink accepts. Both are Pydantic models, so sinks serialise
# either one through model_dump() without a per-type branch.
AnyAuditEvent = AuditEvent | NetworkAuditEvent


def canonical_json(event: AnyAuditEvent, *, exclude: set[str] | None = None) -> str:
    """The one canonical JSON encoding of an audit event.

    Sinks write exactly this, and the HMAC is computed over exactly this with
    `signature` excluded. The two must agree byte-for-byte — otherwise a
    written line cannot be verified against the signature it carries, which is
    what a separate hand-rolled encoder on each side previously cost us.

    mode="json" renders datetimes as ISO 8601 and enums as their values;
    exclude_none keeps null fields off the line; sort_keys makes the encoding
    independent of field declaration order.
    """
    return json.dumps(
        event.model_dump(mode="json", exclude_none=True, exclude=exclude),
        sort_keys=True,
    )


def now_ms() -> int:
    """Current monotonic time in milliseconds — used to measure boundary duration."""
    return int(time.monotonic() * 1000)
