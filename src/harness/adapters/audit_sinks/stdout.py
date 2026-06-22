"""StdoutSink — emits one JSON object per line to stdout."""
from __future__ import annotations

import json
import sys
from typing import IO, Any

from harness.core.events import AuditEvent


def _serialize(event: AuditEvent) -> str:
    data: dict[str, Any] = {
        "timestamp":     event.timestamp.isoformat(),
        "boundary":      event.boundary,
        "decision":      event.decision,
        "disabled":      event.disabled,
        "duration_ms":   event.duration_ms,
        "tenant_id":     event.tenant_id,
        "agent_id":      event.agent_id,
        "sub_agent_id":  event.sub_agent_id,
        "adapters":      event.adapters,
        "finding_count": event.finding_count,
        "max_severity":  event.max_severity,
        "deny_reason":   event.deny_reason,
        "tool_name":     event.tool_name,
        "transport":     event.transport,
        "audit_tags":    event.audit_tags,
        "extra":         event.extra,
    }
    return json.dumps({k: v for k, v in data.items() if v is not None})


class StdoutSink:
    """Reference AuditSink — JSONL to stdout."""

    name = "stdout"

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout

    async def emit(self, event: AuditEvent) -> None:
        line = _serialize(event) + "\n"
        self._stream.write(line)
        self._stream.flush()

    async def close(self) -> None:
        pass
