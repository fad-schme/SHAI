"""StdoutSink — emits one JSON object per line to stdout.

Suitable for development and containers that forward stdout to a log aggregator.
Not suitable as the sole production sink in high-throughput deployments.

Thread/async safety: sys.stdout.write() is GIL-safe for individual calls in
CPython. Concurrent async calls may interleave at the OS level in edge cases.
Use FileSink (with asyncio.Lock) for guaranteed ordering.
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import IO, Any

from harness.core.events import AuditEvent


def _serialize(event: AuditEvent) -> str:
    """Serialize AuditEvent to a single JSON line."""
    data: dict[str, Any] = {
        "timestamp":    event.timestamp.isoformat(),
        "boundary":     event.boundary,
        "decision":     event.decision,
        "disabled":     event.disabled,
        "duration_ms":  event.duration_ms,
        "tenant_id":    event.tenant_id,
        "agent_id":     event.agent_id,
        "sub_agent_id": event.sub_agent_id,
        "user_id":      event.user_id,
        "session_id":   event.session_id,
        "adapters":     event.adapters,
        "finding_count": event.finding_count,
        "max_severity": event.max_severity,
        "deny_reason":  event.deny_reason,
        "tool_name":    event.tool_name,
        "transport":    event.transport,
        "audit_tags":   event.audit_tags,
        "extra":        event.extra,
    }
    # Drop None values to keep output clean
    return json.dumps({k: v for k, v in data.items() if v is not None})


class StdoutSink:
    """Reference AuditSink — JSONL to stdout."""

    name = "stdout"

    def __init__(self, stream: IO[str] | None = None) -> None:
        self._stream = stream or sys.stdout

    async def emit(self, event: AuditEvent) -> None:
        line = _serialize(event) + "\n"
        loop = asyncio.get_event_loop()
        # run_in_executor offloads the blocking write; acceptable for stdout
        await loop.run_in_executor(None, self._stream.write, line)
        await loop.run_in_executor(None, self._stream.flush)

    async def close(self) -> None:
        pass  # stdout is not ours to close
