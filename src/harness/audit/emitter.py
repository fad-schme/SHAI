"""AuditEmitter — fan-out to all configured AuditSinks.

Always on. Exactly one emit() call per boundary call.
Redacts the event before fan-out.
Individual sink failures are logged and swallowed.
All sinks failing raises AuditEmissionError.
Sinks run concurrently via asyncio.gather.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from harness.audit.redaction import redact
from harness.core.errors import AuditEmissionError

if TYPE_CHECKING:
    from harness.audit.sink import AuditSink
    from harness.core.events import AuditEvent

log = logging.getLogger(__name__)


class AuditEmitter:

    def __init__(self, sinks: list["AuditSink"]) -> None:
        if not sinks:
            raise ValueError("AuditEmitter requires at least one sink")
        self._sinks = sinks

    async def emit(self, event: "AuditEvent") -> None:
        """Redact, then fan-out to all sinks concurrently.

        Individual sink failures are logged and swallowed.
        If ALL sinks fail, raises AuditEmissionError.
        """
        safe_event = redact(event)

        results = await asyncio.gather(
            *[self._emit_one(sink, safe_event) for sink in self._sinks],
            return_exceptions=True,
        )

        failures = [
            (self._sinks[i].name, r)
            for i, r in enumerate(results)
            if isinstance(r, Exception)
        ]

        if failures:
            for sink_name, exc in failures:
                log.error(
                    "audit sink emit failed",
                    extra={
                        "sink": sink_name,
                        "boundary": event.boundary,
                        "agent_id": event.agent_id,
                        "error": str(exc),
                        "op": "audit_emit",
                    },
                )

        if len(failures) == len(self._sinks):
            failed_names = [name for name, _ in failures]
            raise AuditEmissionError(
                f"all audit sinks failed: {failed_names}",
                op="audit_emit",
            )

    async def close(self) -> None:
        """Close all sinks. Individual close failures are swallowed."""
        await asyncio.gather(
            *[self._close_one(sink) for sink in self._sinks],
            return_exceptions=True,
        )

    @staticmethod
    async def _emit_one(sink: "AuditSink", event: "AuditEvent") -> None:
        await sink.emit(event)

    @staticmethod
    async def _close_one(sink: "AuditSink") -> None:
        try:
            await sink.close()
        except Exception as e:
            log.warning("audit sink close failed", extra={"sink": sink.name, "error": str(e)})
