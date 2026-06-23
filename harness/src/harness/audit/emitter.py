"""AuditEmitter — fan-out to all configured audit sinks.

AuditSink:    Protocol every sink adapter must satisfy.
AuditEmitter: Fans out to all sinks concurrently. Truncates long deny_reason
              fields before emission. Optionally signs each event with
              HMAC-SHA256 (R3 — mitigates T8 Repudiation & Untraceability).

Individual sink failures are logged and swallowed.
All sinks failing raises AuditEmissionError.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from typing import TYPE_CHECKING, Protocol

from harness.core.errors import AuditEmissionError

if TYPE_CHECKING:
    from harness.core.events import AuditEvent

log = logging.getLogger(__name__)

_MAX_DENY_REASON = 500


class AuditSink(Protocol):
    """Interface every sink adapter must satisfy."""

    name: str

    async def emit(self, event: "AuditEvent") -> None:
        """Emit one event. Raise on failure — AuditEmitter handles it."""
        ...

    async def close(self) -> None:
        """Flush and release resources. No-op for stateless sinks."""
        ...


def _sign_event(event: "AuditEvent", secret: bytes) -> str:
    """Compute HMAC-SHA256 signature over the event body (excluding signature field).

    The payload is the deterministic JSON of all non-None fields excluding
    `signature`. Sorted keys ensure consistent ordering across Python versions.
    """
    payload = {
        k: v for k, v in event.model_dump(exclude_none=True).items()
        if k != "signature"
    }
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


class AuditEmitter:

    def __init__(
        self,
        sinks: list[AuditSink],
        signing_secret: bytes | None = None,
    ) -> None:
        if not sinks:
            raise ValueError("AuditEmitter requires at least one sink")
        self._sinks          = sinks
        self._signing_secret = signing_secret

    async def emit(self, event: "AuditEvent") -> None:
        """Truncate oversized fields, optionally sign, then fan-out concurrently."""
        if event.deny_reason and len(event.deny_reason) > _MAX_DENY_REASON:
            object.__setattr__(event, "deny_reason",
                               event.deny_reason[:_MAX_DENY_REASON - 3] + "...")

        if self._signing_secret is not None:
            sig = _sign_event(event, self._signing_secret)
            object.__setattr__(event, "signature", sig)

        results = await asyncio.gather(
            *[self._emit_one(sink, event) for sink in self._sinks],
            return_exceptions=True,
        )

        failures = [
            (self._sinks[i].name, r)
            for i, r in enumerate(results)
            if isinstance(r, Exception)
        ]

        if failures:
            for sink_name, exc in failures:
                log.error("audit sink emit failed",
                          extra={"sink": sink_name, "boundary": event.boundary,
                                 "agent_id": event.agent_id, "error": str(exc)})

        if len(failures) == len(self._sinks):
            raise AuditEmissionError(
                f"all audit sinks failed: {[n for n, _ in failures]}",
                op="audit_emit",
            )

    async def close(self) -> None:
        await asyncio.gather(
            *[self._close_one(sink) for sink in self._sinks],
            return_exceptions=True,
        )

    @staticmethod
    async def _emit_one(sink: AuditSink, event: "AuditEvent") -> None:
        await sink.emit(event)

    @staticmethod
    async def _close_one(sink: AuditSink) -> None:
        try:
            await sink.close()
        except Exception as e:
            log.warning("audit sink close failed",
                        extra={"sink": sink.name, "error": str(e)})
