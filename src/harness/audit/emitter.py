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
import contextlib
import hashlib
import hmac
import json
import logging
from collections.abc import Iterator
from typing import TYPE_CHECKING, Any, Protocol

from harness.core.errors import AuditEmissionError
from harness.core.events import canonical_json

if TYPE_CHECKING:
    from harness.core.events import AnyAuditEvent

log = logging.getLogger(__name__)

_MAX_DENY_REASON = 500


class AuditSink(Protocol):
    """Interface every sink adapter must satisfy."""

    name: str

    async def emit(self, event: AnyAuditEvent) -> None:
        """Emit one event. Raise on failure — AuditEmitter handles it."""
        ...

    async def close(self) -> None:
        """Flush and release resources. No-op for stateless sinks."""
        ...


def _sign_event(event: AnyAuditEvent, secret: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical encoding, minus `signature`.

    Uses the same `canonical_json` the sinks write, so a written line with its
    `signature` key removed re-encodes to exactly the payload signed here —
    that byte-for-byte agreement is what makes the trail verifiable from the
    file alone.
    """
    body = canonical_json(event, exclude={"signature"}).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify_line(line: dict[str, Any], secret: bytes) -> bool:
    """Verify one written audit line against the signature it carries.

    Takes the parsed JSONL object rather than an `AuditEvent`, because that is
    what a verifier actually has: reconstructing the model first would verify a
    re-serialization of the line instead of the line, and would fail on any
    record written by a version whose schema has since moved on.

    Lifting out `signature` and re-encoding the remainder reproduces exactly
    what `_sign_event` covered — `canonical_json` writes nulls out and sorts
    keys, so the bytes are a function of the record alone. An unsigned or
    malformed line is not verifiable and returns False; deciding whether that
    is acceptable belongs to the caller, which knows if signing was on.
    """
    claimed = line.get("signature")
    if not isinstance(claimed, str) or not claimed:
        return False
    body = json.dumps(
        {k: v for k, v in line.items() if k != "signature"}, sort_keys=True
    ).encode()
    return hmac.compare_digest(
        hmac.new(secret, body, hashlib.sha256).hexdigest(), claimed
    )


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
        # Subscribers added by collect_events() — notified after all sinks
        self._subscribers: list[list[AnyAuditEvent]] = []

    async def emit(self, event: AnyAuditEvent) -> None:
        """Truncate oversized fields, optionally sign, then fan-out concurrently.

        What reaches the sinks is a new object, never the caller's. `AuditEvent`
        and `NetworkAuditEvent` are frozen public shapes; rewriting one in place
        rewrote a record the caller already held, and the boundary that built it
        had no way to know its event had changed after handing it over.

        Truncation happens before signing, so the signature covers the
        `deny_reason` that is actually written. `model_copy` does not re-run
        validators, which is what we want here — the emitter is not re-deciding
        whether the event is well-formed, only shortening and stamping it.
        """
        if event.deny_reason and len(event.deny_reason) > _MAX_DENY_REASON:
            event = event.model_copy(update={
                "deny_reason": event.deny_reason[:_MAX_DENY_REASON - 3] + "...",
            })

        if self._signing_secret is not None:
            try:
                sig = _sign_event(event, self._signing_secret)
            except Exception as e:
                # Invariant 2: only AuditEmissionError may escape the audit path.
                # Fail rather than emit unsigned — a silent gap in a signed trail
                # is the repudiation risk signing exists to close.
                raise AuditEmissionError(
                    f"audit event signing failed: {e}",
                    op="audit_sign",
                ) from e
            event = event.model_copy(update={"signature": sig})

        results = await asyncio.gather(
            *[sink.emit(event) for sink in self._sinks],
            return_exceptions=True,
        )

        failures = [
            (self._sinks[i].name, r)
            for i, r in enumerate(results)
            if isinstance(r, Exception)
        ]

        if failures:
            # boundary is on AuditEvent, event_type on NetworkAuditEvent —
            # neither is common, and reading the wrong one here would raise
            # AttributeError inside the handler and mask the sink failure.
            for sink_name, exc in failures:
                log.error("audit sink emit failed",
                          extra={"sink": sink_name,
                                 "boundary": getattr(event, "boundary", None),
                                 "event_type": getattr(event, "event_type", None),
                                 "agent_id": event.agent_id,
                                 "tenant_id": event.tenant_id,
                                 "error": str(exc)})

        if len(failures) == len(self._sinks):
            raise AuditEmissionError(
                f"all audit sinks failed: {[n for n, _ in failures]}",
                op="audit_emit",
            )

        # Notify in-process subscribers (collect_events context managers)
        for bucket in self._subscribers:
            bucket.append(event)


    @contextlib.contextmanager
    def collect_events(self) -> Iterator[list[AnyAuditEvent]]:
        """Context manager that collects AuditEvents emitted during the block.

        Returns a list that is populated in-place as events are emitted.
        The list is complete when the block exits.

        Usage::

            with harness.collect_events() as events:
                result = await app.ainvoke(...)
            # events is now a list[AuditEvent]
            for ev in events:
                print(ev.boundary, ev.decision)

        Multiple concurrent collect_events() calls are safe — each gets its
        own independent list. Does not affect configured sinks (file, stdout).
        """
        bucket: list[AnyAuditEvent] = []
        self._subscribers.append(bucket)
        try:
            yield bucket
        finally:
            # Unsubscribe by identity, never by equality. list.remove() compares
            # with ==, and two buckets that have collected the same events — most
            # commonly two empty ones — are equal. It would then drop whichever
            # was registered first, leaving this block still subscribed after it
            # exited and making the other block's exit raise ValueError.
            #
            # Scanning in reverse finds the innermost block first, which is the
            # common nesting case. A bucket that is somehow already gone removes
            # nothing rather than raising: this runs in a finally, and an
            # exception here would mask whatever the caller's block was raising.
            for index in range(len(self._subscribers) - 1, -1, -1):
                if self._subscribers[index] is bucket:
                    del self._subscribers[index]
                    break

    async def close(self) -> None:
        await asyncio.gather(
            *[self._close_one(sink) for sink in self._sinks],
            return_exceptions=True,
        )

    @staticmethod
    async def _close_one(sink: AuditSink) -> None:
        try:
            await sink.close()
        except Exception as e:
            # Best-effort shutdown: broad catch is intentional. One misbehaving
            # sink (network hiccup on flush, corrupted file, closed connection)
            # must not prevent the harness from closing the rest.
            log.warning("audit sink close failed",
                        extra={"sink": sink.name, "error": str(e)})
