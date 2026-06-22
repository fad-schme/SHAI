"""AuditSink Protocol — the interface every sink adapter implements.

Reference implementations live in adapters/audit_sinks/.
This module holds only the Protocol so boundaries can import it
without pulling in any adapter dependencies.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from harness.core.events import AuditEvent


@runtime_checkable
class AuditSink(Protocol):
    """Ship one AuditEvent. Best-effort — a sink failure must not break the
    boundary call. The AuditEmitter logs individual failures and continues.

    All methods async. Must be safe for concurrent async calls.
    """

    name: str

    async def emit(self, event: "AuditEvent") -> None:
        """Emit one event. Raise on failure — AuditEmitter handles it."""
        ...

    async def close(self) -> None:
        """Flush and release resources. Default no-op for stateless sinks."""
        ...
