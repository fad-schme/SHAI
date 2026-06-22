"""scan_input boundary — thin wrapper over the shared scan implementation."""
from __future__ import annotations

from typing import TYPE_CHECKING

from harness.boundaries._scan import run_scan
from harness.core.types import BoundaryName, Severity
from harness.core.verdicts import ScanVerdict

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import RuntimeContext


async def run(
    text: str,
    ctx: "RuntimeContext",
    *,
    scanners: list["Scanner"],
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity = Severity.HIGH,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    return await run_scan(
        text,
        ctx,
        tenant_id=tenant_id,
        boundary=BoundaryName.INPUT_SCAN,
        scanners=scanners,
        emitter=emitter,
        enabled=enabled,
        block_at=block_at,
        audit_tags=audit_tags,
    )
