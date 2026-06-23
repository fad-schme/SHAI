"""Shared implementation for scan_input and scan_output.

Both boundaries have identical structure — run scanners concurrently,
aggregate findings, emit exactly one AuditEvent. The only differences
are the BoundaryName and the scanner list used.

scan_input and scan_output import from here; they do not duplicate logic.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from harness.adapters.scanners.base import ScanResult
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, Severity
from harness.core.verdicts import Finding, ScanVerdict

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import AgentContext

log = logging.getLogger(__name__)


async def run_scan(
    text: str,
    ctx: "AgentContext",
    *,
    boundary: BoundaryName,
    scanners: list["Scanner"],
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Run scanners concurrently, aggregate, emit one AuditEvent.

    Invariants:
    - Exactly one AuditEvent emitted per call, on every code path.
    - Disabled boundary → allow verdict + audit event with disabled=True.
    - Scanner exceptions are logged and treated as empty findings — pipeline
      continues. The boundary never raises on scanner failure.
    - No raw text in the audit event.
    """
    start = now_ms()

    if not enabled:
        event = AuditEvent.build(
            boundary=boundary,
            decision=Decision.ALLOW,
            ctx=ctx,
            tenant_id=tenant_id,
            duration_ms=0,
            disabled=True,
            audit_tags=audit_tags or {},
        )
        await emitter.emit(event)
        return ScanVerdict(blocked=False)

    # Run all scanners concurrently; capture exceptions per-scanner
    raw_results = await asyncio.gather(
        *[scanner.scan(text, ctx) for scanner in scanners],
        return_exceptions=True,
    )

    findings: list[Finding] = []
    redacted_text: str | None = None
    adapter_names: list[str] = []

    for scanner, result in zip(scanners, raw_results):
        adapter_names.append(scanner.name)
        if isinstance(result, Exception):
            log.error(
                "scanner failed — treated as empty findings",
                extra={
                    "scanner": scanner.name,
                    "boundary": boundary,
                    "error": str(result),
                    **ctx.to_log_fields(),
                },
            )
            continue
        findings.extend(result.findings)
        if result.redacted_text is not None:
            redacted_text = result.redacted_text  # last redaction wins

    blocked = any(f.severity >= block_at for f in findings)
    decision = Decision.BLOCKED if blocked else Decision.ALLOW

    max_sev: Severity | None = None
    if findings:
        order = [s for s in Severity]
        max_sev = max(findings, key=lambda f: order.index(f.severity)).severity

    duration = now_ms() - start
    event = AuditEvent.build(
        boundary=boundary,
        decision=decision,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=duration,
        adapters=adapter_names,
        finding_count=len(findings),
        max_severity=max_sev,
        audit_tags=audit_tags or {},
    )
    await emitter.emit(event)

    return ScanVerdict(
        blocked=blocked,
        findings=findings,
        redacted_text=redacted_text,
    )


async def run_file_scan(
    path: str,
    ctx: "AgentContext",
    *,
    scanners: list["Scanner"],
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Run file scanners against a file path.

    Structurally identical to run_scan — same AuditEvent invariants.
    The path string is passed as the 'text' argument to each scanner.
    FileScanner interprets this as a path; text scanners can be chained
    after text extraction happens inside FileScanner.

    Invariants (same as run_scan):
    - Exactly one AuditEvent per call on every code path.
    - Disabled → allow verdict + disabled=True audit event.
    - Scanner exceptions treated as empty findings.
    - No file content in audit event.
    """
    return await run_scan(
        path,
        ctx,
        boundary=BoundaryName.FILE_SCAN,
        scanners=scanners,
        emitter=emitter,
        tenant_id=tenant_id,
        enabled=enabled,
        block_at=block_at,
        audit_tags=audit_tags,
    )


async def run_tool_result_scan(
    result: str,
    ctx: "AgentContext",
    *,
    scanners: list["Scanner"],
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Scan a tool's return value before it re-enters the LLM context.

    Identical contract to run_scan — one AuditEvent, same disabled/block logic.
    Uses BoundaryName.TOOL_RESULT_SCAN so SIEM queries can distinguish it.
    """
    return await run_scan(
        result,
        ctx,
        boundary=BoundaryName.TOOL_RESULT_SCAN,
        scanners=scanners,
        emitter=emitter,
        tenant_id=tenant_id,
        enabled=enabled,
        block_at=block_at,
        audit_tags=audit_tags,
    )
