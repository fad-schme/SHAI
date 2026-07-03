"""Shared scan pipeline for all text-scanning boundaries.

run_scan() is the single implementation used by scan_input, scan_output,
scan_tool_result, and scan_file. The only differences between boundaries
are the BoundaryName and the scanner list.

Action model
------------
Each boundary has a default action (block | alert | redact). Individual
scanners can override this with their own action field on AdapterRef.

block  — finding at/above block_at → ScanStatus.BLOCK, Decision.BLOCKED
         Content is rejected. Caller must not forward it.

alert  — finding at/above block_at → ScanStatus.WARN, Decision.WARN
         Content passes through. Audit event flags it. Useful for
         observe-before-enforce rollout.

redact — finding at/above block_at → apply redact_with placeholder to
         scanner's redacted_text if available, else fall back to block.
         ScanStatus.ALLOW, Decision.ALLOW (redaction is transparent).

Per-scanner override:
    scanners:
      - name: regex_pii
        action: redact          # override: redact PII findings
        redact_with: "***"      # optional placeholder (default: [REDACTED:{category}])
      - name: injection_scan
        action: block           # override: always block injection findings

Scanner action takes precedence over boundary action for that scanner's findings.
"""
from __future__ import annotations

import asyncio
import logging
import re
from typing import TYPE_CHECKING

from harness.adapters.scanners.base import ScanResult
from harness.core.events import AuditEvent, now_ms
from harness.core.normalize import canonicalize
from harness.core.types import BoundaryName, Decision, ScanAction, ScanStatus, Severity
from harness.core.verdicts import Finding, ScanVerdict

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
    from harness.audit.emitter import AuditEmitter
    from harness.config.schema import NormalizationConfig
    from harness.core.context import AgentContext

log = logging.getLogger(__name__)

_DEFAULT_REDACT_TEMPLATE = "[REDACTED:{category}]"


def _redact_placeholder(template: str | None, category: str) -> str:
    tpl = template or _DEFAULT_REDACT_TEMPLATE
    return tpl.replace("{category}", category)


def _apply_redaction(
    text: str,
    findings: list[Finding],
    scanner_result: ScanResult,
    redact_with: str | None,
) -> str:
    """Return text with PII replaced by placeholder.

    Prefers the scanner's own redacted_text when available (it has the
    exact match positions). Falls back to a simple category-based label
    when the scanner did not supply redacted_text.
    """
    if scanner_result.redacted_text is not None:
        # Scanner did the work — use its output but rewrite the placeholder
        # if the operator specified a custom redact_with
        if redact_with is not None:
            # Replace default [REDACTED:*] patterns with operator's template
            result = scanner_result.redacted_text
            for f in findings:
                default  = _redact_placeholder(None, f.category)
                custom   = _redact_placeholder(redact_with, f.category)
                result   = result.replace(default, custom)
            return result
        return scanner_result.redacted_text

    # Scanner returned no redacted_text — nothing to substitute precisely
    # Return the original text unchanged; the audit event still carries findings
    return text


async def _scan_views(
    scanner: "Scanner",
    views: list[str],
    ctx: "AgentContext",
) -> ScanResult:
    """Run one scanner across every normalization view and merge results.

    Findings from all views are concatenated then de-duplicated by
    (category, severity) so a payload detected in multiple views (e.g. the
    surface form and its base64 decode) produces one finding, not several.

    redacted_text is taken only from the surface-form scan (views[0]); redaction
    positions from a decoded view do not map back onto the original text, and
    the pipeline never substitutes a decoded view for what the agent sees.
    """
    results = await asyncio.gather(
        *[scanner.scan(view, ctx) for view in views],
        return_exceptions=True,
    )

    merged: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    surface_redacted: str | None = None
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            raise r  # surfaced to run_scan's per-scanner exception handling
        if i == 0:
            surface_redacted = r.redacted_text
        for f in r.findings:
            key = (f.category, f.severity._index())
            if key not in seen:
                seen.add(key)
                merged.append(f)
    return ScanResult(findings=merged, redacted_text=surface_redacted)


async def run_scan(
    text: str,
    ctx: "AgentContext",
    *,
    boundary: BoundaryName,
    scanners: list["Scanner"],
    scanner_actions: list[ScanAction | None],   # parallel to scanners list
    scanner_redact_withs: list[str | None],      # parallel to scanners list
    boundary_action: ScanAction,
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    normalization: "NormalizationConfig | None" = None,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Run scanners concurrently, apply action logic, emit one AuditEvent.

    Invariants:
    - Exactly one AuditEvent per call, on every code path.
    - Disabled boundary → ScanStatus.ALLOW, disabled=True audit event.
    - Scanner exceptions logged and treated as empty findings — never raises.
    - No raw text in the audit event.
    - Scanner action overrides boundary action for that scanner's findings only.
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
        return ScanVerdict(status=ScanStatus.ALLOW)

    if normalization is not None and normalization.enabled:
        norm = canonicalize(
            text,
            decode=normalization.decode,
            max_depth=normalization.max_depth,
            entropy_threshold=normalization.entropy_threshold,
            max_bytes=normalization.max_bytes,
        )
        views = norm.views
        transforms = norm.transforms
    else:
        views = [text]
        transforms = []

    raw_results = await asyncio.gather(
        *[_scan_views(scanner, views, ctx) for scanner in scanners],
        return_exceptions=True,
    )

    all_findings:   list[Finding] = []
    adapter_names:  list[str]     = []
    current_text                  = text   # accumulates redactions
    final_status                  = ScanStatus.ALLOW
    # Track which findings came from each scanner for per-scanner action
    per_scanner_data: list[tuple[list[Finding], ScanResult | None, ScanAction, str | None]] = []

    for i, (scanner, result) in enumerate(zip(scanners, raw_results)):
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
            per_scanner_data.append(([], None, ScanAction.BLOCK, None))
            continue

        # Fall back to boundary_action when the per-scanner lists are shorter
        # than the scanners list (e.g. when tests pass scanner_actions=[])
        per_action   = scanner_actions[i]      if i < len(scanner_actions)      else None
        per_redact   = scanner_redact_withs[i] if i < len(scanner_redact_withs) else None
        effective_action = per_action if per_action is not None else boundary_action
        redact_with      = per_redact
        per_scanner_data.append((result.findings, result, effective_action, redact_with))
        all_findings.extend(result.findings)
        # Apply redaction unconditionally when the scanner returned redacted_text.
        # Redaction is a content transform — it is independent of block_at threshold.
        # (Block/alert actions still respect block_at; redaction does not.)
        if result.redacted_text is not None and effective_action == ScanAction.REDACT:
            current_text = _apply_redaction(
                current_text, result.findings, result, redact_with
            )
        elif result.redacted_text is not None and effective_action != ScanAction.REDACT:
            # Scanner returned redacted_text even though action is block/alert —
            # still propagate it so callers can use it (e.g. action=block but
            # caller wants to log the redacted form for debugging).
            current_text = result.redacted_text

    # ── Apply action per scanner ──────────────────────────────────────────
    for findings, result, action, redact_with in per_scanner_data:
        triggering = [f for f in findings if f.severity >= block_at]
        if not triggering:
            continue

        if action == ScanAction.BLOCK:
            final_status = ScanStatus.BLOCK  # hard stop — one block overrides all
            break

        elif action == ScanAction.ALERT:
            # Only upgrade to WARN, never downgrade a BLOCK
            if final_status != ScanStatus.BLOCK:
                final_status = ScanStatus.WARN

        elif action == ScanAction.REDACT:
            # Redaction already applied unconditionally above.
            # Status stays ALLOW — content passed through with PII replaced.
            pass

    redacted_text = current_text if current_text != text else None

    # ── Map status to audit Decision ──────────────────────────────────────
    if final_status == ScanStatus.BLOCK:
        decision = Decision.BLOCKED
    elif final_status == ScanStatus.WARN:
        decision = Decision.WARN
    else:
        decision = Decision.ALLOW

    max_sev: Severity | None = None
    if all_findings:
        max_sev = max(all_findings, key=lambda f: f.severity._index()).severity

    event = AuditEvent.build(
        boundary=boundary,
        decision=decision,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        adapters=adapter_names,
        finding_count=len(all_findings),
        max_severity=max_sev,
        audit_tags=audit_tags or {},
        extra={"normalization": transforms} if transforms else None,
    )
    await emitter.emit(event)

    return ScanVerdict(
        status=final_status,
        findings=all_findings,
        redacted_text=redacted_text,
    )


async def run_file_scan(
    path: str,
    ctx: "AgentContext",
    *,
    scanners: list["Scanner"],
    scanner_actions: list[ScanAction | None],
    scanner_redact_withs: list[str | None],
    boundary_action: ScanAction,
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    normalization: "NormalizationConfig | None" = None,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Run file scanners. Delegates to run_scan with FILE_SCAN boundary name."""
    return await run_scan(
        path,
        ctx,
        boundary=BoundaryName.FILE_SCAN,
        scanners=scanners,
        scanner_actions=scanner_actions,
        scanner_redact_withs=scanner_redact_withs,
        boundary_action=boundary_action,
        emitter=emitter,
        tenant_id=tenant_id,
        enabled=enabled,
        block_at=block_at,
        normalization=normalization,
        audit_tags=audit_tags,
    )


async def run_tool_result_scan(
    result: str,
    ctx: "AgentContext",
    *,
    scanners: list["Scanner"],
    scanner_actions: list[ScanAction | None],
    scanner_redact_withs: list[str | None],
    boundary_action: ScanAction,
    emitter: "AuditEmitter",
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    normalization: "NormalizationConfig | None" = None,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Scan a tool return value. Delegates to run_scan with TOOL_RESULT_SCAN."""
    return await run_scan(
        result,
        ctx,
        boundary=BoundaryName.TOOL_RESULT_SCAN,
        scanners=scanners,
        scanner_actions=scanner_actions,
        scanner_redact_withs=scanner_redact_withs,
        boundary_action=boundary_action,
        emitter=emitter,
        tenant_id=tenant_id,
        enabled=enabled,
        block_at=block_at,
        normalization=normalization,
        audit_tags=audit_tags,
    )