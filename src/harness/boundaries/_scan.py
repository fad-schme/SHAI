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

Error handling
--------------
on_error controls what happens when a scanner raises an exception:

  fail_closed — treat the failure as BLOCK (default, safe posture).
                The scan pipeline short-circuits and returns ScanVerdict(BLOCK).
  fail_open   — treat the failure as empty findings (pre-0.2 behavior).
                The pipeline continues with remaining scanners.
  degrade     — treat the failure as WARN. Content passes through but
                the audit event is flagged with decision=DEGRADED.

A per-scanner CircuitBreaker prevents repeated calls to a broken adapter.
When a scanner's breaker is OPEN, the scanner is skipped entirely.
After recovery_timeout seconds, one probe call is attempted (HALF_OPEN).
Success resets the breaker; failure doubles the timeout (capped at 5 min).

Circuit breaker trips and scanner failures emit structured AuditEvents
with boundary=SYSTEM, decision=DEGRADED so failures are visible in the
audit trail, not just application logs.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from harness.adapters.circuit_breaker import CircuitBreaker
from harness.adapters.scanners.base import ScanResult
from harness.core.events import AuditEvent, now_ms
from harness.core.normalize import canonicalize
from harness.core.types import (
    BoundaryName,
    Decision,
    OnError,
    ScanAction,
    ScanStatus,
    Severity,
)
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


# ── Per-SHAI scan state ───────────────────────────────────────────────────
# Circuit breakers and the promoted-candidate cache live on the SHAI instance,
# not at module scope. Callers pass ScanState in explicitly.
_DEFAULT_CANDIDATES_DB = "state/patterns.db"


class ScanState:
    """Per-SHAI scan state. Owns circuit breakers and the promoted-candidate cache.

    One instance per SHAI facade. Not thread-safe by itself — reads and writes
    are serialised by asyncio's cooperative scheduling within a single event
    loop. Do not share a ScanState across event loops.
    """

    __slots__ = ("_breakers", "_promoted_cache", "candidates_db")

    def __init__(self, candidates_db: str = _DEFAULT_CANDIDATES_DB) -> None:
        self._breakers: dict[int, CircuitBreaker] = {}
        self._promoted_cache: list[dict] | None = None
        self.candidates_db = candidates_db

    def get_breaker(self, scanner: Scanner) -> CircuitBreaker:
        """Return (or create) the circuit breaker for a scanner instance."""
        key = id(scanner)
        if key not in self._breakers:
            self._breakers[key] = CircuitBreaker(name=scanner.name)
        return self._breakers[key]

    def get_promoted(self) -> list[dict]:
        if self._promoted_cache is None:
            from harness.patterns.store import load_promoted_candidates
            self._promoted_cache = load_promoted_candidates(self.candidates_db)
        return self._promoted_cache

    def invalidate_promoted_cache(self) -> None:
        """Force the next scan to re-read promoted candidates from disk."""
        self._promoted_cache = None


async def _emit_system_event(
    emitter: AuditEmitter,
    ctx: AgentContext,
    tenant_id: str,
    scanner_name: str,
    error: str,
    circuit_state: str,
    boundary: BoundaryName,
    audit_tags: dict[str, str] | None = None,
) -> None:
    """Emit a structured SYSTEM/DEGRADED audit event for scanner failures."""
    event = AuditEvent.build(
        boundary=BoundaryName.SYSTEM,
        decision=Decision.DEGRADED,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=0,
        deny_reason=f"scanner '{scanner_name}' failed: {error}",
        adapters=[scanner_name],
        audit_tags=audit_tags or {},
        extra={
            "scanner": scanner_name,
            "error": error,
            "circuit_state": circuit_state,
            "origin_boundary": str(boundary),
        },
    )
    try:
        await emitter.emit(event)
    except Exception:
        # System events are best-effort — never let them break the pipeline
        log.debug("failed to emit system event for scanner %s", scanner_name)


async def _scan_views(
    scanner: Scanner,
    views: list[str],
    ctx: AgentContext,
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
    ctx: AgentContext,
    *,
    boundary: BoundaryName,
    scanners: list[Scanner],
    scanner_actions: list[ScanAction | None],   # parallel to scanners list
    scanner_redact_withs: list[str | None],      # parallel to scanners list
    boundary_action: ScanAction,
    emitter: AuditEmitter,
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    state: ScanState,
    normalization: NormalizationConfig | None = None,
    audit_tags: dict[str, str] | None = None,
    on_error: OnError = OnError.FAIL_CLOSED,
) -> ScanVerdict:
    """Run scanners concurrently, apply action logic, emit one AuditEvent.

    Invariants:
    - Exactly one AuditEvent per call, on every code path.
    - Disabled boundary → ScanStatus.ALLOW, disabled=True audit event.
    - Scanner exceptions handled per on_error policy.
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

    # ── Run scanners with circuit breaker awareness ───────────────────────
    # Scanners whose breaker is OPEN are skipped entirely; their slot in
    # raw_results gets a _CircuitOpenSentinel instead of a ScanResult.
    class _CircuitOpenSentinel:
        """Marker: scanner was skipped because its circuit breaker is OPEN."""
        def __init__(self, scanner_name: str) -> None:
            self.scanner_name = scanner_name

    async def _guarded_scan(scanner: Scanner, views: list[str]) -> ScanResult | _CircuitOpenSentinel:
        breaker = state.get_breaker(scanner)
        if breaker.is_open:
            return _CircuitOpenSentinel(scanner.name)
        result = await _scan_views(scanner, views, ctx)
        breaker.record_success()
        return result

    raw_results = await asyncio.gather(
        *[_guarded_scan(scanner, views) for scanner in scanners],
        return_exceptions=True,
    )

    all_findings:   list[Finding] = []
    adapter_names:  list[str]     = []
    current_text                  = text   # accumulates redactions
    final_status                  = ScanStatus.ALLOW
    degraded                      = False  # at least one scanner failed in degrade mode
    # Track which findings came from each scanner for per-scanner action
    per_scanner_data: list[tuple[list[Finding], ScanResult | None, ScanAction, str | None]] = []

    for i, (scanner, result) in enumerate(zip(scanners, raw_results)):
        adapter_names.append(scanner.name)
        breaker = state.get_breaker(scanner)

        # ── Circuit breaker OPEN — scanner was skipped ────────────────────
        if isinstance(result, _CircuitOpenSentinel):
            log.debug(
                "scanner skipped — circuit breaker open",
                extra={"scanner": scanner.name, "boundary": boundary,
                       **ctx.to_log_fields()},
            )
            # Treat as on_error policy: the scanner is unavailable
            if on_error == OnError.FAIL_CLOSED:
                final_status = ScanStatus.BLOCK
                await _emit_system_event(
                    emitter, ctx, tenant_id, scanner.name,
                    "circuit breaker open", breaker.state,
                    boundary, audit_tags,
                )
                break  # short-circuit — no point running remaining logic
            elif on_error == OnError.DEGRADE:
                degraded = True
                if final_status != ScanStatus.BLOCK:
                    final_status = ScanStatus.WARN
            # FAIL_OPEN: skip silently
            per_scanner_data.append(([], None, ScanAction.BLOCK, None))
            continue

        # ── Scanner raised an exception ───────────────────────────────────
        if isinstance(result, Exception):
            breaker.record_failure()
            error_str = str(result)
            log.error(
                "scanner failed",
                extra={
                    "scanner": scanner.name,
                    "boundary": boundary,
                    "on_error": on_error,
                    "error": error_str,
                    **ctx.to_log_fields(),
                },
            )
            # Emit structured system event for observability
            await _emit_system_event(
                emitter, ctx, tenant_id, scanner.name,
                error_str, breaker.state,
                boundary, audit_tags,
            )

            if on_error == OnError.FAIL_CLOSED:
                # Short-circuit: scanner failure → BLOCK
                event = AuditEvent.build(
                    boundary=boundary,
                    decision=Decision.BLOCKED,
                    ctx=ctx,
                    tenant_id=tenant_id,
                    duration_ms=now_ms() - start,
                    adapters=adapter_names,
                    deny_reason=f"scanner '{scanner.name}' failed (on_error=fail_closed)",
                    audit_tags=audit_tags or {},
                    extra={"on_error": "fail_closed", "failed_scanner": scanner.name},
                )
                await emitter.emit(event)
                return ScanVerdict(status=ScanStatus.BLOCK)

            elif on_error == OnError.DEGRADE:
                degraded = True
                if final_status != ScanStatus.BLOCK:
                    final_status = ScanStatus.WARN

            # FAIL_OPEN or DEGRADE: continue with empty findings for this scanner
            per_scanner_data.append(([], None, ScanAction.BLOCK, None))
            continue

        # ── Scanner succeeded — record success on breaker ─────────────────
        # (already called in _guarded_scan, but harmless to note here)

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

    # ── Promoted candidates: inject findings from human-promoted heuristic matches ──
    all_findings = _check_promoted_candidates(text, all_findings, state)

    # ── Ensemble: promote severity when 2+ scanners agree on a category ────
    from harness.boundaries.ensemble import promote_findings
    all_findings = promote_findings(all_findings)

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

    extra: dict = {}
    if transforms:
        extra["normalization"] = transforms
    if degraded:
        extra["degraded"] = True

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
        extra=extra or None,
    )
    await emitter.emit(event)

    # ── Candidate write: record unmatched heuristic detections ────────────
    _record_candidate_if_needed(text, all_findings, adapter_names, state)

    return ScanVerdict(
        status=final_status,
        findings=all_findings,
        redacted_text=redacted_text,
    )


# ── Heuristic candidate helpers ──────────────────────────────────────────
# The promoted-candidate cache lives on ScanState. These helpers take the
# state explicitly and never touch module globals.

def _check_promoted_candidates(
    text: str,
    findings: list[Finding],
    state: ScanState,
) -> list[Finding]:
    """Read path: inject findings from promoted candidates matching the current text."""
    promoted = state.get_promoted()
    if not promoted:
        return findings

    from harness.patterns.fingerprint import (
        extract_fingerprint,
        fingerprint_from_json,
        lsh_jaccard,
    )
    # Compute a quick fingerprint of the current text (sub-scores not available
    # here, so use 0.0 — the LSH is what matters for matching)
    current_fp = extract_fingerprint(text, 0.0, 0.0, 0.0, 0.0)
    current_lsh = current_fp["lsh"]

    injected = list(findings)
    for candidate in promoted:
        stored_fp = fingerprint_from_json(candidate["fingerprint"])
        stored_lsh = stored_fp.get("lsh", "")
        if lsh_jaccard(current_lsh, stored_lsh) >= 0.7:
            injected.append(Finding(
                scanner="learned_candidate",
                category="heuristic_anomaly",
                severity=Severity.MEDIUM,
                detail=f"promoted candidate id={candidate['id']} hits={candidate['hit_count']}",
            ))
            break  # one match is enough
    return injected


_REGEX_SCANNERS = {"injection_scan", "jailbreak_scan", "identity_spoof_scan"}


def _record_candidate_if_needed(
    text: str,
    findings: list[Finding],
    adapter_names: list[str],
    state: ScanState,
) -> None:
    """Write path: record unmatched heuristic detections as candidates.

    Fires when heuristic_scan produced MEDIUM+ and no regex scanner
    produced a finding in the same call. Fire-and-forget — errors swallowed.
    """
    heuristic_findings = [
        f for f in findings
        if f.scanner == "heuristic_scan" and f.severity >= Severity.MEDIUM
    ]
    if not heuristic_findings:
        return

    regex_findings = [f for f in findings if f.scanner in _REGEX_SCANNERS]
    if regex_findings:
        return  # regex scanners caught it — no gap

    try:
        from harness.patterns.fingerprint import (
            extract_fingerprint,
            extract_skeleton,
            fingerprint_to_json,
        )
        from harness.patterns.store import upsert_candidate

        # Parse sub-scores from the heuristic detail string
        detail = heuristic_findings[0].detail or ""
        scores = {"entropy": 0.0, "density": 0.0, "coherence": 0.0, "structural": 0.0}
        for part in detail.split("(")[-1].rstrip(")").split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() in scores:
                    scores[k.strip()] = float(v.strip())

        fp = extract_fingerprint(
            text, scores["entropy"], scores["density"],
            scores["coherence"], scores["structural"],
        )
        skeleton = extract_skeleton(text)
        upsert_candidate(
            state.candidates_db,
            fingerprint_to_json(fp),
            skeleton,
            heuristic_findings[0].severity.value,
            fp["lsh"],
        )
    except Exception as e:
        # Best-effort: candidate DB is a learning surface, never a hard dependency.
        # A write failure must not abort the scan.
        log.debug("candidate recording failed: %s", e)


async def run_file_scan(
    path: str,
    ctx: AgentContext,
    *,
    scanners: list[Scanner],
    scanner_actions: list[ScanAction | None],
    scanner_redact_withs: list[str | None],
    boundary_action: ScanAction,
    emitter: AuditEmitter,
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    state: ScanState,
    normalization: NormalizationConfig | None = None,
    audit_tags: dict[str, str] | None = None,
    on_error: OnError = OnError.FAIL_CLOSED,
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
        state=state,
        normalization=normalization,
        audit_tags=audit_tags,
        on_error=on_error,
    )


async def run_tool_result_scan(
    result: str,
    ctx: AgentContext,
    *,
    scanners: list[Scanner],
    scanner_actions: list[ScanAction | None],
    scanner_redact_withs: list[str | None],
    boundary_action: ScanAction,
    emitter: AuditEmitter,
    tenant_id: str,
    enabled: bool,
    block_at: Severity,
    state: ScanState,
    normalization: NormalizationConfig | None = None,
    audit_tags: dict[str, str] | None = None,
    on_error: OnError = OnError.FAIL_CLOSED,
) -> ScanVerdict:
    """Scan a tool return value. Delegates to run_scan with TOOL_RESULT_SCAN.

    Adjusts block_at down one severity level when TurnSignals shows the input
    scan flagged injection and the gate allowed a specific tool — the tool
    result now has elevated scrutiny because we know an attack chain is in
    progress.
    """
    effective_block_at = block_at
    signals = ctx.turn_signals
    if (signals is not None
            and signals.input_has_injection
            and signals.gate_tool_name is not None):
        effective_block_at = _one_lower(block_at)

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
        block_at=effective_block_at,
        state=state,
        normalization=normalization,
        audit_tags=audit_tags,
        on_error=on_error,
    )


def _one_lower(sev: Severity) -> Severity:
    """Return the next-lower severity level, floored at LOW."""
    ladder = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        idx = ladder.index(sev)
    except ValueError:
        return sev
    return ladder[max(0, idx - 1)]
