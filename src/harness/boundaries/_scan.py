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
  fail_open   — treat the failure as empty findings.
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
from typing import TYPE_CHECKING, Any, Protocol

from harness.adapters.circuit_breaker import CircuitBreaker
from harness.adapters.scanners.base import ScanResult
from harness.core.events import AuditEvent, now_ms
from harness.core.normalize import canonicalize_config
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
    from harness.adapters.scanners.base import ConfiguredScanner, Scanner
    from harness.audit.emitter import AuditEmitter
    from harness.config.schema import NormalizationConfig, ToolResultScanConfig
    from harness.core.context import AgentContext

log = logging.getLogger(__name__)


class ScanBoundaryConfig(Protocol):
    """What run_scan needs from a boundary's own config section.

    BoundaryConfig, FileScanConfig, and ToolResultScanConfig all satisfy this
    structurally — run_scan takes the config object itself instead of four
    separate keyword arguments that were always a straight projection of it,
    so a caller can no longer pair one boundary's block_at with another's
    action by hand-copying the wrong field.
    """
    enabled:  bool
    block_at: Severity
    action:   ScanAction
    on_error: OnError

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
    reason: str,
    circuit_state: str,
    boundary: BoundaryName,
    audit_tags: dict[str, str] | None = None,
) -> None:
    """Emit a structured SYSTEM/DEGRADED audit event for scanner failures.

    reason is signed and carries no raw text on any path: an exception
    type name ("ValueError") or a fixed phrase ("circuit breaker open"),
    never str(exception) — a third-party scanner's exception message can
    echo the text it choked on.
    """
    event = AuditEvent.build(
        boundary=BoundaryName.SYSTEM,
        decision=Decision.DEGRADED,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=0,
        deny_reason=f"scanner '{scanner_name}' failed: {reason}",
        adapters=[scanner_name],
        audit_tags=audit_tags or {},
        extra={
            "scanner": scanner_name,
            "reason": reason,
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
    scanners: list[ConfiguredScanner],
    config: ScanBoundaryConfig,
    emitter: AuditEmitter,
    tenant_id: str,
    state: ScanState,
    normalization: NormalizationConfig | None = None,
    audit_tags: dict[str, str] | None = None,
    forced_block_reason: str | None = None,
    forced_block_extra: dict[str, Any] | None = None,
) -> ScanVerdict:
    """Run scanners concurrently, apply action logic, emit one AuditEvent.

    Invariants:
    - Exactly one AuditEvent per call, on every code path.
    - Disabled boundary → ScanStatus.ALLOW, disabled=True audit event.
    - Enabled boundary with no scanner to run → ScanStatus.BLOCK.
    - Scanner exceptions handled per config.on_error policy.
    - No raw text in the audit event.
    - Scanner action overrides boundary action for that scanner's findings only.

    forced_block_reason / forced_block_extra: let a caller with evidence this
    call cannot see on its own (scan_output's cross-boundary consolidated
    turn-risk check) fold a block into *this* call's single event instead of
    emitting a second one after the fact. Applied only when the scanners
    themselves did not already block — it raises the floor, never lowers it.
    """
    start = now_ms()
    on_error = config.on_error

    if not config.enabled:
        # Turning a boundary off is an explicit operator decision, and the
        # event records it as such — unless a forced block applies. That
        # floor comes from evidence outside this boundary's own scanners
        # (scan_output's cross-boundary turn-risk check) and must still hold
        # when there is nothing here to scan.
        if forced_block_reason is not None:
            # disabled=True requires decision=allow (AuditEvent's own
            # invariant) — the block did not come from this boundary being
            # on, so it is not recorded as this boundary's own scan.
            event = AuditEvent.build(
                boundary=boundary,
                decision=Decision.BLOCKED,
                ctx=ctx,
                tenant_id=tenant_id,
                duration_ms=0,
                deny_reason=forced_block_reason,
                audit_tags=audit_tags or {},
                extra=forced_block_extra,
            )
            await emitter.emit(event)
            return ScanVerdict(status=ScanStatus.BLOCK)
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

    if not scanners:
        # Enabled, but nothing is configured to inspect the content. Fail
        # closed: "we looked and found nothing" and "nothing looked" are not
        # the same answer, and returning ALLOW would make them indistinguishable
        # to the caller. An operator who does not want this content scanned
        # disables the boundary — which is the branch above, and says so in the
        # trail. Reaching here means the configuration asks for a scan it cannot
        # perform.
        event = AuditEvent.build(
            boundary=boundary,
            decision=Decision.BLOCKED,
            ctx=ctx,
            tenant_id=tenant_id,
            duration_ms=0,
            deny_reason=(
                "boundary is enabled but no scanner is configured to run — "
                "declare one under scanners:, or disable the boundary"
            ),
            audit_tags=audit_tags or {},
        )
        await emitter.emit(event)
        return ScanVerdict(status=ScanStatus.BLOCK)

    if normalization is not None and normalization.enabled:
        norm = canonicalize_config(text, normalization)
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
        *[_guarded_scan(c.scanner, views) for c in scanners],
        return_exceptions=True,
    )

    all_findings:   list[Finding] = []
    adapter_names:  list[str]     = []
    current_text                  = text   # accumulates redactions
    final_status                  = ScanStatus.ALLOW
    degraded                      = False  # at least one scanner failed in degrade mode
    # Track which findings came from each scanner for per-scanner action
    per_scanner_data: list[tuple[list[Finding], ScanResult | None, ScanAction, str | None]] = []

    for configured, result in zip(scanners, raw_results):
        scanner = configured.scanner
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
            error_type = type(result).__name__
            log.error(
                "scanner failed",
                extra={
                    "scanner": scanner.name,
                    "boundary": boundary,
                    "on_error": on_error,
                    "error_type": error_type,
                    # Bounded preview, not the exception message: a
                    # third-party scanner's exception text can echo the
                    # substring it choked on, but an operator reading this
                    # line still needs to know what was being scanned — a
                    # hash tells them nothing.
                    "text_preview": text[:80],
                    **ctx.to_log_fields(),
                },
            )
            # Emit structured system event for observability. Type only, not
            # the exception message — this event is signed and carries no
            # raw text on any path.
            await _emit_system_event(
                emitter, ctx, tenant_id, scanner.name,
                error_type, breaker.state,
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

        # ── Scanner succeeded ─────────────────────────────────────────────
        # No declared override → the boundary action governs this scanner.
        effective_action = (
            configured.action if configured.action is not None else config.action
        )
        redact_with      = configured.redact_with
        # Stamp the producing scanner's detection technique onto its findings.
        # Scanners declare method_family; they do not set it per finding — except
        # a composite (FileContentScanner), which forwards findings from a chain
        # of other scanners and stamps each with its real producer. Filling in
        # only what is unset keeps those intact; flattening them onto the
        # composite's own family collapsed a whole boundary to one family and
        # made cross-method promotion impossible there.
        family = getattr(scanner, "method_family", "unknown")
        findings = [
            f if f.method_family != "unknown"
            else f.model_copy(update={"method_family": family})
            for f in result.findings
        ]
        per_scanner_data.append((findings, result, effective_action, redact_with))
        all_findings.extend(findings)
        # Redaction is a content transform, so it applies whenever the scanner
        # produced one and the operator asked for it — independent of block_at.
        # (Block/alert actions still respect block_at; redaction does not.)
        #
        # It applies ONLY under action=redact. A scanner returning redacted_text
        # under block or alert is offering a transform the config did not ask
        # for: every caller follows the documented `verdict.redacted_text or
        # text` pattern, so propagating it silently enforces redaction on an
        # alert-configured scanner and mutates content the operator chose to
        # let through.
        if result.redacted_text is not None and effective_action == ScanAction.REDACT:
            current_text = _apply_redaction(
                current_text, result.findings, result, redact_with
            )

    # ── Promoted candidates: inject findings from human-promoted heuristic matches ──
    all_findings = _check_promoted_candidates(text, all_findings, state)

    # ── Ensemble: promote severity when 2+ scanners agree on a category ────
    from harness.boundaries.ensemble import promote_findings
    all_findings = promote_findings(all_findings)

    # ── Apply action per scanner ──────────────────────────────────────────
    for findings, result, action, redact_with in per_scanner_data:
        triggering = [f for f in findings if f.severity >= config.block_at]
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

    # A caller-supplied block floor — never overrides a block the scanners
    # themselves already produced, only raises ALLOW/WARN to BLOCK.
    forced = forced_block_reason is not None and final_status != ScanStatus.BLOCK
    if forced:
        final_status = ScanStatus.BLOCK

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
    if forced and forced_block_extra:
        extra.update(forced_block_extra)

    event = AuditEvent.build(
        boundary=boundary,
        decision=decision,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        adapters=adapter_names,
        finding_count=len(all_findings),
        max_severity=max_sev,
        deny_reason=forced_block_reason if forced else None,
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
        LSH_MATCH_THRESHOLD,
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
        if lsh_jaccard(current_lsh, stored_lsh) >= LSH_MATCH_THRESHOLD:
            injected.append(Finding(
                scanner="learned_candidate",
                category="heuristic_anomaly",
                severity=Severity.MEDIUM,
                detail=f"promoted candidate id={candidate['id']} hits={candidate['hit_count']}",
                # An LSH match over heuristic fingerprints — the same detection
                # technique as heuristic_scan, so the two do not corroborate.
                method_family="structural_heuristic",
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
        # Sub-scores come off the finding, not out of its prose. Every finding
        # the heuristic scanner emits carries the full set, so which one is
        # first no longer decides what gets recorded — picking [0] used to
        # yield all-zero scores whenever the compound-attack finding sorted
        # ahead of the anomaly one, i.e. on the strongest detections.
        signals = heuristic_findings[0].signals
        scores = {
            key: signals.get(key, 0.0)
            for key in ("entropy", "density", "coherence", "structural")
        }

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


async def run_tool_result_scan(
    result: str,
    ctx: AgentContext,
    *,
    scanners: list[ConfiguredScanner],
    config: ToolResultScanConfig,
    emitter: AuditEmitter,
    tenant_id: str,
    state: ScanState,
    normalization: NormalizationConfig | None = None,
    audit_tags: dict[str, str] | None = None,
) -> ScanVerdict:
    """Scan a tool return value. Delegates to run_scan with TOOL_RESULT_SCAN.

    Adjusts block_at down one severity level when TurnSignals shows the input
    scan flagged injection and the gate allowed a specific tool — the tool
    result now has elevated scrutiny because we know an attack chain is in
    progress.
    """
    effective_config = config
    signals = ctx.turn_signals
    if (signals is not None
            and signals.input_has_injection
            and signals.gate_tool_name is not None):
        effective_config = config.model_copy(
            update={"block_at": _one_lower(config.block_at)}
        )

    return await run_scan(
        result,
        ctx,
        boundary=BoundaryName.TOOL_RESULT_SCAN,
        scanners=scanners,
        config=effective_config,
        emitter=emitter,
        tenant_id=tenant_id,
        state=state,
        normalization=normalization,
        audit_tags=audit_tags,
    )


def _one_lower(sev: Severity) -> Severity:
    """Return the next-lower severity level, floored at LOW."""
    ladder = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    try:
        idx = ladder.index(sev)
    except ValueError:
        return sev
    return ladder[max(0, idx - 1)]
