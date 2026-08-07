"""check_tool_call — the mandatory tool-call gate.

Seven layers, strict order. Exactly one AuditEvent per call.
Never dispatches the tool — gates only.

Receives pre-resolved AgentConfig and tools dict from the Harness instance.
No registry lookups on the hot path.

Layer 1: tool.name in agent's allowed_tool_names?  (hard pre-policy gate)
Layer 2: argument rules — deterministic parameter constraints
Layer 3: irreversibility — blast-radius gate, requires signed approval grants
Layer 4: tool.tags ⊆ ctx.allowed_tags?             (subagent capability gate)
Layer 5: intersection policy (subagent ∩ parent ∩ global rules)
Layer 6: signal correlation — deny high-risk tools when input scan flagged
         injection (A) or when a user_origin argument carries a value ingested
         from a tool result (C); mark WARN+write-capable calls for tightened
         arg scanning (B)
Layer 7: optional arg scanning (unconditional if layer 6 marked TIGHTEN)
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from harness.boundaries.argument_policy import check_argument_rules, check_irreversibility
from harness.core.approval import ApprovalPolicy
from harness.core.errors import (
    ArgumentViolationError,
    IrreversibleActionError,
    PolicyEvaluationError,
)
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, ScanAction, ScanStatus, Severity
from harness.core.verdicts import GateDecision

if TYPE_CHECKING:
    from harness.adapters.scanners.base import ConfiguredScanner
    from harness.agents.agent_config import AgentConfig, SubAgentConfig
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import AgentContext
    from harness.core.turn_signals import TurnSignals
    from harness.policy.engine import PolicyEngine
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)

# Sentinel returned by _check_signal_correlation when the input scan warned
# and the target tool is write-capable. Causes layer 7 to run arg scanning
# unconditionally, regardless of the tool's `sensitive` tag.
_TIGHTEN_MARKER = object()

_HIGH_RISK_TAGS = frozenset({"destructive", "financial", "external"})


async def run(
    name: str,
    args: dict[str, Any],
    ctx: AgentContext,
    *,
    agent_config: AgentConfig,
    tools: dict[str, Tool],
    policy: PolicyEngine,
    arg_scanners: list[ConfiguredScanner],
    emitter: AuditEmitter,
    tenant_id: str,
    scan_args_for_tags: frozenset[str] = frozenset({"sensitive"}),
    turn_signals: TurnSignals | None = None,
    source_name: str = "local",
    issue_token: Callable[[], tuple[str, str]] | None = None,
    approvals: ApprovalPolicy | None = None,
) -> GateDecision:
    """Gate one tool call.

    agent_config: pre-resolved AgentConfig from the harness (not looked up here).
    tools:        pre-resolved {name: Tool} for this agent (not looked up here).
    turn_signals: cross-boundary signal bus. When present, layer 6 correlates
                  earlier boundary findings against the proposed tool call.
    source_name:  which source owns the tool; stamped on the returned decision.
    issue_token:  mints a dispatch token, returning (encoded, token_id). Called
                  only when the gate allows, and before the audit event is built
                  so token_id joins the event to the NetworkAuditEvent the
                  dispatch produces. None when connectivity is disabled.
    approvals:    resolved approval policy for layer 3. None means unconfigured,
                  which denies every SENSITIVE and IRREVERSIBLE tool — there is
                  no weaker check to fall back to.
    """
    start = now_ms()

    # Resolve effective profile — parent or subagent
    if ctx.sub_agent_id is not None:
        try:
            effective: AgentConfig | SubAgentConfig = agent_config.get_sub_agent(ctx.sub_agent_id)
        except Exception as e:
            return await emit_deny(str(e), name, None, ctx, emitter, start, tenant_id,
                               audit_tags=agent_config.audit_tags)
    else:
        effective = agent_config

    # ── Layer 1: allowed_tool_names hard gate ─────────────────────────────
    if name not in effective.allowed_tool_names:
        return await emit_deny(
            f"tool '{name}' not in agent allowed_tool_names",
            name, None, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    # ── Tool lookup (from pre-resolved dict — no registry call) ──────────
    tool = tools.get(name)
    if tool is None:
        return await emit_deny(
            f"tool '{name}' not registered",
            name, None, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    # ── Layer 2: argument rules ───────────────────────────────────────────
    try:
        check_argument_rules(tool, args, ctx)
    except ArgumentViolationError as e:
        return await emit_deny(str(e), name, tool, ctx, emitter, start, tenant_id,
                           audit_tags=agent_config.audit_tags)

    # ── Layer 3: irreversibility gate ─────────────────────────────────────
    try:
        approvers = check_irreversibility(
            tool, ctx,
            args=args,
            tenant_id=tenant_id,
            approvals=approvals or ApprovalPolicy(),
        )
    except IrreversibleActionError as e:
        return await emit_deny(str(e), name, tool, ctx, emitter, start, tenant_id,
                           audit_tags=agent_config.audit_tags)

    # ── Layer 4: allowed_tags capability gate ─────────────────────────────
    # Applies to parents and subagents alike. The effective profile's declared
    # allowed_tags always binds — a parent that declares `allowed_tags: [read]`
    # is gated by it, not just its children. ctx.allowed_tags narrows further
    # when a subagent context carries one.
    #
    # Intersected rather than "ctx wins": AgentContext is caller-constructible,
    # so preferring it would let a hand-built context widen its own capability
    # set, while preferring the config alone would ignore a deliberately
    # narrowed one. Neither side can widen the other.
    capability_tags = set(effective.allowed_tags)
    if ctx.allowed_tags is not None:
        capability_tags &= set(ctx.allowed_tags)
    extra_tags = set(tool.tags) - capability_tags
    if extra_tags:
        scope = "subagent" if ctx.sub_agent_id is not None else "agent"
        return await emit_deny(
            f"tool '{name}' requires tags {sorted(extra_tags)} "
            f"not in {scope} capability set",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    # ── Layer 5: intersection policy ──────────────────────────────────────
    combined_rules = list(effective.policy_rules)
    if ctx.sub_agent_id is not None:
        combined_rules = list(effective.policy_rules) + list(agent_config.policy_rules)

    try:
        policy_decision = await policy.evaluate(
            tool, args, ctx,
            rules=combined_rules if combined_rules else None,
        )
    except PolicyEvaluationError as e:
        log.error("policy evaluation error",
                  extra={"tool": name, "error": str(e), **ctx.to_log_fields()})
        return await emit_deny(
            f"policy evaluation failed: {e}",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    if policy_decision.action == "deny":
        return await emit_deny(
            policy_decision.reason or f"denied by rule '{policy_decision.rule_id}'",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    effective_args = (
        policy_decision.redacted_args
        if policy_decision.action == "redact" and policy_decision.redacted_args is not None
        else args
    )

    # ── Layer 6: signal correlation ──────────────────────────────────────
    # Reads TurnSignals recorded by earlier boundaries. Either denies (Pattern A:
    # injection + high-risk tool; Pattern C: a user_origin argument carrying an
    # ingested value) or marks the call for tightened arg scanning (Pattern B:
    # WARN + write-capable tool). No effect when signals absent.
    #
    # Runs on effective_args — layer 5 may have redacted them, and the gate must
    # correlate against what would actually be dispatched.
    correlation = _check_signal_correlation(tool, effective_args, turn_signals)
    if isinstance(correlation, GateDecision):
        # Pattern A denial — emit and return
        return await emit_deny(
            correlation.deny_reason or "signal correlation denial",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )
    tighten_arg_scan = correlation is _TIGHTEN_MARKER

    # ── Layer 7: optional arg scanning ───────────────────────────────────
    # Runs when tool has a scan_args_for_tags tag OR when layer 6 tightened.
    should_scan_args = bool(arg_scanners) and (
        bool(scan_args_for_tags & set(tool.tags)) or tighten_arg_scan
    )
    scanned_redactions: dict[str, Any] = {}
    if should_scan_args:
        # One scan per argument rather than one over the joined block, because a
        # redaction has to land back on the argument that produced it and the
        # joined form cannot say which key a replacement belongs to.
        #
        # Each scan still carries the `key: value` framing. The key is load
        # bearing, not decoration: regex_pii matches `api_key: sk-live-…` and
        # finds nothing in `sk-live-…` alone, so scanning bare values would
        # quietly stop detecting credentials here.
        #
        # The cost is that a payload split across two arguments no longer
        # corroborates — the joined form could match across them, this cannot.
        scan_targets = [
            (configured, key, f"{key}: {value}")
            for configured in arg_scanners
            for key, value in effective_args.items()
            if value is not None
        ]
        scan_results = await asyncio.gather(
            *[configured.scanner.scan(text, ctx) for configured, _, text in scan_targets],
            return_exceptions=True,
        )
        for (configured, key, _text), result in zip(scan_targets, scan_results, strict=True):
            scanner = configured.scanner
            if isinstance(result, Exception):
                log.warning("arg scanner failed — skipped",
                            extra={"scanner": scanner.name, "tool": name,
                                   **ctx.to_log_fields()})
                continue
            blocking = [f for f in result.findings if f.severity >= Severity.HIGH]
            if not blocking:
                continue

            # Layer 7 has no boundary action of its own, so an undeclared
            # scanner blocks — the historical behaviour and the safe default.
            action = configured.action if configured.action is not None else ScanAction.BLOCK

            # REDACT with nothing to substitute falls back to BLOCK, matching
            # ScanAction's documented contract. The `key: ` framing added for
            # detection comes back off the redacted form — the argument value is
            # what gets substituted, not the line the scanner saw.
            if action == ScanAction.REDACT and result.redacted_text is not None:
                prefix = f"{key}: "
                redacted_value = result.redacted_text
                if redacted_value.startswith(prefix):
                    redacted_value = redacted_value[len(prefix):]
                scanned_redactions[key] = redacted_value
                continue
            if action == ScanAction.ALERT:
                continue

            return await emit_deny(
                f"arg scan blocked: {blocking[0].category}",
                name, tool, ctx, emitter, start, tenant_id,
                audit_tags=agent_config.audit_tags,
            )

    if scanned_redactions:
        effective_args = {**effective_args, **scanned_redactions}

    # ── Allow ──────────────────────────────────────────────────────────────
    # The token is minted here, before the event is built, so token_id lands on
    # the gate event that authorised it. Issuing it afterwards — in the caller —
    # left AuditEvent.token_id permanently null and the documented SIEM join
    # with only a right-hand side. issue_token is called only on this path, so
    # a denied call still mints nothing.
    token: tuple[str, str] | None = issue_token() if issue_token is not None else None

    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=(
            Decision.REDACT
            if policy_decision.action == "redact" or scanned_redactions
            else Decision.ALLOW
        ),
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        tool_name=name,
        transport=tool.transport,
        token_id=token[1] if token is not None else None,
        adapters=[policy.name],
        audit_tags=agent_config.audit_tags,
        # Who authorised a SENSITIVE/IRREVERSIBLE call. Identifiers only — the
        # audit trail must be able to answer "who approved this" without ever
        # carrying the approval prompt or the arguments it covered.
        extra={"approvers": approvers} if approvers else None,
    )
    await emitter.emit(event)
    return GateDecision(
        allowed=True,
        redacted_args=(
            effective_args
            if policy_decision.action == "redact" or scanned_redactions
            else None
        ),
        dispatch_token=token[0] if token is not None else None,
        source_name=source_name,
    )


async def emit_deny(
    reason: str,
    tool_name: str,
    tool: Tool | None,
    ctx: AgentContext,
    emitter: AuditEmitter,
    start: int,
    tenant_id: str,
    *,
    audit_tags: dict[str, str] | None = None,
) -> GateDecision:
    """Emit the gate's deny event and return the decision.

    The one place a tool_call_gate deny is written. The facade's pre-gate
    refusals (rate limit, session budget, unregistered agent) call it too, so
    every deny at this boundary produces the same event shape.
    """
    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.DENY,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        tool_name=tool_name,
        transport=str(tool.transport) if tool else None,
        deny_reason=reason,
        audit_tags=audit_tags or {},
    )
    await emitter.emit(event)
    return GateDecision(allowed=False, deny_reason=reason)


def _check_signal_correlation(
    tool: Tool,
    args: dict[str, Any],
    signals: TurnSignals | None,
) -> GateDecision | object | None:
    """Layer 6: correlate proposed tool call against earlier boundary signals.

    Returns:
      GateDecision(allowed=False, ...) — deny (Pattern A or C)
      _TIGHTEN_MARKER                  — Pattern B tighten: WARN input + write-capable tool
      None                             — no signals or nothing to correlate

    Every deny is evaluated before the tighten. Pattern B returning early would
    let a WARN input downgrade a Pattern C deny to a scan, so more evidence
    would produce the weaker outcome.
    """
    if signals is None:
        return None

    tool_tags = set(tool.tags)

    # Pattern A: injection input + high-risk tool → deny
    if signals.input_has_injection:
        risky_overlap = tool_tags & _HIGH_RISK_TAGS
        if risky_overlap:
            return GateDecision(
                allowed=False,
                deny_reason=(
                    f"correlated with input injection signal — "
                    f"tool has high-risk tag(s): {sorted(risky_overlap)}"
                ),
            )

    # Pattern C: an argument the tool declares user_origin carries a value that
    # entered this turn through a tool result and not through the user's prompt.
    #
    # Independent of every finding: a base-setting indirect injection is a plain
    # imperative sentence that no catalog matches and that reads as legitimate
    # in isolation, so gating on what the scanners said reproduces their
    # blindness one layer down. What the attacker cannot avoid is supplying the
    # *value* — the payload is only worth writing if it redirects the call
    # somewhere the user never named.
    #
    # Denies. The known cost is entity resolution — the user names a person, the
    # agent reads a contact list, and the address it sends to was spelled out
    # only by the tool result. Provenance cannot tell that from an injected
    # destination, and the operator resolves it by declaring user_origin on the
    # arguments where it holds, not by the gate deferring the decision. SHAI is
    # a filter with no human in it; a boundary that answers "ask someone" has
    # not decided anything.
    for rule in tool.argument_rules:
        if not rule.user_origin:
            continue
        value = args.get(rule.arg)
        if value is None or not signals.arg_is_ingested(str(value)):
            continue
        return GateDecision(
            allowed=False,
            deny_reason=(
                f"argument '{rule.arg}' is declared user_origin but its "
                f"value entered this turn through a tool result"
            ),
        )

    # Pattern B: input WARN + write-capable tool → tighten scrutiny
    if signals.input_verdict == ScanStatus.WARN and "read" not in tool_tags:
        return _TIGHTEN_MARKER

    return None
