"""check_tool_call — the mandatory tool-call gate.

Seven layers, strict order. Exactly one AuditEvent per call.
Never dispatches the tool — gates only.

Receives pre-resolved AgentConfig and tools dict from the Harness instance.
No registry lookups on the hot path.

Layer 1: tool.name in agent's allowed_tool_names?  (hard pre-policy gate)
Layer 2: argument rules — deterministic parameter constraints
Layer 3: irreversibility — blast-radius gate, requires human_approved
Layer 4: tool.tags ⊆ ctx.allowed_tags?             (subagent capability gate)
Layer 5: intersection policy (subagent ∩ parent ∩ global rules)
Layer 6: signal correlation — deny high-risk tools when input scan flagged
         injection; mark WARN+write-capable calls for tightened arg scanning
Layer 7: optional arg scanning (unconditional if layer 6 marked TIGHTEN)
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from harness.boundaries.argument_policy import check_argument_rules, check_irreversibility
from harness.core.errors import (
    ArgumentViolationError,
    IrreversibleActionError,
    PolicyEvaluationError,
)
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, ScanStatus, Severity
from harness.core.verdicts import GateDecision

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
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
    arg_scanners: list[Scanner],
    emitter: AuditEmitter,
    tenant_id: str,
    scan_args_for_tags: frozenset[str] = frozenset({"sensitive"}),
    correlate_tool_result: bool = False,
    turn_signals: TurnSignals | None = None,
    source_name: str = "local",
    issue_token: Callable[[], tuple[str, str]] | None = None,
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
        check_irreversibility(tool, ctx)
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
    # injection + high-risk tool) or marks the call for tightened arg scanning
    # (Pattern B: WARN + write-capable tool). No effect when signals absent.
    correlation = _check_signal_correlation(
        tool, turn_signals, correlate_tool_result)
    if isinstance(correlation, GateDecision):
        # Pattern A/C denial — emit and return
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
    if should_scan_args:
        arg_text = "\n".join(f"{k}: {v}" for k, v in effective_args.items())
        scan_results = await asyncio.gather(
            *[scanner.scan(arg_text, ctx) for scanner in arg_scanners],
            return_exceptions=True,
        )
        for scanner, result in zip(arg_scanners, scan_results):
            if isinstance(result, Exception):
                log.warning("arg scanner failed — skipped",
                            extra={"scanner": scanner.name, "tool": name,
                                   **ctx.to_log_fields()})
                continue
            blocking = [f for f in result.findings if f.severity >= Severity.HIGH]
            if blocking:
                return await emit_deny(
                    f"arg scan blocked: {blocking[0].category}",
                    name, tool, ctx, emitter, start, tenant_id,
                    audit_tags=agent_config.audit_tags,
                )

    # ── Allow ──────────────────────────────────────────────────────────────
    # The token is minted here, before the event is built, so token_id lands on
    # the gate event that authorised it. Issuing it afterwards — in the caller —
    # left AuditEvent.token_id permanently null and the documented SIEM join
    # with only a right-hand side. issue_token is called only on this path, so
    # a denied call still mints nothing.
    token: tuple[str, str] | None = issue_token() if issue_token is not None else None

    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.REDACT if policy_decision.action == "redact" else Decision.ALLOW,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        tool_name=name,
        transport=tool.transport,
        token_id=token[1] if token is not None else None,
        adapters=[policy.name],
        audit_tags=agent_config.audit_tags,
    )
    await emitter.emit(event)
    return GateDecision(
        allowed=True,
        redacted_args=effective_args if policy_decision.action == "redact" else None,
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
    signals: TurnSignals | None,
    correlate_tool_result: bool = False,
) -> GateDecision | object | None:
    """Layer 6: correlate proposed tool call against earlier boundary signals.

    Returns:
      GateDecision(allowed=False, ...) — Pattern A/C deny
      _TIGHTEN_MARKER                  — Pattern B tighten: WARN input + write-capable tool
      None                             — no signals or nothing to correlate

    Patterns A and B read input-side signals; C reads result-side. They are
    guarded independently — an integration that never calls scan_input still
    gets C, and one whose tool results are clean still gets A and B.
    """
    if signals is None:
        return None

    tool_tags = set(tool.tags)

    if signals.input_verdict is not None:
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

        # Pattern B: input WARN + write-capable tool → tighten scrutiny
        if signals.input_verdict == ScanStatus.WARN and "read" not in tool_tags:
            return _TIGHTEN_MARKER

    # Pattern C: an earlier tool result in this turn produced findings the
    # scan boundary did not block on, and the agent now wants to act.
    #
    # Indirect injection whose payload carries no blocking-severity signal
    # still tends to leave a trace — a heuristic anomaly, an off-threshold
    # category. On its own that trace is far too weak to block a tool result;
    # paired with a write-capable call it did not precede by accident, it is
    # the same corroboration Pattern A applies to the input side.
    #
    # Write-capable rather than _HIGH_RISK_TAGS: a read-only tool cannot
    # complete an injection's objective, and the tag vocabulary for "this
    # writes somewhere" is deployment-specific, whereas `read` is the one tag
    # Pattern B already relies on meaning what it says.
    if correlate_tool_result and signals.tool_result_categories:
        if "read" not in tool_tags:
            return GateDecision(
                allowed=False,
                deny_reason=(
                    "correlated with tool-result scan signal — write-capable "
                    "tool call follows a tool result with findings"
                ),
            )

    return None
