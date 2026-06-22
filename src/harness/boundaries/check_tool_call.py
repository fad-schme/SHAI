"""check_tool_call — the mandatory tool-call gate.

Four layers, strict order. Exactly one AuditEvent per call.
Never dispatches the tool — gates only.

Receives pre-resolved AgentConfig and tools dict from the Harness instance.
No registry lookups on the hot path.

Layer 1: tool.name in agent's allowed_tool_names?  (hard pre-policy gate)
Layer 2: tool.tags ⊆ ctx.allowed_tags?             (subagent capability gate)
Layer 3: intersection policy (subagent ∩ parent ∩ global rules)
Layer 4: optional arg scanning for tools tagged "sensitive"
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from harness.core.errors import PolicyEvaluationError
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, Severity
from harness.core.verdicts import GateDecision

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
    from harness.agents.agent_config import AgentConfig, SubAgentConfig
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import AgentContext
    from harness.policy.engine import PolicyEngine
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)


async def run(
    name: str,
    args: dict[str, Any],
    ctx: "AgentContext",
    *,
    agent_config: "AgentConfig",
    tools: dict[str, "Tool"],
    policy: "PolicyEngine",
    arg_scanners: list["Scanner"],
    emitter: "AuditEmitter",
    tenant_id: str,
    scan_args_for_tags: frozenset[str] = frozenset({"sensitive"}),
) -> GateDecision:
    """Gate one tool call.

    agent_config: pre-resolved AgentConfig from the harness (not looked up here).
    tools:        pre-resolved {name: Tool} for this agent (not looked up here).
    """
    start = now_ms()

    # Resolve effective profile — parent or subagent
    if ctx.sub_agent_id is not None:
        try:
            effective: "AgentConfig | SubAgentConfig" = agent_config.get_sub_agent(ctx.sub_agent_id)
        except Exception as e:
            return await _deny(str(e), name, None, ctx, emitter, start, tenant_id,
                               audit_tags=agent_config.audit_tags)
    else:
        effective = agent_config

    # ── Layer 1: allowed_tool_names hard gate ─────────────────────────────
    if name not in effective.allowed_tool_names:
        return await _deny(
            f"tool '{name}' not in agent allowed_tool_names",
            name, None, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    # ── Tool lookup (from pre-resolved dict — no registry call) ──────────
    tool = tools.get(name)
    if tool is None:
        return await _deny(
            f"tool '{name}' not registered",
            name, None, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    # ── Layer 2: allowed_tags subagent capability gate ────────────────────
    if ctx.allowed_tags is not None:
        extra_tags = set(tool.tags) - set(ctx.allowed_tags)
        if extra_tags:
            return await _deny(
                f"tool '{name}' requires tags {sorted(extra_tags)} "
                f"not in subagent capability set",
                name, tool, ctx, emitter, start, tenant_id,
                audit_tags=agent_config.audit_tags,
            )

    # ── Layer 3: intersection policy ──────────────────────────────────────
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
        return await _deny(
            f"policy evaluation failed: {e}",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    if policy_decision.action == "deny":
        return await _deny(
            policy_decision.reason or f"denied by rule '{policy_decision.rule_id}'",
            name, tool, ctx, emitter, start, tenant_id,
            audit_tags=agent_config.audit_tags,
        )

    effective_args = (
        policy_decision.redacted_args
        if policy_decision.action == "redact" and policy_decision.redacted_args is not None
        else args
    )

    # ── Layer 4: optional arg scanning ───────────────────────────────────
    if arg_scanners and scan_args_for_tags & set(tool.tags):
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
                return await _deny(
                    f"arg scan blocked: {blocking[0].category}",
                    name, tool, ctx, emitter, start, tenant_id,
                    audit_tags=agent_config.audit_tags,
                )

    # ── Allow ──────────────────────────────────────────────────────────────
    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.REDACT if policy_decision.action == "redact" else Decision.ALLOW,
        ctx=ctx,
        tenant_id=tenant_id,
        duration_ms=now_ms() - start,
        tool_name=name,
        transport=tool.transport,
        adapters=[policy.name],
        audit_tags=agent_config.audit_tags,
    )
    await emitter.emit(event)
    return GateDecision(
        allowed=True,
        redacted_args=effective_args if policy_decision.action == "redact" else None,
    )


async def _deny(
    reason: str,
    tool_name: str,
    tool: "Tool | None",
    ctx: "AgentContext",
    emitter: "AuditEmitter",
    start: int,
    tenant_id: str,
    *,
    audit_tags: dict[str, str] | None = None,
) -> GateDecision:
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
