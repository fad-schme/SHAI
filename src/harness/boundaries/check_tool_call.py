"""check_tool_call — the mandatory tool-call gate.

Four layers, strict order. Exactly one AuditEvent per call.
Never dispatches the tool — gates only.

Layer 1a: agent/subagent registered?
Layer 1b: tool.name in agent's allowed_tool_names?  (hard pre-policy gate)
Layer 1c: tool.tags ⊆ ctx.allowed_tags?             (capability gate)
Layer 2:  intersection policy (subagent ∩ parent ∩ global rules)
Layer 3:  optional arg scanning for tools tagged "sensitive"
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from harness.core.errors import (
    AgentNotRegisteredError,
    PolicyEvaluationError,
    SubAgentNotDeclaredError,
    ToolNotRegisteredError,
)
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, Severity
from harness.core.verdicts import GateDecision

if TYPE_CHECKING:
    from harness.adapters.scanners.base import Scanner
    from harness.adapters.tool_registry.memory import InMemoryRegistryView
    from harness.agents.agent_config import AgentConfig, SubAgentConfig
    from harness.agents.registry import AgentRegistry
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import RuntimeContext
    from harness.policy.engine import PolicyEngine
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)


async def run(
    name: str,
    args: dict[str, Any],
    ctx: "RuntimeContext",
    *,
    agent_registry: "AgentRegistry",
    registry_view: "InMemoryRegistryView",
    policy: "PolicyEngine",
    arg_scanners: list["Scanner"],
    emitter: "AuditEmitter",
    scan_args_for_tags: frozenset[str] = frozenset({"sensitive"}),
) -> GateDecision:
    """Gate one tool call. Returns GateDecision. Never raises (emits deny on error)."""
    start = now_ms()

    # ── Layer 1a: agent/subagent registered ──────────────────────────────
    try:
        agent_config = agent_registry.get(ctx.agent_id)
    except AgentNotRegisteredError:
        return await _deny(
            f"agent '{ctx.agent_id}' not registered",
            name, None, ctx, emitter, start,
        )

    # Resolve effective profile (parent or subagent)
    if ctx.sub_agent_id is not None:
        try:
            effective = agent_config.get_sub_agent(ctx.sub_agent_id)
        except SubAgentNotDeclaredError:
            return await _deny(
                f"sub_agent '{ctx.sub_agent_id}' not declared under '{ctx.agent_id}'",
                name, None, ctx, emitter, start,
            )
    else:
        effective = agent_config

    # ── Layer 1b: allowed_tool_names hard gate ────────────────────────────
    if name not in effective.allowed_tool_names:
        return await _deny(
            f"tool '{name}' not in agent allowed_tool_names",
            name, None, ctx, emitter, start,
            audit_tags=agent_config.audit_tags,
        )

    # ── Tool lookup ───────────────────────────────────────────────────────
    try:
        tool = await registry_view.get(name)
    except ToolNotRegisteredError:
        return await _deny(
            f"tool '{name}' not found in registry",
            name, None, ctx, emitter, start,
            audit_tags=agent_config.audit_tags,
        )

    # ── Layer 1c: allowed_tags capability gate ────────────────────────────
    if ctx.allowed_tags is not None:
        extra_tags = set(tool.tags) - set(ctx.allowed_tags)
        if extra_tags:
            return await _deny(
                f"tool '{name}' requires tags {sorted(extra_tags)} "
                f"not in agent capability set",
                name, tool, ctx, emitter, start,
                audit_tags=agent_config.audit_tags,
            )

    # ── Layer 2: intersection policy ─────────────────────────────────────
    # Combine subagent rules + parent rules; global rules evaluated inside engine
    combined_rules = list(effective.policy_rules)
    if ctx.sub_agent_id is not None:
        combined_rules = list(effective.policy_rules) + list(agent_config.policy_rules)

    try:
        policy_decision = await policy.evaluate(
            tool, args, ctx, rules=combined_rules if combined_rules else None
        )
    except PolicyEvaluationError as e:
        log.error(
            "policy evaluation error",
            extra={"tool": name, "error": str(e), **ctx.to_log_fields()},
        )
        return await _deny(
            f"policy evaluation failed: {e}",
            name, tool, ctx, emitter, start,
            audit_tags=agent_config.audit_tags,
        )

    if policy_decision.action == "deny":
        return await _deny(
            policy_decision.reason or f"denied by rule '{policy_decision.rule_id}'",
            name, tool, ctx, emitter, start,
            audit_tags=agent_config.audit_tags,
        )

    # Determine effective args after potential redaction
    effective_args = (
        policy_decision.redacted_args
        if policy_decision.action == "redact" and policy_decision.redacted_args is not None
        else args
    )

    # ── Layer 3: optional arg scanning ───────────────────────────────────
    if arg_scanners and scan_args_for_tags & set(tool.tags):
        arg_text = _args_to_text(effective_args)
        scan_results = await asyncio.gather(
            *[scanner.scan(arg_text, ctx) for scanner in arg_scanners],
            return_exceptions=True,
        )
        for scanner, result in zip(arg_scanners, scan_results):
            if isinstance(result, Exception):
                log.warning(
                    "arg scanner failed — skipped",
                    extra={"scanner": scanner.name, "tool": name, **ctx.to_log_fields()},
                )
                continue
            blocking = [f for f in result.findings if f.severity >= Severity.HIGH]
            if blocking:
                return await _deny(
                    f"arg scan blocked: {blocking[0].category}",
                    name, tool, ctx, emitter, start,
                    audit_tags=agent_config.audit_tags,
                )

    # ── Allow ─────────────────────────────────────────────────────────────
    duration = now_ms() - start
    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.REDACT if policy_decision.action == "redact" else Decision.ALLOW,
        ctx=ctx,
        duration_ms=duration,
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


# ── Helpers ───────────────────────────────────────────────────────────────

async def _deny(
    reason: str,
    tool_name: str,
    tool: "Tool | None",
    ctx: "RuntimeContext",
    emitter: "AuditEmitter",
    start: int,
    *,
    audit_tags: dict[str, str] | None = None,
) -> GateDecision:
    duration = now_ms() - start
    event = AuditEvent.build(
        boundary=BoundaryName.TOOL_CALL_GATE,
        decision=Decision.DENY,
        ctx=ctx,
        duration_ms=duration,
        tool_name=tool_name,
        transport=str(tool.transport) if tool else None,
        deny_reason=reason,
        audit_tags=audit_tags or {},
    )
    await emitter.emit(event)
    return GateDecision(allowed=False, deny_reason=reason)


def _args_to_text(args: dict[str, Any]) -> str:
    """Flatten args dict to a single string for scanner input."""
    parts = []
    for k, v in args.items():
        parts.append(f"{k}: {v}")
    return "\n".join(parts)
