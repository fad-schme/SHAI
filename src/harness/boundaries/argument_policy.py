"""argument_policy — deterministic argument-level gate.

Two checks called by check_tool_call after tool lookup, before Layer 2.

  1. check_argument_rules  — evaluates ArgumentRule declarations on the tool.
                             First violation raises ArgumentViolationError.

  2. check_irreversibility — enforces the tool's blast-radius classification
                             against signed approval grants. Returns the
                             approvers, or raises IrreversibleActionError.

Both are pure deterministic code. No LLM, no scoring, no probability.
check_tool_call catches both errors and converts them to _deny().
"""
from __future__ import annotations

import logging
from typing import Any

from harness.core.approval import ApprovalError, ApprovalPolicy, verify_grants
from harness.core.context import AgentContext
from harness.core.errors import ArgumentViolationError, IrreversibleActionError
from harness.core.types import Irreversibility
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


def check_argument_rules(
    tool: Tool,
    args: dict[str, Any],
    ctx: AgentContext,
) -> None:
    """Evaluate all ArgumentRules on the tool. No-op when tool has none.

    Raises ArgumentViolationError on the first violation.
    """
    for rule in tool.argument_rules:
        violation = rule.evaluate(args)
        if violation:
            log.warning(
                "argument rule violation",
                extra={
                    "op": "argument_rule",
                    "tool_name": tool.name,
                    "violation": violation,
                    **ctx.to_log_fields(),
                },
            )
            raise ArgumentViolationError(
                f"argument rule violation on '{tool.name}': {violation}",
                agent_id=ctx.agent_id,
                op="argument_rule",
            )


def check_irreversibility(
    tool: Tool,
    ctx: AgentContext,
    *,
    args: dict[str, Any],
    tenant_id: str,
    approvals: ApprovalPolicy,
) -> list[str]:
    """Enforce the tool's irreversibility classification.

    REVERSIBLE   — always passes, with no approvers.
    SENSITIVE    — requires `approvals.sensitive_quorum` distinct approvers.
    IRREVERSIBLE — requires `approvals.irreversible_quorum` distinct approvers.

    Returns the distinct approver ids the gate should record on the audit event;
    empty for REVERSIBLE. Raises IrreversibleActionError when blocked.

    Grants are verified against the arguments passed here — the pre-redaction
    ones the caller proposed, which are also what the approver saw. Layer 5 may
    redact afterwards; that narrows the call and cannot invalidate consent.
    """
    tier = tool.irreversibility

    if tier == Irreversibility.REVERSIBLE:
        return []

    quorum = (
        approvals.irreversible_quorum
        if tier == Irreversibility.IRREVERSIBLE
        else approvals.sensitive_quorum
    )

    def _block(reason: str) -> IrreversibleActionError:
        log.warning(
            "irreversible action blocked",
            extra={
                "op": "irreversibility_gate",
                "tool_name": tool.name,
                "irreversibility": tier.value,
                "quorum_required": quorum,
                **ctx.to_log_fields(),
            },
        )
        return IrreversibleActionError(
            f"tool '{tool.name}' is {tier.value}: {reason}",
            agent_id=ctx.agent_id,
            op="irreversibility_gate",
        )

    if approvals.secret is None:
        # No fallback by design. Approvals unconfigured is not "approval not
        # required" — it is a deployment that cannot verify one, and the tool is
        # classified as needing verification.
        raise _block(
            "approval grants are not configured "
            "(set check_tool_call.approvals.secret)"
        )

    try:
        approvers = verify_grants(
            ctx.approvals,
            secret=approvals.secret,
            agent_id=ctx.agent_id,
            tenant_id=tenant_id,
            tool_name=tool.name,
            args=args,
            quorum=quorum,
        )
    except ApprovalError as e:
        raise _block(str(e)) from e
    except Exception as e:
        # Anything else — an argument whose repr raises inside the digest, a
        # malformed grant shape no validator caught — is an approval that could
        # not be established. Fail closed rather than let it escape the gate:
        # boundaries never raise (Invariant 2), and an unverified approval is a
        # denial by definition.
        log.error("approval verification error",
                  extra={"op": "irreversibility_gate", "tool_name": tool.name,
                         "error": type(e).__name__, **ctx.to_log_fields()},
                  exc_info=True)
        raise _block("approval verification failed") from e

    log.info(
        "irreversible action approved",
        extra={
            "op": "irreversibility_gate",
            "tool_name": tool.name,
            "irreversibility": tier.value,
            "approver_count": len(approvers),
            **ctx.to_log_fields(),
        },
    )
    return approvers
