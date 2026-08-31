"""PolicyEngine Protocol, PolicyDecision, and SourceDecision.

PolicyDecision is internal — agents see GateDecision on the facade.
SourceDecision is returned by evaluate_source() to control source activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol

if TYPE_CHECKING:
    from harness.agents.agent_config import RuleConfig
    from harness.core.context import AgentContext
    from harness.tools.source import ToolSource
    from harness.tools.tool import Tool


@dataclass(frozen=True)
class PolicyDecision:
    """Internal result from PolicyEngine.evaluate().

    check_tool_call translates this to GateDecision before returning to the agent.
    """
    action:        Literal["allow", "deny", "redact"]
    reason:        str | None = None        # required when action="deny"
    redacted_args: dict[str, Any] | None = None  # required when action="redact"
    rule_id:       str | None = None        # which rule fired — for audit

    def __post_init__(self) -> None:
        if self.action == "deny" and not self.reason:
            raise ValueError("reason required for deny PolicyDecision")
        if self.action == "redact" and self.redacted_args is None:
            raise ValueError("redacted_args required for redact PolicyDecision")


@dataclass(frozen=True)
class SourceDecision:
    """Result from PolicyEngine.evaluate_source()."""
    active: bool
    reason: str | None = None  # why suppressed; None when active=True


class PolicyEngine(Protocol):
    """Evaluate tool calls and source activation.

    evaluate() receives every rule governing the call as one ordered list;
    there is no second, engine-held pass. First match wins, default allow.

    All methods are async — production engines (OPA, Cedar) make network calls.
    Reference implementation (RuleBasedPolicy) returns immediately.
    """

    name: str

    async def evaluate(
        self,
        tool: Tool,
        args: dict[str, Any],
        ctx: AgentContext,
        *,
        rules: list[RuleConfig] | None = None,
    ) -> PolicyDecision:
        """Gate one tool call.

        rules: every rule governing this call, in the order it must be
        evaluated — manifest-compiled denials first, then AgentConfig
        .policy_rules (subagent before parent). The order is load-bearing:
        an implementation MUST walk the list in order and return on the first
        match. Reordering it lets an agent rule lift a hash-approved manifest
        denial. None means no rules apply; return allow.

        Raises PolicyEvaluationError ONLY on engine failure (bad bundle,
        network error). A normal deny is a PolicyDecision, not an exception.
        """
        ...

    async def evaluate_source(
        self,
        source: ToolSource,
        ctx: AgentContext,
    ) -> SourceDecision:
        """Decide whether a tool source is active for this agent/turn.

        Default: SourceDecision(active=True) — sources are active unless
        a rule suppresses them.
        """
        ...
