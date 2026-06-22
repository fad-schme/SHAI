"""PolicyEngine Protocol, PolicyDecision, and SourceDecision.

PolicyDecision is internal — agents see GateDecision on the facade.
SourceDecision is returned by evaluate_source() to control source activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:
    from harness.agents.agent_config import RuleConfig
    from harness.adapters.tool_sources.base import ToolSource
    from harness.core.context import RuntimeContext
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


@runtime_checkable
class PolicyEngine(Protocol):
    """Evaluate tool calls and source activation.

    Intersection model for evaluate():
      - agent-scoped rules (passed as `rules`) evaluated first
      - then engine's own global rules
      - first deny anywhere wins; default allow on no match

    All methods are async — production engines (OPA, Cedar) make network calls.
    Reference implementation (RuleBasedPolicy) returns immediately.
    """

    name: str

    async def evaluate(
        self,
        tool: "Tool",
        args: dict[str, Any],
        ctx: "RuntimeContext",
        *,
        rules: list["RuleConfig"] | None = None,
    ) -> PolicyDecision:
        """Gate one tool call.

        rules: agent-scoped rules from AgentConfig.policy_rules, evaluated
        before the engine's own global rules. None means no agent rules.

        Raises PolicyEvaluationError ONLY on engine failure (bad bundle,
        network error). A normal deny is a PolicyDecision, not an exception.
        """
        ...

    async def evaluate_source(
        self,
        source: "ToolSource",
        ctx: "RuntimeContext",
    ) -> SourceDecision:
        """Decide whether a tool source is active for this agent/turn.

        Default: SourceDecision(active=True) — sources are active unless
        a rule suppresses them.
        """
        ...
