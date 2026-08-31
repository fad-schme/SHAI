"""RuleBasedPolicy — reference PolicyEngine backed by YAML-declared rules.

evaluate() takes the rules that govern one tool call as its `rules` kwarg —
manifest-compiled denials first, then the agent's own rules (subagent before
parent). First match wins; no match → PolicyDecision(action="allow"). There is
no second, global pass: per-tool-call policy belongs to the agent's own config
and, for an MCP source, to its manifest.

evaluate_source() uses the source-activation rules held on the instance, every
one of them action="suppress". Default: SourceDecision(active=True).

Rules are validated at construction. Not reloaded at runtime — restart to change.
"""
from __future__ import annotations

import logging
from typing import Any

from harness.agents.agent_config import RuleConfig, RuleMatchConfig
from harness.core.context import AgentContext
from harness.core.errors import PolicyEvaluationError
from harness.policy.engine import PolicyDecision, SourceDecision
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class RuleBasedPolicy:
    """Reference PolicyEngine — YAML rule evaluator."""

    name = "rules"

    def __init__(
        self,
        source_rules: list[RuleConfig] | None = None,
    ) -> None:
        """source_rules: pre-parsed `policy.source_rules` from harness.yaml.
        They govern source activation only and are never consulted by evaluate().
        """
        self._source_rules = list(source_rules) if source_rules else []

    # ── Public interface ──────────────────────────────────────────────────

    async def evaluate(
        self,
        tool: Tool,
        args: dict[str, Any],
        ctx: AgentContext,
        *,
        rules: list[RuleConfig] | None = None,
    ) -> PolicyDecision:
        """Evaluate the rules governing this call, in the order given.
        First match wins. Default allow on no match.
        """
        try:
            if rules:
                decision = self._evaluate_rules(rules, tool, args, ctx)
                if decision is not None:
                    return decision

            return PolicyDecision(action="allow")

        except Exception as e:
            # Boundary catch: convert any unexpected error into the domain-level
            # PolicyEvaluationError so callers get a stable exception type.
            # PolicyEvaluationError raised inside the try body passes through
            # unchanged.
            if isinstance(e, PolicyEvaluationError):
                raise
            raise PolicyEvaluationError(
                f"policy evaluation error: {e}",
                op="evaluate",
            ) from e

    async def evaluate_source(
        self,
        source: Any,  # ToolSource — avoid circular import
        ctx: AgentContext,
    ) -> SourceDecision:
        """Check source-activation rules. Default: active=True."""
        try:
            for rule in self._source_rules:
                if self._match_source(rule.match, source, ctx):
                    log.debug(
                        "source suppressed",
                        extra={
                            "source": source.name,
                            "rule_id": rule.id,
                            **ctx.to_log_fields(),
                        },
                    )
                    return SourceDecision(active=False, reason=rule.reason or rule.id)

            return SourceDecision(active=True)

        except Exception as e:
            if isinstance(e, PolicyEvaluationError):
                raise
            raise PolicyEvaluationError(
                f"source evaluation error: {e}",
                op="evaluate_source",
            ) from e

    # ── Private helpers ───────────────────────────────────────────────────

    def _evaluate_rules(
        self,
        rules: list[RuleConfig],
        tool: Tool,
        args: dict[str, Any],
        ctx: AgentContext,
    ) -> PolicyDecision | None:
        """Return first matching PolicyDecision, or None if no rule matches."""
        for rule in rules:
            if rule.action == "suppress":
                continue  # suppress is only for evaluate_source
            if self._match_tool(rule.match, tool, ctx):
                log.debug(
                    "policy rule matched",
                    extra={
                        "rule_id": rule.id,
                        "action": rule.action,
                        "tool": tool.name,
                        **ctx.to_log_fields(),
                    },
                )
                if rule.action == "allow":
                    return PolicyDecision(action="allow", rule_id=rule.id)
                if rule.action == "deny":
                    return PolicyDecision(
                        action="deny",
                        reason=rule.reason or f"denied by rule {rule.id!r}",
                        rule_id=rule.id,
                    )
                if rule.action == "redact":
                    # Merge, never replace. `redact:` names the arguments to
                    # mask; the rest of the call travels through untouched.
                    # Replacing the dict dropped every argument the rule did not
                    # name — frequently the ones that *constrain* the call — so a
                    # rule written to narrow a dispatch widened it instead. Layer
                    # 7's scanner redaction in check_tool_call merges for the same
                    # reason.
                    return PolicyDecision(
                        action="redact",
                        redacted_args={**args, **(rule.redact or {})},
                        rule_id=rule.id,
                    )
        return None

    def _match_tool(
        self, match: RuleMatchConfig, tool: Tool, ctx: AgentContext
    ) -> bool:
        """Return True if all declared match conditions are satisfied."""
        if match.tool_names and tool.name not in match.tool_names:
            return False
        if match.tool_tags and not set(match.tool_tags) & set(tool.tags):
            return False
        if match.transport and tool.transport not in match.transport:
            return False
        if match.agent_ids and ctx.agent_id not in match.agent_ids:
            return False
        if match.sub_agent_ids:
            if ctx.sub_agent_id not in match.sub_agent_ids:
                return False
        if match.any:
            sub_rules = [self._parse_inline_rule(r) for r in match.any]
            if not any(self._match_tool(r, tool, ctx) for r in sub_rules):
                return False
        if match.all:
            sub_rules = [self._parse_inline_rule(r) for r in match.all]
            if not all(self._match_tool(r, tool, ctx) for r in sub_rules):
                return False
        if match.not_ is not None:
            sub = self._parse_inline_rule(match.not_)
            if self._match_tool(sub, tool, ctx):
                return False
        return True

    def _match_source(
        self, match: RuleMatchConfig, source: Any, ctx: AgentContext
    ) -> bool:
        if match.source_tags and not set(match.source_tags) & set(source.tags):
            return False
        # transport is honoured here exactly as _match_tool honours it. Dropping
        # it turned a rule narrowed to one transport into one matching every
        # source — a narrowing rule that widens is the dangerous direction.
        if match.transport and source.transport not in match.transport:
            return False
        if match.agent_ids and ctx.agent_id not in match.agent_ids:
            return False
        if match.sub_agent_ids:
            if ctx.sub_agent_id not in match.sub_agent_ids:
                return False
        return True

    @staticmethod
    def _parse_inline_rule(data: Any) -> RuleMatchConfig:
        """Parse an inline match dict from any/all/not combinator."""
        if isinstance(data, dict):
            return RuleMatchConfig.model_validate(data)
        raise PolicyEvaluationError(
            f"invalid inline match expression: {data!r}",
            op="parse_rule",
        )
