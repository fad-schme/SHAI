"""RuleBasedPolicy — reference PolicyEngine backed by YAML-declared rules.

Implements the intersection model:
  1. Agent-scoped rules (passed as `rules` kwarg) evaluated first, in order.
  2. Global rules (loaded at construction) evaluated next.
  3. First match in either pass wins and returns immediately.
  4. No match anywhere → PolicyDecision(action="allow") — default allow.

evaluate_source() uses source-activation rules (action="suppress").
Default: SourceDecision(active=True).

Rules are validated at construction. Not reloaded at runtime — restart to change.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from harness.agents.agent_config import RuleConfig, RuleMatchConfig
from harness.core.context import AgentContext
from harness.core.errors import ConfigError, PolicyEvaluationError
from harness.policy.engine import PolicyDecision, SourceDecision
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class RuleBasedPolicy:
    """Reference PolicyEngine — YAML rule evaluator."""

    name = "rules"

    def __init__(
        self,
        rules: list[RuleConfig] | None = None,
    ) -> None:
        """Rules passed as a pre-parsed list from harness.yaml inline policy config."""
        self._global_rules = list(rules) if rules else []

    # ── Public interface ──────────────────────────────────────────────────

    async def evaluate(
        self,
        tool: Tool,
        args: dict[str, Any],
        ctx: AgentContext,
        *,
        rules: list[RuleConfig] | None = None,
    ) -> PolicyDecision:
        """Intersection model: agent rules first, then global rules.
        First match wins. Default allow on no match.
        """
        try:
            # Pass 1: agent-scoped rules
            if rules:
                decision = self._evaluate_rules(rules, tool, ctx)
                if decision is not None:
                    return decision

            # Pass 2: global rules
            decision = self._evaluate_rules(self._global_rules, tool, ctx)
            if decision is not None:
                return decision

            return PolicyDecision(action="allow")

        except Exception as e:
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
            for rule in self._global_rules:
                if rule.action != "suppress":
                    continue
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
                    return PolicyDecision(
                        action="redact",
                        redacted_args=rule.redact or {},
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

    @staticmethod
    def _load(path: Path) -> list[RuleConfig]:
        """Load and validate rules from a YAML file."""
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise ConfigError(f"cannot read rules file {path}: {e}", op="load_rules") from e

        try:
            data = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise ConfigError(f"invalid YAML in {path}: {e}", op="load_rules") from e

        if not isinstance(data, list):
            raise ConfigError(
                f"rules file {path} must be a YAML list, got {type(data).__name__}",
                op="load_rules",
            )

        rules = []
        for i, item in enumerate(data):
            try:
                rules.append(RuleConfig.model_validate(item))
            except Exception as e:
                raise ConfigError(
                    f"invalid rule at index {i} in {path}: {e}",
                    op="load_rules",
                ) from e
        return rules
