"""SkillSource — activates a named group of tools on demand.

Progressive disclosure: the agent's source list declares which skill groups
it needs; only those tools are surfaced to the LLM for this turn.

Tools in the group are resolved from the shared registry at construction time.
ConfigError if any declared tool name is not registered.
"""
from __future__ import annotations

import logging

from harness.adapters.tool_registry.memory import InMemoryRegistry
from harness.core.context import RuntimeContext
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class SkillSource:
    """Reference ToolSource — named group of tools from the shared registry."""

    transport = Transport.SKILL

    def __init__(
        self,
        skill_name: str,
        tool_names: list[str],
        registry: InMemoryRegistry,
        tags: list[str] | None = None,
    ) -> None:
        """
        Args:
            skill_name:  identifier used in agent-xx.yaml sources list.
            tool_names:  list of tool names that belong to this skill group.
            registry:    shared InMemoryRegistry to resolve tools from.
            tags:        source-level tags (used by PolicyEngine.evaluate_source).
        """
        self.name  = skill_name
        self.tags  = list(tags or [])
        self._tool_names = tool_names
        self._registry   = registry

    async def load(self, ctx: RuntimeContext) -> list[Tool]:
        tools: list[Tool] = []
        for name in self._tool_names:
            try:
                tool = await self._registry.get(name)
            except Exception:
                log.warning(
                    "skill tool not found in registry — skipped",
                    extra={"tool": name, "skill": self.name, **ctx.to_log_fields()},
                )
                continue

            # Subagent capability filter
            if ctx.allowed_tags is not None:
                if set(tool.tags) - set(ctx.allowed_tags):
                    continue  # tool requires capabilities beyond this subagent's scope

            tools.append(tool)

        log.debug(
            "skill source loaded",
            extra={
                "skill": self.name,
                "requested": len(self._tool_names),
                "returned": len(tools),
                **ctx.to_log_fields(),
            },
        )
        return tools
