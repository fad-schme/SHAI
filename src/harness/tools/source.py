"""ToolSource and SourceRegistry.

ToolSource:     Protocol every source adapter implements.
SourceRegistry: Concrete registry for ToolSource objects.
                Satisfies SHAIRegistry[ToolSource]. Adds activate().
LocalSource:    Reference implementation — all registered tools for an agent.
SkillSource:    Reference implementation — named subset of registered tools.

Sources are registered once at startup and activated at load_agent() time.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Iterable, Protocol

from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.tools.registry import ToolRegistry
from harness.tools.tool import Tool

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.policy.engine import PolicyEngine

log = logging.getLogger(__name__)


# ── ToolSource Protocol ───────────────────────────────────────────────────

class ToolSource(Protocol):
    """Interface every source adapter must satisfy."""

    name:      str
    transport: str
    tags:      list[str]

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        """Return tools for this agent. Called once at load_agent() time."""
        ...


# ── SourceRegistry ────────────────────────────────────────────────────────

class SourceRegistry:
    """Concrete registry for ToolSource objects.

    Satisfies SHAIRegistry[ToolSource] structurally.
    Adds activate() — called at load_agent() time to build the agent's tool set.
    """

    def __init__(self, policy: "PolicyEngine") -> None:
        self._sources: dict[str, ToolSource] = {}
        self._policy  = policy

    async def register(self, item: ToolSource) -> bool:
        """True = newly registered. False = same name already registered (idempotent).
        Raises ConfigError if same name registered with different object.
        """
        existing = self._sources.get(item.name)
        if existing is None:
            self._sources[item.name] = item
            log.debug("source registered", extra={"source": item.name})
            return True
        if existing is item:
            return False  # idempotent — same object
        raise ConfigError(
            f"source '{item.name}' already registered with a different object",
            op="register_source",
        )

    async def deregister(self, item: ToolSource) -> bool:
        """True = removed. False = was not registered."""
        if item.name in self._sources:
            del self._sources[item.name]
            log.debug("source deregistered", extra={"source": item.name})
            return True
        return False

    async def register_many(self, items: Iterable[ToolSource]) -> None:
        for item in items:
            await self.register(item)

    async def get(self, name: str) -> ToolSource:
        """Raises ConfigError on miss."""
        source = self._sources.get(name)
        if source is None:
            raise ConfigError(
                f"source '{name}' not registered. "
                f"Known sources: {sorted(self._sources)}",
                op="source_lookup",
            )
        return source

    async def list(self) -> list[ToolSource]:
        return list(self._sources.values())

    async def activate(
        self,
        ctx: "AgentContext",
        source_names: list[str],
    ) -> list[Tool]:
        """Activate declared sources and return their tools.

        Called once at load_agent() time — not per turn.
        Missing sources are logged and skipped.
        Suppressed sources are logged and skipped.
        Failed loads are logged and skipped.
        """
        active_tasks: list[tuple[str, asyncio.Task]] = []

        for name in source_names:
            source = self._sources.get(name)
            if source is None:
                log.warning("declared source not found — skipped",
                            extra={"source": name, **ctx.to_log_fields()})
                continue

            decision = await self._policy.evaluate_source(source, ctx)
            if not decision.active:
                log.debug("source suppressed by policy",
                          extra={"source": name, "reason": decision.reason,
                                 **ctx.to_log_fields()})
                continue

            active_tasks.append((name, asyncio.create_task(source.load(ctx))))

        all_tools: list[Tool] = []
        if active_tasks:
            results = await asyncio.gather(
                *[t for _, t in active_tasks],
                return_exceptions=True,
            )
            for (src_name, _), result in zip(active_tasks, results):
                if isinstance(result, Exception):
                    log.error("source load failed",
                              extra={"source": src_name, "error": str(result),
                                     **ctx.to_log_fields()})
                    continue
                all_tools.extend(result)

        return all_tools


# ── Reference implementations ─────────────────────────────────────────────

class LocalSource:
    """Reference ToolSource — all registered tools, filtered by capability."""

    name      = "local"
    transport = Transport.LOCAL
    tags: list[str] = []

    def __init__(self, registry: ToolRegistry, tags: list[str] | None = None) -> None:
        self._registry = registry
        self.tags = list(tags or [])

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        all_tools = await self._registry.list()
        if ctx.allowed_tags is not None:
            allowed   = set(ctx.allowed_tags)
            all_tools = [t for t in all_tools if not set(t.tags) - allowed]
        log.debug("local source loaded",
                  extra={"returned": len(all_tools), **ctx.to_log_fields()})
        return all_tools


class SkillSource:
    """Reference ToolSource — named subset of registered tools."""

    transport = Transport.SKILL

    def __init__(
        self,
        skill_name: str,
        tool_names: list[str],
        registry: ToolRegistry,
        tags: list[str] | None = None,
    ) -> None:
        self.name        = skill_name
        self.tags        = list(tags or [])
        self._tool_names = tool_names
        self._registry   = registry

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        tools: list[Tool] = []
        for name in self._tool_names:
            try:
                tool = await self._registry.get(name)
            except Exception:
                log.warning("skill tool not found — skipped",
                            extra={"tool": name, "skill": self.name,
                                   **ctx.to_log_fields()})
                continue
            if ctx.allowed_tags is not None:
                if set(tool.tags) - set(ctx.allowed_tags):
                    continue
            tools.append(tool)
        log.debug("skill source loaded",
                  extra={"skill": self.name, "requested": len(self._tool_names),
                         "returned": len(tools), **ctx.to_log_fields()})
        return tools
