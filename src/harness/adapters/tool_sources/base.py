"""ToolSource Protocol and SourceRegistry.

ToolSource: what every source adapter implements.
SourceRegistry: activates sources per turn per agent/subagent, populates
                the ScopedRegistryView, returns the active tool list.

This is the implementation of Harness.load_sources() — the registry is
owned by the Harness instance and called from the facade.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from harness.adapters.tool_registry.memory import InMemoryRegistryView
    from harness.agents.agent_config import AgentConfig, SubAgentConfig
    from harness.core.context import RuntimeContext
    from harness.policy.engine import PolicyEngine
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)


@runtime_checkable
class ToolSource(Protocol):
    """Load tools for one agent/subagent turn. All methods async."""

    name:      str
    transport: str   # Transport enum value
    tags:      list[str]

    async def load(self, ctx: "RuntimeContext") -> list["Tool"]:
        """Load tools available for this turn.

        Credential-free — credentials injected at construction time.
        ctx.agent_id and ctx.sub_agent_id identify the caller.
        ctx.user_id and ctx.session_id are ignored — not relevant to
        which tools a source provides.
        Safe for concurrent async calls from multiple agents.
        """
        ...


class SourceRegistry:
    """Activates sources per turn and populates the ScopedRegistryView.

    One SourceRegistry per Harness instance. Shared across all agents.
    Per-turn state lives entirely in the ScopedRegistryView passed in.
    """

    def __init__(
        self,
        sources: dict[str, "ToolSource"],
        policy: "PolicyEngine",
    ) -> None:
        self._sources = sources        # name → ToolSource
        self._policy  = policy

    async def activate(
        self,
        ctx: "RuntimeContext",
        source_names: list[str],
        view: "InMemoryRegistryView",
    ) -> list["Tool"]:
        """Activate the declared sources, load their tools into the view.

        Args:
            ctx:          RuntimeContext for this agent/subagent turn.
            source_names: list from AgentConfig.sources or SubAgentConfig.sources.
            view:         per-turn ScopedRegistryView to populate.

        Returns the flat list of all active tools (for passing to the LLM).
        Sources not found in the registry are logged and skipped — not an error,
        because sources may be declared for future use.
        """
        active_loads: list[tuple[str, asyncio.Task]] = []

        for name in source_names:
            source = self._sources.get(name)
            if source is None:
                log.warning(
                    "declared source not found in registry — skipped",
                    extra={"source_name": name, **ctx.to_log_fields()},
                )
                continue

            decision = await self._policy.evaluate_source(source, ctx)
            if not decision.active:
                log.debug(
                    "source suppressed by policy",
                    extra={
                        "source_name": name,
                        "reason": decision.reason,
                        **ctx.to_log_fields(),
                    },
                )
                continue

            # Schedule loads concurrently
            task = asyncio.create_task(source.load(ctx))
            active_loads.append((name, task))

        # Gather all loads concurrently; log individual failures, don't abort
        all_tools: list["Tool"] = []
        if active_loads:
            results = await asyncio.gather(
                *[task for _, task in active_loads],
                return_exceptions=True,
            )
            for (src_name, _), result in zip(active_loads, results):
                if isinstance(result, Exception):
                    log.error(
                        "source load failed",
                        extra={
                            "source_name": src_name,
                            "error": str(result),
                            **ctx.to_log_fields(),
                        },
                    )
                    continue
                for tool in result:
                    await view.add(tool)
                    all_tools.append(tool)

        return all_tools
