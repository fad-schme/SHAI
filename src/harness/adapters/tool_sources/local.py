"""LocalSource — surfaces startup-registered tools through source activation.

Reads from the shared InMemoryRegistry base (never the view).
Returns only tools whose tags intersect with ctx.allowed_tags when that
field is set (subagent turns). Top-level agents get all registered tools.
"""
from __future__ import annotations

import logging

from harness.adapters.tool_registry.memory import InMemoryRegistry
from harness.core.context import RuntimeContext
from harness.core.types import Transport
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class LocalSource:
    """Reference ToolSource — returns tools from the shared startup registry."""

    name      = "local"
    transport = Transport.LOCAL
    tags: list[str] = []

    def __init__(self, registry: InMemoryRegistry, tags: list[str] | None = None) -> None:
        self._registry = registry
        self.tags = list(tags or [])

    async def load(self, ctx: RuntimeContext) -> list[Tool]:
        all_tools = await self._registry.list()

        # Subagent capability filter — allowed_tags set only for subagents
        if ctx.allowed_tags is not None:
            allowed = set(ctx.allowed_tags)
            filtered = [t for t in all_tools if not set(t.tags) - allowed]
        else:
            filtered = all_tools

        log.debug(
            "local source loaded",
            extra={
                "total": len(all_tools),
                "returned": len(filtered),
                **ctx.to_log_fields(),
            },
        )
        return filtered
