"""InMemoryRegistry — reference ToolRegistry backed by a plain dict.

InMemoryRegistryView — per-turn, per-agent overlay over the shared base.

Concurrency:
  - register/register_many hold a threading.Lock (write path, startup only)
  - get/list on the base are lock-free (GIL-safe dict reads in CPython)
  - InMemoryRegistryView is single-agent single-turn — no locking needed
"""
from __future__ import annotations

import logging
import threading
from typing import Iterable

from harness.core.context import RuntimeContext
from harness.core.errors import ConfigError, ToolNotRegisteredError
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class InMemoryRegistryView:
    """Per-turn overlay. Writes never touch the shared base."""

    def __init__(self, base: "InMemoryRegistry", ctx: RuntimeContext) -> None:
        self._base = base
        self.ctx = ctx
        self._overlay: dict[str, Tool] = {}

    async def add(self, tool: Tool) -> None:
        """Add a source-loaded tool to this turn's overlay only."""
        self._overlay[tool.name] = tool

    async def get(self, name: str) -> Tool:
        """Overlay first, then base. Raises ToolNotRegisteredError on miss."""
        t = self._overlay.get(name)
        if t is not None:
            return t
        return await self._base.get(name)

    async def list(self) -> list[Tool]:
        """Base tools + overlay tools; overlay wins on name conflict."""
        base_tools = {t.name: t for t in await self._base.list()}
        base_tools.update(self._overlay)
        return list(base_tools.values())


class InMemoryRegistry:
    """Reference ToolRegistry — in-process dict, suitable for single-process agents."""

    name = "memory"

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._lock = threading.Lock()

    async def register(self, tool: Tool) -> None:
        """Idempotent on identical Tool. ConfigError on conflicting definition."""
        with self._lock:
            existing = self._tools.get(tool.name)
            if existing is None:
                self._tools[tool.name] = tool
                log.debug("tool registered", extra={"tool": tool.name, "op": "register"})
                return
            if existing == tool:
                return  # identical — no-op
            raise ConfigError(
                f"tool '{tool.name}' already registered with a different definition "
                f"(transport={existing.transport!r} tags={existing.tags}); "
                f"attempted re-registration with transport={tool.transport!r} tags={tool.tags}",
                op="register_tool",
            )

    async def register_many(self, tools: Iterable[Tool]) -> None:
        for tool in tools:
            await self.register(tool)

    async def get(self, name: str) -> Tool:
        """Lock-free read. Raises ToolNotRegisteredError on miss."""
        t = self._tools.get(name)
        if t is None:
            available = sorted(self._tools)[:20]  # cap for readability
            raise ToolNotRegisteredError(
                f"tool '{name}' not registered. "
                f"Known tools (up to 20): {available}",
                op="tool_lookup",
            )
        return t

    async def list(self) -> list[Tool]:
        return list(self._tools.values())

    def scoped_view(self, ctx: RuntimeContext) -> InMemoryRegistryView:
        """Return a fresh per-turn view for this context."""
        return InMemoryRegistryView(base=self, ctx=ctx)
