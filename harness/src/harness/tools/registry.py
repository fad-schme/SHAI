"""ToolRegistry — concrete registry for Tool objects.

Satisfies SHAIRegistry[Tool]. Adds as_dict() for startup tool resolution.

Writes hold a threading.Lock (startup only).
Reads are lock-free — GIL-safe dict reads in CPython.
"""
from __future__ import annotations

import logging
import threading
from typing import Iterable

from harness.core.errors import ConfigError, ToolNotRegisteredError
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class ToolRegistry:
    """Concrete registry for Tool objects.

    Satisfies SHAIRegistry[Tool] structurally.
    Adds as_dict() — used by Harness._resolve_tools() at load_agent() time.
    """

    name = "memory"

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._lock = threading.Lock()

    async def register(self, item: Tool) -> bool:
        """True = newly registered. False = identical already existed.
        Raises ConfigError on same name with different content.
        """
        with self._lock:
            existing = self._tools.get(item.name)
            if existing is None:
                self._tools[item.name] = item
                log.debug("tool registered", extra={"tool": item.name})
                return True
            if existing == item:
                return False  # idempotent
            raise ConfigError(
                f"tool '{item.name}' already registered with a different definition "
                f"(transport={existing.transport!r} tags={existing.tags}); "
                f"attempted re-registration with transport={item.transport!r} tags={item.tags}",
                op="register_tool",
            )

    async def deregister(self, item: Tool) -> bool:
        """True = removed. False = was not registered."""
        with self._lock:
            if item.name in self._tools:
                del self._tools[item.name]
                log.debug("tool deregistered", extra={"tool": item.name})
                return True
            return False

    async def register_many(self, items: Iterable[Tool]) -> None:
        for item in items:
            await self.register(item)

    async def get(self, name: str) -> Tool:
        """Lock-free read. Raises ToolNotRegisteredError on miss."""
        t = self._tools.get(name)
        if t is None:
            raise ToolNotRegisteredError(
                f"tool '{name}' not registered. "
                f"Known tools (up to 20): {sorted(self._tools)[:20]}",
                op="tool_lookup",
            )
        return t

    async def list(self) -> list[Tool]:
        return list(self._tools.values())

    def as_dict(self) -> dict[str, Tool]:
        """Snapshot used by Harness._resolve_tools() at load_agent() time."""
        return dict(self._tools)
