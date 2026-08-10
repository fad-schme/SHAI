"""ToolRegistry — in-memory registry for Tool objects.

register / deregister / get / list, plus as_dict() for startup tool resolution.

Writes hold a threading.Lock (startup only).
Reads are lock-free — GIL-safe dict reads in CPython.

Every method here is synchronous, because none of them awaits anything: this is
a dict behind a threading.Lock. The rule across the three registries is `async`
iff the method actually awaits — `AgentRegistry.load` is async because it parses
YAML off the event loop, `SourceRegistry.activate` because it loads sources
concurrently. Nothing in this module has an equivalent. Marking these `async`
made `list()` and `as_dict()` two spellings of the same read on one class.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Iterable

from harness.core.errors import ConfigError, ToolNotRegisteredError
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class ToolRegistry:
    """In-memory registry for Tool objects.

    as_dict() is used by Harness._resolve_tools() at load_agent() time.
    """

    name = "memory"

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}
        self._lock = threading.Lock()

    def register(self, item: Tool) -> bool:
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
            diff = [
                f for f in ("transport", "tags", "description",
                            "argument_rules", "irreversibility")
                if getattr(existing, f) != getattr(item, f)
            ]
            # Names only for description and argument_rules — a tool description is
            # attacker-controlled MCP metadata and must not reach logs verbatim.
            raise ConfigError(
                f"tool '{item.name}' already registered with a different definition "
                f"(differs in: {', '.join(diff)}); "
                f"existing transport={existing.transport!r} "
                f"irreversibility={existing.irreversibility!r}, "
                f"attempted transport={item.transport!r} "
                f"irreversibility={item.irreversibility!r}",
                op="register_tool",
            )

    def deregister(self, item: Tool) -> bool:
        """True = removed. False = was not registered."""
        with self._lock:
            if item.name in self._tools:
                del self._tools[item.name]
                log.debug("tool deregistered", extra={"tool": item.name})
                return True
            return False

    def register_many(self, items: Iterable[Tool]) -> None:
        for item in items:
            self.register(item)

    def get(self, name: str) -> Tool:
        """Lock-free read. Raises ToolNotRegisteredError on miss."""
        t = self._tools.get(name)
        if t is None:
            raise ToolNotRegisteredError(
                f"tool '{name}' not registered. "
                f"Known tools (up to 20): {sorted(self._tools)[:20]}",
                op="tool_lookup",
            )
        return t

    def list(self) -> list[Tool]:
        return list(self._tools.values())

    def as_dict(self) -> dict[str, Tool]:
        """Snapshot used by Harness._resolve_tools() at load_agent() time."""
        return dict(self._tools)
