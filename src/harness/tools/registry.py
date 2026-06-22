"""ToolRegistry Protocol and ScopedRegistryView.

ToolRegistry: the shared base, written only at startup via register_tools().
ScopedRegistryView: per-turn, per-agent overlay — never touches the shared base.

Both are internal. The public API surface for tools is Tool (tools/tool.py)
and Harness.register_tools() on the facade.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Protocol, runtime_checkable

if TYPE_CHECKING:
    from harness.core.context import RuntimeContext
    from harness.tools.tool import Tool


@runtime_checkable
class ToolRegistry(Protocol):
    """Shared base registry. Writes happen only at startup."""

    name: str

    async def register(self, tool: "Tool") -> None:
        """Idempotent on identical (name, tags, transport).
        Raises ConfigError on conflicting definition for the same name.
        STARTUP ONLY — must not be called during a turn.
        """
        ...

    async def register_many(self, tools: Iterable["Tool"]) -> None:
        """Convenience wrapper around register(). Loops in order."""
        ...

    async def get(self, name: str) -> "Tool":
        """Raises ToolNotRegisteredError on miss. Thread-safe (GIL-safe read)."""
        ...

    async def list(self) -> list["Tool"]:
        """All registered tools in insertion order. CLI / debug use only."""
        ...

    def scoped_view(self, ctx: "RuntimeContext") -> "ScopedRegistryView":
        """Return a fresh per-call overlay for this context.

        The view reads from the shared base; writes go to an in-call overlay
        invisible to other agents. The caller holds the view and passes it
        through the call chain. Never stored on the registry instance.
        """
        ...


class ScopedRegistryView(Protocol):
    """Per-turn, per-agent overlay over the shared ToolRegistry base.

    NEVER writes to the shared base. Discarded after unload_sources().
    Not part of the public API — agents never hold a ScopedRegistryView directly.
    """

    ctx: "RuntimeContext"

    async def add(self, tool: "Tool") -> None:
        """Add a source-loaded tool to this turn's overlay only."""
        ...

    async def get(self, name: str) -> "Tool":
        """Overlay first, then shared base. Raises ToolNotRegisteredError on miss."""
        ...

    async def list(self) -> list["Tool"]:
        """Overlay tools + base tools, overlay wins on name conflict."""
        ...
