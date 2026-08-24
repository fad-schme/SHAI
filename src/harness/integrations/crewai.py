"""SHAI integration for CrewAI.

Quickstart::

    from harness.integrations.crewai import shai_tool, wrap_tools

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str:
        \"\"\"Search internal documentation.\"\"\"
        return _impl(query)

    tools   = [search_docs]
    harness = await SHAI.from_yaml(...)
    ctx     = await harness.load_agent(...)

    gated = await wrap_tools(tools, harness=harness, ctx=ctx)

    researcher = Agent(role="Researcher", tools=gated, ...)

CrewAI is imported lazily.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import (  # shai_tool re-exported
    make_gated_tool,
    shai_tool,
)

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

log = logging.getLogger(__name__)

__all__ = ["shai_tool", "wrap_tool", "wrap_tools"]


def wrap_tool(tool: Any, *, harness: SHAI, ctx: AgentContext) -> Any:
    """Return a gated CrewAI-compatible version of a tool.

    Note: does not call register_tools(). Use wrap_tools() for that.
    """
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))

    # CrewAI has no denial artifact — the shared default render (message on
    # denial/block, text otherwise) is exactly the tool output it expects.
    _gated_async = make_gated_tool(tool, harness=harness, ctx=ctx, tool_name=tool_name)

    def _gated_sync(**kwargs: Any) -> Any:
        return asyncio.run(_gated_async(**kwargs))

    try:
        from crewai.tools import StructuredTool
        return StructuredTool(
            name=tool_name,
            description=getattr(tool, "description", getattr(tool, "__doc__", "") or ""),
            func=_gated_sync,
            coroutine=_gated_async,
            args_schema=getattr(tool, "args_schema", None),
        )
    except ImportError:
        pass

    _gated_async.__name__ = tool_name
    _gated_async.__doc__  = getattr(tool, "__doc__", "")
    return _gated_async


async def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: SHAI,
    ctx: AgentContext,
) -> list[Any]:
    """Register tools with the harness and return gated CrewAI wrappers."""
    await harness.register_tools(tools)
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
