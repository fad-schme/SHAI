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

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import (  # shai_tool re-exported
    make_gated_tool,
    run_sync,
    shai_tool,
    tool_callable,
    tool_input_schema,
)

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

__all__ = ["shai_tool", "wrap_tool", "wrap_tools"]


def wrap_tool(tool: Any, *, harness: SHAI, ctx: AgentContext) -> Any:
    """Return a gated CrewAI-compatible version of a tool.

    Note: does not call register_tools(). Use wrap_tools() for that.
    """
    from crewai.tools import BaseTool
    from pydantic import PrivateAttr, model_validator

    function = tool_callable(tool)
    tool_name = getattr(tool, "name", None) or function.__name__
    schema = tool_input_schema(function, name=tool_name)
    if "security_context" not in schema.model_fields:
        class CrewToolInput(schema):
            @model_validator(mode="before")
            @classmethod
            def _without_sdk_fingerprint(cls, value: Any) -> Any:
                # CrewAI injects this transport metadata after constructing
                # the tool request. It is not a function argument or a source
                # of SHAI authority. Preserve it when the tool declares it.
                if isinstance(value, dict) and "security_context" in value:
                    return {key: item for key, item in value.items() if key != "security_context"}
                return value

        schema = CrewToolInput

    # CrewAI has no denial artifact — the shared default render (message on
    # denial/block, text otherwise) is exactly the tool output it expects.
    _gated_async = make_gated_tool(tool, harness=harness, ctx=ctx, tool_name=tool_name)

    class GatedCrewTool(BaseTool):
        _gated: Callable = PrivateAttr(default_factory=lambda: _gated_async)

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            return await self._gated(*args, **kwargs)

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            return run_sync(self._arun(*args, **kwargs))

    return GatedCrewTool(
        name=tool_name,
        description=getattr(tool, "description", None) or function.__doc__ or tool_name,
        args_schema=schema,
    )


async def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: SHAI,
    ctx: AgentContext,
) -> list[Any]:
    """Register tools with the harness and return gated CrewAI wrappers."""
    await harness.register_tools(tools)
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
