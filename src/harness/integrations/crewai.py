"""SHAI integration for CrewAI.

Provides wrap_tool() which wraps any CrewAI tool (or any callable decorated
with @tool) with a gated version that calls harness.check_tool_call.

Usage::

    from harness.integrations.crewai import wrap_tool, wrap_tools

    @tool("Search documents")
    def search_docs(query: str) -> str:
        ...

    gated_search = wrap_tool(search_docs, harness=harness, ctx=ctx)

    researcher = Agent(
        role="Researcher",
        tools=[gated_search],
        ...
    )

Subagent handoff — when CrewAI delegates to a sub-crew::

    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    child_tools = wrap_tools(research_tools, harness=harness, ctx=child_ctx)

CrewAI is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import Harness

log = logging.getLogger(__name__)


def wrap_tool(tool: Any, *, harness: "Harness", ctx: "AgentContext") -> Any:
    """Return a gated version of a CrewAI tool.

    Works with @tool decorated functions and BaseTool subclasses.
    Denied calls raise an Exception with the deny reason — CrewAI surfaces
    this as the tool result so the agent can continue.
    """
    harness_ = harness
    ctx_ = ctx
    tool_name = getattr(tool, "name", None) or getattr(tool, "__name__", str(tool))

    async def _gated_async(**kwargs: Any) -> Any:
        gate = await harness_.check_tool_call(tool_name, kwargs, ctx_)
        if not gate.allowed:
            log.info(
                "tool call denied",
                extra={"tool": tool_name, "reason": gate.deny_reason,
                       **ctx_.to_log_fields()},
            )
            return f"Tool call denied: {gate.deny_reason}"
        effective = gate.redacted_args if gate.redacted_args is not None else kwargs
        if asyncio.iscoroutinefunction(tool):
            return await tool(**effective)
        return await asyncio.to_thread(tool, **effective)

    def _gated_sync(**kwargs: Any) -> Any:
        return asyncio.get_event_loop().run_until_complete(_gated_async(**kwargs))

    # Try to build a proper CrewAI StructuredTool if crewai is installed
    try:
        from crewai.tools import StructuredTool

        gated = StructuredTool(
            name=tool_name,
            description=getattr(tool, "description", getattr(tool, "__doc__", "") or ""),
            func=_gated_sync,
            coroutine=_gated_async,
            args_schema=getattr(tool, "args_schema", None),
        )
        return gated
    except ImportError:
        pass

    # Fallback: return an async callable with the right name
    _gated_async.__name__ = tool_name
    _gated_async.__doc__ = getattr(tool, "__doc__", "")
    return _gated_async


def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: "Harness",
    ctx: "AgentContext",
) -> list[Any]:
    """Wrap a list of CrewAI tools."""
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
