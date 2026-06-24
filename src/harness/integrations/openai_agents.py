"""SHAI integration for the OpenAI Agents SDK.

Quickstart::

    from harness.integrations.openai_agents import shai_tool, wrap_tools

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str:
        \"\"\"Search internal documentation.\"\"\"
        return _impl(query)

    tools   = [search_docs]
    harness = await SHAI.from_yaml(...)
    ctx     = await harness.load_agent(...)

    # Registers tools and returns gated SDK FunctionTools
    gated = await wrap_tools(tools, harness=harness, ctx=ctx)
    agent = Agent(name="assistant", tools=gated)

    # Or use a before_tool_call hook on an existing agent:
    hook  = make_before_tool_hook(harness=harness, ctx=ctx)
    agent = Agent(..., hooks=AgentHooks(before_tool_call=hook))

OpenAI Agents SDK is imported lazily.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import TYPE_CHECKING, Any, Callable, Sequence

from harness.integrations.base import ShaiTool, shai_tool  # re-export

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

log = logging.getLogger(__name__)

__all__ = ["shai_tool", "make_before_tool_hook", "wrap_tool", "wrap_tools"]


def make_before_tool_hook(*, harness: "SHAI", ctx: "AgentContext") -> Callable:
    """Return an async before_tool_call hook for AgentHooks.

    Gates each tool call. Returns deny reason (SDK uses as tool result) on deny.
    """
    harness_ = harness
    ctx_     = ctx

    async def before_tool_call(tool: Any, args: Any) -> Any:
        tool_name = getattr(tool, "name", str(tool))
        tool_args = (args if isinstance(args, dict)
                     else vars(args) if hasattr(args, "__dict__") else {})
        gate = await harness_.check_tool_call(tool_name, tool_args, ctx_)
        if not gate.allowed:
            log.info("tool call denied",
                     extra={"tool": tool_name, "reason": gate.deny_reason,
                            **ctx_.to_log_fields()})
            return f"Tool call denied: {gate.deny_reason}"
        return gate.redacted_args if gate.redacted_args is not None else None

    return before_tool_call


def wrap_tool(tool: Any, *, harness: "SHAI", ctx: "AgentContext") -> Any:
    """Return a gated OpenAI Agents FunctionTool.

    Note: does not call register_tools(). Use wrap_tools() for that.
    """
    harness_  = harness
    ctx_      = ctx
    tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
    original_fn = (getattr(tool, "_fn", None) or getattr(tool, "fn", None)
                   or (tool if callable(tool) else None))
    if original_fn is None:
        log.warning("wrap_tool: cannot find callable on %s — returning unwrapped", tool_name)
        return tool

    base_fn = original_fn._fn if isinstance(original_fn, ShaiTool) else original_fn

    @functools.wraps(base_fn)
    async def gated(**kwargs: Any) -> Any:
        gate = await harness_.check_tool_call(tool_name, kwargs, ctx_)
        if not gate.allowed:
            return f"Tool call denied: {gate.deny_reason}"
        effective = gate.redacted_args if gate.redacted_args is not None else kwargs
        if isinstance(original_fn, ShaiTool):
            return await original_fn._async_call(**effective)
        if asyncio.iscoroutinefunction(original_fn):
            return await original_fn(**effective)
        return await asyncio.to_thread(original_fn, **effective)

    try:
        from agents import function_tool
        return function_tool(gated, name_override=tool_name)
    except ImportError:
        pass

    gated.__name__ = tool_name
    return gated


async def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: "SHAI",
    ctx: "AgentContext",
) -> list[Any]:
    """Register tools with the harness and return gated SDK FunctionTools."""
    await harness.register_tools(tools)
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
