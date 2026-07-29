"""SHAI integration for PydanticAI.

Quickstart::

    from harness.integrations.pydantic_ai import shai_tool, create_tools

    @shai_tool(tags=["read", "internal"])
    async def search_docs(query: str) -> str:
        \"\"\"Search internal documentation.\"\"\"
        return await _impl(query)

    tools   = [search_docs]
    harness = await SHAI.from_yaml(...)
    ctx     = await harness.load_agent(...)

    # Registers tools and returns gated PydanticAI-compatible callables
    gated = await create_tools(tools, harness=harness, ctx=ctx)
    agent = Agent(model, tools=gated)

    # Or use add_harness_middleware() on an existing agent:
    add_harness_middleware(agent, harness=harness, ctx=ctx)

PydanticAI is imported lazily.
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import (  # shai_tool re-exported
    ShaiTool,
    execute_gated_tool_call,
    invoke_tool,
    shai_tool,
)

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

log = logging.getLogger(__name__)

__all__ = ["shai_tool", "harness_tool", "create_tools", "add_harness_middleware"]


def harness_tool(*, harness: SHAI, ctx: AgentContext) -> Callable:
    """Decorator that gates a plain function through the harness.

    For when you cannot use @shai_tool (e.g. third-party functions).
    Does not call register_tools() — register separately if needed.
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs or ({"input": args[0]} if args else {})
            call = await execute_gated_tool_call(
                harness=harness,
                ctx=ctx,
                tool_name=tool_name,
                tool_args=tool_args,
                invoke=lambda a: invoke_tool(fn, a),
            )
            # PydanticAI has no denial artifact — the message is the output.
            return call.message if not call.allowed else call.text

        return wrapper
    return decorator


async def create_tools(
    tools: Sequence[Any],
    *,
    harness: SHAI,
    ctx: AgentContext,
) -> list[Callable]:
    """Register tools with the harness and return gated callables for PydanticAI.

    Preferred entry point — calls harness.register_tools() automatically.
    """
    await harness.register_tools(tools)
    result = []
    for tool in tools:
        tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
        harness_  = harness
        ctx_      = ctx
        original  = tool

        @functools.wraps(original._fn if isinstance(original, ShaiTool) else original)
        async def gated(*args: Any, _name: str = tool_name,
                        _orig: Any = original, **kwargs: Any) -> Any:
            tool_args = kwargs or ({"input": args[0]} if args else {})
            call = await execute_gated_tool_call(
                harness=harness_,
                ctx=ctx_,
                tool_name=_name,
                tool_args=tool_args,
                invoke=lambda a, _t=_orig: invoke_tool(_t, a),
            )
            return call.message if not call.allowed else call.text

        gated.__name__ = tool_name
        result.append(gated)
    return result


def add_harness_middleware(agent: Any, *, harness: SHAI, ctx: AgentContext) -> None:
    """Patch a PydanticAI agent to gate all tool calls through the harness.

    Modifies the agent in-place. Must be called after all tools are
    registered and before agent.run().
    """
    tools = getattr(agent, "_function_tools", None) or getattr(agent, "tools", [])
    if not tools:
        log.warning("add_harness_middleware: no tools found on agent — nothing to gate")
        return
    for tool_obj in tools:
        _patch_tool(tool_obj, harness=harness, ctx=ctx)


def _patch_tool(tool_obj: Any, *, harness: SHAI, ctx: AgentContext) -> None:
    original_fn = (getattr(tool_obj, "function", None)
                   or getattr(tool_obj, "_function", None))
    if original_fn is None:
        return
    tool_name = getattr(tool_obj, "name", original_fn.__name__)

    @functools.wraps(original_fn)
    async def gated(*args: Any, **kwargs: Any) -> Any:
        call = await execute_gated_tool_call(
            harness=harness,
            ctx=ctx,
            tool_name=tool_name,
            tool_args=kwargs or {},
            invoke=lambda a: invoke_tool(original_fn, a),
        )
        return call.message if not call.allowed else call.text

    for attr in ("function", "_function"):
        if hasattr(tool_obj, attr):
            try:
                setattr(tool_obj, attr, gated)
                return
            except (AttributeError, TypeError):
                pass
