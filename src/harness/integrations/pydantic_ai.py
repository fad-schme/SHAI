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

import asyncio
import functools
import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import ShaiTool, shai_tool  # re-export

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
            gate = await harness.check_tool_call(tool_name, tool_args, ctx)
            if not gate.allowed:
                log.info("tool call denied",
                         extra={"tool": tool_name, "reason": gate.deny_reason,
                                **ctx.to_log_fields()})
                return f"Tool call denied: {gate.deny_reason}"
            effective = gate.redacted_args if gate.redacted_args is not None else kwargs
            if asyncio.iscoroutinefunction(fn):
                return await fn(*args, **effective)
            return await asyncio.to_thread(fn, *args, **effective)

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
            gate = await harness_.check_tool_call(_name, tool_args, ctx_)
            if not gate.allowed:
                return f"Tool call denied: {gate.deny_reason}"
            effective = gate.redacted_args if gate.redacted_args is not None else kwargs
            if isinstance(_orig, ShaiTool):
                return await _orig._async_call(**effective)
            if asyncio.iscoroutinefunction(_orig):
                return await _orig(*args, **effective)
            return await asyncio.to_thread(_orig, *args, **effective)

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
        gate = await harness.check_tool_call(tool_name, kwargs or {}, ctx)
        if not gate.allowed:
            return f"Tool call denied: {gate.deny_reason}"
        effective = gate.redacted_args if gate.redacted_args is not None else kwargs
        if asyncio.iscoroutinefunction(original_fn):
            return await original_fn(*args, **effective)
        return await asyncio.to_thread(original_fn, *args, **effective)

    for attr in ("function", "_function"):
        if hasattr(tool_obj, attr):
            try:
                setattr(tool_obj, attr, gated)
                return
            except (AttributeError, TypeError):
                pass
