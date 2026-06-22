"""SHAI integration for PydanticAI.

Provides a harness_tool() decorator and make_middleware() for gating
tool calls on a PydanticAI agent.

Two patterns:

Pattern A — wrap individual tools with harness_tool()::

    from harness.integrations.pydantic_ai import harness_tool

    @harness_tool(harness=harness, ctx=ctx)
    async def search_docs(query: str) -> str:
        ...

    agent = Agent(model, tools=[search_docs])

Pattern B — use add_harness_middleware() on an existing agent::

    from harness.integrations.pydantic_ai import add_harness_middleware

    # Gates all tool calls on the agent
    add_harness_middleware(agent, harness=harness, ctx=ctx)

PydanticAI is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from harness.core.context import RuntimeContext
    from harness.core.harness import Harness

log = logging.getLogger(__name__)


def harness_tool(
    *,
    harness: "Harness",
    ctx: "RuntimeContext",
) -> Callable:
    """Decorator that gates a tool function through the harness.

    Usage::

        @harness_tool(harness=h, ctx=ctx)
        async def search_docs(query: str) -> str:
            return "results"
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs or ({"input": args[0]} if args else {})
            gate = await harness.check_tool_call(tool_name, tool_args, ctx)
            if not gate.allowed:
                log.info(
                    "tool call denied",
                    extra={"tool": tool_name, "reason": gate.deny_reason,
                           **ctx.to_log_fields()},
                )
                return f"Tool call denied: {gate.deny_reason}"
            effective = gate.redacted_args if gate.redacted_args is not None else kwargs
            if asyncio.iscoroutinefunction(fn):
                return await fn(*args, **effective)
            return await asyncio.to_thread(fn, *args, **effective)

        return wrapper
    return decorator


def add_harness_middleware(
    agent: Any,
    *,
    harness: "Harness",
    ctx: "RuntimeContext",
) -> None:
    """Patch a PydanticAI agent to gate all tool calls through the harness.

    Modifies the agent in-place. Must be called after all tools are
    registered and before agent.run().
    """
    try:
        # PydanticAI exposes tools via agent._function_tools or agent.tools
        tools = getattr(agent, "_function_tools", None) or getattr(agent, "tools", [])
    except Exception:
        tools = []

    if not tools:
        log.warning("add_harness_middleware: no tools found on agent — nothing to gate")
        return

    for tool_obj in tools:
        _patch_pydantic_ai_tool(tool_obj, harness=harness, ctx=ctx)


def _patch_pydantic_ai_tool(
    tool_obj: Any,
    *,
    harness: "Harness",
    ctx: "RuntimeContext",
) -> None:
    """Wrap the run method of a PydanticAI Tool object."""
    original_fn = getattr(tool_obj, "function", None) or getattr(tool_obj, "_function", None)
    if original_fn is None:
        return

    tool_name = getattr(tool_obj, "name", original_fn.__name__)

    @functools.wraps(original_fn)
    async def gated(*args: Any, **kwargs: Any) -> Any:
        tool_args = kwargs or {}
        gate = await harness.check_tool_call(tool_name, tool_args, ctx)
        if not gate.allowed:
            return f"Tool call denied: {gate.deny_reason}"
        effective = gate.redacted_args if gate.redacted_args is not None else kwargs
        if asyncio.iscoroutinefunction(original_fn):
            return await original_fn(*args, **effective)
        return await asyncio.to_thread(original_fn, *args, **effective)

    # Attempt to replace the function on the tool object
    for attr in ("function", "_function"):
        if hasattr(tool_obj, attr):
            try:
                setattr(tool_obj, attr, gated)
                return
            except (AttributeError, TypeError):
                pass
