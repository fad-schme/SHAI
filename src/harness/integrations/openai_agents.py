"""SHAI integration for the OpenAI Agents SDK.

Provides a before_tool_call hook and a wrap_tool() helper for gating
tool calls on an OpenAI Agent.

Usage with the hook::

    from harness.integrations.openai_agents import make_before_tool_hook

    hook = make_before_tool_hook(harness=harness, ctx=ctx)

    agent = Agent(
        name="assistant",
        tools=[search_docs, send_email],
        hooks=AgentHooks(before_tool_call=hook),
    )

Usage with wrap_tool()::

    from harness.integrations.openai_agents import wrap_tool, wrap_tools

    gated_tools = wrap_tools([search_docs, send_email], harness=harness, ctx=ctx)
    agent = Agent(name="assistant", tools=gated_tools)

Subagent handoff::

    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    hook = make_before_tool_hook(harness=harness, ctx=child_ctx)

OpenAI Agents SDK is imported lazily.
"""
from __future__ import annotations

import asyncio
import functools
import logging
from typing import TYPE_CHECKING, Any, Callable, Sequence

if TYPE_CHECKING:
    from harness.core.context import RuntimeContext
    from harness.core.harness import Harness

log = logging.getLogger(__name__)


def make_before_tool_hook(
    *,
    harness: "Harness",
    ctx: "RuntimeContext",
) -> Callable:
    """Return an async before_tool_call hook for AgentHooks.

    The hook gates each tool call. When denied, it raises StopToolCall
    (the SDK's mechanism for preventing tool execution) and the deny
    reason is returned as the tool result.
    """
    harness_ = harness
    ctx_ = ctx

    async def before_tool_call(tool: Any, args: Any) -> Any:
        tool_name = getattr(tool, "name", str(tool))
        tool_args = args if isinstance(args, dict) else vars(args) if hasattr(args, "__dict__") else {}

        gate = await harness_.check_tool_call(tool_name, tool_args, ctx_)
        if not gate.allowed:
            log.info(
                "tool call denied",
                extra={"tool": tool_name, "reason": gate.deny_reason,
                       **ctx_.to_log_fields()},
            )
            # Return the deny reason — the SDK will use this as the tool result
            return f"Tool call denied: {gate.deny_reason}"

        # Return redacted args if policy applied redaction
        if gate.redacted_args is not None:
            return gate.redacted_args
        return None  # None means proceed with original args

    return before_tool_call


def wrap_tool(tool: Any, *, harness: "Harness", ctx: "RuntimeContext") -> Any:
    """Wrap a single OpenAI Agents tool with a harness gate.

    Returns a FunctionTool (or the original with a gated _run) depending
    on which SDK version is installed.
    """
    harness_ = harness
    ctx_ = ctx
    tool_name = getattr(tool, "name", getattr(tool, "__name__", str(tool)))
    original_fn = getattr(tool, "_fn", None) or getattr(tool, "fn", None) or (
        tool if callable(tool) else None
    )

    if original_fn is None:
        log.warning("wrap_tool: cannot find callable on tool %s — returning unwrapped", tool_name)
        return tool

    @functools.wraps(original_fn)
    async def gated(**kwargs: Any) -> Any:
        gate = await harness_.check_tool_call(tool_name, kwargs, ctx_)
        if not gate.allowed:
            return f"Tool call denied: {gate.deny_reason}"
        effective = gate.redacted_args if gate.redacted_args is not None else kwargs
        if asyncio.iscoroutinefunction(original_fn):
            return await original_fn(**effective)
        return await asyncio.to_thread(original_fn, **effective)

    # Try to build an SDK FunctionTool with the gated function
    try:
        from agents import function_tool
        return function_tool(gated, name_override=tool_name)
    except ImportError:
        pass

    gated.__name__ = tool_name
    return gated


def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: "Harness",
    ctx: "RuntimeContext",
) -> list[Any]:
    """Wrap a list of OpenAI Agents tools."""
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
