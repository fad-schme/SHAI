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

`wrap_tools` is the only entry point, because it is the only shape that can run
the whole sequence. A `before_tool_call` hook — which this module used to
provide — gates and then hands control back to the SDK, which dispatches the
tool itself; the hook never sees the result, so `scan_tool_result` cannot run
and tool output reaches the model unscanned. That is the T6 indirect-injection
boundary, and an integration that silently omits it is not a weaker option,
it is a different security posture wearing the same name.

OpenAI Agents SDK is imported lazily.
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Sequence
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

__all__ = ["shai_tool", "wrap_tool", "wrap_tools"]


def wrap_tool(tool: Any, *, harness: SHAI, ctx: AgentContext) -> Any:
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
        call = await execute_gated_tool_call(
            harness=harness_,
            ctx=ctx_,
            tool_name=tool_name,
            tool_args=kwargs,
            invoke=lambda a: invoke_tool(original_fn, a),
        )
        # The SDK has no denial artifact — the message is the tool output.
        return call.message if not call.allowed else call.text

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
    harness: SHAI,
    ctx: AgentContext,
) -> list[Any]:
    """Register tools with the harness and return gated SDK FunctionTools."""
    await harness.register_tools(tools)
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
