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

from harness.core.errors import ConfigError
from harness.integrations.base import (  # shai_tool re-exported
    ShaiTool,
    make_gated_tool,
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
        # PydanticAI has no denial artifact — the shared default render
        # (message on denial/block, text otherwise) is the output it expects.
        wrapper = functools.wraps(fn)(
            make_gated_tool(fn, harness=harness, ctx=ctx, tool_name=fn.__name__)
        )
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
        base_fn = tool._fn if isinstance(tool, ShaiTool) else tool
        gated = functools.wraps(base_fn)(
            make_gated_tool(tool, harness=harness, ctx=ctx, tool_name=tool_name)
        )
        result.append(gated)
    return result


_GATED_MARK = "__shai_gated__"


def add_harness_middleware(agent: Any, *, harness: SHAI, ctx: AgentContext) -> None:
    """Gate every function tool of a PydanticAI agent through the harness.

    Modifies the agent in place. Call it after all tools are registered and
    before ``agent.run()``. The tools must also be registered with the harness
    (``harness.register_tools``), as for any gated tool.

    Tools are discovered through the agent's public ``toolsets``: each function
    toolset's ``tools`` mapping has every tool replaced by one whose function
    runs ``check_tool_call`` and ``scan_tool_result`` and renders a denial the
    way ``create_tools`` does. Verified against pydantic-ai-slim 2.61.

    Raises ConfigError, before the agent runs and with the agent left
    unchanged, when a tool or toolset cannot be gated: a toolset that is not a
    ``FunctionToolset`` (MCP servers, dynamic toolsets), a tool that takes a
    ``RunContext``, or a tool whose gated form would expose a different schema
    to the model. An agent with no tools logs a warning and returns.
    """
    try:
        from pydantic_ai import Tool
        from pydantic_ai.toolsets import FunctionToolset
    except ImportError as e:
        raise ImportError(
            "pydantic-ai is required for add_harness_middleware. "
            "pip install pydantic-ai-slim"
        ) from e

    toolsets = getattr(agent, "toolsets", None)
    if toolsets is None:
        raise ConfigError(
            f"add_harness_middleware: {type(agent).__name__} exposes no toolsets"
        )

    replacements: list[tuple[dict[str, Any], str, Any]] = []
    for toolset in toolsets:
        if not isinstance(toolset, FunctionToolset):
            raise ConfigError(
                f"add_harness_middleware: cannot gate a toolset of type "
                f"{type(toolset).__name__}; only function toolsets are supported"
            )
        for name, tool in toolset.tools.items():
            if getattr(tool.function, _GATED_MARK, False):
                continue   # already gated by an earlier call
            replacements.append(
                (toolset.tools, name, _gated_tool(tool, name, Tool, harness, ctx))
            )

    if not replacements and not any(ts.tools for ts in toolsets):
        log.warning("add_harness_middleware: no tools found on agent — nothing to gate")
        return
    for tools, name, gated in replacements:
        tools[name] = gated


def _gated_tool(tool: Any, name: str, tool_cls: type, harness: SHAI, ctx: AgentContext) -> Any:
    """A copy of `tool` whose function is gated, or ConfigError."""
    if tool.takes_ctx:
        raise ConfigError(
            f"add_harness_middleware: tool {name!r} takes a RunContext and cannot "
            "be gated; use create_tools() instead"
        )
    gated_fn = functools.wraps(tool.function)(
        make_gated_tool(tool.function, harness=harness, ctx=ctx, tool_name=name)
    )
    setattr(gated_fn, _GATED_MARK, True)
    try:
        gated = tool_cls(
            gated_fn,
            takes_ctx=False,
            name=name,
            description=tool.description,
            max_retries=tool.max_retries,
            prepare=tool.prepare,
            args_validator=tool.args_validator,
            docstring_format=tool.docstring_format,
            strict=tool.strict,
            sequential=tool.sequential,
            requires_approval=tool.requires_approval,
            metadata=tool.metadata,
            tool_kind=tool.tool_kind,
            timeout=tool.timeout,
            defer_loading=tool.defer_loading,
            include_return_schema=tool.include_return_schema,
        )
        same_schema = (
            gated.tool_def.parameters_json_schema == tool.tool_def.parameters_json_schema
        )
    except Exception as e:
        raise ConfigError(
            f"add_harness_middleware: tool {name!r} cannot be wrapped "
            f"({type(e).__name__})"
        ) from None
    if not same_schema:
        raise ConfigError(
            f"add_harness_middleware: tool {name!r} would change its parameter "
            "schema when gated"
        )
    return gated
