"""SHAI integration for LangChain.

Provides wrap_tool() which wraps any LangChain BaseTool with a gated
version that calls harness.check_tool_call before executing.

Usage::

    from harness.integrations.langchain import wrap_tool, wrap_tools

    # Wrap a single tool
    gated_search = wrap_tool(search_tool, harness=harness, ctx=ctx)

    # Wrap a list of tools for an agent
    gated_tools = wrap_tools([search_tool, send_email_tool], harness=harness, ctx=ctx)
    agent = create_react_agent(llm, gated_tools)

LangChain is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import Harness

log = logging.getLogger(__name__)


def wrap_tool(tool: Any, *, harness: "Harness", ctx: "AgentContext") -> Any:
    """Return a gated version of a LangChain tool.

    The returned tool has the same name, description, and schema as the
    original. All calls are gated through harness.check_tool_call.
    Denied calls raise ToolException so the agent can continue.
    """
    try:
        from langchain_core.tools import BaseTool, ToolException
    except ImportError as e:
        raise ImportError(
            "langchain-core is required for wrap_tool. pip install langchain-core"
        ) from e

    import asyncio

    original = tool
    harness_ = harness
    ctx_ = ctx

    class _GatedTool(BaseTool):
        name: str = original.name if hasattr(original, "name") else str(original)
        description: str = getattr(original, "description", "")

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            return asyncio.get_event_loop().run_until_complete(self._arun(*args, **kwargs))

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs or ({"input": args[0]} if args else {})
            gate = await harness_.check_tool_call(self.name, tool_args, ctx_)
            if not gate.allowed:
                log.info(
                    "tool call denied",
                    extra={"tool": self.name, "reason": gate.deny_reason,
                           **ctx_.to_log_fields()},
                )
                raise ToolException(f"Tool call denied: {gate.deny_reason}")
            effective = gate.redacted_args if gate.redacted_args is not None else tool_args
            if asyncio.iscoroutinefunction(getattr(original, "arun", None)):
                return await original.arun(**effective)
            return await asyncio.to_thread(original.run, **effective)

    gated = _GatedTool()
    # Copy args_schema if present so the LLM gets the right function spec
    if hasattr(original, "args_schema") and original.args_schema is not None:
        gated.__class__.args_schema = original.args_schema
    return gated


def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: "Harness",
    ctx: "AgentContext",
) -> list[Any]:
    """Wrap a list of LangChain tools. Convenience wrapper around wrap_tool."""
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]
