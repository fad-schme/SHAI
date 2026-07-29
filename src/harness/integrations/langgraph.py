"""SHAI integration for LangGraph.

Provides HarnessToolNode — drop-in for LangGraph's ToolNode — and the
shai_tool decorator for defining tools once with full SHAI metadata.

Quickstart::

    from harness.integrations.langgraph import shai_tool, HarnessToolNode

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str:
        \"\"\"Search internal documentation.\"\"\"
        return _impl(query)

    @shai_tool(tags=["external_write"])
    async def send_email(to: str, subject: str, body: str) -> str:
        \"\"\"Send an email.\"\"\"
        return await _impl(to, subject, body)

    tools = [search_docs, send_email]

    harness  = await SHAI.from_yaml("config/harness.yaml")
    ctx      = await harness.load_agent("config/agents/my_agent.yaml")
    llm      = ChatOllama(...).bind_tools(tools)
    node     = await HarnessToolNode.create(tools, harness, ctx)

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", node)
    ...

HarnessToolNode.create() calls register_tools() internally — no separate
harness.register_tools() call needed.

Subagent handoff::

    child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")
    child_node = await HarnessToolNode.create(tools, harness, child_ctx)

LangGraph is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import (  # shai_tool re-exported
    execute_gated_tool_call,
    invoke_tool,
    shai_tool,
)

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

log = logging.getLogger(__name__)

__all__ = ["shai_tool", "HarnessToolNode"]


class HarnessToolNode:
    """LangGraph node that gates tool calls through the harness.

    Drop-in replacement for langgraph.prebuilt.ToolNode.

    Per tool call:
      1. check_tool_call  — gate (policy, capability, rate limit, arg scan)
      2. invoke tool      — only if gate allows
      3. scan_tool_result — scan result for indirect injection before LLM sees it
      4. return ToolMessage — allowed result or denial/block reason as error

    Preferred constructor: await HarnessToolNode.create(tools, harness, ctx)
    This registers tools with the harness automatically.
    """

    def __init__(
        self,
        tools: Sequence[Any],
        harness: SHAI,
        ctx: AgentContext,
    ) -> None:
        self._tools   = {self._tool_name(t): t for t in tools}
        self._harness = harness
        self._ctx     = ctx

    @classmethod
    async def create(
        cls,
        tools: Sequence[Any],
        harness: SHAI,
        ctx: AgentContext,
    ) -> HarnessToolNode:
        """Preferred constructor — registers tools then builds the node.

        Accepts ShaiTool instances (from @shai_tool) or plain Tool descriptors.
        Calls harness.register_tools() internally so you don't have to.

        Args:
            tools:   list of @shai_tool-decorated functions (or plain callables
                     with SHAI Tool descriptors already registered separately)
            harness: the SHAI instance from await SHAI.from_yaml(...)
            ctx:     AgentContext from await harness.load_agent(...)
        """
        await harness.register_tools(tools)
        return cls(tools, harness, ctx)

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph node entrypoint."""
        try:
            from langchain_core.messages import AIMessage, ToolMessage
        except ImportError as e:
            raise ImportError(
                "langchain-core is required for HarnessToolNode. "
                "pip install langchain-core"
            ) from e

        messages = state.get("messages", [])
        last = messages[-1] if messages else None
        if not isinstance(last, AIMessage) or not last.tool_calls:
            return state

        results: list[ToolMessage] = []
        for tool_call in last.tool_calls:
            name    = tool_call["name"]
            args    = tool_call["args"]
            call_id = tool_call["id"]

            # No local callable → let the helper dispatch through the MCP
            # source the gate resolved, carrying the dispatch token. The
            # lookup stays inside invoke so the gate runs, and records, first.
            tool_fn = self._tools.get(name)
            invoke = (
                (lambda a, _t=tool_fn: invoke_tool(_t, a))
                if tool_fn is not None else None
            )

            try:
                call = await execute_gated_tool_call(
                    harness=self._harness,
                    ctx=self._ctx,
                    tool_name=name,
                    tool_args=args,
                    invoke=invoke,
                )
            except Exception as exc:
                # One failing tool must not abort the rest of the batch.
                log.error("tool execution error",
                          extra={"tool": name, "error": str(exc),
                                 **self._ctx.to_log_fields()})
                results.append(ToolMessage(
                    content=f"Tool error: {exc}",
                    tool_call_id=call_id,
                    status="error",
                ))
                continue

            if not call.allowed:
                results.append(ToolMessage(
                    content=call.message,
                    tool_call_id=call_id,
                    status="error",
                ))
                continue

            results.append(ToolMessage(
                content=call.text,
                tool_call_id=call_id,
            ))

        return {"messages": results}

    @staticmethod
    def _tool_name(tool: Any) -> str:
        if hasattr(tool, "name"):
            return tool.name
        if hasattr(tool, "__name__"):
            return tool.__name__
        return str(tool)
