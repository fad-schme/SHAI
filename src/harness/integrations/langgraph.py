"""SHAI integration for LangGraph.

Provides a HarnessToolNode that replaces LangGraph's standard ToolNode.
It gates every tool call through harness.check_tool_call before executing.

Usage::

    from harness.integrations.langgraph import HarnessToolNode

    tool_node = HarnessToolNode(tools=[search, send_email], harness=harness, ctx=ctx)

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent)
    graph.add_node("tools", tool_node)
    graph.add_edge("tools", "agent")
    graph.add_conditional_edges("agent", should_continue)

Subagent handoff::

    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    child_node = HarnessToolNode(tools=[search], harness=harness, ctx=child_ctx)

LangGraph is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from harness.core.context import RuntimeContext
    from harness.core.harness import Harness

log = logging.getLogger(__name__)


class HarnessToolNode:
    """LangGraph node that gates tool calls through the harness.

    Drop-in replacement for langgraph.prebuilt.ToolNode.
    Denied tool calls are returned as ToolMessage errors so the agent
    can continue the conversation rather than raising an exception.
    """

    def __init__(
        self,
        tools: Sequence[Any],
        harness: "Harness",
        ctx: "RuntimeContext",
    ) -> None:
        self._tools = {self._tool_name(t): t for t in tools}
        self._harness = harness
        self._ctx = ctx

    async def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        """LangGraph node entrypoint. Receives graph state, returns updated state."""
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
            name = tool_call["name"]
            args = tool_call["args"]
            call_id = tool_call["id"]

            gate = await self._harness.check_tool_call(name, args, self._ctx)
            if not gate.allowed:
                log.info(
                    "tool call denied",
                    extra={"tool": name, "reason": gate.deny_reason,
                           **self._ctx.to_log_fields()},
                )
                results.append(ToolMessage(
                    content=f"Tool call denied: {gate.deny_reason}",
                    tool_call_id=call_id,
                    status="error",
                ))
                continue

            effective_args = gate.redacted_args if gate.redacted_args is not None else args
            tool_fn = self._tools.get(name)
            if tool_fn is None:
                results.append(ToolMessage(
                    content=f"Tool '{name}' not found in node tools list",
                    tool_call_id=call_id,
                    status="error",
                ))
                continue

            try:
                result = await self._invoke_tool(tool_fn, effective_args)
                results.append(ToolMessage(
                    content=str(result),
                    tool_call_id=call_id,
                ))
            except Exception as exc:
                log.error(
                    "tool execution error",
                    extra={"tool": name, "error": str(exc), **self._ctx.to_log_fields()},
                )
                results.append(ToolMessage(
                    content=f"Tool error: {exc}",
                    tool_call_id=call_id,
                    status="error",
                ))

        return {"messages": results}

    @staticmethod
    async def _invoke_tool(tool: Any, args: dict[str, Any]) -> Any:
        """Invoke a LangChain tool (sync or async)."""
        import asyncio
        if asyncio.iscoroutinefunction(getattr(tool, "ainvoke", None)):
            return await tool.ainvoke(args)
        if asyncio.iscoroutinefunction(getattr(tool, "arun", None)):
            return await tool.arun(**args)
        if callable(getattr(tool, "invoke", None)):
            return await asyncio.to_thread(tool.invoke, args)
        if callable(tool):
            return await asyncio.to_thread(tool, **args)
        raise TypeError(f"Cannot invoke tool of type {type(tool)}")

    @staticmethod
    def _tool_name(tool: Any) -> str:
        if hasattr(tool, "name"):
            return tool.name
        if hasattr(tool, "__name__"):
            return tool.__name__
        return str(tool)
