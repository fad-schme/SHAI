"""SHAI integration for LangChain.

Two integration patterns:

Pattern A — wrap_tools() for any LangChain version::

    from harness.integrations.langchain import shai_tool, wrap_tools
    from langchain.agents import create_react_agent

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str: ...

    gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
    agent = create_react_agent(llm, gated)

Pattern B — ShaiMiddleware for LangChain Agent Loop (langchain>=0.3)::

    from harness.integrations.langchain import shai_tool, ShaiMiddleware
    from langchain.agents import create_agent

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str: ...

    agent = create_agent(
        "ollama:qwen2.5:3b",
        tools=[search_docs],
        middleware=[await ShaiMiddleware.create([search_docs], harness=harness, ctx=ctx)],
    )

    with harness.collect_events() as events:
        result = await agent.ainvoke({"messages": [HumanMessage(question)]})

ShaiMiddleware uses the official LangChain middleware API:
  before_agent  → scan_input
  wrap_tool_call → check_tool_call (gate) + scan_tool_result (after dispatch)
  after_agent   → scan_output

LangChain is imported lazily — this module is importable without it installed.
"""
from __future__ import annotations

import asyncio
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

__all__ = ["shai_tool", "wrap_tool", "wrap_tools", "ShaiMiddleware"]


# ── Pattern A — wrap_tools (any LangChain version) ────────────────────────

def wrap_tool(tool: Any, *, harness: SHAI, ctx: AgentContext) -> Any:
    """Return a gated LangChain-compatible version of a tool.

    Accepts ShaiTool (from @shai_tool) or any LangChain BaseTool.
    Denied calls raise ToolException so the agent can continue.
    Note: does not call register_tools(). Use wrap_tools() for that.
    """
    try:
        from langchain_core.tools import BaseTool, ToolException
    except ImportError as e:
        raise ImportError(
            "langchain-core is required for wrap_tool. pip install langchain-core"
        ) from e

    harness_ = harness
    ctx_     = ctx
    original = tool

    class _GatedTool(BaseTool):
        name: str        = original.name if hasattr(original, "name") else str(original)
        description: str = getattr(original, "description", "")

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            return asyncio.run(self._arun(*args, **kwargs))

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            tool_args = kwargs or ({"input": args[0]} if args else {})
            call = await execute_gated_tool_call(
                harness=harness_,
                ctx=ctx_,
                tool_name=self.name,
                tool_args=tool_args,
                invoke=lambda a: invoke_tool(original, a),
            )
            if not call.allowed:
                raise ToolException(call.message)
            return call.text

    gated = _GatedTool()
    if hasattr(original, "args_schema") and original.args_schema is not None:
        gated.__class__.args_schema = original.args_schema
    return gated


async def wrap_tools(
    tools: Sequence[Any],
    *,
    harness: SHAI,
    ctx: AgentContext,
) -> list[Any]:
    """Register tools with the harness and return gated LangChain wrappers."""
    await harness.register_tools(tools)
    return [wrap_tool(t, harness=harness, ctx=ctx) for t in tools]


# ── Pattern B — ShaiMiddleware (LangChain Agent Loop, langchain>=0.3) ─────

def _build_shai_middleware_class() -> type:
    """Build ShaiMiddleware as a true AgentMiddleware subclass.

    Called once on first use so the import is lazy — this module stays
    importable without langchain installed.
    """
    from langchain.agents.middleware import AgentMiddleware

    class ShaiMiddleware(AgentMiddleware):
        """SHAI security middleware for the LangChain Agent Loop (langchain>=0.3).

        Wires all four SHAI scan boundaries into create_agent's hook system:
          abefore_agent   -> scan_input
          awrap_tool_call -> check_tool_call + scan_tool_result
          aafter_agent    -> scan_output

        Usage::

            middleware = await ShaiMiddleware.create(tools, harness=harness, ctx=ctx)
            agent = create_agent(llm, tools=tools, middleware=[middleware])

            with harness.collect_events() as events:
                result = await agent.ainvoke({"messages": [HumanMessage(question)]})
        """

        name = "shai"

        def __init__(self, harness: Any, ctx: Any) -> None:
            super().__init__()
            self._harness = harness
            self._ctx     = ctx

        @classmethod
        async def create(cls, tools: Any, *, harness: Any, ctx: Any) -> ShaiMiddleware:
            """Preferred constructor — registers tools then builds the middleware."""
            await harness.register_tools(tools)
            return cls(harness=harness, ctx=ctx)

        # ── Sync stubs — required for class inspection at create_agent() ─
        def before_agent(self, state: Any, runtime: Any = None) -> Any: return None
        def before_model(self, state: Any, runtime: Any = None) -> Any: return None
        def after_model(self, state: Any, runtime: Any = None) -> Any: return None
        def after_agent(self, state: Any, runtime: Any = None) -> Any: return None
        def wrap_model_call(self, request: Any, handler: Any) -> Any: return handler(request)
        def wrap_tool_call(self, request: Any, handler: Any) -> Any: return handler(request)

        # ── Async implementations — called by ainvoke() / astream() ───────

        async def abefore_agent(self, state: Any, runtime: Any = None) -> Any:
            """scan_input — once before the loop starts."""
            user_text = _last_human_message(state.get("messages", []))
            if not user_text:
                return None
            verdict = await self._harness.scan_input(user_text, self._ctx)
            if verdict.blocked:
                log.warning("scan_input blocked",
                            extra={"findings": len(verdict.findings),
                                   **self._ctx.to_log_fields()})
                from langchain_core.messages import AIMessage
                return {
                    "messages": [AIMessage(
                        content="I cannot process this request — "
                                "it was blocked by the security policy."
                    )],
                    "jump_to": "end",
                }
            if verdict.warned:
                log.warning("scan_input flagged (action=alert)",
                            extra={"findings": len(verdict.findings),
                                   **self._ctx.to_log_fields()})
            return None

        async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
            """check_tool_call + scan_tool_result — around every tool call."""
            tool_name = _tool_name_from_request(request)
            tool_args = _tool_args_from_request(request)

            async def _invoke(effective: dict[str, Any]) -> Any:
                # The handler owns dispatch — substitute the gate's args into
                # the request rather than calling the tool ourselves.
                req = (_replace_args_in_request(request, effective)
                       if effective is not tool_args else request)
                return await _await_if_needed(handler(req))

            call = await execute_gated_tool_call(
                harness=self._harness,
                ctx=self._ctx,
                tool_name=tool_name,
                tool_args=tool_args,
                invoke=_invoke,
                extract_text=_extract_result_text,
            )

            if not call.allowed:
                return self._denial_artifact(request, call.message)
            if call.verdict is not None and call.verdict.redacted_text:
                return _replace_result_text(call.result, call.verdict.redacted_text)
            return call.result

        @staticmethod
        def _denial_artifact(request: Any, message: str) -> Any:
            """Render a denial as a graph update, or plain text when the
            graph types are unavailable."""
            try:
                from langchain_core.messages import ToolMessage
                from langgraph.types import Command
                return Command(update={
                    "messages": [ToolMessage(
                        content=message,
                        tool_call_id=_tool_call_id_from_request(request),
                    )]
                })
            except ImportError:
                return message

        async def aafter_agent(self, state: Any, runtime: Any = None) -> Any:
            """scan_output — once after the loop completes."""
            response = _last_ai_message(state.get("messages", []))
            if not response:
                return None
            verdict = await self._harness.scan_output(response, self._ctx)
            if verdict.blocked:
                log.warning("scan_output blocked",
                            extra={"findings": len(verdict.findings),
                                   **self._ctx.to_log_fields()})
                from langchain_core.messages import AIMessage
                return {"messages": [AIMessage(content="[Response blocked by security policy]")]}
            if verdict.redacted_text:
                from langchain_core.messages import AIMessage
                return {"messages": [AIMessage(content=verdict.redacted_text)]}
            return None

        async def abefore_model(self, state: Any, runtime: Any = None) -> Any: return None
        async def aafter_model(self, state: Any, runtime: Any = None) -> Any: return None
        async def awrap_model_call(self, request: Any, handler: Any) -> Any:
            return await _await_if_needed(handler(request))

    return ShaiMiddleware


# Build the class once and expose it as a module-level name.
# Wrapped in a try so the module stays importable without langchain installed.
try:
    ShaiMiddleware = _build_shai_middleware_class()
except ImportError:
    class ShaiMiddleware:  # type: ignore[no-redef]
        """Placeholder — requires pip install 'langchain>=0.3'."""
        name = "shai"

        def __init__(self, *a: Any, **kw: Any) -> None:
            raise ImportError(
                "ShaiMiddleware requires langchain>=0.3. "
                "pip install 'langchain>=0.3' langgraph"
            )

        @classmethod
        async def create(cls, tools: Any, *, harness: Any, ctx: Any) -> ShaiMiddleware:
            raise ImportError(
                "ShaiMiddleware requires langchain>=0.3. "
                "pip install 'langchain>=0.3' langgraph"
            )


# ── Private helpers ────────────────────────────────────────────────────────

def _last_human_message(messages: list) -> str | None:
    try:
        from langchain_core.messages import HumanMessage
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage):
                return str(msg.content)
    except ImportError:
        pass
    return None


def _last_ai_message(messages: list) -> str | None:
    try:
        from langchain_core.messages import AIMessage
        for msg in reversed(messages):
            if isinstance(msg, AIMessage) and not getattr(msg, "tool_calls", None):
                return str(msg.content)
    except ImportError:
        pass
    return None


def _tool_name_from_request(request: Any) -> str:
    if hasattr(request, "name"):
        return str(request.name)
    if hasattr(request, "tool"):
        return str(getattr(request.tool, "name", request.tool))
    return str(request)


def _tool_args_from_request(request: Any) -> dict:
    for attr in ("args", "input", "kwargs"):
        val = getattr(request, attr, None)
        if isinstance(val, dict):
            return val
    return {}


def _tool_call_id_from_request(request: Any) -> str:
    return str(getattr(request, "id", getattr(request, "tool_call_id", "")))


def _replace_args_in_request(request: Any, new_args: dict) -> Any:
    try:
        import copy
        r = copy.copy(request)
        for attr in ("args", "input", "kwargs"):
            if hasattr(r, attr) and isinstance(getattr(r, attr), dict):
                object.__setattr__(r, attr, new_args)
                return r
    except Exception:  # nosec B110 — best-effort mutation of unknown LangChain request type; original returned on failure
        pass
    return request


def _extract_result_text(result: Any) -> str | None:
    if result is None:
        return None
    try:
        from langgraph.types import Command
        if isinstance(result, Command):
            msgs = (result.update or {}).get("messages", [])
            if msgs:
                return str(getattr(msgs[-1], "content", ""))
    except ImportError:
        pass
    if isinstance(result, str):
        return result
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)


def _replace_result_text(result: Any, new_text: str) -> Any:
    try:
        from langgraph.types import Command
        if isinstance(result, Command):
            msgs = list((result.update or {}).get("messages", []))
            if msgs and hasattr(msgs[-1], "content"):
                object.__setattr__(msgs[-1], "content", new_text)
            return result
    except ImportError:
        pass
    if hasattr(result, "content"):
        try:
            object.__setattr__(result, "content", new_text)
        except Exception:  # nosec B110 — best-effort mutation of frozen LangChain result type; original returned on failure
            pass
    return result


async def _await_if_needed(value: Any) -> Any:
    import inspect
    if inspect.isawaitable(value):
        return await value
    return value
