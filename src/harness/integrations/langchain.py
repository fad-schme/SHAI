"""SHAI integration for LangChain.

Two integration patterns:

Pattern A — wrap_tools() for any LangChain version::

    from harness.integrations.langchain import shai_tool, wrap_tools
    from langchain.agents import create_react_agent

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str: ...

    gated = await wrap_tools([search_docs], harness=harness, ctx=ctx)
    agent = create_react_agent(llm, gated)

Pattern B — ShaiMiddleware for LangChain Agent Loop (langchain>=1.0)::

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
import contextvars
import logging
import threading
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from harness.integrations.base import (  # shai_tool re-exported
    execute_gated_tool_call,
    invoke_tool,
    run_sync,
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
            return run_sync(self._arun(*args, **kwargs))

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


# ── Pattern B — ShaiMiddleware (LangChain Agent Loop, langchain>=1.0) ─────

def _build_shai_middleware_class() -> type:
    """Build ShaiMiddleware as a true AgentMiddleware subclass.

    Called once on first use so the import is lazy — this module stays
    importable without langchain installed.
    """
    from langchain.agents.middleware import AgentMiddleware, hook_config

    class ShaiMiddleware(AgentMiddleware):
        """SHAI security middleware for the LangChain Agent Loop (langchain>=1.0).

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

        # ── Sync hooks — agent.invoke() runs the same boundaries as ainvoke() ─
        # Each boundary hook delegates to its async twin, so there is one
        # implementation of the boundary logic. before_model / after_model /
        # wrap_model_call carry no boundary; create_agent needs them defined.
        # can_jump_to: LangChain ignores a hook's jump_to unless the hook
        # declares its targets, and a blocked input must not reach the model.
        @hook_config(can_jump_to=["end"])
        def before_agent(self, state: Any, runtime: Any = None) -> Any:
            return run_sync(self.abefore_agent(state, runtime))
        def before_model(self, state: Any, runtime: Any = None) -> Any: return None
        def after_model(self, state: Any, runtime: Any = None) -> Any: return None
        def after_agent(self, state: Any, runtime: Any = None) -> Any:
            return run_sync(self.aafter_agent(state, runtime))
        def wrap_model_call(self, request: Any, handler: Any) -> Any: return handler(request)
        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            # The sync handler runs the tool; a worker thread keeps it off the
            # shared bridge loop so parallel tool calls stay parallel.
            async def _dispatch(req: Any) -> Any:
                return await _run_in_thread(handler, req)
            return run_sync(self.awrap_tool_call(request, _dispatch))

        # ── Async implementations — called by ainvoke() / astream() ───────

        @hook_config(can_jump_to=["end"])
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
            # The call is request.tool_call — {name, args, id}. request.tool is
            # None for a name the agent's tool list does not hold, so the name
            # comes from the call, which the gate must see either way.
            tool_call = request.tool_call
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            async def _invoke(effective: dict[str, Any]) -> Any:
                # The handler owns dispatch — substitute the gate's args into a
                # copy of the request rather than calling the tool ourselves.
                req = (request if effective is tool_args
                       else request.override(tool_call={**tool_call, "args": effective}))
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
                        tool_call_id=request.tool_call["id"],
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
        """Placeholder — requires pip install 'langchain>=1.0'."""
        name = "shai"

        def __init__(self, *a: Any, **kw: Any) -> None:
            raise ImportError(
                "ShaiMiddleware requires langchain>=1.0. "
                "pip install 'langchain>=1.0' langgraph"
            )

        @classmethod
        async def create(cls, tools: Any, *, harness: Any, ctx: Any) -> ShaiMiddleware:
            raise ImportError(
                "ShaiMiddleware requires langchain>=1.0. "
                "pip install 'langchain>=1.0' langgraph"
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
        # Best-effort mutation of a frozen LangChain result type; on failure the
        # original result is returned unchanged.
        except Exception:  # nosec B110
            pass
    return result


async def _run_in_thread(fn: Any, *args: Any) -> Any:
    """Run a sync tool body on a thread of its own, with the caller's context.

    A pool would cap concurrent bodies, and a body that runs another sync gated
    call (an agent used as a tool) waits on a thread it needs itself. Neither the
    bridge loop's executor, which the audit sinks write through, nor a tool pool
    is shared.
    """
    loop = asyncio.get_running_loop()
    done: asyncio.Future[Any] = loop.create_future()
    ctx = contextvars.copy_context()

    def settle(result: Any, exc: BaseException | None) -> None:
        if done.done():                         # the awaiting task was cancelled
            return
        if exc is not None:
            done.set_exception(exc)
        else:
            done.set_result(result)

    def body() -> None:
        try:
            result = ctx.run(fn, *args)
        except BaseException as exc:
            loop.call_soon_threadsafe(settle, None, exc)
        else:
            loop.call_soon_threadsafe(settle, result, None)

    threading.Thread(target=body, name="shai-tool").start()
    return await done


async def _await_if_needed(value: Any) -> Any:
    import inspect
    if inspect.isawaitable(value):
        return await value
    return value
