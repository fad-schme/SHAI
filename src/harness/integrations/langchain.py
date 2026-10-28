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
import copy
import dataclasses
import logging
import re
import threading
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from harness.core.normalize import canonicalize
from harness.integrations.base import (  # shai_tool re-exported
    BLOCKED_RESULT_MESSAGE,
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
            messages = state.get("messages", [])
            user_text = _last_human_message(messages)
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
            if verdict.redacted_text:
                return _redacted_input_update(messages, verdict.redacted_text)
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
                try:
                    return _replace_result_text(call.result, call.verdict.redacted_text)
                except _ResultNotRewritable:
                    # The scan supplied a replacement this result's shape cannot
                    # carry. Returning the raw result would hand the model the
                    # text the scan just redacted, so the call takes the same
                    # denial a blocked result gets. Type names only in the log.
                    log.warning(
                        "tool result could not be rewritten — blocked",
                        extra={"tool": tool_name,
                               "result_type": type(call.result).__name__,
                               **self._ctx.to_log_fields()},
                    )
                    return self._denial_artifact(request, BLOCKED_RESULT_MESSAGE)
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
            """scan_output — once after the loop completes.

            Runs whenever the turn produced an AI message OR signals are still
            attached: the boundary computes the consolidated turn risk and
            clears TurnSignals (Invariant 7). Skipping it on a run that ended
            on a tool-calling message left that message's text unscanned and
            leaked the turn's signals into the next turn. A block or redaction
            REPLACES the final message (same mechanics as the input side) —
            appending a sanitized copy left the raw text in graph state and
            checkpoints, where it re-enters the model's context next turn.
            """
            messages = state.get("messages", [])
            final = _last_ai_message(messages)
            if final is None and self._ctx.turn_signals is None:
                return None
            response = str(final.content) if final is not None else ""
            verdict = await self._harness.scan_output(response, self._ctx)
            if verdict.blocked:
                log.warning("scan_output blocked",
                            extra={"findings": len(verdict.findings),
                                   **self._ctx.to_log_fields()})
                return _replaced_output_update(
                    messages, final, "[Response blocked by security policy]"
                )
            if verdict.redacted_text:
                return _replaced_output_update(messages, final, verdict.redacted_text)
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


def _redacted_input_update(messages: list, redacted: str) -> dict:
    """State update that replaces the last human message with redacted text.

    LangGraph's message reducer replaces a message that shares an id with an
    existing one and appends otherwise. A message in graph state normally has an
    id (the reducer assigns one on entry); when it has none the replacement
    cannot be keyed to it, so the update clears the list and restores it with
    the redacted message in place — still one human message, never two.
    """
    from langchain_core.messages import HumanMessage
    index = max(i for i, m in enumerate(messages) if isinstance(m, HumanMessage))
    original = messages[index]
    replacement = original.model_copy(update={"content": redacted})
    if original.id is not None:
        return {"messages": [replacement]}
    from langchain_core.messages import RemoveMessage
    from langgraph.graph.message import REMOVE_ALL_MESSAGES
    rebuilt = list(messages)
    rebuilt[index] = replacement
    return {"messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *rebuilt]}


def _last_ai_message(messages: list):
    """The final AIMessage, tool-calling or not — its text is what scan_output
    covers. Returns the message object (its content may be empty), or None
    when the run produced no AI message at all."""
    try:
        from langchain_core.messages import AIMessage
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                return msg
    except ImportError:
        pass
    return None


def _replaced_output_update(messages: list, final: Any, new_text: str) -> dict:
    """State update that replaces the final AI message's content with new_text.

    Same id-or-rebuild mechanics as _redacted_input_update, so the raw blocked
    or un-redacted text does not survive in graph state and checkpoints beside
    the sanitized copy. With no AI message to replace (a consolidated-risk
    block on a turn that ended without one), the notice is appended instead.
    """
    from langchain_core.messages import AIMessage
    if final is None:
        return {"messages": [AIMessage(content=new_text)]}
    replacement = final.model_copy(update={"content": new_text})
    if final.id is not None:
        return {"messages": [replacement]}
    from langchain_core.messages import RemoveMessage
    from langgraph.graph.message import REMOVE_ALL_MESSAGES
    index = max(i for i, m in enumerate(messages) if m is final)
    rebuilt = list(messages)
    rebuilt[index] = replacement
    return {"messages": [RemoveMessage(id=REMOVE_ALL_MESSAGES), *rebuilt]}


class _ResultNotRewritable(Exception):
    """A tool result carries text the extractor reads but the replacer cannot
    write back. Raised so the caller fails closed; never swallowed."""


def _command_messages(result: Any) -> list | None:
    """A Command's message list, or None when it carries no messages."""
    try:
        from langgraph.types import Command
    except ImportError:  # langgraph absent: no result can be a Command
        return None
    if not isinstance(result, Command):
        return None
    update = result.update
    if not isinstance(update, dict):
        return None
    messages = update.get("messages")
    if not messages:
        return None
    if isinstance(messages, (list, tuple)):
        return list(messages)
    if isinstance(messages, (str, dict)) or hasattr(messages, "content"):
        return [messages]      # add_messages accepts one message in place of a list
    return None                # a shape this reader does not know: read as str(result)


def _with_content(obj: Any, text: str) -> Any:
    """A copy of obj whose `content` is text; obj itself is not touched.

    A pydantic message is copied with model_copy. Anything else is shallow-copied
    and written to, and an object that refuses the write is not rewritable.
    """
    if hasattr(obj, "model_copy"):
        return obj.model_copy(update={"content": text})
    clone = copy.copy(obj)
    try:
        clone.content = text
    except (AttributeError, TypeError) as exc:
        raise _ResultNotRewritable(type(obj).__name__) from exc
    return clone


# The text a tool result carries, and where it lives. The extractor and the
# replacer both read this one table, so a shape one can read the other can
# write or refuse by name:
#   Command with messages  → every message's text, joined by _MESSAGE_SEP, where a
#                            message is an object with `content`, a dict with
#                            "content", a (role, content) tuple or list, or a str;
#                            non-message update keys are appended to the scanned
#                            text (they enter graph state) and make the Command
#                            not rewritable — a redaction then fails closed.
#   str                    → the string itself
#   dict of only "content" → that entry
#   any other dict         → str of the WHOLE dict — the framework serialises
#                            every key into the ToolMessage, so a payload
#                            outside "content" enters context too; such a dict
#                            is not rewritable (scanning a projection while
#                            returning the whole object was an unscanned channel)
#   object with `content`  → that attribute
# Any other shape is read as str(result) and is not rewritable.
#
# A Command's messages are scanned as one text, so one scan and one audit event
# cover the whole result. _MESSAGE_SEP joins them and splits a redaction back into
# per-message pieces. The separator is set off by spaces, and the scan's normalised
# view collapses whitespace around it, so it is split on `\s*␞\s*`; a redaction
# pattern that runs to the end of a word cannot cross it; a redaction whose pieces
# do not number one per message, or a message that itself holds the separator
# character, cannot be written back and is refused (fail closed), never guessed.
_MESSAGE_SEP = " \u241e "
_SEP_CHAR = "\u241e"
_SEP_SPLIT = re.compile(r"\s*\u241e\s*")


def _surface_form(text: str) -> str:
    """The text as the scan's folded surface view carries it, from the one
    normaliser. A message whose redacted piece equals this held nothing to redact
    and is returned as it was."""
    return canonicalize(text, decode=False).views[0]


def _message_text(message: Any) -> str:
    """The text one Command message carries. A shape with no readable text is read
    as str(message) so that it is still scanned."""
    if isinstance(message, str):
        return message
    if isinstance(message, dict) and "content" in message:
        return str(message["content"])
    if isinstance(message, (tuple, list)) and len(message) == 2:
        return str(message[1])
    if hasattr(message, "content"):
        return str(message.content)
    return str(message)


def _message_with_text(message: Any, text: str) -> Any:
    """A copy of one Command message carrying text; the original is not touched."""
    if isinstance(message, str):
        return text
    if isinstance(message, dict) and "content" in message:
        return {**message, "content": text}
    if isinstance(message, (tuple, list)) and len(message) == 2:
        return (message[0], text) if isinstance(message, tuple) else [message[0], text]
    if hasattr(message, "content"):
        return _with_content(message, text)
    raise _ResultNotRewritable(type(message).__name__)


def _command_extra(result: Any) -> str | None:
    """A Command's non-message update entries as one scannable string, or None.

    They enter graph state and are readable by later model turns, so the scan
    must cover them; their shapes are arbitrary, so they are never rewritten."""
    rest = {k: v for k, v in result.update.items() if k != "messages"}
    return str(rest) if rest else None


def _extract_result_text(result: Any) -> str | None:
    if result is None:
        return None
    messages = _command_messages(result)
    if messages:
        joined = _MESSAGE_SEP.join(_message_text(m) for m in messages)
        extra = _command_extra(result)
        return joined if extra is None else f"{joined}{_MESSAGE_SEP}{extra}"
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if set(result) <= {"content"}:
            return str(result.get("content", ""))
        return str(result)
    if hasattr(result, "content"):
        return str(result.content)
    return str(result)


def _replace_result_text(result: Any, new_text: str) -> Any:
    """The result with its text replaced; a new object, never a mutation.

    Raises _ResultNotRewritable for a shape that cannot carry the replacement.
    """
    messages = _command_messages(result)
    if messages:
        if _command_extra(result) is not None:
            # Non-message update keys were part of the scanned text and have
            # no rewritable home — the caller falls back to a denial.
            raise _ResultNotRewritable(type(result).__name__)
        texts = [_message_text(m) for m in messages]
        if len(messages) == 1:
            pieces = [new_text]
        else:
            if any(_SEP_CHAR in t for t in texts):
                raise _ResultNotRewritable(type(result).__name__)
            pieces = _SEP_SPLIT.split(new_text)
            if len(pieces) != len(messages):
                raise _ResultNotRewritable(type(result).__name__)
        rewritten = []
        for message, text, piece in zip(messages, texts, pieces, strict=True):
            keep = piece == text or piece == _surface_form(text)
            rewritten.append(message if keep else _message_with_text(message, piece))
        single = not isinstance(result.update["messages"], (list, tuple))
        return dataclasses.replace(
            result, update={**result.update, "messages": rewritten[0] if single else rewritten})
    if isinstance(result, str):
        return new_text
    if isinstance(result, dict):
        if set(result) <= {"content"}:
            return {**result, "content": new_text}
        # The scan covered the whole dict (see the table above); writing the
        # redacted whole into "content" would corrupt the shape, so refuse.
        raise _ResultNotRewritable("dict")
    if hasattr(result, "content"):
        return _with_content(result, new_text)
    raise _ResultNotRewritable(type(result).__name__)


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
