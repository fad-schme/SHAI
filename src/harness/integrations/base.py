"""harness.integrations.base — framework-agnostic tool plumbing.

Owns two things every integration needs and none of them should reimplement:

  invoke_tool()              the one dispatch ladder — ShaiTool, LangChain
                             tools, plain sync/async callables.
  execute_gated_tool_call()  the boundary contract — check_tool_call, arg
                             substitution, invoke, scan_tool_result.

Every adapter runs the same sequence through execute_gated_tool_call and
renders the returned GatedCall into its own framework artifact (ToolMessage,
ToolException, Command, plain string). The security sequence lives here once;
only the rendering differs per framework.

Defines ShaiTool: the single object that is simultaneously:
  - A SHAI Tool descriptor (name, tags, transport, description)
  - A callable implementation (sync or async)
  - A LangChain-compatible BaseTool (for bind_tools, wrap_tool, HarnessToolNode)
  - A CrewAI / OpenAI Agents / PydanticAI compatible callable

Usage::

    from harness.integrations.base import shai_tool

    @shai_tool(tags=["read", "internal"])
    def search_docs(query: str) -> str:
        \"\"\"Search internal documentation for HR policies and procedures.\"\"\"
        return _search_impl(query)

    @shai_tool(tags=["external_write", "sensitive"])
    async def send_email(to: str, subject: str, body: str) -> str:
        \"\"\"Send an email to a recipient.\"\"\"
        return await _send_impl(to, subject, body)

    tools = [search_docs, send_email]

    # All three accept the same list:
    harness  = await SHAI.from_yaml(...)
    ctx      = await harness.load_agent(...)
    llm      = ChatOllama(...).bind_tools(tools)          # LangChain-compatible
    node     = await HarnessToolNode.create(tools, harness, ctx)  # registers + wires

The shai_tool decorator returns a ShaiTool instance. It preserves the
function's __name__, __doc__, and type annotations so framework inspection
(for schema generation, function calling spec) works correctly.
"""
from __future__ import annotations

import asyncio
import functools
import inspect
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from harness.core.types import Transport
from harness.tools.tool import Tool

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI
    from harness.core.verdicts import GateDecision, ScanVerdict

log = logging.getLogger(__name__)


class ShaiTool:
    """A tool with both security metadata and an implementation.

    Satisfies:
      - harness.tools.tool.Tool  (via .to_shai_tool())
      - LangChain BaseTool protocol (name, description, invoke, ainvoke)
      - Plain async callable (for CrewAI, PydanticAI, OpenAI Agents)

    Never construct directly — use the @shai_tool decorator.
    """

    def __init__(
        self,
        fn: Callable,
        *,
        tags:        list[str],
        transport:   Transport = Transport.LOCAL,
        name:        str | None = None,
        description: str | None = None,
    ) -> None:
        self._fn          = fn
        self._is_async    = asyncio.iscoroutinefunction(fn)

        # SHAI metadata
        self.tags        = list(tags)
        self.transport   = transport
        self.name        = name or fn.__name__
        self.description = description or (inspect.getdoc(fn) or "")

        # Preserve introspection attributes for framework schema generation
        functools.update_wrapper(self, fn)
        self.__name__    = self.name
        self.__doc__     = self.description
        self.__wrapped__ = fn

    # ── SHAI protocol ─────────────────────────────────────────────────────

    def to_shai_tool(self) -> Tool:
        """Return the SHAI Tool descriptor for this tool."""
        return Tool(
            name=self.name,
            tags=self.tags,
            transport=self.transport,
            description=self.description,
        )

    # ── Callable protocol ─────────────────────────────────────────────────

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Sync call — runs the underlying function (blocks if async)."""
        if self._is_async:
            return asyncio.run(self._fn(*args, **kwargs))
        return self._fn(*args, **kwargs)

    async def _async_call(self, *args: Any, **kwargs: Any) -> Any:
        """Internal async dispatch."""
        if self._is_async:
            return await self._fn(*args, **kwargs)
        return await asyncio.to_thread(self._fn, *args, **kwargs)

    # ── LangChain BaseTool protocol ────────────────────────────────────────
    # LangChain checks for .invoke() and .ainvoke() — we implement both.
    # The schema is derived from the wrapped function's type annotations.

    def invoke(self, input: Any, **kwargs: Any) -> Any:
        """LangChain sync invocation."""
        args = input if isinstance(input, dict) else {"input": input}
        if self._is_async:
            return asyncio.run(self._fn(**args))
        return self._fn(**args)

    async def ainvoke(self, input: Any, **kwargs: Any) -> Any:
        """LangChain async invocation."""
        args = input if isinstance(input, dict) else {"input": input}
        return await self._async_call(**args)

    # ── LangChain bind_tools compatibility ────────────────────────────────
    # bind_tools() inspects .name, .description, and the function signature
    # to build the JSON schema for the LLM. We expose these directly.

    @property
    def args_schema(self) -> Any:
        """Return a pydantic model for the function's args (for LangChain)."""
        try:
            from langchain_core.utils.function_calling import create_schema_from_function
            return create_schema_from_function(self.name, self._fn)
        except Exception:
            return None

    # ── repr ──────────────────────────────────────────────────────────────

    def __repr__(self) -> str:
        return (
            f"ShaiTool(name={self.name!r}, tags={self.tags!r}, "
            f"transport={self.transport!r})"
        )


def shai_tool(
    *,
    tags:        list[str],
    transport:   Transport = Transport.LOCAL,
    name:        str | None = None,
    description: str | None = None,
) -> Callable[[Callable], ShaiTool]:
    """Decorator that creates a ShaiTool from a plain function.

    Args:
        tags:        SHAI security tags — e.g. ["read", "internal"].
                     These drive policy rules, capability gates, and arg scanning.
        transport:   Transport.LOCAL (default) for Python callables.
                     Transport.SKILL for curated skill tools.
                     Transport.MCP for tools dispatched via MCPSource.
        name:        Override the tool name. Defaults to the function name.
        description: Override the description. Defaults to the docstring.

    Returns a ShaiTool that can be passed to:
        - HarnessToolNode.create(tools, harness, ctx)
        - harness.register_tools(tools)
        - llm.bind_tools(tools)           (LangChain)
        - wrap_tools(tools, ...)          (LangChain, CrewAI, OpenAI Agents)
        - any callable context (PydanticAI, hand-rolled loops)

    Example::

        @shai_tool(tags=["read", "internal"])
        def search_docs(query: str) -> str:
            \"\"\"Search internal documentation.\"\"\"
            return _impl(query)

        @shai_tool(tags=["external_write"], transport=Transport.LOCAL)
        async def send_email(to: str, subject: str, body: str) -> str:
            \"\"\"Send an email to a recipient.\"\"\"
            return await _impl(to, subject, body)
    """
    def decorator(fn: Callable) -> ShaiTool:
        return ShaiTool(
            fn,
            tags=tags,
            transport=transport,
            name=name,
            description=description,
        )
    return decorator


# ── The gated-call contract ───────────────────────────────────────────────

# Model-facing text. A blocked result never carries the scanner's reason:
# findings describe matched content, which must not be echoed back.
BLOCKED_RESULT_MESSAGE = "Tool result blocked by SHAI (indirect injection detected)"


@dataclass(frozen=True)
class GatedCall:
    """Outcome of running one tool call through the SHAI contract.

    status:
        allowed  — the call ran and its result passed scan_tool_result.
                   `text` is what the model may see (redacted when the scan
                   redacted); `result` is the raw tool return.
        denied   — the gate refused; the tool never ran. `gate` carries why.
        blocked  — the tool ran but its result was blocked as indirect
                   injection. `verdict` carries the findings.

    Invocation errors are not a status — they propagate to the caller, which
    is the framework's business, not the harness's.
    """
    status:  str
    text:    str | None = None
    result:  Any = None
    gate:    GateDecision | None = None
    verdict: ScanVerdict | None = None

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    @property
    def message(self) -> str:
        """Model-facing text for a denied or blocked call. Identical wording
        across every integration — one contract, one explanation."""
        if self.status == "denied":
            return f"Tool call denied: {self.gate.deny_reason if self.gate else 'policy'}"
        if self.status == "blocked":
            return BLOCKED_RESULT_MESSAGE
        return self.text or ""


async def invoke_tool(tool: Any, args: dict[str, Any]) -> Any:
    """Invoke a tool by keyword arguments, whatever shape it is.

    Recognises ShaiTool, LangChain tools (ainvoke/arun/invoke/run), and plain
    sync or async callables. Sync forms run on a worker thread so a blocking
    tool never stalls the event loop.
    """
    if isinstance(tool, ShaiTool):
        return await tool._async_call(**args)
    if asyncio.iscoroutinefunction(getattr(tool, "ainvoke", None)):
        return await tool.ainvoke(args)
    if asyncio.iscoroutinefunction(getattr(tool, "arun", None)):
        return await tool.arun(**args)
    if asyncio.iscoroutinefunction(tool):
        return await tool(**args)
    if callable(getattr(tool, "invoke", None)):
        return await asyncio.to_thread(tool.invoke, args)
    if callable(getattr(tool, "run", None)):
        return await asyncio.to_thread(tool.run, **args)
    if callable(tool):
        return await asyncio.to_thread(tool, **args)
    raise TypeError(f"Cannot invoke tool of type {type(tool)}")


async def dispatch_remote(
    harness: SHAI,
    tool_name: str,
    args: dict[str, Any],
    gate: GateDecision,
) -> Any:
    """Invoke a tool on the MCP source that owns it, carrying the gate's token.

    The dispatch token is the whole point: ShaiTransport reads it off the
    outbound request and checks HMAC, expiry, source binding, URL and method.
    A call dispatched without it is refused under no_token_policy=strict and
    leaves no NetworkAuditEvent to correlate under permissive.
    """
    source = await harness.get_source(gate.source_name)
    return await source.call(tool_name, args, dispatch_token=gate.dispatch_token)


async def execute_gated_tool_call(
    *,
    harness: SHAI,
    ctx: AgentContext,
    tool_name: str,
    tool_args: dict[str, Any],
    invoke: Callable[[dict[str, Any]], Awaitable[Any]] | None = None,
    extract_text: Callable[[Any], str] | None = None,
) -> GatedCall:
    """Run one tool call through every boundary it must cross.

    check_tool_call → (redacted args) → dispatch → scan_tool_result.

    invoke receives the effective arguments — the gate's redacted_args when it
    produced them, the originals otherwise — and returns the tool result. Pass
    None when the caller holds no local callable: the tool is then dispatched
    through the MCP source the gate resolved, with its dispatch token. A local
    tool with no invoke is a wiring error and raises LookupError.

    extract_text turns the result into the text scan_tool_result sees;
    defaults to str(). A result with no text is not scanned — there is
    nothing for a scanner to read.

    Never raises on a denial or a block: both come back as a GatedCall the
    caller renders. Exceptions from dispatch propagate untouched.
    """
    gate = await harness.check_tool_call(tool_name, tool_args, ctx)
    if not gate.allowed:
        log.info("tool call denied",
                 extra={"tool": tool_name, "reason": gate.deny_reason,
                        **ctx.to_log_fields()})
        return GatedCall(status="denied", gate=gate)

    effective_args = gate.redacted_args if gate.redacted_args is not None else tool_args
    if invoke is not None:
        result = await invoke(effective_args)
    elif gate.source_name and gate.source_name != "local":
        result = await dispatch_remote(harness, tool_name, effective_args, gate)
    else:
        raise LookupError(
            f"no local callable for tool '{tool_name}' and no remote source "
            f"to dispatch it to (source_name={gate.source_name!r})")

    # T6: a tool result is untrusted input. Scan before it re-enters context.
    text = (extract_text or str)(result)
    if not text:
        return GatedCall(status="allowed", text=text, result=result, gate=gate)

    verdict = await harness.scan_tool_result(text, ctx)
    if verdict.blocked:
        log.warning("tool result blocked — indirect injection detected",
                    extra={"tool": tool_name, **ctx.to_log_fields()})
        return GatedCall(status="blocked", gate=gate, verdict=verdict)
    if verdict.warned:
        log.warning("tool result flagged — potential injection (action=alert)",
                    extra={"tool": tool_name, **ctx.to_log_fields()})
    return GatedCall(
        status="allowed",
        text=verdict.redacted_text or text,
        result=result,
        gate=gate,
        verdict=verdict,
    )


def extract_shai_tools(tools: Sequence[Any]) -> list[Tool]:
    """Extract SHAI Tool descriptors from a mixed list of ShaiTool and Tool."""
    result: list[Tool] = []
    for t in tools:
        if isinstance(t, ShaiTool):
            result.append(t.to_shai_tool())
        elif isinstance(t, Tool):
            result.append(t)
        # plain callables or LangChain tools without SHAI metadata are skipped
    return result
