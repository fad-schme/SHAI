"""harness.integrations.base — framework-agnostic shai_tool decorator.

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
from typing import Any, Callable, Sequence

from harness.core.types import Transport
from harness.tools.tool import Tool


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
