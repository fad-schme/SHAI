"""ToolRegistry contract suite — ToolRegistry must pass."""
from __future__ import annotations

import asyncio

import pytest

from harness.core.context import AgentContext
from harness.core.errors import ConfigError, ToolNotRegisteredError
from harness.core.types import Transport
from harness.tools.registry import ToolRegistry
from harness.tools.tool import Tool

_CTX = AgentContext(
        agent_id="a1")


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read"], transport=Transport.LOCAL)


# ── ToolRegistry ──────────────────────────────────────────────────────

async def test_name():
    assert ToolRegistry().name == "memory"


async def test_register_and_get():
    reg = ToolRegistry()
    t = make_tool("search_docs")
    reg.register(t)
    result = reg.get("search_docs")
    assert result.name == "search_docs"


async def test_register_idempotent():
    reg = ToolRegistry()
    t = make_tool("search_docs")
    first  = reg.register(t)
    second = reg.register(t)  # identical — idempotent
    assert first  is True
    assert second is False
    assert len(reg.list()) == 1


async def test_register_conflict_raises():
    reg = ToolRegistry()
    reg.register(make_tool("search_docs", tags=["read"]))
    with pytest.raises(ConfigError):
        reg.register(make_tool("search_docs", tags=["write"]))  # different tags


async def test_get_unknown_raises():
    reg = ToolRegistry()
    with pytest.raises(ToolNotRegisteredError):
        reg.get("nonexistent")


async def test_register_many():
    reg = ToolRegistry()
    tools = [make_tool(f"tool_{i}") for i in range(5)]
    reg.register_many(tools)
    listed = reg.list()
    assert len(listed) == 5


async def test_list_insertion_order():
    reg = ToolRegistry()
    names = ["c_tool", "a_tool", "b_tool"]
    for n in names:
        reg.register(make_tool(n))
    listed = [t.name for t in reg.list()]
    assert listed == names


async def test_concurrent_get_safe():
    reg = ToolRegistry()
    reg.register(make_tool("search_docs"))

    async def _get():
        return reg.get("search_docs")

    results = await asyncio.gather(*[_get() for _ in range(50)], return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors


async def test_deregister_removes_tool():
    reg = ToolRegistry()
    t = make_tool("search_docs")
    reg.register(t)
    removed = reg.deregister(t)
    assert removed is True
    with pytest.raises(ToolNotRegisteredError):
        reg.get("search_docs")


async def test_deregister_not_registered_returns_false():
    reg = ToolRegistry()
    t   = make_tool("search_docs")
    result = reg.deregister(t)
    assert result is False
