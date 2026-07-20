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
    await reg.register(t)
    result = await reg.get("search_docs")
    assert result.name == "search_docs"


async def test_register_idempotent():
    reg = ToolRegistry()
    t = make_tool("search_docs")
    first  = await reg.register(t)
    second = await reg.register(t)  # identical — idempotent
    assert first  is True
    assert second is False
    assert len(await reg.list()) == 1


async def test_register_conflict_raises():
    reg = ToolRegistry()
    await reg.register(make_tool("search_docs", tags=["read"]))
    with pytest.raises(ConfigError):
        await reg.register(make_tool("search_docs", tags=["write"]))  # different tags


async def test_get_unknown_raises():
    reg = ToolRegistry()
    with pytest.raises(ToolNotRegisteredError):
        await reg.get("nonexistent")


async def test_register_many():
    reg = ToolRegistry()
    tools = [make_tool(f"tool_{i}") for i in range(5)]
    await reg.register_many(tools)
    listed = await reg.list()
    assert len(listed) == 5


async def test_list_insertion_order():
    reg = ToolRegistry()
    names = ["c_tool", "a_tool", "b_tool"]
    for n in names:
        await reg.register(make_tool(n))
    listed = [t.name for t in await reg.list()]
    assert listed == names


async def test_concurrent_get_safe():
    reg = ToolRegistry()
    await reg.register(make_tool("search_docs"))

    async def _get():
        return await reg.get("search_docs")

    results = await asyncio.gather(*[_get() for _ in range(50)], return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors


async def test_deregister_removes_tool():
    reg = ToolRegistry()
    t = make_tool("search_docs")
    await reg.register(t)
    removed = await reg.deregister(t)
    assert removed is True
    with pytest.raises(ToolNotRegisteredError):
        await reg.get("search_docs")


async def test_deregister_not_registered_returns_false():
    reg = ToolRegistry()
    t   = make_tool("search_docs")
    result = await reg.deregister(t)
    assert result is False
