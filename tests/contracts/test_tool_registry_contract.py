"""ToolRegistry contract suite — InMemoryRegistry must pass."""
from __future__ import annotations

import asyncio

import pytest

from harness.adapters.tool_registry.memory import InMemoryRegistry, InMemoryRegistryView
from harness.core.context import RuntimeContext
from harness.core.errors import ConfigError, ToolNotRegisteredError
from harness.core.types import Transport
from harness.tools.tool import Tool

_CTX = RuntimeContext(tenant_id="t1", agent_id="a1")


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read"], transport=Transport.LOCAL)


# ── InMemoryRegistry ──────────────────────────────────────────────────────

async def test_name():
    assert InMemoryRegistry().name == "memory"


async def test_register_and_get():
    reg = InMemoryRegistry()
    t = make_tool("search_docs")
    await reg.register(t)
    result = await reg.get("search_docs")
    assert result.name == "search_docs"


async def test_register_idempotent():
    reg = InMemoryRegistry()
    t = make_tool("search_docs")
    await reg.register(t)
    await reg.register(t)  # identical — must not raise
    assert len(await reg.list()) == 1


async def test_register_conflict_raises():
    reg = InMemoryRegistry()
    await reg.register(make_tool("search_docs", tags=["read"]))
    with pytest.raises(ConfigError):
        await reg.register(make_tool("search_docs", tags=["write"]))  # different tags


async def test_get_unknown_raises():
    reg = InMemoryRegistry()
    with pytest.raises(ToolNotRegisteredError):
        await reg.get("nonexistent")


async def test_register_many():
    reg = InMemoryRegistry()
    tools = [make_tool(f"tool_{i}") for i in range(5)]
    await reg.register_many(tools)
    listed = await reg.list()
    assert len(listed) == 5


async def test_list_insertion_order():
    reg = InMemoryRegistry()
    names = ["c_tool", "a_tool", "b_tool"]
    for n in names:
        await reg.register(make_tool(n))
    listed = [t.name for t in await reg.list()]
    assert listed == names


async def test_concurrent_get_safe():
    reg = InMemoryRegistry()
    await reg.register(make_tool("search_docs"))

    async def _get():
        return await reg.get("search_docs")

    results = await asyncio.gather(*[_get() for _ in range(50)], return_exceptions=True)
    errors = [r for r in results if isinstance(r, Exception)]
    assert not errors


# ── InMemoryRegistryView ──────────────────────────────────────────────────

async def test_view_overlay_does_not_affect_base():
    reg = InMemoryRegistry()
    await reg.register(make_tool("base_tool"))
    view = reg.scoped_view(_CTX)
    await view.add(make_tool("overlay_tool"))

    base_tools = [t.name for t in await reg.list()]
    assert "overlay_tool" not in base_tools


async def test_view_get_overlay_first():
    reg = InMemoryRegistry()
    base_t = Tool(name="shared", tags=["read"], transport=Transport.LOCAL)
    overlay_t = Tool(name="shared", tags=["read", "extra"], transport=Transport.LOCAL)
    await reg.register(base_t)
    view = reg.scoped_view(_CTX)
    await view.add(overlay_t)

    result = await view.get("shared")
    assert "extra" in result.tags  # overlay wins


async def test_view_get_falls_back_to_base():
    reg = InMemoryRegistry()
    await reg.register(make_tool("base_only"))
    view = reg.scoped_view(_CTX)
    result = await view.get("base_only")
    assert result.name == "base_only"


async def test_view_get_miss_raises():
    reg = InMemoryRegistry()
    view = reg.scoped_view(_CTX)
    with pytest.raises(ToolNotRegisteredError):
        await view.get("nonexistent")


async def test_view_list_merges():
    reg = InMemoryRegistry()
    await reg.register(make_tool("base_tool"))
    view = reg.scoped_view(_CTX)
    await view.add(make_tool("overlay_tool"))
    names = {t.name for t in await view.list()}
    assert "base_tool" in names
    assert "overlay_tool" in names


async def test_two_views_are_isolated():
    reg = InMemoryRegistry()
    v1 = reg.scoped_view(_CTX)
    ctx2 = RuntimeContext(tenant_id="t1", agent_id="other_agent")
    v2 = reg.scoped_view(ctx2)
    await v1.add(make_tool("tool_for_v1"))
    with pytest.raises(ToolNotRegisteredError):
        await v2.get("tool_for_v1")
