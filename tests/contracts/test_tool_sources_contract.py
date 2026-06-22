"""ToolSource contract suite — LocalSource and SkillSource must pass."""
from __future__ import annotations

import asyncio

import pytest

from harness.adapters.tool_registry.memory import InMemoryRegistry
from harness.adapters.tool_sources.base import SourceRegistry, ToolSource
from harness.adapters.tool_sources.local import LocalSource
from harness.adapters.tool_sources.skill import SkillSource
from harness.core.context import RuntimeContext
from harness.core.types import Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


async def make_registry(*tools: Tool) -> InMemoryRegistry:
    reg = InMemoryRegistry()
    for t in tools:
        await reg.register(t)
    return reg


# ── Protocol conformance ──────────────────────────────────────────────────

async def test_local_implements_protocol():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(registry=reg)
    assert isinstance(src, ToolSource)


async def test_skill_implements_protocol():
    reg = await make_registry(make_tool("search_docs"))
    src = SkillSource("docs_skill", ["search_docs"], reg)
    assert isinstance(src, ToolSource)


# ── LocalSource ───────────────────────────────────────────────────────────

async def test_local_name_and_transport():
    src = LocalSource(registry=InMemoryRegistry())
    assert src.name == "local"
    assert src.transport == Transport.LOCAL


async def test_local_returns_registered_tools():
    reg = await make_registry(make_tool("search_docs"), make_tool("fetch_doc"))
    src = LocalSource(registry=reg)
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"search_docs", "fetch_doc"} == names


async def test_local_empty_registry():
    src = LocalSource(registry=InMemoryRegistry())
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    tools = await src.load(ctx)
    assert tools == []


async def test_local_subagent_tag_filter():
    """Subagent with allowed_tags=["read"] must not see external_write tools."""
    reg = await make_registry(
        make_tool("read_tool",  tags=["read"]),
        make_tool("write_tool", tags=["external_write"]),
    )
    src = LocalSource(registry=reg)
    ctx = RuntimeContext(
        tenant_id="t1", agent_id="a1", sub_agent_id="sub",
        allowed_tags=["read"],
    )
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert "read_tool" in names
    assert "write_tool" not in names


async def test_local_top_level_no_tag_filter():
    """Top-level agent (no allowed_tags) sees all tools."""
    reg = await make_registry(
        make_tool("read_tool",  tags=["read"]),
        make_tool("write_tool", tags=["external_write"]),
    )
    src = LocalSource(registry=reg)
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"read_tool", "write_tool"} == names


async def test_local_concurrent_safe():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(registry=reg)
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    results = await asyncio.gather(
        *[src.load(ctx) for _ in range(20)],
        return_exceptions=True,
    )
    assert not any(isinstance(r, Exception) for r in results)


# ── SkillSource ───────────────────────────────────────────────────────────

async def test_skill_name_and_transport():
    reg = await make_registry(make_tool("search_docs"))
    src = SkillSource("docs_skill", ["search_docs"], reg)
    assert src.name == "docs_skill"
    assert src.transport == Transport.SKILL


async def test_skill_loads_declared_tools():
    reg = await make_registry(make_tool("search_docs"), make_tool("fetch_doc"))
    src = SkillSource("docs_skill", ["search_docs"], reg)
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    tools = await src.load(ctx)
    assert len(tools) == 1
    assert tools[0].name == "search_docs"


async def test_skill_missing_tool_skipped():
    reg = await make_registry(make_tool("search_docs"))
    src = SkillSource("docs_skill", ["search_docs", "nonexistent"], reg)
    ctx = RuntimeContext(tenant_id="t1", agent_id="a1")
    tools = await src.load(ctx)
    # nonexistent is skipped; search_docs is returned
    assert len(tools) == 1
    assert tools[0].name == "search_docs"


async def test_skill_subagent_tag_filter():
    reg = await make_registry(
        make_tool("read_tool",  tags=["read"]),
        make_tool("write_tool", tags=["external_write"]),
    )
    src = SkillSource("mixed_skill", ["read_tool", "write_tool"], reg)
    ctx = RuntimeContext(
        tenant_id="t1", agent_id="a1", sub_agent_id="sub",
        allowed_tags=["read"],
    )
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert "read_tool" in names
    assert "write_tool" not in names


# ── SourceRegistry ────────────────────────────────────────────────────────

async def test_source_registry_activate():
    reg = await make_registry(make_tool("search_docs"))
    local_src = LocalSource(registry=reg)
    src_registry = SourceRegistry(
        sources={"local": local_src},
        policy=RuleBasedPolicy(),
    )
    ctx  = RuntimeContext(tenant_id="t1", agent_id="a1")
    view = reg.scoped_view(ctx)
    tools = await src_registry.activate(ctx, ["local"], view)
    assert any(t.name == "search_docs" for t in tools)


async def test_source_registry_unknown_source_skipped():
    src_registry = SourceRegistry(sources={}, policy=RuleBasedPolicy())
    reg  = InMemoryRegistry()
    ctx  = RuntimeContext(tenant_id="t1", agent_id="a1")
    view = reg.scoped_view(ctx)
    # no exception — missing source is logged and skipped
    tools = await src_registry.activate(ctx, ["nonexistent"], view)
    assert tools == []


async def test_source_registry_policy_suppress():
    from harness.agents.agent_config import RuleConfig, RuleMatchConfig

    reg = await make_registry(make_tool("search_docs"))
    local_src = LocalSource(registry=reg, tags=["internal"])
    suppress_rule = RuleConfig(
        id="suppress_internal",
        match=RuleMatchConfig(source_tags=["internal"]),
        action="suppress",
        reason="suppressed for test",
    )
    policy = RuleBasedPolicy(rules=[suppress_rule])
    src_registry = SourceRegistry(
        sources={"local": local_src},
        policy=policy,
    )
    ctx  = RuntimeContext(tenant_id="t1", agent_id="a1")
    view = reg.scoped_view(ctx)
    tools = await src_registry.activate(ctx, ["local"], view)
    # suppressed — no tools returned
    assert tools == []
