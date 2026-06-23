"""ToolSource contract suite — LocalSource and SkillSource must pass."""
from __future__ import annotations

import asyncio

import pytest

from harness.tools.registry import ToolRegistry
from harness.tools.source import SourceRegistry, ToolSource
from harness.tools.source import LocalSource
from harness.tools.source import SkillSource
from harness.core.context import AgentContext
from harness.core.types import Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


async def make_registry(*tools: Tool) -> ToolRegistry:
    reg = ToolRegistry()
    for t in tools:
        await reg.register(t)
    return reg


# ── Protocol conformance ──────────────────────────────────────────────────

async def test_local_satisfies_toolsource_protocol():
    """Duck-type check — ToolSource is a Protocol, not runtime_checkable."""
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(registry=reg)
    assert hasattr(src, "name")
    assert hasattr(src, "transport")
    assert hasattr(src, "tags")
    assert hasattr(src, "load")


async def test_skill_satisfies_toolsource_protocol():
    reg = await make_registry(make_tool("search_docs"))
    src = SkillSource("docs_skill", ["search_docs"], reg)
    assert hasattr(src, "name")
    assert hasattr(src, "transport")
    assert hasattr(src, "tags")
    assert hasattr(src, "load")


# ── LocalSource ───────────────────────────────────────────────────────────

async def test_local_name_and_transport():
    src = LocalSource(registry=ToolRegistry())
    assert src.name == "local"
    assert src.transport == Transport.LOCAL


async def test_local_returns_registered_tools():
    reg = await make_registry(make_tool("search_docs"), make_tool("fetch_doc"))
    src = LocalSource(registry=reg)
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"search_docs", "fetch_doc"} == names


async def test_local_empty_registry():
    src = LocalSource(registry=ToolRegistry())
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    assert tools == []


async def test_local_subagent_tag_filter():
    """Subagent with allowed_tags=["read"] must not see external_write tools."""
    reg = await make_registry(
        make_tool("read_tool",  tags=["read"]),
        make_tool("write_tool", tags=["external_write"]),
    )
    src = LocalSource(registry=reg)
    ctx = AgentContext(
        agent_id="a1", sub_agent_id="sub",
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
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"read_tool", "write_tool"} == names


async def test_local_concurrent_safe():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(registry=reg)
    ctx = AgentContext(
        agent_id="a1")
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
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    assert len(tools) == 1
    assert tools[0].name == "search_docs"


async def test_skill_missing_tool_skipped():
    reg = await make_registry(make_tool("search_docs"))
    src = SkillSource("docs_skill", ["search_docs", "nonexistent"], reg)
    ctx = AgentContext(
        agent_id="a1")
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
    ctx = AgentContext(
        agent_id="a1", sub_agent_id="sub",
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
    src_registry = SourceRegistry(policy=RuleBasedPolicy())
    await src_registry.register(local_src)
    ctx  = AgentContext(
        agent_id="a1")
    tools = await src_registry.activate(ctx, ["local"])
    assert any(t.name == "search_docs" for t in tools)


async def test_source_registry_unknown_source_skipped():
    src_registry = SourceRegistry(policy=RuleBasedPolicy())
    reg  = ToolRegistry()
    ctx  = AgentContext(
        agent_id="a1")
    # no exception — missing source is logged and skipped
    tools = await src_registry.activate(ctx, ["nonexistent"])
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
    src_registry = SourceRegistry(policy=policy)
    await src_registry.register(local_src)
    ctx  = AgentContext(
        agent_id="a1")
    tools = await src_registry.activate(ctx, ["local"])
    # suppressed — no tools returned
    assert tools == []
