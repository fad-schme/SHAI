"""ToolSource contract suite — LocalSource (local and skill) must pass."""
from __future__ import annotations

import asyncio

import pytest

from harness.config.schema import SourceConfig
from harness.core.context import AgentContext
from harness.core.types import Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, SourceRegistry
from harness.tools.tool import Tool


def _local(name: str = "local", **kw) -> SourceConfig:
    return SourceConfig(name=name, **kw)


def _skill(name: str = "docs_skill", **kw) -> SourceConfig:
    return SourceConfig(name=name, transport=Transport.SKILL, **kw)


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


async def make_registry(*tools: Tool) -> ToolRegistry:
    reg = ToolRegistry()
    for t in tools:
        reg.register(t)
    return reg


# ── Protocol conformance ──────────────────────────────────────────────────

async def test_local_satisfies_toolsource_protocol():
    """Duck-type check — ToolSource is a Protocol, not runtime_checkable."""
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(_local(), registry=reg)
    assert hasattr(src, "name")
    assert hasattr(src, "transport")
    assert hasattr(src, "tags")
    assert hasattr(src, "load")


async def test_skill_satisfies_toolsource_protocol():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(_skill(tool_names=["search_docs"]), registry=reg)
    assert hasattr(src, "name")
    assert hasattr(src, "transport")
    assert hasattr(src, "tags")
    assert hasattr(src, "load")


# ── LocalSource ───────────────────────────────────────────────────────────

async def test_local_name_and_transport():
    src = LocalSource(_local(), registry=ToolRegistry())
    assert src.name == "local"
    assert src.transport == Transport.LOCAL


async def test_local_source_rejects_mcp_transport():
    """A registry-backed source must not claim to be MCP.

    `transport: mcp` is now a valid SourceConfig declaration (see
    config.schema.SourceConfig, harness.mcp.discovery) — the harness build
    loop routes it to MCPSource, never LocalSource. This is LocalSource's
    own defense-in-depth check for the case where it's constructed with one
    anyway.
    """
    from harness.core.errors import ConfigError
    cfg = SourceConfig(name="wrong", transport=Transport.MCP,
                        tags=[], tool_names=[], required=True)
    with pytest.raises(ConfigError, match="cannot serve mcp"):
        LocalSource(cfg, registry=ToolRegistry())


async def test_local_returns_registered_tools():
    reg = await make_registry(make_tool("search_docs"), make_tool("fetch_doc"))
    src = LocalSource(_local(), registry=reg)
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"search_docs", "fetch_doc"} == names


async def test_local_empty_registry():
    src = LocalSource(_local(), registry=ToolRegistry())
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
    src = LocalSource(_local(), registry=reg)
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
    src = LocalSource(_local(), registry=reg)
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    names = {t.name for t in tools}
    assert {"read_tool", "write_tool"} == names


async def test_local_concurrent_safe():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(_local(), registry=reg)
    ctx = AgentContext(
        agent_id="a1")
    results = await asyncio.gather(
        *[src.load(ctx) for _ in range(20)],
        return_exceptions=True,
    )
    assert not any(isinstance(r, Exception) for r in results)


# ── Skill transport ───────────────────────────────────────────────────────
# Same class, same behaviour — the declared transport travels with the source.

async def test_skill_name_and_transport():
    """A skill source reports skill, not local — it is not downgraded."""
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(_skill(tool_names=["search_docs"]), registry=reg)
    assert src.name == "docs_skill"
    assert src.transport == Transport.SKILL


async def test_skill_loads_declared_tools():
    reg = await make_registry(make_tool("search_docs"), make_tool("fetch_doc"))
    src = LocalSource(_skill(tool_names=["search_docs"]), registry=reg)
    ctx = AgentContext(
        agent_id="a1")
    tools = await src.load(ctx)
    assert len(tools) == 1
    assert tools[0].name == "search_docs"


async def test_skill_missing_tool_skipped():
    reg = await make_registry(make_tool("search_docs"))
    src = LocalSource(_skill(tool_names=["search_docs", "nonexistent"]), registry=reg)
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
    src = LocalSource(_skill("mixed_skill", tool_names=["read_tool", "write_tool"]),
                      registry=reg)
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
    local_src = LocalSource(_local(), registry=reg)
    src_registry = SourceRegistry(policy=RuleBasedPolicy())
    src_registry.register(local_src)
    ctx  = AgentContext(
        agent_id="a1")
    tools = await src_registry.activate(ctx, ["local"])
    assert any(t.name == "search_docs" for t in tools)


async def test_source_registry_unknown_required_source_raises():
    """Missing required source (default) raises ConfigError — fail-safe default."""
    from harness.core.errors import ConfigError
    src_registry = SourceRegistry(policy=RuleBasedPolicy())
    ctx = AgentContext(agent_id="a1")
    with pytest.raises(ConfigError, match="nonexistent"):
        await src_registry.activate(ctx, ["nonexistent"])


async def test_source_registry_unknown_optional_source_skipped():
    """Missing optional source (required=False) is logged and skipped, not raised."""
    src_registry = SourceRegistry(policy=RuleBasedPolicy())
    ctx = AgentContext(agent_id="a1")
    tools = await src_registry.activate(
        ctx, ["nonexistent"], required_flags={"nonexistent": False}
    )
    assert tools == []


async def test_source_registry_policy_suppress():
    from harness.agents.agent_config import RuleConfig, RuleMatchConfig

    reg = await make_registry(make_tool("search_docs"))
    local_src = LocalSource(_local(tags=["internal"]), registry=reg)
    suppress_rule = RuleConfig(
        id="suppress_internal",
        match=RuleMatchConfig(source_tags=["internal"]),
        action="suppress",
        reason="suppressed for test",
    )
    policy = RuleBasedPolicy(source_rules=[suppress_rule])
    src_registry = SourceRegistry(policy=policy)
    src_registry.register(local_src)
    ctx  = AgentContext(
        agent_id="a1")
    tools = await src_registry.activate(ctx, ["local"])
    # suppressed — no tools returned
    assert tools == []
