"""Unit tests for SourceRegistry, LocalSource, and MCPSource scaffolding."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, MCPSource, SourceRegistry
from harness.tools.tool import Tool

CTX = AgentContext(agent_id="test_agent")


# ── Fixtures ──────────────────────────────────────────────────────────────

def _make_policy(active: bool = True):
    """Minimal policy stub."""
    decision = MagicMock()
    decision.active = active
    decision.reason = "test"
    policy = MagicMock()
    policy.evaluate_source = AsyncMock(return_value=decision)
    return policy


async def _make_registry(*tools: Tool) -> ToolRegistry:
    reg = ToolRegistry()
    for t in tools:
        await reg.register(t)
    return reg


# ── SourceRegistry ────────────────────────────────────────────────────────

async def test_register_and_get():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(name="docs", registry=ToolRegistry())
    await reg.register(src)
    got = await reg.get("docs")
    assert got is src


async def test_register_same_object_idempotent():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(name="docs", registry=ToolRegistry())
    r1 = await reg.register(src)
    r2 = await reg.register(src)
    assert r1 is True
    assert r2 is False


async def test_register_different_object_same_name_raises():
    reg = SourceRegistry(_make_policy())
    src1 = LocalSource(name="docs", registry=ToolRegistry())
    src2 = LocalSource(name="docs", registry=ToolRegistry())
    await reg.register(src1)
    with pytest.raises(ConfigError):
        await reg.register(src2)


async def test_get_unknown_raises():
    reg = SourceRegistry(_make_policy())
    with pytest.raises(ConfigError):
        await reg.get("nonexistent")


async def test_deregister():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(name="docs", registry=ToolRegistry())
    await reg.register(src)
    removed = await reg.deregister(src)
    assert removed is True
    with pytest.raises(ConfigError):
        await reg.get("docs")


async def test_deregister_unknown_returns_false():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(name="docs", registry=ToolRegistry())
    result = await reg.deregister(src)
    assert result is False


async def test_list():
    reg = SourceRegistry(_make_policy())
    s1 = LocalSource(name="a", registry=ToolRegistry())
    s2 = LocalSource(name="b", registry=ToolRegistry())
    await reg.register(s1)
    await reg.register(s2)
    sources = await reg.list()
    assert {s.name for s in sources} == {"a", "b"}


# ── activate ──────────────────────────────────────────────────────────────

async def test_activate_returns_tools():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = await _make_registry(tool)
    src = LocalSource(name="docs", registry=tool_reg, tool_names=["search"])

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(src)
    tools = await reg.activate(CTX, ["docs"])
    assert len(tools) == 1
    assert tools[0].name == "search"


async def test_activate_suppressed_by_policy():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = await _make_registry(tool)
    src = LocalSource(name="docs", registry=tool_reg, tool_names=["search"])

    reg = SourceRegistry(_make_policy(active=False))  # policy blocks it
    await reg.register(src)
    tools = await reg.activate(CTX, ["docs"])
    assert tools == []


async def test_activate_unknown_source_skipped():
    reg = SourceRegistry(_make_policy())
    # "nonexistent" not registered — should skip, not raise
    tools = await reg.activate(CTX, ["nonexistent"])
    assert tools == []


async def test_activate_failed_source_skipped():
    """A source whose load() raises must not crash the whole activation."""
    bad = MagicMock()
    bad.name = "bad_source"
    bad.transport = Transport.LOCAL
    bad.tags = []
    bad.load = AsyncMock(side_effect=RuntimeError("network error"))
    bad.close = AsyncMock()

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(bad)
    tools = await reg.activate(CTX, ["bad_source"])
    assert tools == []


async def test_activate_merges_multiple_sources():
    t1 = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    t2 = Tool(name="send_email", tags=["write"], transport=Transport.LOCAL)
    reg1 = await _make_registry(t1)
    reg2 = await _make_registry(t2)
    s1 = LocalSource(name="read_src",  registry=reg1, tool_names=["search"])
    s2 = LocalSource(name="write_src", registry=reg2, tool_names=["send_email"])

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(s1)
    await reg.register(s2)
    tools = await reg.activate(CTX, ["read_src", "write_src"])
    names = {t.name for t in tools}
    assert names == {"search", "send_email"}


# ── LocalSource ───────────────────────────────────────────────────────────

async def test_local_source_returns_named_tools():
    t1 = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    t2 = Tool(name="write", tags=["write"], transport=Transport.LOCAL)
    reg = await _make_registry(t1, t2)
    src = LocalSource(name="read_only", registry=reg, tool_names=["search"])
    tools = await src.load(CTX)
    assert len(tools) == 1
    assert tools[0].name == "search"


async def test_local_source_all_tools_when_no_names():
    t1 = Tool(name="a", tags=[], transport=Transport.LOCAL)
    t2 = Tool(name="b", tags=[], transport=Transport.LOCAL)
    reg = await _make_registry(t1, t2)
    src = LocalSource(name="all", registry=reg)
    tools = await src.load(CTX)
    assert {t.name for t in tools} == {"a", "b"}


async def test_local_source_merges_tags():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    reg = await _make_registry(tool)
    src = LocalSource(name="docs", registry=reg, tool_names=["search"],
                      tags=["internal"])
    tools = await src.load(CTX)
    assert "internal" in tools[0].tags
    assert "read" in tools[0].tags


async def test_local_source_missing_tool_skipped():
    reg = await _make_registry()  # empty registry
    src = LocalSource(name="docs", registry=reg, tool_names=["nonexistent"])
    tools = await src.load(CTX)
    assert tools == []


async def test_local_source_close_noop():
    src = LocalSource(name="docs", registry=ToolRegistry())
    await src.close()  # must not raise


# ── MCPSource construction and config ─────────────────────────────────────

def test_mcp_source_constructed():
    src = MCPSource(
        name="slack",
        url="https://mcp.slack.com/sse",
        credentials={"token": "tok_abc"},
        tags=["messaging"],
    )
    assert src.name == "slack"
    assert src.transport == Transport.MCP
    assert "messaging" in src.tags
    assert not src._connected


async def test_mcp_source_load_raises_without_httpx(monkeypatch):
    """When httpx is not installed, load() raises ConfigError."""
    import sys
    monkeypatch.setitem(sys.modules, "httpx", None)

    src = MCPSource(name="slack", url="https://mcp.slack.com/sse")
    with pytest.raises(ConfigError, match="httpx"):
        await src.load(CTX)


async def test_mcp_source_call_raises_when_not_connected():
    src = MCPSource(name="slack", url="https://mcp.slack.com/sse")
    from harness.core.errors import ConfigError
    with pytest.raises(ConfigError, match="not connected"):
        await src.call("search", {})


async def test_mcp_source_close_when_not_connected():
    src = MCPSource(name="slack", url="https://mcp.slack.com/sse")
    await src.close()  # must not raise
    assert not src._connected


# ── MCPSource header building ─────────────────────────────────────────────

def test_mcp_token_credential_becomes_bearer():
    src = MCPSource(name="s", url="http://x", credentials={"token": "mytoken"})
    headers = src._build_headers()
    assert headers.get("Authorization") == "Bearer mytoken"


def test_mcp_authorization_credential_used_asis():
    src = MCPSource(name="s", url="http://x",
                    credentials={"Authorization": "Basic abc"})
    headers = src._build_headers()
    assert headers["Authorization"] == "Basic abc"


def test_mcp_custom_header_passed_through():
    src = MCPSource(name="s", url="http://x",
                    credentials={"X-Custom-Header": "value"})
    headers = src._build_headers()
    assert headers["X-Custom-Header"] == "value"


# ── SSE helpers ───────────────────────────────────────────────────────────

def test_extract_session_id_from_path():
    from harness.tools.source import _extract_session_id
    result = _extract_session_id("/message?sessionId=abc123")
    assert result == "abc123"


def test_extract_session_id_from_full_url():
    from harness.tools.source import _extract_session_id
    result = _extract_session_id("https://server.com/message?sessionId=xyz")
    assert result == "xyz"


def test_extract_session_id_missing_returns_none():
    from harness.tools.source import _extract_session_id
    result = _extract_session_id("/message?foo=bar")
    assert result is None


# ── SourceConfig schema ───────────────────────────────────────────────────

def test_source_config_mcp_requires_url():
    from harness.config.schema import SourceConfig
    from pydantic import ValidationError
    with pytest.raises(ValidationError, match="url"):
        SourceConfig(name="slack", transport="mcp")  # missing url


def test_source_config_mcp_valid():
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(name="slack", transport="mcp",
                       url="https://mcp.slack.com/sse")
    assert cfg.url == "https://mcp.slack.com/sse"


def test_source_config_local_no_url_needed():
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(name="docs", transport="local")
    assert cfg.url is None


# ── Integration: SHAI.from_yaml with sources ──────────────────────────────

async def test_shai_from_yaml_with_sources_section(tmp_path: Path):
    """from_yaml builds source_registry from config.sources."""
    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "sources:\n"
        "  - name: docs_local\n"
        "    transport: local\n"
        "    tags:\n      - internal\n"
    )
    from harness.core.harness import SHAI
    harness = await SHAI.from_yaml(cfg_file)
    source = await harness.get_source("docs_local")
    assert source.name == "docs_local"
    assert source.transport == Transport.LOCAL
    await harness.close()


async def test_shai_source_tools_available_at_load_agent(tmp_path: Path):
    """Tools from a local source are resolved into the agent's tool set."""
    from harness.core.harness import SHAI
    from harness.core.types import Transport

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "sources:\n"
        "  - name: docs_local\n"
        "    transport: local\n"
    )
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: test_agent\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
        "sources:\n  - docs_local\n"
    )
    harness = await SHAI.from_yaml(cfg_file)
    # Register tool before loading agent
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    ctx = await harness.load_agent(agent_file)
    tools = harness._agent_tools.get("test_agent", {})
    assert "search_docs" in tools
    await harness.close()
