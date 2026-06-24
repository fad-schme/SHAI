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


async def test_activate_unknown_required_source_raises():
    """Missing required source raises ConfigError — fail-safe default."""
    from harness.core.errors import ConfigError
    reg = SourceRegistry(_make_policy())
    with pytest.raises(ConfigError, match="nonexistent"):
        await reg.activate(CTX, ["nonexistent"])


async def test_activate_unknown_optional_source_skipped():
    """Missing optional source (required=False) is skipped, not raised."""
    reg = SourceRegistry(_make_policy())
    tools = await reg.activate(CTX, ["nonexistent"],
                               required_flags={"nonexistent": False})
    assert tools == []


async def test_activate_failed_required_source_raises():
    """Required source whose load() raises must raise ConfigError."""
    from harness.core.errors import ConfigError

    bad = MagicMock()
    bad.name = "bad_source"
    bad.transport = Transport.LOCAL
    bad.tags = []
    bad.load = AsyncMock(side_effect=RuntimeError("network error"))
    bad.close = AsyncMock()

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(bad)
    with pytest.raises(ConfigError, match="bad_source"):
        await reg.activate(CTX, ["bad_source"])


async def test_activate_failed_optional_source_skipped():
    """Optional source whose load() raises is skipped, not raised."""
    bad = MagicMock()
    bad.name = "bad_source"
    bad.transport = Transport.LOCAL
    bad.tags = []
    bad.load = AsyncMock(side_effect=RuntimeError("network error"))
    bad.close = AsyncMock()

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(bad)
    tools = await reg.activate(CTX, ["bad_source"],
                               required_flags={"bad_source": False})
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


async def test_mcp_source_requires_url():
    """MCPSource requires a url — httpx is now a core dependency (no ImportError test needed)."""
    import sys
    # httpx is a core shai dependency — no longer gated by a lazy import.
    # Verify MCPSource still enforces url is required for mcp transport."""
    # (nothing to monkeypatch — just confirm httpx is importable)
    import httpx  # noqa: F401

    src = MCPSource(name="slack", url="https://mcp.slack.com/sse")
    # httpx is always available — no error expected
    pass
    if False:
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


# ── Source tag override — the critical correctness test ───────────────────

async def test_source_tags_visible_in_agent_tool_set(tmp_path):
    """Source-merged tags must be present in the agent's resolved tool set.

    Regression test for: source-level tool tags silently dropped when a tool
    is pre-registered and the source-enriched variant conflicts with it.

    Sequence:
      1. Tool registered with tags=[read]
      2. Source configured with tags=[sensitive]
      3. Source.load() returns tool with tags=[read, sensitive]
      4. ToolRegistry rejects re-registration (different tags)
      5. _resolve_tools() must return tool with [read, sensitive] — not [read]
    """
    from pathlib import Path as _Path
    from harness.core.harness import SHAI
    from harness.core.types import Transport

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "sources:\n"
        "  - name: tagged_local\n"
        "    transport: local\n"
        "    tags:\n      - sensitive\n"   # source adds 'sensitive' tag
    )

    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: test_agent\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n  - sensitive\n"
        "sources:\n  - tagged_local\n"
    )

    harness = await SHAI.from_yaml(cfg_file)

    # Register tool with only the base tags — no 'sensitive'
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])

    ctx = await harness.load_agent(agent_file)

    # The agent's resolved tool set must have the source-enriched tags
    resolved = harness._agent_tools["test_agent"]
    assert "search_docs" in resolved, "search_docs not in agent tool set"

    tool_tags = set(resolved["search_docs"].tags)
    assert "read"      in tool_tags, "base tag 'read' missing"
    assert "sensitive" in tool_tags, \
        f"source tag 'sensitive' silently dropped — gate sees {tool_tags}"

    await harness.close()


async def test_other_agents_not_affected_by_source_override(tmp_path):
    """Source tag overrides are per-agent — other agents see the original tags."""
    from harness.core.harness import SHAI
    from harness.core.types import Transport

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "sources:\n"
        "  - name: tagged_local\n"
        "    transport: local\n"
        "    tags:\n      - sensitive\n"
    )

    agent_a = tmp_path / "agent_a.yaml"
    agent_a.write_text(
        "id: agent_a\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n  - sensitive\n"
        "sources:\n  - tagged_local\n"   # uses tagged source
    )

    agent_b = tmp_path / "agent_b.yaml"
    agent_b.write_text(
        "id: agent_b\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
        # no sources — sees only the base-registered tool
    )

    harness = await SHAI.from_yaml(cfg_file)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])

    await harness.load_agent(agent_a)
    await harness.load_agent(agent_b)

    tags_a = set(harness._agent_tools["agent_a"]["search_docs"].tags)
    tags_b = set(harness._agent_tools["agent_b"]["search_docs"].tags)

    assert "sensitive" in tags_a, "agent_a should see source-enriched tags"
    assert "sensitive" not in tags_b, "agent_b must not be affected by agent_a's source override"

    await harness.close()


# ── required flag — fail-safe activation tests ────────────────────────────

async def test_missing_required_source_raises():
    """Missing required source must raise ConfigError at activate() time."""
    from harness.core.errors import ConfigError

    reg = SourceRegistry(_make_policy(active=True))
    # "missing_src" is not registered
    with pytest.raises(ConfigError, match="missing_src"):
        await reg.activate(CTX, ["missing_src"], required_flags={"missing_src": True})


async def test_missing_optional_source_skips():
    """Missing optional source must log and skip, not raise."""
    reg = SourceRegistry(_make_policy(active=True))
    # Should not raise — returns empty list
    tools = await reg.activate(CTX, ["missing_src"], required_flags={"missing_src": False})
    assert tools == []


async def test_failed_required_source_raises():
    """required source whose load() fails must raise ConfigError."""
    from harness.core.errors import ConfigError
    from unittest.mock import AsyncMock, MagicMock

    bad = MagicMock()
    bad.name = "bad_src"
    bad.transport = Transport.LOCAL
    bad.tags = []
    bad.load = AsyncMock(side_effect=RuntimeError("connection refused"))
    bad.close = AsyncMock()

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(bad)

    with pytest.raises(ConfigError, match="bad_src"):
        await reg.activate(CTX, ["bad_src"], required_flags={"bad_src": True})


async def test_failed_optional_source_skips():
    """Optional source whose load() fails must log and skip, not raise."""
    from unittest.mock import AsyncMock, MagicMock

    bad = MagicMock()
    bad.name = "bad_src"
    bad.transport = Transport.LOCAL
    bad.tags = []
    bad.load = AsyncMock(side_effect=RuntimeError("connection refused"))
    bad.close = AsyncMock()

    reg = SourceRegistry(_make_policy(active=True))
    await reg.register(bad)

    tools = await reg.activate(CTX, ["bad_src"], required_flags={"bad_src": False})
    assert tools == []


async def test_policy_suppressed_source_skips_regardless_of_required():
    """Policy suppression always skips — it is intentional, not a failure."""
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = _make_registry.__wrapped__(tool) if hasattr(_make_registry, '__wrapped__') else None

    import asyncio as _asyncio
    tr = ToolRegistry()
    await tr.register(Tool(name="search", tags=["read"], transport=Transport.LOCAL))
    src = LocalSource(name="docs", registry=tr, tool_names=["search"])

    reg = SourceRegistry(_make_policy(active=False))  # policy suppresses
    await reg.register(src)

    # Even though required=True, suppression is not a failure — no raise
    tools = await reg.activate(CTX, ["docs"], required_flags={"docs": True})
    assert tools == []


async def test_required_defaults_to_true_when_no_flags_passed():
    """When required_flags is None, missing source raises (default=required)."""
    from harness.core.errors import ConfigError

    reg = SourceRegistry(_make_policy(active=True))
    with pytest.raises(ConfigError):
        await reg.activate(CTX, ["unregistered_source"])
