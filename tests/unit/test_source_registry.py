"""Unit tests for SourceRegistry, LocalSource, and MCPSource scaffolding."""
from __future__ import annotations

from pathlib import Path

import pytest

import harness.tools.source as source_module
from harness.agents.agent_config import RuleConfig, RuleMatchConfig
from harness.config.schema import SourceConfig
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.policy.rules import RuleBasedPolicy
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, MCPSource, MCPSourceParams, SourceRegistry
from harness.tools.tool import Tool


def _local(name: str = "docs", **kw) -> SourceConfig:
    return SourceConfig(name=name, **kw)


def _mcp(name: str = "slack", url: str = "https://mcp.slack.com/sse", **kw) -> MCPSourceParams:
    return MCPSourceParams(name, url, **kw)

CTX = AgentContext(agent_id="test_agent")


# ── Fixtures ──────────────────────────────────────────────────────────────

def _make_policy(active: bool = True) -> RuleBasedPolicy:
    """Real policy engine — suppression comes from a real rule, not a stub.

    RuleBasedPolicy is pure in-process code, so there is nothing to gain from
    faking it, and a stub cannot catch a change in how suppression is decided.
    """
    if active:
        return RuleBasedPolicy()
    return RuleBasedPolicy(source_rules=[RuleConfig(
        id="suppress_for_test_agent",
        match=RuleMatchConfig(agent_ids=[CTX.agent_id]),
        action="suppress",
        reason="suppressed by test policy",
    )])


class FailingSource:
    """ToolSource whose load() always raises — real class, not a MagicMock.

    Satisfies the ToolSource protocol exactly, so it fails the same way a
    real source with a dead connection does.
    """

    transport = Transport.LOCAL
    tags: list[str] = []

    def __init__(self, name: str, error: str = "network error") -> None:
        self.name   = name
        self._error = error

    async def load(self, ctx: AgentContext) -> list[Tool]:
        raise RuntimeError(self._error)

    async def close(self) -> None:
        pass


async def _make_registry(*tools: Tool) -> ToolRegistry:
    reg = ToolRegistry()
    for t in tools:
        reg.register(t)
    return reg


# ── SourceRegistry ────────────────────────────────────────────────────────

async def test_register_and_get():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(_local("docs"), registry=ToolRegistry())
    reg.register(src)
    got = reg.get("docs")
    assert got is src


async def test_register_same_object_idempotent():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(_local("docs"), registry=ToolRegistry())
    r1 = reg.register(src)
    r2 = reg.register(src)
    assert r1 is True
    assert r2 is False


async def test_register_different_object_same_name_raises():
    reg = SourceRegistry(_make_policy())
    src1 = LocalSource(_local("docs"), registry=ToolRegistry())
    src2 = LocalSource(_local("docs"), registry=ToolRegistry())
    reg.register(src1)
    with pytest.raises(ConfigError):
        reg.register(src2)


async def test_get_unknown_raises():
    reg = SourceRegistry(_make_policy())
    with pytest.raises(ConfigError):
        reg.get("nonexistent")


async def test_deregister():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(_local("docs"), registry=ToolRegistry())
    reg.register(src)
    removed = reg.deregister(src)
    assert removed is True
    with pytest.raises(ConfigError):
        reg.get("docs")


async def test_deregister_unknown_returns_false():
    reg = SourceRegistry(_make_policy())
    src = LocalSource(_local("docs"), registry=ToolRegistry())
    result = reg.deregister(src)
    assert result is False


async def test_list():
    reg = SourceRegistry(_make_policy())
    s1 = LocalSource(_local("a"), registry=ToolRegistry())
    s2 = LocalSource(_local("b"), registry=ToolRegistry())
    reg.register(s1)
    reg.register(s2)
    sources = reg.list()
    assert {s.name for s in sources} == {"a", "b"}


# ── activate ──────────────────────────────────────────────────────────────

async def test_activate_returns_tools():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = await _make_registry(tool)
    src = LocalSource(_local("docs", tool_names=["search"]), registry=tool_reg)

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(src)
    tools = await reg.activate(CTX, ["docs"])
    assert len(tools) == 1
    assert tools[0].name == "search"


async def test_activate_suppressed_by_policy():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = await _make_registry(tool)
    src = LocalSource(_local("docs", tool_names=["search"]), registry=tool_reg)

    reg = SourceRegistry(_make_policy(active=False))  # policy blocks it
    reg.register(src)
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

    bad = FailingSource("bad_source")

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(bad)
    with pytest.raises(ConfigError, match="bad_source"):
        await reg.activate(CTX, ["bad_source"])


async def test_activate_failed_optional_source_skipped():
    """Optional source whose load() raises is skipped, not raised."""
    bad = FailingSource("bad_source")

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(bad)
    tools = await reg.activate(CTX, ["bad_source"],
                               required_flags={"bad_source": False})
    assert tools == []


async def test_activate_merges_multiple_sources():
    t1 = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    t2 = Tool(name="send_email", tags=["write"], transport=Transport.LOCAL)
    reg1 = await _make_registry(t1)
    reg2 = await _make_registry(t2)
    s1 = LocalSource(_local("read_src", tool_names=["search"]),  registry=reg1)
    s2 = LocalSource(_local("write_src", tool_names=["send_email"]), registry=reg2)

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(s1)
    reg.register(s2)
    tools = await reg.activate(CTX, ["read_src", "write_src"])
    names = {t.name for t in tools}
    assert names == {"search", "send_email"}


# ── LocalSource ───────────────────────────────────────────────────────────

async def test_local_source_returns_named_tools():
    t1 = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    t2 = Tool(name="write", tags=["write"], transport=Transport.LOCAL)
    reg = await _make_registry(t1, t2)
    src = LocalSource(_local("read_only", tool_names=["search"]), registry=reg)
    tools = await src.load(CTX)
    assert len(tools) == 1
    assert tools[0].name == "search"


async def test_local_source_all_tools_when_no_names():
    t1 = Tool(name="a", tags=[], transport=Transport.LOCAL)
    t2 = Tool(name="b", tags=[], transport=Transport.LOCAL)
    reg = await _make_registry(t1, t2)
    src = LocalSource(_local("all"), registry=reg)
    tools = await src.load(CTX)
    assert {t.name for t in tools} == {"a", "b"}


async def test_local_source_merges_tags():
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    reg = await _make_registry(tool)
    src = LocalSource(_local("docs", tool_names=["search"], tags=["internal"]),
                      registry=reg)
    tools = await src.load(CTX)
    assert "internal" in tools[0].tags
    assert "read" in tools[0].tags


async def test_local_source_missing_tool_skipped():
    reg = await _make_registry()  # empty registry
    src = LocalSource(_local("docs", tool_names=["nonexistent"]), registry=reg)
    tools = await src.load(CTX)
    assert tools == []


async def test_local_source_close_noop():
    src = LocalSource(_local("docs"), registry=ToolRegistry())
    await src.close()  # must not raise


# ── MCPSource construction and config ─────────────────────────────────────

def test_mcp_source_constructed():
    src = MCPSource(_mcp(credentials={"token": "tok_abc"}, tags=["messaging"]))
    assert src.name == "slack"
    assert src.transport == Transport.MCP
    assert "messaging" in src.tags
    assert not src._connected


def test_mcp_source_requires_url():
    """An empty url must raise, not produce a source with no endpoint."""
    unresolved = MCPSourceParams("slack", "")
    with pytest.raises(ConfigError, match="url is required"):
        MCPSource(unresolved)


async def test_mcp_source_call_raises_when_not_connected():
    src = MCPSource(_mcp())
    from harness.core.errors import ConfigError
    with pytest.raises(ConfigError, match="not connected"):
        await src.call("search", {})


async def test_mcp_source_close_when_not_connected():
    src = MCPSource(_mcp())
    await src.close()  # must not raise
    assert not src._connected


# ── Source attribution (ticket: fix source attribution loss) ──────────────

async def test_mcp_fetch_tools_stamps_own_source_name(monkeypatch):
    """_fetch_tools() must stamp source_name=self.name on every tool it

    builds — the one place remote tool identity is established. Nothing
    downstream should have to guess it back.
    """
    src = MCPSource(_mcp("weather_api", tool_specs={
        "get_forecast": {"description": "d", "tags": [], "action": "allow"}
    }))

    async def fake_post(payload, dispatch_token=None):
        return {"result": {"tools": [{"name": "get_forecast", "description": "d"}]}}

    monkeypatch.setattr(src, "_post", fake_post)
    tools = await src._fetch_tools()

    assert len(tools) == 1
    assert tools[0].source_name == "weather_api"


async def test_two_unrestricted_mcp_sources_resolve_independently(tmp_path: Path, monkeypatch):
    """Regression: two unrestricted MCP sources (no tool_names, no manifest

    tool specs) used to be indistinguishable to the old heuristic, which always
    picked "the first unrestricted MCP source" for every MCP tool regardless
    of which source actually produced it. With source_name carried from
    MCPSource._fetch_tools(), a tool from the second source must resolve to
    the second source — not the first, and not "local".
    """
    from harness.core.harness import SHAI
    from harness.mcp.baseline import record_baseline
    from harness.mcp.manifest import manifest_file_hash

    async def fake_connect(self):
        self._connected = True

    async def fake_fetch_tools(self):
        return [Tool(name=f"{self.name}_tool", tags=["read"], transport=Transport.MCP,
                     source_name=self.name)]

    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_fetch_tools", fake_fetch_tools)

    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    baseline_db = tmp_path / "baseline.db"
    secret = b"test-secret"
    for source_id, host in (("source_a", "a.example"), ("source_b", "b.example")):
        manifest_path = mcp_dir / f"{source_id}.yaml"
        manifest_path.write_text(
            f"id: {source_id}\ndisplay_name: \"{source_id}\"\n"
            f"url: \"http://{host}/sse\"\n"
        )
        record_baseline(baseline_db, source_id, manifest_file_hash(manifest_path), secret)

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "sources:\n"
        "  - name: source_a\n    transport: mcp\n"
        "  - name: source_b\n    transport: mcp\n"
        f"mcp_manifests_dir: {mcp_dir}\n"
        "mcp_baseline:\n"
        f"  path: {baseline_db}\n"
        "  secret: test-secret\n"
    )
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: test_agent\n"
        "sources:\n  - source_a\n  - source_b\n"
        "allowed_tool_names:\n  - source_a_tool\n  - source_b_tool\n"
        "allowed_tags:\n  - read\n"
    )

    harness = await SHAI.from_yaml(cfg_file)
    ctx = await harness.load_agent(agent_file)

    gate_a = await harness.check_tool_call("source_a_tool", {}, ctx)
    gate_b = await harness.check_tool_call("source_b_tool", {}, ctx)

    assert gate_a.source_name == "source_a"
    assert gate_b.source_name == "source_b"
    assert gate_b.source_name != "local"

    await harness.close()


# ── MCPSource header building ─────────────────────────────────────────────

def test_mcp_token_credential_becomes_bearer():
    src = MCPSource(_mcp("s", "http://x", credentials={"token": "mytoken"}))
    headers = src._build_headers()
    assert headers.get("Authorization") == "Bearer mytoken"


def test_mcp_authorization_credential_used_asis():
    src = MCPSource(_mcp("s", "http://x",
                           credentials={"Authorization": "Basic abc"}))
    headers = src._build_headers()
    assert headers["Authorization"] == "Basic abc"


def test_mcp_custom_header_passed_through():
    src = MCPSource(_mcp("s", "http://x",
                           credentials={"X-Custom-Header": "value"}))
    headers = src._build_headers()
    assert headers["X-Custom-Header"] == "value"


# ── SSE session establishment ─────────────────────────────────────────────
#
# Exercised through _open_sse_session() — the behavioral unit that actually
# owns "parse the endpoint event, fail loudly if it carries no sessionId" —
# rather than importing the private sessionId-string-parsing helper directly.
# SSE parsing itself (_parse_sse) is faked so no real network/stream is needed.

class _FakeSSEResponse:
    status_code = 200


class _FakeStreamCtx:
    async def __aenter__(self):
        return _FakeSSEResponse()

    async def __aexit__(self, *exc_info):
        return False


class _FakeClient:
    def stream(self, method, path):
        return _FakeStreamCtx()


def _mcp_source_with_fake_transport(monkeypatch, endpoint_data: str):
    src = MCPSource(_mcp())
    src._client = _FakeClient()

    async def fake_parse_sse(response):
        yield ("endpoint", endpoint_data)

    monkeypatch.setattr(source_module, "_parse_sse", fake_parse_sse)
    return src


async def test_open_sse_session_extracts_session_id_from_path(monkeypatch):
    src = _mcp_source_with_fake_transport(monkeypatch, "/message?sessionId=abc123")
    assert await src._open_sse_session() == "abc123"


async def test_open_sse_session_extracts_session_id_from_full_url(monkeypatch):
    src = _mcp_source_with_fake_transport(
        monkeypatch, "https://server.com/message?sessionId=xyz"
    )
    assert await src._open_sse_session() == "xyz"


async def test_open_sse_session_raises_when_sessionid_missing(monkeypatch):
    """A malformed endpoint event fails loudly rather than connecting with

    no session id — the same contract _extract_session_id's return-None
    used to leave the caller to enforce.
    """
    src = _mcp_source_with_fake_transport(monkeypatch, "/message?foo=bar")
    with pytest.raises(ConfigError, match="no sessionId"):
        await src._open_sse_session()


# ── SourceConfig schema ───────────────────────────────────────────────────

def test_source_config_accepts_mcp_transport_by_name():
    """An MCP source is declared here by name only — its manifest resolves
    by convention from mcp_manifests_dir (see harness.mcp.discovery)."""
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(name="slack", transport="mcp")
    assert cfg.transport == Transport.MCP


def test_source_config_local_valid():
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(name="docs", transport="local")
    assert cfg.transport == Transport.LOCAL


def _minimal_config_kwargs() -> dict:
    return dict(
        scan_input={"enabled": False},
        scan_output={"enabled": False},
    )


def test_harness_config_requires_manifests_dir_for_mcp_source():
    from pydantic import ValidationError

    from harness.config.schema import HarnessConfig
    with pytest.raises(ValidationError, match="mcp_manifests_dir is required"):
        HarnessConfig(
            sources=[SourceConfig(name="slack", transport=Transport.MCP)],
            **_minimal_config_kwargs(),
        )


def test_harness_config_requires_baseline_secret_for_mcp_source():
    from pydantic import ValidationError

    from harness.config.schema import HarnessConfig
    with pytest.raises(ValidationError, match="mcp_baseline.secret is required"):
        HarnessConfig(
            sources=[SourceConfig(name="slack", transport=Transport.MCP)],
            mcp_manifests_dir="./mcp",
            **_minimal_config_kwargs(),
        )


def test_harness_config_local_only_needs_no_mcp_baseline_config():
    from harness.config.schema import HarnessConfig
    config = HarnessConfig(
        sources=[SourceConfig(name="docs")],
        **_minimal_config_kwargs(),
    )
    assert config.mcp_manifests_dir is None


# ── Integration: SHAI.from_yaml with sources ──────────────────────────────

async def test_shai_from_yaml_with_sources_section(tmp_path: Path):
    """from_yaml builds source_registry from config.sources."""
    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
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
    names = {t.name for t in harness.tools_for(ctx)}
    assert "search_docs" in names
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
    from harness.core.harness import SHAI
    from harness.core.types import Transport

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
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
    resolved = {t.name: t for t in harness.tools_for(ctx)}
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

    ctx_a = await harness.load_agent(agent_a)
    ctx_b = await harness.load_agent(agent_b)

    tool_a = {t.name: t for t in harness.tools_for(ctx_a)}["search_docs"]
    tool_b = {t.name: t for t in harness.tools_for(ctx_b)}["search_docs"]
    tags_a = set(tool_a.tags)
    tags_b = set(tool_b.tags)

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

    bad = FailingSource("bad_src", error="connection refused")

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(bad)

    with pytest.raises(ConfigError, match="bad_src"):
        await reg.activate(CTX, ["bad_src"], required_flags={"bad_src": True})


async def test_failed_optional_source_skips():
    """Optional source whose load() fails must log and skip, not raise."""
    bad = FailingSource("bad_src", error="connection refused")

    reg = SourceRegistry(_make_policy(active=True))
    reg.register(bad)

    tools = await reg.activate(CTX, ["bad_src"], required_flags={"bad_src": False})
    assert tools == []


async def test_policy_suppressed_source_skips_regardless_of_required():
    """Policy suppression always skips — it is intentional, not a failure."""
    tool = Tool(name="search", tags=["read"], transport=Transport.LOCAL)
    tool_reg = _make_registry.__wrapped__(tool) if hasattr(_make_registry, '__wrapped__') else None

    tr = ToolRegistry()
    tr.register(Tool(name="search", tags=["read"], transport=Transport.LOCAL))
    src = LocalSource(_local("docs", tool_names=["search"]), registry=tr)

    reg = SourceRegistry(_make_policy(active=False))  # policy suppresses
    reg.register(src)

    # Even though required=True, suppression is not a failure — no raise
    tools = await reg.activate(CTX, ["docs"], required_flags={"docs": True})
    assert tools == []


async def test_required_defaults_to_true_when_no_flags_passed():
    """When required_flags is None, missing source raises (default=required)."""
    from harness.core.errors import ConfigError

    reg = SourceRegistry(_make_policy(active=True))
    with pytest.raises(ConfigError):
        await reg.activate(CTX, ["unregistered_source"])


async def test_reload_agent_honours_required_false(tmp_path: Path):
    """reload_agent must apply the same required_flags load_agent does.

    Regression (C4): reload_agent was a copy of load_agent that called
    activate() with no required_flags. activate defaults a missing flag to
    True, so a source declared `required: false` was optional at load and
    mandatory at reload — an enrichment source that had gone away turned a
    reload into ConfigError while the original load had succeeded.
    """
    from harness.core.harness import SHAI

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "sources:\n"
        "  - name: optional_src\n"
        "    transport: local\n"
        "    required: false\n"
    )
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: reload_agent_test\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
        "sources:\n  - optional_src\n"
    )

    harness = await SHAI.from_yaml(cfg_file)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent_file)

    # The optional source goes away between load and reload.
    harness._source_registry._sources.pop("optional_src")

    ctx = await harness.maintenance.reload_agent(agent_file)      # must not raise
    assert ctx.agent_id == "reload_agent_test"
    assert "search_docs" in {t.name for t in harness.tools_for(ctx)}
    await harness.close()


async def _tools_for_harness(tmp_path: Path):
    """A parent with a narrower subagent, and a tool whose tag the parent lacks."""
    from harness.core.harness import SHAI

    cfg_file = tmp_path / "h.yaml"
    cfg_file.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
    )
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: parent_agent\n"
        # wipe_db is named here but its `destructive` tag is NOT in allowed_tags,
        # so gate layer 4 denies it — tools_for must not list it either.
        "allowed_tool_names:\n  - search_docs\n  - send_email\n  - wipe_db\n"
        "allowed_tags:\n  - read\n  - external_write\n"
        "sub_agents:\n"
        "  - id: research_sub\n"
        "    allowed_tool_names:\n      - search_docs\n"
        "    allowed_tags:\n      - read\n"
    )
    harness = await SHAI.from_yaml(cfg_file)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL),
        Tool(name="send_email", tags=["external_write"], transport=Transport.LOCAL),
        Tool(name="wipe_db", tags=["destructive"], transport=Transport.LOCAL),
    ])
    ctx = await harness.load_agent(agent_file)
    return harness, ctx


async def test_tools_for_applies_the_gates_static_layers(tmp_path: Path):
    """tools_for() applies L1 (allowed_tool_names) and L4 (allowed_tags)."""
    harness, ctx = await _tools_for_harness(tmp_path)

    names = [t.name for t in harness.tools_for(ctx)]
    assert names == ["search_docs", "send_email"]     # wipe_db fails L4
    assert all(isinstance(t, Tool) for t in harness.tools_for(ctx))
    # Unknown agent is empty, not an error.
    assert harness.tools_for(AgentContext(agent_id="nobody")) == []
    await harness.close()


async def test_tools_for_narrows_to_the_subagent(tmp_path: Path):
    """A subagent context must not be handed the parent's tool set.

    Regression: tools_for keyed on ctx.agent_id alone, so a subagent context
    returned every tool the parent could reach. The gate denied them at L1, but
    an integration building an LLM tool list from this — run_turn does — offered
    a subagent's model tools that were refused on every call.
    """
    harness, ctx = await _tools_for_harness(tmp_path)
    child = harness.scope_context_for_subagent(ctx, "research_sub")

    assert [t.name for t in harness.tools_for(child)] == ["search_docs"]
    # A subagent the parent does not declare reaches nothing, as at the gate.
    undeclared = AgentContext(agent_id="parent_agent", sub_agent_id="nope")
    assert harness.tools_for(undeclared) == []
    await harness.close()


async def test_tools_for_agrees_with_the_gate(tmp_path: Path):
    """The listed set and the set check_tool_call allows must be identical."""
    harness, ctx = await _tools_for_harness(tmp_path)
    child = harness.scope_context_for_subagent(ctx, "research_sub")

    for scope in (ctx, child):
        listed = {t.name for t in harness.tools_for(scope)}
        allowed = {
            name for name in ("search_docs", "send_email", "wipe_db")
            if (await harness.check_tool_call(name, {}, scope)).allowed
        }
        assert listed == allowed, f"{listed} != {allowed}"
    await harness.close()
