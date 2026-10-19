"""An MCP tool that reaches the filesystem declares its path arguments in the
manifest and is governed by the same path check as a local tool.

The manifest's bytes are what `shai mcp onboard` approves, so `path_args` is
covered by the baseline hash: editing it denies the source until re-onboarding.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.config.loader import build_secrets_provider, load_dict, read_yaml
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.mcp.manifest import MCPManifest, load_manifest_file
from harness.mcp.onboard import run_onboarding
from harness.policy.rules import RuleBasedPolicy
from harness.tools.source import MCPSource
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

_HEAD = (
    "id: svc\n"
    'display_name: "Service"\n'
    'url: "https://mcp.example.test/sse"\n'
    'allowed_urls: ["https://mcp.example.test/*"]\n'
    "tools:\n"
)


def _manifest(tool: str) -> str:
    return _HEAD + tool


READ_FILE = (
    "  - name: read_file\n"
    "    tags: [fs]\n"
    '    description: "Read a file."\n'
    "    path_args: {path: read}\n"
)


async def _world(tmp_path: Path, monkeypatch, manifest: str, allow: str | None = "data"):
    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    manifest_path = mcp_dir / "svc.yaml"
    manifest_path.write_text(manifest)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "f.txt").write_text("x")
    (tmp_path / "elsewhere").mkdir()
    cfg_path = tmp_path / "harness.yaml"
    cfg_path.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
        "sources:\n  - name: svc\n    transport: mcp\n"
        f"mcp_manifests_dir: '{mcp_dir.as_posix()}'\n"
        f"mcp_baseline:\n  path: '{(tmp_path / 'baseline.db').as_posix()}'\n"
        "  secret: test-secret\n  cache_ttl_seconds: 0\n"
    )
    grant = f"allowed_paths:\n  read: ['{(tmp_path / allow).as_posix()}']\n" if allow else ""
    agent_path = tmp_path / "agent.yaml"
    agent_path.write_text(
        "id: test_agent\nallowed_tool_names: [read_file]\nallowed_tags: [fs, mcp]\n"
        f"sources: [svc]\n{grant}"
    )

    async def fake_connect(self):
        self._connected = True

    async def fake_connect_token(self, method, path):
        return "connect-token"

    async def fake_post(self, payload, dispatch_token=None):
        names = [{"name": n} for n in self._tool_specs]
        return {"jsonrpc": "2.0", "id": payload["id"], "result": {"tools": names}}

    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_connect_token", fake_connect_token)
    monkeypatch.setattr(MCPSource, "_post", fake_post)

    async def fake_fetch_live_tools(manifest, *, provider, **_):
        return [{"name": t.name, "description": t.description} for t in manifest.tools]

    from harness.mcp import onboard as onboard_module
    monkeypatch.setattr(onboard_module, "_fetch_live_tools", fake_fetch_live_tools)

    raw = read_yaml(cfg_path)
    provider = build_secrets_provider(raw.get("secrets"))
    config = load_dict(raw, provider=provider, source=str(cfg_path))
    emitter = AuditEmitter([RecordingSink()])
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter
    )).passed
    return cfg_path, agent_path, manifest_path, config, provider, emitter


async def test_manifest_path_args_reach_the_registered_tool(tmp_path: Path, monkeypatch):
    cfg, agent, *_ = await _world(tmp_path, monkeypatch, _manifest(READ_FILE))
    h = await SHAI.from_yaml(cfg)
    await h.load_agent(agent)
    tool = h._agent_tools["test_agent"]["read_file"][1]
    assert tool.transport == Transport.MCP
    assert tool.path_args == {"path": "read"}
    await h.close()


async def test_gate_checks_an_mcp_tools_path_argument_against_the_agent_grant(tmp_path: Path, monkeypatch):
    cfg, agent, *_ = await _world(tmp_path, monkeypatch, _manifest(READ_FILE))
    h = await SHAI.from_yaml(cfg)
    ctx = await h.load_agent(agent)
    inside = await h.check_tool_call("read_file", {"path": str(tmp_path / "data" / "f.txt")}, ctx)
    outside = await h.check_tool_call("read_file", {"path": str(tmp_path / "elsewhere" / "f.txt")}, ctx)
    assert inside.allowed
    assert not outside.allowed
    assert "path not allowed" in outside.deny_reason
    await h.close()


async def test_an_agent_without_a_grant_is_denied_every_mcp_path(tmp_path: Path, monkeypatch):
    cfg, agent, *_ = await _world(tmp_path, monkeypatch, _manifest(READ_FILE), allow=None)
    h = await SHAI.from_yaml(cfg)
    ctx = await h.load_agent(agent)
    gate = await h.check_tool_call("read_file", {"path": str(tmp_path / "data" / "f.txt")}, ctx)
    assert not gate.allowed
    await h.close()


async def test_an_fs_tagged_manifest_tool_without_path_args_is_refused(tmp_path: Path, monkeypatch):
    undeclared = READ_FILE.replace("    path_args: {path: read}\n", "")
    cfg, agent, *_ = await _world(tmp_path, monkeypatch, _manifest(undeclared))
    h = await SHAI.from_yaml(cfg)
    with pytest.raises(ConfigError, match="path_args"):
        await h.load_agent(agent)
    await h.close()


def test_an_invalid_access_value_fails_manifest_validation(tmp_path: Path):
    path = tmp_path / "svc.yaml"
    path.write_text(_manifest(READ_FILE.replace("{path: read}", "{path: delete}")))
    with pytest.raises(ConfigError):
        load_manifest_file(path)


def test_path_args_default_to_empty_and_round_trip():
    plain = MCPManifest.model_validate({
        "id": "svc", "display_name": "S", "url": "https://mcp.example.test/sse",
        "allowed_urls": ["https://mcp.example.test/*"],
        "tools": [{"name": "search", "tags": ["read"]}],
    })
    assert plain.tools[0].path_args == {}


async def test_editing_path_args_changes_the_hash_and_the_source_needs_reonboarding(
    tmp_path: Path, monkeypatch
):
    cfg, agent, manifest_path, config, provider, emitter = await _world(
        tmp_path, monkeypatch, _manifest(READ_FILE),
    )
    h = await SHAI.from_yaml(cfg)
    ctx = await h.load_agent(agent)
    call = {"path": str(tmp_path / "data" / "f.txt")}
    assert (await h.check_tool_call("read_file", call, ctx)).allowed

    manifest_path.write_text(_manifest(READ_FILE.replace("{path: read}", "{path: write}")))
    denied = await h.check_tool_call("read_file", call, ctx)
    assert not denied.allowed
    assert "re-onboarding required" in denied.deny_reason

    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter
    )).passed
    # The source is built once at startup, so the edited declaration takes effect
    # on restart, like every other manifest field.
    assert (await h.check_tool_call("read_file", call, ctx)).allowed
    await h.close()

    restarted = await SHAI.from_yaml(cfg)
    ctx2 = await restarted.load_agent(agent)
    needs_write = await restarted.check_tool_call("read_file", call, ctx2)
    assert not needs_write.allowed  # the agent holds a read grant only
    await restarted.close()


async def test_protected_set_applies_to_an_mcp_tool(tmp_path: Path):
    tool = Tool(name="read_file", tags=["fs"], transport=Transport.MCP, path_args={"path": "read"})
    (tmp_path / "state").mkdir()
    from harness.agents.agent_config import AgentConfig
    from harness.core.path_scope import canonicalize_path
    agent = AgentConfig.model_validate({
        "id": "test_agent", "allowed_tool_names": ["read_file"], "allowed_tags": ["fs"],
        "allowed_paths": {"read": [str(tmp_path)]},
    })
    sink = RecordingSink()
    decision = await check_tool_call.run(
        "read_file", {"path": str(tmp_path / "state" / "baseline.db")},
        AgentContext(agent_id="test_agent"),
        agent_config=agent, tools={"read_file": tool}, policy=RuleBasedPolicy(),
        arg_scanners=[], emitter=AuditEmitter([sink]), tenant_id="test",
        protected_paths=(canonicalize_path(str(tmp_path / "state")),),
    )
    assert not decision.allowed
    assert sink.events[0].extra == {"fs_rule": "protected"}
