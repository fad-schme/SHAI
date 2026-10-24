"""End-to-end: an MCP source is only ever built — connected, tools
registered — for a `sources:` entry whose manifest has an approved,
matching baseline record at startup. Once built, though, the source stays
connected: `check_tool_call` re-checks the baseline on every call, so an
edit denies the very next call without a restart. A re-approved edit takes
effect on restart: the gate admits only the manifest the process loaded.
(tickets 02/05, corrected in ticket 10 — sources: declares MCP, approval gates
the build.)
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config.loader import build_secrets_provider, load_dict, read_yaml
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Transport
from harness.mcp.onboard import run_onboarding
from harness.tools.source import MCPSource
from harness.tools.tool import Tool


def _write_manifest(path: Path, description: str = "Search internal documentation for a query.") -> None:
    path.write_text(
        "id: svc\n"
        "display_name: \"Service\"\n"
        "url: \"https://mcp.example.test/sse\"\n"
        "allowed_urls: [\"https://mcp.example.test/*\"]\n"
        "tools:\n"
        "  - name: search\n"
        "    tags: [read]\n"
        f"    description: \"{description}\"\n"
    )


def _harness_config(tmp_path: Path) -> Path:
    cfg_path = tmp_path / "harness.yaml"
    cfg_path.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
        "sources:\n  - name: svc\n    transport: mcp\n"
        f"mcp_manifests_dir: {tmp_path / 'mcp'}\n"
        "mcp_baseline:\n"
        f"  path: {tmp_path / 'baseline.db'}\n"
        "  secret: test-secret\n"
        "  cache_ttl_seconds: 0\n"
    )
    return cfg_path


def _write_agent(tmp_path: Path) -> Path:
    agent_path = tmp_path / "agent.yaml"
    agent_path.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search]\n"
        "allowed_tags: [read]\n"
        "sources: [svc]\n"
    )
    return agent_path


async def test_onboard_then_allowed_then_reonboard_after_edit(tmp_path: Path, monkeypatch):
    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    manifest_path = mcp_dir / "svc.yaml"
    _write_manifest(manifest_path)

    cfg_path = _harness_config(tmp_path)
    agent_path = _write_agent(tmp_path)

    async def fake_connect(self):
        self._connected = True

    async def fake_fetch_tools(self):
        return [
            Tool(name=n, tags=spec.get("tags", []), transport=Transport.MCP,
                 description=spec.get("description"), source_name=self.name)
            for n, spec in self._tool_specs.items()
        ]

    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_fetch_tools", fake_fetch_tools)

    async def fake_fetch_live_tools(manifest, *, provider, **_):
        return [{"name": t.name, "description": t.description} for t in manifest.tools]

    from harness.mcp import onboard as onboard_module
    monkeypatch.setattr(onboard_module, "_fetch_live_tools", fake_fetch_live_tools)

    # 1. Before onboarding: no approved baseline exists, so the declared
    # `svc` source is never built at all — the agent's declared source is
    # "not registered", and required=True (the default) makes that a
    # ConfigError at load_agent() time, exactly like any other missing
    # required source.
    harness = await SHAI.from_yaml(cfg_path)
    with pytest.raises(ConfigError, match="not registered"):
        await harness.load_agent(agent_path)
    await harness.close()

    # 2. Onboard the manifest — a clean pass.
    raw = read_yaml(cfg_path)
    provider = build_secrets_provider(raw.get("secrets"))
    config = load_dict(raw, provider=provider, source=str(cfg_path))
    from harness.audit.emitter import AuditEmitter
    from tests.conftest import RecordingSink
    emitter = AuditEmitter([RecordingSink()])

    result = await run_onboarding(manifest_path, config=config, provider=provider, emitter=emitter)
    assert result.passed
    assert result.baseline_recorded

    # 3. Restart the harness — the hash now matches an approved baseline, so
    # the source is built and the tool call is allowed.
    harness2 = await SHAI.from_yaml(cfg_path)
    ctx2 = await harness2.load_agent(agent_path)
    gate2 = await harness2.check_tool_call("search", {}, ctx2)
    assert gate2.allowed

    # 4. Edit the manifest — no restart. The source stays connected (built
    # once at startup), but the gate re-checks the baseline on every call,
    # so the very next call denies without needing to restart.
    _write_manifest(manifest_path, description="A completely different tool now.")
    gate3 = await harness2.check_tool_call("search", {}, ctx2)
    assert not gate3.allowed
    assert "re-onboarding required" in gate3.deny_reason

    # 5. Re-onboard the edited manifest — still no restart. The file now matches
    # the baseline again, but the running source was built from the earlier
    # manifest, so the call stays denied with the restart reason.
    result2 = await run_onboarding(manifest_path, config=config, provider=provider, emitter=emitter)
    assert result2.passed
    gate4 = await harness2.check_tool_call("search", {}, ctx2)
    assert not gate4.allowed
    assert "restart" in gate4.deny_reason
    await harness2.close()

    # 6. Restart — the source is built from the re-approved manifest.
    harness3 = await SHAI.from_yaml(cfg_path)
    ctx3 = await harness3.load_agent(agent_path)
    gate5 = await harness3.check_tool_call("search", {}, ctx3)
    assert gate5.allowed
    await harness3.close()


def _patch_mcp_source(monkeypatch) -> None:
    async def fake_connect(self):
        self._connected = True

    async def fake_fetch_tools(self):
        return [
            Tool(name=n, tags=spec.get("tags", []), transport=Transport.MCP,
                 description=spec.get("description"), source_name=self.name)
            for n, spec in self._tool_specs.items()
        ]

    async def fake_fetch_live_tools(manifest, *, provider, **_):
        return [{"name": t.name, "description": t.description} for t in manifest.tools]

    from harness.mcp import onboard as onboard_module
    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_fetch_tools", fake_fetch_tools)
    monkeypatch.setattr(onboard_module, "_fetch_live_tools", fake_fetch_live_tools)


_MANIFEST_A = (
    'id: svc\ndisplay_name: "Service"\nurl: "https://mcp.example.test/sse"\n'
    'allowed_urls: ["https://mcp.example.test/*"]\n'
    "tools:\n"
    "  - name: search\n    tags: [read]\n    description: \"Search.\"\n"
    "  - name: delete_all\n    tags: [read]\n    description: \"Delete everything.\"\n"
)
_MANIFEST_B = (
    'id: svc\ndisplay_name: "Service"\nurl: "https://mcp.example.test/sse"\n'
    'allowed_urls: ["https://mcp.example.test/search/*"]\n'
    "tools:\n"
    "  - name: search\n    tags: [read]\n    description: \"Search.\"\n"
)


async def test_reapproved_stricter_manifest_is_not_enforced_until_restart(
    tmp_path: Path, monkeypatch
):
    """The reproduction behind the loaded-manifest check: manifest A declares
    search and delete_all; B drops delete_all and narrows the URL scope, and is
    re-onboarded while the process still runs A. The process must not call that
    state approved — the gate denies until a restart builds the source from B.
    """
    from harness.audit.emitter import AuditEmitter
    from harness.connectivity.token import verify_token
    from tests.conftest import RecordingSink

    _patch_mcp_source(monkeypatch)
    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    manifest_path = mcp_dir / "svc.yaml"
    manifest_path.write_text(_MANIFEST_A)
    cfg_path = _harness_config(tmp_path)
    agent_path = tmp_path / "agent.yaml"
    agent_path.write_text(
        "id: test_agent\nallowed_tool_names: [search, delete_all]\n"
        "allowed_tags: [read]\nsources: [svc]\n"
    )

    raw = read_yaml(cfg_path)
    provider = build_secrets_provider(raw.get("secrets"))
    config = load_dict(raw, provider=provider, source=str(cfg_path))
    sink = RecordingSink()
    emitter = AuditEmitter([sink])
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter)).passed

    running = await SHAI.from_yaml(cfg_path)
    ctx = await running.load_agent(agent_path)
    before = await running.check_tool_call("delete_all", {}, ctx)
    assert before.allowed
    token_a = verify_token(before.dispatch_token, b"test-connectivity-secret")
    assert token_a.allowed_urls == ["https://mcp.example.test/*"]

    manifest_path.write_text(_MANIFEST_B)
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter)).passed

    events_before = len(sink.events)
    denied = await running.check_tool_call("delete_all", {}, ctx)
    assert not denied.allowed
    assert denied.dispatch_token is None
    assert "restart" in denied.deny_reason
    assert "mcp.example.test" not in denied.deny_reason
    await running.close()

    restarted = await SHAI.from_yaml(cfg_path)
    ctx2 = await restarted.load_agent(agent_path)
    gone = await restarted.check_tool_call("delete_all", {}, ctx2)
    assert not gone.allowed and gone.dispatch_token is None
    kept = await restarted.check_tool_call("search", {}, ctx2)
    assert kept.allowed
    token_b = verify_token(kept.dispatch_token, b"test-connectivity-secret")
    assert token_b.allowed_urls == ["https://mcp.example.test/search/*"]
    await restarted.close()
    assert events_before >= 0


async def test_reapproved_looser_manifest_is_not_enforced_until_restart(
    tmp_path: Path, monkeypatch
):
    from harness.audit.emitter import AuditEmitter
    from tests.conftest import RecordingSink

    _patch_mcp_source(monkeypatch)
    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    manifest_path = mcp_dir / "svc.yaml"
    manifest_path.write_text(_MANIFEST_B)
    cfg_path = _harness_config(tmp_path)
    agent_path = tmp_path / "agent.yaml"
    agent_path.write_text(
        "id: test_agent\nallowed_tool_names: [search, delete_all]\n"
        "allowed_tags: [read]\nsources: [svc]\n"
    )
    raw = read_yaml(cfg_path)
    provider = build_secrets_provider(raw.get("secrets"))
    config = load_dict(raw, provider=provider, source=str(cfg_path))
    emitter = AuditEmitter([RecordingSink()])
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter)).passed

    running = await SHAI.from_yaml(cfg_path)
    ctx = await running.load_agent(agent_path)
    assert (await running.check_tool_call("search", {}, ctx)).allowed

    manifest_path.write_text(_MANIFEST_A)
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter)).passed
    denied = await running.check_tool_call("search", {}, ctx)
    assert not denied.allowed and "restart" in denied.deny_reason

    # Reverting the file to the loaded manifest admits calls again, no restart:
    # B is still the process's manifest and its hash is re-approved.
    manifest_path.write_text(_MANIFEST_B)
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter)).passed
    assert (await running.check_tool_call("search", {}, ctx)).allowed
    await running.close()


async def test_manifest_action_block_denies_through_the_real_harness(
    tmp_path: Path, monkeypatch
):
    """A manifest tool declared `action: block` is denied at the gate of a
    harness built by from_yaml — the compiled deny rule is keyed by source
    name and reaches layer 5 (ticket 11).
    """
    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    manifest_path = mcp_dir / "svc.yaml"
    manifest_path.write_text(
        "id: svc\n"
        'display_name: "Service"\n'
        'url: "https://mcp.example.test/sse"\n'
        'allowed_urls: ["https://mcp.example.test/*"]\n'
        "tools:\n"
        "  - name: search\n"
        "    tags: [read]\n"
        '    description: "Search internal documentation for a query."\n'
        "    action: allow\n"
        "  - name: delete_repo\n"
        "    tags: [read]\n"
        '    description: "Delete a repository and all of its history."\n'
        "    action: block\n"
    )
    cfg_path = _harness_config(tmp_path)
    agent_path = tmp_path / "agent.yaml"
    agent_path.write_text(
        "id: test_agent\n"
        "allowed_tool_names: [search, delete_repo]\n"
        "allowed_tags: [read]\n"
        "sources: [svc]\n"
    )

    async def fake_connect(self):
        self._connected = True

    async def fake_fetch_tools(self):
        return [
            Tool(name=n, tags=spec.get("tags", []), transport=Transport.MCP,
                 description=spec.get("description"), source_name=self.name)
            for n, spec in self._tool_specs.items()
        ]

    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_fetch_tools", fake_fetch_tools)

    async def fake_fetch_live_tools(manifest, *, provider, **_):
        return [{"name": t.name, "description": t.description} for t in manifest.tools]

    from harness.mcp import onboard as onboard_module
    monkeypatch.setattr(onboard_module, "_fetch_live_tools", fake_fetch_live_tools)

    raw = read_yaml(cfg_path)
    provider = build_secrets_provider(raw.get("secrets"))
    config = load_dict(raw, provider=provider, source=str(cfg_path))
    from harness.audit.emitter import AuditEmitter
    from tests.conftest import RecordingSink
    emitter = AuditEmitter([RecordingSink()])
    assert (await run_onboarding(
        manifest_path, config=config, provider=provider, emitter=emitter
    )).passed

    harness = await SHAI.from_yaml(cfg_path)
    ctx = await harness.load_agent(agent_path)
    assert (await harness.check_tool_call("search", {}, ctx)).allowed

    denied = await harness.check_tool_call("delete_repo", {}, ctx)
    assert not denied.allowed
    assert "delete_repo" in denied.deny_reason
    assert "action: block" in denied.deny_reason
    await harness.close()
