"""SHAI's own files are off limits to every agent.

The protected set is derived from the loaded harness config. A grant that
overlaps it fails `load_agent()`, and a call whose path argument resolves into it
is denied whatever the agent's grant says.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.config.protected_paths import protected_paths
from harness.config.schema import HarnessConfig
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.path_scope import canonicalize_path, is_within
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

READ_FILE = Tool(name="read_file", tags=["fs"], path_args={"path": "read"})
SAVE_FILE = Tool(name="save_file", tags=["fs"], path_args={"path": "write"})


def _config(**overrides: Any) -> HarnessConfig:
    return HarnessConfig.model_validate({"connectivity": {"token_secret": "s"}, **overrides})


def _real(path: Path) -> str:
    resolved = canonicalize_path(str(path))
    assert resolved is not None
    return resolved


def _link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
        return
    except (OSError, NotImplementedError):
        if os.name == "nt":
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True, check=False,
            )
            if made.returncode == 0:
                return
    pytest.skip("platform cannot create symlinks or junctions")


# ── the derived set ────────────────────────────────────────────────────────

def test_every_declared_source_is_protected(tmp_path: Path):
    config = _config(
        audit_sinks=[{"name": "file", "config": {"path": str(tmp_path / "audit.jsonl")}}],
        session={"enabled": True, "store": {"name": "sqlite", "config": {"path": str(tmp_path / "sess.db")}}},
        session_budget={"store": {"name": "sqlite", "config": {"path": str(tmp_path / "budget.db")}}},
        patterns_db={"path": str(tmp_path / "patterns.db")},
        mcp_baseline={"path": str(tmp_path / "baseline.db")},
        mcp_manifests_dir=str(tmp_path / "manifests"),
        revocation={"path": str(tmp_path / "revoked.json")},
    )
    got = protected_paths(
        config, config_path=tmp_path / "harness.yaml", agents_dir=tmp_path / "agents",
    )
    for name in ("audit.jsonl", "sess.db", "budget.db", "patterns.db", "baseline.db",
                 "manifests", "revoked.json", "harness.yaml", "agents"):
        assert _real(tmp_path / name) in got, name


def test_defaults_resolve_against_the_working_directory(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config = _config(session={"enabled": True, "store": {"name": "sqlite"}})
    got = protected_paths(config)
    assert _real(tmp_path / "state" / "patterns.db") in got
    assert _real(tmp_path / "state" / "mcp_baseline.db") in got
    assert _real(tmp_path / "state" / "store.db") in got

    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.chdir(other)
    assert _real(other / "state" / "patterns.db") in protected_paths(config)


def test_unset_keys_contribute_nothing(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    got = protected_paths(_config())
    assert all(is_within(p, _real(tmp_path)) for p in got)
    assert _real(tmp_path / "state" / "store.db") not in got  # memory stores have no file


def test_symlinked_state_directory_is_protected_under_its_real_location(tmp_path: Path):
    (tmp_path / "real_state").mkdir()
    _link(tmp_path / "state_link", tmp_path / "real_state")
    config = _config(patterns_db={"path": str(tmp_path / "state_link" / "patterns.db")})
    assert _real(tmp_path / "real_state" / "patterns.db") in protected_paths(config)


# ── a grant overlapping the protected set fails to load ────────────────────

def _agent(read: list[str] | None = None, write: list[str] | None = None) -> AgentConfig:
    return AgentConfig.model_validate({
        "id": "a1", "allowed_tool_names": ["read_file"], "allowed_tags": ["fs"],
        "allowed_paths": {"read": read or [], "write": write or []},
    })


@pytest.mark.parametrize("mode", ["read", "write"])
@pytest.mark.parametrize("entry", ["{state}", "{root}", "{state}/store.db", "{state}/sub/deeper"])
def test_grant_equal_containing_or_inside_a_protected_path_is_refused(tmp_path: Path, mode, entry):
    state = tmp_path / "state"
    registry = AgentRegistry(protected_paths=(_real(state),))
    grant = entry.format(root=tmp_path, state=state)
    with pytest.raises(ConfigError, match="protected"):
        registry.register(_agent(**{mode: [grant]}))


def test_a_sibling_prefix_of_a_protected_path_is_not_an_overlap(tmp_path: Path):
    registry = AgentRegistry(protected_paths=(_real(tmp_path / "state"),))
    assert registry.register(_agent(read=[str(tmp_path / "state-extra")]))


async def test_loading_an_agent_file_protects_it_and_refuses_a_grant_over_it(tmp_path: Path):
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: a1\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{tmp_path.as_posix()}']\n"
    )
    registry = AgentRegistry()
    with pytest.raises(ConfigError, match="protected"):
        await registry.load(agent_file)
    assert _real(agent_file) in registry.protected_paths


async def test_reload_applies_the_same_check(tmp_path: Path):
    agent_file = tmp_path / "agent.yaml"
    agent_file.write_text(
        "id: a1\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{(tmp_path / 'data').as_posix()}']\n"
    )
    registry = AgentRegistry()
    await registry.load(agent_file)
    agent_file.write_text(
        "id: a1\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{tmp_path.as_posix()}']\n"
    )
    with pytest.raises(ConfigError, match="protected"):
        await registry.reload(agent_file)


async def test_facade_refuses_a_grant_that_covers_its_audit_file(tmp_path: Path):
    cfg = tmp_path / "h.yaml"
    audit = tmp_path / "state" / "audit.jsonl"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
        f"audit_sinks:\n  - name: file\n    config:\n      path: '{audit.as_posix()}'\n"
    )
    agent = tmp_path / "agents" / "a.yaml"
    agent.parent.mkdir()
    agent.write_text(
        "id: a1\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{tmp_path.as_posix()}']\n"
    )
    h = await SHAI.from_yaml(cfg)
    with pytest.raises(ConfigError, match="protected"):
        await h.load_agent(agent)

    narrow = tmp_path / "agents" / "b.yaml"
    narrow.write_text(
        "id: b1\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n"
        f"allowed_paths:\n  read: ['{(tmp_path / 'data').as_posix()}']\n"
    )
    await h.load_agent(narrow)


# ── the gate denies a call that resolves into the protected set ────────────

async def _gate(tool: Tool, value: str, grant: Path, protected: tuple[str, ...], *, sub: bool = False):
    data: dict[str, Any] = {
        "id": "test_agent", "allowed_tool_names": [tool.name], "allowed_tags": ["fs"],
        "allowed_paths": {"read": [str(grant)], "write": [str(grant)]},
    }
    if sub:
        data["sub_agents"] = [{
            "id": "sub", "allowed_tool_names": [tool.name], "allowed_tags": ["fs"],
            "allowed_paths": {"read": [str(grant)], "write": [str(grant)]},
        }]
    sink = RecordingSink()
    decision = await check_tool_call.run(
        tool.name, {"path": value},
        AgentContext(agent_id="test_agent", sub_agent_id="sub" if sub else None,
                     allowed_tags=["fs"] if sub else None),
        agent_config=AgentConfig.model_validate(data), tools={tool.name: tool},
        policy=RuleBasedPolicy(), arg_scanners=[], emitter=AuditEmitter([sink]),
        tenant_id="test", protected_paths=protected,
    )
    return decision, sink


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "data" / "state").mkdir(parents=True)
    (tmp_path / "data" / "state" / "audit.jsonl").write_text("x")
    (tmp_path / "data" / "f.txt").write_text("x")
    return tmp_path


@pytest.mark.parametrize("tool", [READ_FILE, SAVE_FILE])
async def test_protected_path_denied_for_read_and_write_despite_the_grant(tree, tool):
    protected = (_real(tree / "data" / "state"),)
    d, _ = await _gate(tool, str(tree / "data" / "state" / "audit.jsonl"), tree / "data", protected)
    assert not d.allowed
    assert "protected" in d.deny_reason


async def test_unprotected_path_beside_it_is_still_allowed(tree):
    protected = (_real(tree / "data" / "state"),)
    d, _ = await _gate(READ_FILE, str(tree / "data" / "f.txt"), tree / "data", protected)
    assert d.allowed


async def test_protected_path_denied_to_a_subagent_too(tree):
    protected = (_real(tree / "data" / "state"),)
    d, _ = await _gate(READ_FILE, str(tree / "data" / "state" / "audit.jsonl"),
                       tree / "data", protected, sub=True)
    assert not d.allowed


async def test_protected_directory_reached_through_a_link_is_denied(tree):
    (tree / "out").mkdir()
    _link(tree / "out" / "alias", tree / "data" / "state")
    protected = (_real(tree / "data" / "state"),)
    d, _ = await _gate(READ_FILE, str(tree / "out" / "alias" / "audit.jsonl"), tree, protected)
    assert not d.allowed


async def test_protected_denial_emits_one_event_without_path_text(tree):
    protected = (_real(tree / "data" / "state"),)
    d, sink = await _gate(READ_FILE, str(tree / "data" / "state" / "audit.jsonl"), tree / "data", protected)
    assert not d.allowed
    assert len(sink.events) == 1
    dumped = sink.events[0].model_dump_json()
    assert "audit.jsonl" not in dumped
    assert str(tree) not in dumped
