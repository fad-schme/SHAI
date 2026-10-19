"""What a path denial puts on the audit trail, and what startup attests.

The event names which control refused the path (`extra.fs_rule`) and carries no
path. The startup attestation carries a count and digest of the protected set so
two startups can be compared without a path in the event.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from harness.agents.agent_config import AgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.config.protected_paths import protected_paths
from harness.config.schema import HarnessConfig
from harness.core.attestation import build_config_attestation
from harness.core.context import AgentContext
from harness.core.events import canonical_json
from harness.core.harness import SHAI
from harness.core.path_scope import canonicalize_path
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool
from tests.conftest import RecordingSink

SECRET = b"path-audit-secret"
READ_FILE = Tool(name="read_file", tags=["fs"], path_args={"path": "read"})
SAVE_FILE = Tool(name="save_file", tags=["fs"], path_args={"path": "write"})


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for d in ("data", "elsewhere"):
        (tmp_path / d / "state").mkdir(parents=True)
        (tmp_path / d / "state" / "distinctive_name.txt").write_text("x")
    return tmp_path


async def _deny(tool: Tool, value: str, tree: Path, protected: tuple[str, ...] = ()):
    agent = AgentConfig.model_validate({
        "id": "test_agent", "allowed_tool_names": [tool.name], "allowed_tags": ["fs"],
        "allowed_paths": {"read": [str(tree / "data")]},
    })
    sink = RecordingSink()
    decision = await check_tool_call.run(
        tool.name, {"path": value}, AgentContext(agent_id="test_agent"),
        agent_config=agent, tools={tool.name: tool}, policy=RuleBasedPolicy(),
        arg_scanners=[], emitter=AuditEmitter([sink], signing_secret=SECRET),
        tenant_id="test", protected_paths=protected,
    )
    return decision, sink


async def test_outside_read_rule_id(tree):
    d, sink = await _deny(READ_FILE, str(tree / "elsewhere" / "state" / "distinctive_name.txt"), tree)
    assert not d.allowed
    assert sink.events[0].extra == {"fs_rule": "outside_read"}


async def test_outside_write_rule_id(tree):
    d, sink = await _deny(SAVE_FILE, str(tree / "data" / "state" / "distinctive_name.txt"), tree)
    assert not d.allowed
    assert sink.events[0].extra == {"fs_rule": "outside_write"}


async def test_protected_rule_id(tree):
    protected = (canonicalize_path(str(tree / "data" / "state")),)
    d, sink = await _deny(READ_FILE, str(tree / "data" / "state" / "distinctive_name.txt"), tree, protected)
    assert not d.allowed
    assert sink.events[0].extra == {"fs_rule": "protected"}
    assert "protected" in sink.events[0].deny_reason


async def test_rule_id_is_inside_the_signed_body_and_verifies(tree):
    _, sink = await _deny(READ_FILE, str(tree / "elsewhere" / "state" / "distinctive_name.txt"), tree)
    event = sink.events[0]
    body = canonical_json(event, exclude={"signature"}).encode()
    assert "outside_read" in body.decode()
    assert hmac.compare_digest(event.signature, hmac.new(SECRET, body, hashlib.sha256).hexdigest())


async def test_one_event_and_no_path_text_in_any_field(tree):
    protected = (canonicalize_path(str(tree / "data" / "state")),)
    for value, prot in (
        (str(tree / "elsewhere" / "state" / "distinctive_name.txt"), ()),
        (str(tree / "data" / "state" / "distinctive_name.txt"), protected),
    ):
        d, sink = await _deny(READ_FILE, value, tree, prot)
        assert not d.allowed and len(sink.events) == 1
        dumped = sink.events[0].model_dump_json()
        assert "distinctive_name" not in dumped
        assert str(tree) not in dumped


async def test_a_non_path_violation_carries_no_fs_rule():
    tool = Tool(name="t", tags=["x"], argument_rules=[{"arg": "n", "max_value": 1}])
    agent = AgentConfig.model_validate({"id": "test_agent", "allowed_tool_names": ["t"], "allowed_tags": ["x"]})
    sink = RecordingSink()
    d = await check_tool_call.run(
        "t", {"n": 5}, AgentContext(agent_id="test_agent"),
        agent_config=agent, tools={"t": tool}, policy=RuleBasedPolicy(),
        arg_scanners=[], emitter=AuditEmitter([sink]), tenant_id="test",
    )
    assert not d.allowed
    assert sink.events[0].extra is None or "fs_rule" not in sink.events[0].extra


# ── attestation ────────────────────────────────────────────────────────────

def _config(**overrides: Any) -> HarnessConfig:
    return HarnessConfig.model_validate({"connectivity": {"token_secret": "s"}, **overrides})


def test_attestation_carries_count_and_digest_only(tree):
    protected = tuple(sorted([canonicalize_path(str(tree / "a")), canonicalize_path(str(tree / "b"))]))
    att = build_config_attestation(config=_config(), sources=[], protected=protected)
    assert att["protected_paths"]["count"] == 2
    assert len(att["protected_paths"]["digest"]) == 64
    assert str(tree) not in json.dumps(att)


def test_digest_is_stable_for_the_same_set_and_moves_when_it_changes(tree):
    a, b = canonicalize_path(str(tree / "a")), canonicalize_path(str(tree / "b"))

    def digest(*paths: str) -> str:
        return build_config_attestation(config=_config(), sources=[], protected=paths)["protected_paths"]["digest"]

    assert digest(a, b) == digest(b, a)
    assert digest(a, b) != digest(a)
    assert digest(a) != digest(b)


async def test_startup_event_attests_the_protected_set(tmp_path: Path):
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
        f"audit_sinks:\n  - name: file\n    config:\n      path: '{audit.as_posix()}'\n"
    )
    h = await SHAI.from_yaml(cfg)
    startup = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    att = startup["extra"]["protected_paths"]
    expected = build_config_attestation(
        config=_config(audit_sinks=[{"name": "file", "config": {"path": str(audit)}}]),
        sources=[], protected=h._agent_registry.protected_paths,
    )["protected_paths"]
    assert att == expected
    assert att["count"] >= 2  # the audit file and the config file at least
    assert str(tmp_path) not in json.dumps(startup["extra"]["protected_paths"])
    assert canonicalize_path(str(audit)) in protected_paths(
        _config(audit_sinks=[{"name": "file", "config": {"path": str(audit)}}]), config_path=cfg,
    )
