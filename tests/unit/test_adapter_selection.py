"""Adapter selection is limited to the built-ins.

Scanners, audit sinks, the policy engine and the secrets provider are built
from fixed in-tree tables. An unknown scanner or sink name is rejected when the
config is validated; an unknown policy engine or secrets provider when it is
built. Either way nothing starts with less than the operator declared.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from harness.agents.agent_config import AgentConfig
from harness.config.loader import build_secrets_provider, load_dict
from harness.config.schema import AdapterRef, PolicyConfig
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import SCANNER_NAMES, SINK_NAMES
from harness.core.wiring import (
    _SCANNER_FACTORIES,
    _SINK_FACTORIES,
    _build_policy,
    _build_sinks,
)
from harness.policy.engine import PolicyDecision, SourceDecision
from harness.policy.rules import RuleBasedPolicy

_BUILTIN_SCANNERS = [
    "regex_pii", "injection_scan", "heuristic_scan", "mcp_metadata_scan",
    "jailbreak_scan", "identity_spoof_scan", "command_injection_scan",
]


def _config(**overrides: Any) -> dict:
    base = {
        "scan_input":  {"enabled": False},
        "scan_output": {"enabled": False},
        "connectivity": {"token_secret": "test-connectivity-secret"},
        "audit_sinks": [{"name": "stdout"}],
    }
    base.update(overrides)
    return base


def _write(path: Path, body: str) -> Path:
    cfg = path / "harness.yaml"
    cfg.write_text(body, encoding="utf-8")
    return cfg


# ── scanner and sink names — checked when the config is validated ─────────
#
# Asserted through load_dict, not from_yaml: that pins *where* the check lives.
# `shai validate` stops at validation, so a check any later lets it pass a
# config that then refuses to start — or, as before, starts degraded.

_TYPO = "injection_scann"   # one character off injection_scan

_SCANNER_LISTS: dict[str, dict[str, Any]] = {
    "scan_input":        {"scan_input":  {"enabled": True, "scanners": [{"name": _TYPO}]}},
    "scan_output":       {"scan_output": {"enabled": True, "scanners": [{"name": _TYPO}]}},
    "scan_tool_result":  {"scan_tool_result":  {"scanners": [{"name": _TYPO}]}},
    "scan_file":         {"scan_file": {"enabled": True, "scanners": [{"name": _TYPO}]}},
    "scan_mcp_metadata": {"scan_mcp_metadata": {"scanners": [{"name": _TYPO}]}},
    "check_tool_call":   {"check_tool_call":   {"scanners": [{"name": _TYPO}]}},
}


@pytest.mark.parametrize("boundary", list(_SCANNER_LISTS))
def test_unknown_scanner_name_fails_validation(boundary: str):
    with pytest.raises(ConfigError, match=_TYPO):
        load_dict(_config(**_SCANNER_LISTS[boundary]))


def test_unknown_scanner_error_names_the_valid_set():
    # regex_pii, not injection_scan — the typo contains the latter as a substring.
    with pytest.raises(ConfigError, match="regex_pii"):
        load_dict(_config(**_SCANNER_LISTS["scan_input"]))


def test_file_scanner_is_not_a_declarable_name():
    """The structural file scanner always runs and is not YAML-driven. Naming
    it under scan_file.scanners used to be filtered out silently at build time;
    it is now an unknown name like any other."""
    with pytest.raises(ConfigError, match="file_scanner"):
        load_dict(_config(
            scan_file={"enabled": True, "scanners": [{"name": "file_scanner"}]},
        ))


def test_unknown_sink_name_fails_validation():
    with pytest.raises(ConfigError, match="fille"):
        load_dict(_config(
            audit_sinks=[{"name": "fille", "config": {"path": "audit.jsonl"}}],
        ))


def test_empty_sink_list_fails_validation():
    """Explicitly empty is not the same fact as omitted — see the next test."""
    with pytest.raises(ConfigError, match="audit_sinks"):
        load_dict(_config(audit_sinks=[]))


def test_omitted_sink_list_means_stdout():
    cfg = load_dict({"scan_input": {"enabled": False}, "scan_output": {"enabled": False},
                     "connectivity": {"token_secret": "test-connectivity-secret"}})
    assert [ref.name for ref in cfg.audit_sinks] == ["stdout"]
    assert [type(s).__name__ for s in _build_sinks(cfg.audit_sinks)] == ["StdoutSink"]


def test_scanner_names_match_the_factory_table():
    """Adding a scanner to one without the other must fail here, not in a
    deployment: the schema would reject a buildable name, or accept one the
    builder cannot build."""
    assert set(_SCANNER_FACTORIES) == SCANNER_NAMES


def test_sink_names_match_the_factory_table():
    assert set(_SINK_FACTORIES) == SINK_NAMES


# ── policy.engine ─────────────────────────────────────────────────────────

def test_default_engine_is_the_builtin_rule_evaluator():
    assert isinstance(_build_policy(PolicyConfig()), RuleBasedPolicy)


def test_unknown_engine_is_fatal():
    with pytest.raises(ConfigError, match="unknown policy engine"):
        _build_policy(PolicyConfig(engine=AdapterRef(name="opa")))


def test_unknown_engine_error_names_the_valid_engine():
    with pytest.raises(ConfigError, match="rules"):
        _build_policy(PolicyConfig(engine=AdapterRef(name="cedar")))


# ── secrets ───────────────────────────────────────────────────────────────

def test_absent_block_yields_env_provider():
    from harness.adapters.secrets.env import EnvVarProvider
    assert isinstance(build_secrets_provider(None), EnvVarProvider)


def test_unknown_provider_is_fatal():
    with pytest.raises(ConfigError, match="unknown secrets provider"):
        build_secrets_provider({"name": "vault", "config": {"addr": "x"}})


def test_env_provider_still_takes_its_config():
    from harness.adapters.secrets.env import EnvVarProvider
    assert isinstance(
        build_secrets_provider({"name": "env", "config": {"prefix": "APP"}}),
        EnvVarProvider,
    )


def test_secrets_block_validates_as_config():
    """HarnessConfig must accept the block it declares — extra="forbid"
    otherwise rejects a config that from_yaml() reads successfully."""
    cfg = load_dict(_config(secrets={"name": "env", "config": {"prefix": "APP"}}))
    assert cfg.secrets.name == "env"


# ── built-ins still build ─────────────────────────────────────────────────

@pytest.mark.parametrize("name", _BUILTIN_SCANNERS)
async def test_every_builtin_scanner_still_builds(name, tmp_path: Path):
    """Regression: removing discovery must not have cost a legitimate name."""
    cfg = _write(tmp_path, (
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  enabled: true\n  scanners:\n"
        f"    - name: {name}\n"
        "scan_output:\n  enabled: false\n"
        "audit_sinks:\n  - name: stdout\n"
    ))
    harness = await SHAI.from_yaml(cfg)
    await harness.close()


@pytest.mark.parametrize("block", [
    "audit_sinks:\n  - name: stdout\n",
    "audit_sinks:\n  - name: file\n    config: {path: audit.jsonl}\n",
])
async def test_builtin_sinks_still_build(block, tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cfg = _write(tmp_path, (
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n" + block
    ))
    harness = await SHAI.from_yaml(cfg)
    await harness.close()


# ── the gate's catch around a policy engine ───────────────────────────────

async def test_engine_raising_outside_its_contract_denies_and_emits_one_event():
    """Invariant 2 + 1. RuleBasedPolicy wraps its internal failures in
    PolicyEvaluationError, but the gate's broad catch is what guarantees a
    verdict and exactly one event when an engine raises anything else. The
    reason carries the exception *type* only — a message could quote the
    arguments it was evaluating (Invariant 3).
    """
    from harness.audit.emitter import AuditEmitter
    from harness.boundaries import check_tool_call
    from harness.core.context import AgentContext
    from harness.core.types import Decision, Transport
    from harness.tools.tool import Tool
    from tests.conftest import RecordingSink

    class HostilePolicy:
        name = "hostile"

        async def evaluate(self, tool, args, ctx, *, rules=None) -> PolicyDecision:
            raise RuntimeError("bundle fetch failed for recipient=bank_acct_88213")

        async def evaluate_source(self, source, ctx) -> SourceDecision:
            return SourceDecision(active=True)

    sink = RecordingSink()
    decision = await check_tool_call.run(
        "transfer_funds",
        {"recipient": "bank_acct_88213"},
        AgentContext(agent_id="a"),
        agent_config=AgentConfig(
            id="a",
            allowed_tool_names=["transfer_funds"],
            allowed_tags=["financial"],
            policy_rules=[],
            sub_agents=[],
        ),
        tools={"transfer_funds": Tool(
            name="transfer_funds", tags=["financial"], transport=Transport.LOCAL
        )},
        policy=HostilePolicy(),
        arg_scanners=[],
        emitter=AuditEmitter([sink]),
        tenant_id="t",
    )

    assert not decision.allowed
    assert decision.deny_reason == "policy engine failed: RuntimeError"
    assert "bank_acct_88213" not in decision.deny_reason
    assert len(sink.events) == 1
    assert sink.events[0].decision == Decision.DENY
    assert "bank_acct_88213" not in (sink.events[0].deny_reason or "")
