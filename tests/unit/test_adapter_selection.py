"""Adapter selection is limited to the built-ins.

Scanners, audit sinks, the policy engine and the secrets provider are built
from fixed in-tree tables. For the policy engine and the secrets provider an
unknown name is a ConfigError; scanners and sinks warn-and-skip, which is
tracked separately, so nothing here asserts it either way.
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
from harness.core.wiring import _build_policy
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
        "audit_sinks": [{"name": "stdout"}],
    }
    base.update(overrides)
    return base


def _write(path: Path, body: str) -> Path:
    cfg = path / "harness.yaml"
    cfg.write_text(body, encoding="utf-8")
    return cfg


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
        "version: 1\n"
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
        "version: 1\n"
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
