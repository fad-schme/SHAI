"""Policy engine and secrets provider are selected by name, like every other adapter.

Both groups were declared in `pyproject.toml` from the first commit and both sat
in `discovery.GROUPS`, but nothing ever resolved them: `from_yaml()` constructed
`RuleBasedPolicy` and `EnvVarProvider` directly, and no config field named an
alternative. A package registering under either group could not be reached.

Fake adapters are installed by seeding `discovery._cache`, the seam `clear_cache()`
exists for — it avoids depending on package metadata for a class that is not
installed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from harness.adapters import discovery
from harness.adapters.secrets.env import Secret, SecretsProvider
from harness.agents.agent_config import AgentConfig
from harness.config.loader import build_secrets_provider, load_dict
from harness.config.schema import AdapterRef, PolicyConfig
from harness.core.errors import AdapterDiscoveryError, ConfigError
from harness.core.harness import SHAI, _build_policy
from harness.policy.engine import PolicyDecision, SourceDecision

_RULE = {
    "id":     "deny_destructive",
    "match":  {"tool_tags": ["destructive"]},
    "action": "deny",
    "reason": "destructive tools are denied",
}


class FakePolicy:
    """Minimal PolicyEngine. Records the config it was constructed with."""

    name = "fake_policy"

    def __init__(self, **config: Any) -> None:
        self.config = config

    async def evaluate(self, tool, args, ctx, *, rules=None) -> PolicyDecision:
        return PolicyDecision(action="allow")

    async def evaluate_source(self, source, ctx) -> SourceDecision:
        return SourceDecision(active=True)


class FakeSecrets(SecretsProvider):
    name = "fake_secrets"

    def __init__(self, **config: Any) -> None:
        self.config = config

    def resolve(self, reference: str) -> Secret:
        return Secret(value=f"fake:{reference}")


@pytest.fixture
def registered(monkeypatch):
    """Install both fakes under their entry-point groups for one test."""
    monkeypatch.setitem(discovery._cache, "harness.policy", {"fake_policy": FakePolicy})
    monkeypatch.setitem(discovery._cache, "harness.secrets", {"fake_secrets": FakeSecrets})
    yield
    discovery.clear_cache()


# ── policy.engine ─────────────────────────────────────────────────────────

def test_default_engine_is_the_builtin_rule_evaluator():
    policy = _build_policy(PolicyConfig(rules=[]))
    assert policy.name == "rules"


def test_engine_resolved_by_name_with_its_config(registered):
    cfg = PolicyConfig(engine=AdapterRef(name="fake_policy", config={"bundle": "b"}))
    policy = _build_policy(cfg)
    assert isinstance(policy, FakePolicy)
    assert policy.config == {"bundle": "b"}


def test_unknown_engine_is_fatal():
    """A missing scanner or sink degrades to a warning; a missing engine must not.

    Skipping the policy engine leaves the tool-call gate with nothing to ask,
    which allows every call.
    """
    with pytest.raises(AdapterDiscoveryError):
        _build_policy(PolicyConfig(engine=AdapterRef(name="no_such_engine")))


def test_engine_construction_failure_becomes_config_error(monkeypatch):
    class Exploding:
        name = "exploding"

        def __init__(self, **config: Any) -> None:
            raise RuntimeError("bad bundle url")

    monkeypatch.setitem(discovery._cache, "harness.policy", {"exploding": Exploding})
    with pytest.raises(ConfigError, match="failed to construct"):
        _build_policy(PolicyConfig(engine=AdapterRef(name="exploding")))
    discovery.clear_cache()


def test_inline_rules_with_a_foreign_engine_are_rejected():
    """Inline rules only reach RuleBasedPolicy. Silently ignoring them would
    leave an operator believing a global deny is in force when nothing reads it."""
    with pytest.raises(ValueError, match="rules` engine only"):
        PolicyConfig(engine=AdapterRef(name="fake_policy"), rules=[_RULE])


def test_inline_rules_with_the_default_engine_are_accepted():
    assert len(_build_policy(PolicyConfig(rules=[_RULE]))._global_rules) == 1


# ── secrets ───────────────────────────────────────────────────────────────

def test_absent_block_yields_env_provider():
    assert build_secrets_provider(None).name == "env"


def test_provider_resolved_by_name_with_its_config(registered):
    provider = build_secrets_provider({"name": "fake_secrets", "config": {"addr": "a"}})
    assert isinstance(provider, FakeSecrets)
    assert provider.config == {"addr": "a"}


def test_env_vars_expand_inside_the_secrets_block(registered, monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", "https://vault.example.com")
    provider = build_secrets_provider(
        {"name": "fake_secrets", "config": {"addr": "${VAULT_ADDR}"}}
    )
    assert provider.config == {"addr": "https://vault.example.com"}


def test_secret_uri_inside_the_secrets_block_is_rejected():
    """The block defines the provider that resolves secret:// — it cannot use one."""
    with pytest.raises(ConfigError, match="may not contain a secret://"):
        build_secrets_provider({"name": "env", "config": {"token": "secret://VAULT"}})


def test_unknown_provider_is_fatal():
    with pytest.raises(AdapterDiscoveryError):
        build_secrets_provider({"name": "no_such_provider"})


def test_non_mapping_block_is_rejected():
    with pytest.raises(ConfigError, match="must be a mapping"):
        build_secrets_provider("env")


def test_secrets_block_validates_as_config():
    """HarnessConfig must accept the block it declares — extra="forbid" otherwise
    rejects a config that from_yaml() reads successfully."""
    cfg = load_dict(
        {
            "scan_input":  {"enabled": False},
            "scan_output": {"enabled": False},
            "secrets":     {"name": "env", "config": {"prefix": "APP"}},
            "audit_sinks": [{"name": "stdout"}],
        }
    )
    assert cfg.secrets.name == "env"


# ── end-to-end through from_yaml ──────────────────────────────────────────

_CONFIG = (
    "version: 1\n"
    "scan_input:\n"
    "  enabled: false\n"
    "scan_output:\n"
    "  enabled: false\n"
    "secrets:\n"
    "  name: fake_secrets\n"
    "policy:\n"
    "  engine:\n"
    "    name: fake_policy\n"
    "sources:\n"
    "  - name: s\n"
    "    transport: mcp\n"
    "    url: https://mcp.example.com/mcp\n"
    "    required: false\n"
    "    credentials:\n"
    "      token: secret://MCP_TOKEN\n"
)


async def test_engine_raising_outside_its_contract_denies_and_emits_one_event():
    """Invariant 2 + 1 under a pluggable engine.

    RuleBasedPolicy wraps every internal failure in PolicyEvaluationError, so the
    gate's narrow catch was sufficient while it was the only engine. An operator
    -selected engine can raise anything — a bundle fetch timing out, a bad
    duck-type — and an exception escaping run() returns no verdict and emits no
    event. The reason carries the exception *type* only: a third-party message
    can quote the arguments it was evaluating (Invariant 3).
    """
    from harness.audit.emitter import AuditEmitter
    from harness.boundaries import check_tool_call
    from harness.core.context import AgentContext
    from harness.core.types import Decision, Transport
    from harness.tools.tool import Tool
    from tests.conftest import RecordingSink

    class HostilePolicy(FakePolicy):
        async def evaluate(self, tool, args, ctx, *, rules=None):
            raise RuntimeError("bundle fetch failed for recipient=bank_acct_88213")

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


async def test_from_yaml_wires_both_declared_adapters(registered, tmp_path: Path):
    """The whole point: a package registering under either group is actually used."""
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(_CONFIG + "audit_sinks:\n  - name: stdout\n", encoding="utf-8")

    harness = await SHAI.from_yaml(cfg)
    try:
        assert isinstance(harness._policy, FakePolicy)
        # The declared provider resolved the config's own secret:// URI —
        # EnvVarProvider would have raised on the unset MCP_TOKEN.
        assert harness._config.sources[0].credentials["token"] == "fake:MCP_TOKEN"
    finally:
        await harness.close()
