"""Tests for SHAI facade — phases 1–3."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.errors import AgentNotRegisteredError, ConfigError, SubAgentNotDeclaredError
from harness.core.harness import SHAI


@pytest.fixture
async def harness(tmp_path: Path) -> SHAI:
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    return await SHAI.from_yaml(cfg)


async def test_load_and_list_agents(harness, orchestrator_yaml, research_yaml):
    await harness.load_agent(orchestrator_yaml)
    await harness.load_agent(research_yaml)
    agents = harness.maintenance.registered_agents()
    ids = {a.id for a in agents}
    assert ids == {"orchestrator_agent", "research_agent"}


async def test_reload_agent(harness, orchestrator_yaml, tmp_path):
    await harness.load_agent(orchestrator_yaml)
    updated = tmp_path / "upd.yaml"
    updated.write_text(
        "id: orchestrator_agent\n"
        "display_name: Updated\n"
        "allowed_tool_names: [search_docs]\n"
        "allowed_tags: [read]\n"
    )
    agent = await harness.maintenance.reload_agent(updated)
    # reload_agent returns AgentContext — verify via registry that config updated
    assert agent.agent_id == "orchestrator_agent"
    cfg = harness._agent_registry.get("orchestrator_agent")
    assert cfg.display_name == "Updated"


async def test_deregister_agent(harness, orchestrator_yaml):
    await harness.load_agent(orchestrator_yaml)
    harness.maintenance.deregister_agent("orchestrator_agent")
    agents = harness.maintenance.registered_agents()
    assert not any(a.id == "orchestrator_agent" for a in agents)


async def test_scope_context_for_subagent(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)
    assert agent.agent_id == "orchestrator_agent"   # load_agent returns AgentContext

    child = harness.scope_context_for_subagent(agent, sub_agent_id="research_sub")
    assert child.agent_id     == "orchestrator_agent"
    assert child.sub_agent_id == "research_sub"
    assert set(child.allowed_tags) == {"read", "internal"}

    # Also works via agent.scope_subagent() directly
    child2 = agent.scope_subagent(
        "research_sub",
        allowed_tags=list(child.allowed_tags),
    )
    assert child2.sub_agent_id == "research_sub"


async def test_scope_context_unknown_subagent(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)
    with pytest.raises(SubAgentNotDeclaredError):
        harness.scope_context_for_subagent(agent, sub_agent_id="nonexistent_sub")


async def test_scope_context_unregistered_agent(harness):
    ctx = AgentContext(
        agent_id="nobody")
    with pytest.raises(AgentNotRegisteredError):
        harness.scope_context_for_subagent(ctx, sub_agent_id="sub")


async def test_scope_context_child_tags_are_subset(harness, orchestrator_yaml):
    agent = await harness.load_agent(orchestrator_yaml)

    # research_sub has read + internal (subset of parent's read + internal + external_write)
    child = harness.scope_context_for_subagent(agent, sub_agent_id="research_sub")
    assert "external_write" not in child.allowed_tags

    # email_sub has all three
    child2 = harness.scope_context_for_subagent(agent, sub_agent_id="email_sub")
    assert "external_write" in child2.allowed_tags


async def test_boundaries_are_wired_in_phase5(harness):
    """All boundary methods are wired and never raise on unknown agents —
    they return deny-with-audit instead (pre-gate guarantee).
    """
    ctx = AgentContext(agent_id="a1")
    # scan_input disabled in fixture → allow verdict, no error
    verdict = await harness.scan_input("hello", ctx)
    assert not verdict.blocked
    # check_tool_call on unregistered agent → GateDecision deny, no exception
    gate = await harness.check_tool_call("search_docs", {}, ctx)
    assert gate.allowed is False
    assert gate.deny_reason is not None

async def test_from_yaml_missing_file():
    with pytest.raises(ConfigError):
        await SHAI.from_yaml("/nonexistent/path/harness.yaml")


async def test_async_context_manager_closes_the_harness(tmp_path: Path):
    """`async with` releases what close() releases — sources, sinks, session DB."""
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    closed: list[bool] = []

    async with await SHAI.from_yaml(cfg) as h:
        assert isinstance(h, SHAI)
        original = h.close

        async def _record() -> None:
            closed.append(True)
            await original()

        h.close = _record            # type: ignore[method-assign]

    assert closed == [True], "__aexit__ did not close the harness"


async def test_close_is_still_public_and_idempotent(tmp_path: Path):
    """Applications that manage lifetime themselves keep calling close()."""
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
    )
    h = await SHAI.from_yaml(cfg)
    await h.close()
    await h.close()      # second call must not raise


# ── NHI profile: stored and returned, never enforced ──────────────────────

_PROFILE_YAML = (
    "id: {id}\n"
    "allowed_tool_names: [search_docs]\n"
    "allowed_tags: [read]\n"
    "{extra}"
)

_FULL_PROFILE = (
    "description: Answers support tickets\n"
    "owners: [alice@example.com]\n"
    "sponsors: [bob@example.com]\n"
    "environment: production\n"
    "review_due: 2026-12-01\n"
    "delegation_mode: autonomous\n"
    "credential_refs:\n"
    "  - name: slack_bot_token\n"
    "    expires_at: 2027-01-15\n"
    "    rotated_at: 2026-07-01\n"
)


def _agent_file(tmp_path: Path, agent_id: str, extra: str = "") -> Path:
    path = tmp_path / f"{agent_id}_{abs(hash(extra))}.yaml"
    path.write_text(_PROFILE_YAML.format(id=agent_id, extra=extra))
    return path


async def test_listing_returns_the_full_profile(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "profiled", _FULL_PROFILE))
    (agent,) = harness.maintenance.registered_agents()
    assert agent.description == "Answers support tickets"
    assert agent.owners == ["alice@example.com"]
    assert agent.sponsors == ["bob@example.com"]
    assert agent.environment == "production"
    assert agent.review_due.isoformat() == "2026-12-01"
    assert agent.delegation_mode == "autonomous"
    (cred,) = agent.credential_refs
    assert (cred.name, cred.expires_at.isoformat(), cred.rotated_at.isoformat()) == (
        "slack_bot_token", "2027-01-15", "2026-07-01",
    )


async def test_listing_returns_defaults_without_a_profile(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "plain"))
    (agent,) = harness.maintenance.registered_agents()
    assert agent.owners == [] and agent.credential_refs == []
    assert agent.description is None and agent.delegation_mode is None


@pytest.mark.parametrize("extra", [
    "owners: alice\n",
    "review_due: someday\n",
    "delegation_mode: sometimes\n",
    "credential_refs:\n  - expires_at: 2027-01-15\n",
    "not_a_field: 1\n",
])
async def test_malformed_profile_registers_nothing(harness, tmp_path, extra):
    with pytest.raises(ConfigError):
        await harness.load_agent(_agent_file(tmp_path, "broken", extra))
    assert harness.maintenance.registered_agents() == []


async def test_profile_does_not_change_gate_decisions(harness, tmp_path):
    from harness.tools.tool import Tool

    await harness.register_tools([Tool(name="search_docs", tags=["read"])])
    plain = await harness.load_agent(_agent_file(tmp_path, "plain"))
    profiled = await harness.load_agent(_agent_file(tmp_path, "profiled", _FULL_PROFILE))
    for call in ("search_docs", "unlisted_tool"):
        a = await harness.check_tool_call(call, {}, plain)
        b = await harness.check_tool_call(call, {}, profiled)
        assert (a.allowed, a.deny_reason, a.redacted_args) == (b.allowed, b.deny_reason, b.redacted_args)


async def test_profile_only_change_needs_reload(harness, tmp_path):
    from harness.core.errors import AgentConflictError

    await harness.load_agent(_agent_file(tmp_path, "a1", "environment: staging\n"))
    changed = _agent_file(tmp_path, "a1", "environment: production\n")
    with pytest.raises(AgentConflictError):
        await harness.load_agent(changed)
    await harness.maintenance.reload_agent(changed)
    (agent,) = harness.maintenance.registered_agents()
    assert agent.environment == "production"


async def test_lookup_returns_the_listed_definition(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "profiled", _FULL_PROFILE))
    (listed,) = harness.maintenance.registered_agents()
    assert harness.maintenance.registered_agent("profiled") == listed
    assert harness.maintenance.registered_agent("profiled").owners == ["alice@example.com"]


async def test_lookup_of_unknown_id_raises(harness):
    with pytest.raises(AgentNotRegisteredError):
        harness.maintenance.registered_agent("nobody")


async def test_lookup_after_deregister_raises(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "gone"))
    harness.maintenance.deregister_agent("gone")
    with pytest.raises(AgentNotRegisteredError):
        harness.maintenance.registered_agent("gone")


async def test_lookup_after_reload_shows_new_profile(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "a1", "environment: staging\n"))
    await harness.maintenance.reload_agent(_agent_file(tmp_path, "a1", "environment: production\n"))
    assert harness.maintenance.registered_agent("a1").environment == "production"


# ── Returned definitions are copies: editing one never reaches the gate ───

async def _loaded_with_wipe(harness, tmp_path):
    from harness.tools.tool import Tool

    tools = [Tool(name="search_docs", tags=["read"]), Tool(name="wipe", tags=["read"])]
    await harness.register_tools(tools)
    ctx = await harness.load_agent(_agent_file(tmp_path, "a1", _FULL_PROFILE))
    return tools, ctx


async def test_mutating_a_looked_up_definition_leaves_the_gate_unchanged(harness, tmp_path):
    tools, ctx = await _loaded_with_wipe(harness, tmp_path)
    harness.maintenance.registered_agent("a1").allowed_tool_names.append("wipe")
    await harness.register_tools(tools)          # re-resolves every loaded agent
    assert not (await harness.check_tool_call("wipe", {}, ctx)).allowed
    assert harness.maintenance.registered_agent("a1").allowed_tool_names == ["search_docs"]


async def test_mutating_a_listed_definition_leaves_the_gate_unchanged(harness, tmp_path):
    tools, ctx = await _loaded_with_wipe(harness, tmp_path)
    harness.maintenance.registered_agents()[0].allowed_tool_names.append("wipe")
    await harness.register_tools(tools)
    assert not (await harness.check_tool_call("wipe", {}, ctx)).allowed


async def test_mutating_nested_profile_lists_does_not_change_the_next_listing(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "a1", _FULL_PROFILE))
    returned = harness.maintenance.registered_agent("a1")
    returned.owners.append("mallory")
    returned.credential_refs.clear()
    again = harness.maintenance.registered_agents()[0]
    assert again.owners == ["alice@example.com"]
    assert len(again.credential_refs) == 1


async def test_returned_definition_equals_the_stored_one(harness, tmp_path):
    await harness.load_agent(_agent_file(tmp_path, "a1", _FULL_PROFILE))
    stored = harness._agent_registry.get("a1")
    assert harness.maintenance.registered_agent("a1") == stored
    assert harness.maintenance.registered_agents() == [stored]
    assert harness.maintenance.registered_agent("a1") is not stored
