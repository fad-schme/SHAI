"""Agent kill switch end-to-end — SHAI.revoke_agent() and the CLI file.

Covers the property that makes it a kill switch rather than a config change:
one revoked agent stops calling tools while every other agent in the same
process keeps running, and no restart is involved.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.harness import SHAI
from harness.core.types import Decision
from harness.tools.tool import Tool

_AGENT = (
    "id: {id}\n"
    "allowed_tool_names: [search_docs]\n"
    "allowed_tags: [read]\n"
)


async def _harness(tmp_path: Path, *, revocation: bool = True) -> tuple[SHAI, Path]:
    revoked_path = tmp_path / "state" / "revoked.json"
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        + (
            # 0 = read every call. Any nonzero TTL would race these tests, which
            # is the contract working: the TTL is the kill latency.
            f"revocation:\n  path: {revoked_path.as_posix()}\n  cache_ttl_seconds: 0\n"
            if revocation else ""
        )
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.register_tools([Tool(name="search_docs", tags=["read"])])
    return harness, revoked_path


async def _load(harness: SHAI, tmp_path: Path, agent_id: str) -> AgentContext:
    path = tmp_path / f"{agent_id}.yaml"
    path.write_text(_AGENT.format(id=agent_id))
    return await harness.load_agent(path)


# ── The kill switch ───────────────────────────────────────────────────────

async def test_revoked_agent_is_denied_at_the_gate(tmp_path):
    harness, _ = await _harness(tmp_path)
    ctx = await _load(harness, tmp_path, "billing_agent")
    assert (await harness.check_tool_call("search_docs", {}, ctx)).allowed

    harness.revoke_agent("billing_agent", reason="anomalous spend")

    gate = await harness.check_tool_call("search_docs", {}, ctx)
    assert not gate.allowed
    assert "revoked" in gate.deny_reason
    await harness.close()


async def test_other_agents_keep_running(tmp_path):
    """Containment, not a restart: revoking one leaves the rest untouched."""
    harness, _ = await _harness(tmp_path)
    bad = await _load(harness, tmp_path, "bad_agent")
    good = await _load(harness, tmp_path, "good_agent")

    harness.revoke_agent("bad_agent")

    assert not (await harness.check_tool_call("search_docs", {}, bad)).allowed
    assert (await harness.check_tool_call("search_docs", {}, good)).allowed
    await harness.close()


async def test_revocation_emits_exactly_one_deny_event(tmp_path):
    harness, _ = await _harness(tmp_path)
    ctx = await _load(harness, tmp_path, "a1")
    harness.revoke_agent("a1")

    with harness.collect_events() as events:
        await harness.check_tool_call("search_docs", {}, ctx)

    assert len(events) == 1
    assert events[0].decision == Decision.DENY
    assert events[0].boundary == "tool_call_gate"
    assert "revoked" in events[0].deny_reason
    await harness.close()


async def test_restore_lets_it_run_again(tmp_path):
    harness, _ = await _harness(tmp_path)
    ctx = await _load(harness, tmp_path, "a1")
    harness.revoke_agent("a1")
    assert harness.restore_agent("a1") is True
    assert (await harness.check_tool_call("search_docs", {}, ctx)).allowed
    await harness.close()


async def test_agent_stays_registered_while_revoked(tmp_path):
    """Revocation stops actions, not conversation — unlike deregister_agent()."""
    harness, _ = await _harness(tmp_path)
    await _load(harness, tmp_path, "a1")
    harness.revoke_agent("a1")
    assert [a.id for a in await harness.list_agents()] == ["a1"]
    await harness.close()


async def test_cli_side_write_reaches_the_running_harness(tmp_path):
    """`shai agents revoke` runs in its own process and writes the same file."""
    harness, revoked_path = await _harness(tmp_path)
    ctx = await _load(harness, tmp_path, "a1")

    revoked_path.parent.mkdir(parents=True, exist_ok=True)
    revoked_path.write_text(json.dumps({"revoked": {"a1": {"reason": "cli"}}}))

    gate = await harness.check_tool_call("search_docs", {}, ctx)
    assert not gate.allowed
    await harness.close()


async def test_revocation_survives_a_restart(tmp_path):
    harness, _ = await _harness(tmp_path)
    await _load(harness, tmp_path, "a1")
    harness.revoke_agent("a1")
    await harness.close()

    restarted, _ = await _harness(tmp_path)
    ctx = await _load(restarted, tmp_path, "a1")
    assert not (await restarted.check_tool_call("search_docs", {}, ctx)).allowed
    await restarted.close()


# ── Unconfigured ──────────────────────────────────────────────────────────

async def test_unconfigured_revocation_raises_rather_than_no_op(tmp_path):
    """A kill switch that silently did nothing would be worse than none."""
    harness, _ = await _harness(tmp_path, revocation=False)
    with pytest.raises(ConfigError, match="revocation is not configured"):
        harness.revoke_agent("a1")
    assert harness.revoked_agents() == frozenset()
    await harness.close()


async def test_unconfigured_revocation_does_not_affect_the_gate(tmp_path):
    harness, _ = await _harness(tmp_path, revocation=False)
    ctx = await _load(harness, tmp_path, "a1")
    assert (await harness.check_tool_call("search_docs", {}, ctx)).allowed
    await harness.close()
