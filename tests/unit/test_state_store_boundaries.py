"""A failing state store, driven through the real boundaries."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.boundaries.session_accumulator import ThreatAccumulator
from harness.boundaries.session_budget import SessionBudget
from harness.config.schema import (
    PatternsDBConfig,
    SessionBudgetConfig,
    ThreatAccumulatorConfig,
)
from harness.core.context import AgentContext
from harness.core.harness import SHAI
from harness.core.types import BoundaryName, Decision, Transport
from harness.tools.tool import Tool
from tests.conftest import RecordingSink
from tests.unit.test_state_store_contract import _BoomStore

AGENTS = Path(__file__).parent.parent / "fixtures" / "agents"

_BASE = (
    "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
    "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
)


async def _harness(tmp_path, extra: str = "") -> SHAI:
    cfg = tmp_path / "h.yaml"
    cfg.write_text(_BASE + "audit_sinks:\n  - name: stdout\n" + extra)
    h = await SHAI.from_yaml(cfg)
    h._emitter._sinks.append(RecordingSink())
    return h


def _events(h: SHAI):
    return next(s for s in h._emitter._sinks if isinstance(s, RecordingSink)).events


async def test_gate_denies_with_one_event_when_budget_store_fails(tmp_path):
    h = await _harness(tmp_path, "check_tool_call:\n  execution_budget:\n    max_steps: 5\n")
    await h.load_agent(AGENTS / "orchestrator_agent.yaml")
    await h.register_tools([Tool(name="search_docs", tags=["read", "internal"],
                                 transport=Transport.LOCAL)])
    h._session_budget = SessionBudget(_BoomStore())
    ctx = AgentContext(agent_id="orchestrator_agent", conversation_id="c")

    decision = await h.check_tool_call("search_docs", {"q": "x"}, ctx)

    assert not decision.allowed
    gate = [e for e in _events(h) if e.boundary == BoundaryName.TOOL_CALL_GATE]
    assert len(gate) == 1 and "unreachable" in (gate[0].deny_reason or "")


async def test_scan_input_blocks_with_one_event_when_accumulator_store_fails(tmp_path):
    h = await _harness(tmp_path, "session:\n  enabled: true\n  store:\n    name: memory\n")
    await h.load_agent(AGENTS / "orchestrator_agent.yaml")
    h._threat_accumulator = ThreatAccumulator(_BoomStore())
    ctx = AgentContext(agent_id="orchestrator_agent", conversation_id="c")

    verdict = await h.scan_input("hello", ctx)

    assert verdict.blocked
    events = [e for e in _events(h) if e.boundary == BoundaryName.INPUT_SCAN]
    assert len(events) == 1 and events[0].decision == Decision.BLOCKED


async def test_scan_output_never_raises_when_accumulator_store_fails(tmp_path):
    h = await _harness(tmp_path, "session:\n  enabled: true\n  store:\n    name: memory\n")
    await h.load_agent(AGENTS / "orchestrator_agent.yaml")
    ctx = AgentContext(agent_id="orchestrator_agent", conversation_id="c")
    await h.scan_input("hello", ctx)
    h._threat_accumulator = ThreatAccumulator(_BoomStore())

    verdict = await h.scan_output("hi there", ctx)

    assert verdict is not None
    assert ctx.turn_signals is None


@pytest.mark.parametrize("cls, kwargs, field", [
    (ThreatAccumulatorConfig, {"enabled": True}, "session.store"),
    (PatternsDBConfig, {"enabled": True, "secret": "x"}, "patterns_db.store"),
])
def test_enabled_subsystem_without_store_names_the_missing_field(cls, kwargs, field):
    with pytest.raises(ValueError, match=field):
        cls(**kwargs)


@pytest.mark.parametrize("cls, kwargs", [
    (ThreatAccumulatorConfig, {}),
    (SessionBudgetConfig, {"store": {"name": "memory"}}),
])
def test_on_error_accepts_only_fail_closed_and_fail_open(cls, kwargs):
    assert cls(**kwargs, on_error="fail_open").on_error == "fail_open"
    assert cls(**kwargs, on_error="fail_closed").on_error == "fail_closed"
    with pytest.raises(ValueError, match="degrade"):
        cls(**kwargs, on_error="degrade")


async def test_attestation_lists_every_enabled_store(tmp_path, monkeypatch):
    monkeypatch.setenv("PATTERNS_TEST_KEY", "k")
    log_path = tmp_path / "audit.jsonl"
    db_path = (tmp_path / "p.db").as_posix()
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        _BASE
        + f"audit_sinks:\n  - name: file\n    config:\n      path: {log_path.as_posix()}\n"
        + "session:\n  enabled: true\n  store:\n    name: memory\n"
        + "patterns_db:\n  enabled: true\n  secret: secret://PATTERNS_TEST_KEY\n"
        + f"  store:\n    name: sqlite\n    config:\n      path: {db_path}\n"
    )
    h = await SHAI.from_yaml(cfg)
    await h.close()

    extra = json.loads(log_path.read_text().splitlines()[0])["extra"]
    groups = {a["group"] for a in extra["adapters"]}
    assert {"state_store:session_budget", "state_store:session",
            "state_store:patterns_db"} <= groups
    assert extra["patterns_db"]["store"] == "sqlite"


async def test_rules_store_is_closed_when_startup_fails_after_loading_rules(tmp_path, monkeypatch):
    from harness.adapters.state_store.sqlite_store import SQLiteStore

    monkeypatch.setenv("PATTERNS_TEST_KEY", "k")
    closed = []
    real_close = SQLiteStore.close

    async def tracking_close(self):
        closed.append(self._path)
        await real_close(self)

    monkeypatch.setattr(SQLiteStore, "close", tracking_close)
    monkeypatch.setattr("harness.core.wiring._build_policy",
                        lambda cfg: (_ for _ in ()).throw(RuntimeError("startup failed")))
    cfg = tmp_path / "h.yaml"
    db_path = (tmp_path / "p.db").as_posix()
    cfg.write_text(
        _BASE + "audit_sinks:\n  - name: stdout\n"
        + "patterns_db:\n  enabled: true\n  secret: secret://PATTERNS_TEST_KEY\n"
        + f"  store:\n    name: sqlite\n    config:\n      path: {db_path}\n"
    )
    with pytest.raises(RuntimeError, match="startup failed"):
        await SHAI.from_yaml(cfg)
    assert closed == [db_path]
