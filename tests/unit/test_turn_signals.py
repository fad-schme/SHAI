"""Tests for TurnSignals — cross-boundary signal accumulator.

Covers:
  * Method family deduplication (catalog scanners agreeing is not corroboration)
  * Refined risk algorithm calibration (six specific scenarios)
  * Gate correlation Patterns A (deny) and B (tighten)
  * Tool result block_at adjustment when input flagged injection
  * Option A risk-based block at scan_output
  * Accumulator turn_risk contribution to session score

All tests use real Scanner, Tool, AgentConfig, AuditEmitter, AgentContext,
ScanVerdict — no mocks.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.agents.agent_config import AgentConfig
from harness.audit.emitter import AuditEmitter
from harness.boundaries import check_tool_call
from harness.core.context import AgentContext
from harness.core.events import AuditEvent
from harness.core.turn_signals import RISK_ELEVATED, RISK_HIGH, TurnSignals
from harness.core.types import Decision, ScanStatus, Severity, Transport
from harness.core.verdicts import Finding, ScanVerdict
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool


# ── Helpers ───────────────────────────────────────────────────────────────

class RecordingSink:
    name = "recording"
    def __init__(self):
        self.events: list[AuditEvent] = []
    async def emit(self, e):
        self.events.append(e)
    async def close(self):
        pass


class FakeScanner:
    """Minimal scanner stub for method-family testing.

    Not a mock — a real scanner class with a real scan method.
    Configured to produce specific findings deterministically.
    """
    def __init__(self, name: str, method_family: str, findings: list = None):
        self.name = name
        self.method_family = method_family
        self._findings = findings or []

    async def scan(self, text, ctx):
        from harness.adapters.scanners.base import ScanResult
        return ScanResult(findings=list(self._findings))


def _finding(scanner: str, category: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        scanner=scanner,
        category=category,
        severity=severity,
        detail="",
    )


def make_tool(name: str, tags: list[str] | None = None) -> Tool:
    return Tool(name=name, tags=tags or ["read", "internal"], transport=Transport.LOCAL)


def make_agent(allowed_tools=None, allowed_tags=None):
    return AgentConfig(
        id="test_agent",
        allowed_tool_names=allowed_tools or ["search_docs", "send_email", "delete_all", "write_data"],
        allowed_tags=allowed_tags or ["read", "internal", "external", "destructive", "sensitive"],
        policy_rules=[],
        sub_agents=[],
    )


# ── Method family dedup ───────────────────────────────────────────────────

class TestMethodFamilyDedup:
    """Corroboration bonus requires distinct method families, not distinct scanner names."""

    def test_single_scanner_no_bonus(self):
        ts = TurnSignals()
        scanners = [FakeScanner("injection_scan", "regex_catalog")]
        verdict = ScanVerdict(
            status=ScanStatus.WARN,
            findings=[_finding("injection_scan", "tool_injection", Severity.MEDIUM)],
        )
        ts.record_input(verdict, scanners)
        assert ts.input_method_families == {"regex_catalog"}
        assert len(ts.input_method_families) == 1

    def test_two_catalog_scanners_same_family_no_bonus(self):
        """Injection + jailbreak both fire — same family, still 1."""
        ts = TurnSignals()
        scanners = [
            FakeScanner("injection_scan", "regex_catalog"),
            FakeScanner("jailbreak_scan", "regex_catalog"),
        ]
        verdict = ScanVerdict(
            status=ScanStatus.WARN,
            findings=[
                _finding("injection_scan", "tool_injection", Severity.MEDIUM),
                _finding("jailbreak_scan", "jailbreak_attempt", Severity.MEDIUM),
            ],
        )
        ts.record_input(verdict, scanners)
        assert ts.input_method_families == {"regex_catalog"}

    def test_two_different_families_earns_bonus(self):
        """Injection (catalog) + heuristic (structural) → 2 families."""
        ts = TurnSignals()
        scanners = [
            FakeScanner("injection_scan", "regex_catalog"),
            FakeScanner("heuristic_scan", "structural_heuristic"),
        ]
        verdict = ScanVerdict(
            status=ScanStatus.WARN,
            findings=[
                _finding("injection_scan", "tool_injection", Severity.MEDIUM),
                _finding("heuristic_scan", "heuristic_anomaly", Severity.MEDIUM),
            ],
        )
        ts.record_input(verdict, scanners)
        assert ts.input_method_families == {"regex_catalog", "structural_heuristic"}
        assert len(ts.input_method_families) == 2

    def test_scanner_without_method_family_uses_unknown(self):
        """Custom scanner without method_family attribute falls back to 'unknown'."""
        class LegacyScanner:
            name = "legacy_scan"
            # No method_family attribute
            async def scan(self, text, ctx):
                from harness.adapters.scanners.base import ScanResult
                return ScanResult(findings=[])

        ts = TurnSignals()
        scanners = [LegacyScanner()]
        verdict = ScanVerdict(
            status=ScanStatus.WARN,
            findings=[_finding("legacy_scan", "custom_cat", Severity.MEDIUM)],
        )
        ts.record_input(verdict, scanners)
        assert ts.input_method_families == {"unknown"}

    def test_scanners_that_did_not_fire_not_counted(self):
        """Only scanners with findings contribute to the family set."""
        ts = TurnSignals()
        scanners = [
            FakeScanner("injection_scan", "regex_catalog"),
            FakeScanner("heuristic_scan", "structural_heuristic"),
            FakeScanner("regex_pii", "regex_pii"),
        ]
        verdict = ScanVerdict(
            status=ScanStatus.WARN,
            findings=[_finding("injection_scan", "tool_injection", Severity.MEDIUM)],
        )
        ts.record_input(verdict, scanners)
        assert ts.input_method_families == {"regex_catalog"}


# ── Risk algorithm calibration ────────────────────────────────────────────

class TestRiskAlgorithm:
    """Verify the six calibration scenarios."""

    def test_clean_turn_is_zero(self):
        ts = TurnSignals()
        assert ts.compute_risk() == 0.0

    def test_input_warn_alone(self):
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.WARN
        # No categories, no families — pure verdict contribution
        assert 0.15 < ts.compute_risk() < 0.20

    def test_input_warn_with_tool_injection(self):
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.WARN
        ts.input_categories = {"tool_injection"}
        # 0.18 + 0.15 = 0.33 → 1 - e^(-0.33) ≈ 0.28
        assert 0.26 < ts.compute_risk() < 0.30

    def test_injection_exposure_no_result_injection(self):
        """Injection input + gate allowed + clean result — exposure multiplier fires."""
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.WARN
        ts.input_categories = {"tool_injection"}
        ts.gate_verdict = "allowed"
        ts.gate_tool_name = "send_email"
        # raw = (0.18 + 0.15 + 0.18) × 1.08 = 0.5508 → ≈ 0.424
        risk = ts.compute_risk()
        assert 0.40 < risk < 0.45

    def test_full_chain_result_warn(self):
        """Injection propagates through the chain — result WARN with injection category."""
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.WARN
        ts.input_categories = {"tool_injection"}
        ts.gate_verdict = "allowed"
        ts.gate_tool_name = "send_email"
        ts.tool_result_verdict = ScanStatus.WARN
        ts.tool_result_categories = {"tool_injection"}
        # Full chain multiplier × 1.20 — result should cross RISK_ELEVATED
        risk = ts.compute_risk()
        assert risk > RISK_ELEVATED
        assert 0.60 < risk < 0.68

    def test_full_chain_result_block_crosses_risk_high(self):
        """Full attack chain with a blocking result — score should cross RISK_HIGH."""
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.WARN
        ts.input_categories = {"tool_injection"}
        ts.gate_verdict = "allowed"
        ts.gate_tool_name = "send_email"
        ts.tool_result_verdict = ScanStatus.BLOCK
        ts.tool_result_categories = {"tool_injection"}
        risk = ts.compute_risk()
        assert risk >= RISK_HIGH
        assert 0.68 < risk < 0.72

    def test_maxed_scenario_stays_below_one(self):
        """Everything on — score asymptotes below 1.0."""
        ts = TurnSignals()
        ts.input_verdict = ScanStatus.BLOCK
        ts.input_categories = {"tool_injection", "prompt_injection"}
        ts.input_method_families = {"regex_catalog", "structural_heuristic", "regex_pii"}
        ts.gate_verdict = "allowed"
        ts.gate_tool_name = "delete_all"
        ts.tool_result_verdict = ScanStatus.BLOCK
        ts.tool_result_categories = {"tool_injection", "prompt_injection"}
        risk = ts.compute_risk()
        assert risk >= RISK_HIGH
        assert risk < 1.0     # asymptote
        assert risk > 0.75    # very high

    def test_gate_denial_alone_is_small(self):
        """A gate denial is a small positive signal — attack contained."""
        ts = TurnSignals()
        ts.gate_verdict = "denied"
        risk = ts.compute_risk()
        # raw = 0.08 → 1 - e^(-0.08) ≈ 0.077
        assert 0.06 < risk < 0.10
        assert risk < RISK_ELEVATED    # containment does not elevate the turn


# ── Gate correlation ─────────────────────────────────────────────────────

class TestGateCorrelationPatternA:
    """Pattern A: injection input + high-risk tool tag → deny."""

    async def test_injection_plus_destructive_tag_denies(self):
        """Injection in input + tool tagged 'destructive' → correlation deny."""
        tools = {"delete_all": make_tool("delete_all", ["destructive", "internal"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"tool_injection"}
        # (we attach signals to ctx via _attach_signals, but the gate takes
        # turn_signals=parameter directly, which is what we want to test)

        result = await check_tool_call.run(
            "delete_all", {}, ctx,
            agent_config=agent,
            tools=tools,
            policy=RuleBasedPolicy(),
            arg_scanners=[],
            emitter=emitter,
            tenant_id="test",
            turn_signals=signals,
        )

        assert not result.allowed
        assert "correlated with input injection signal" in result.deny_reason
        assert "destructive" in result.deny_reason
        # Exactly one DENY audit event with the correlation reason
        assert len(sink.events) == 1
        assert sink.events[0].decision == Decision.DENY

    async def test_injection_plus_external_tag_denies(self):
        """External tool + injection → also denies."""
        tools = {"send_email": make_tool("send_email", ["external", "internal"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"prompt_injection"}

        result = await check_tool_call.run(
            "send_email", {}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[], emitter=emitter, tenant_id="test",
            turn_signals=signals,
        )
        assert not result.allowed
        assert "external" in result.deny_reason

    async def test_injection_plus_readonly_tool_allowed(self):
        """Read-only tool + injection input → gate still allows (no dangerous overlap)."""
        tools = {"search_docs": make_tool("search_docs", ["read", "internal"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"tool_injection"}

        result = await check_tool_call.run(
            "search_docs", {}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[], emitter=emitter, tenant_id="test",
            turn_signals=signals,
        )
        assert result.allowed

    async def test_no_signals_operates_normally(self):
        """turn_signals=None means gate operates as before."""
        tools = {"delete_all": make_tool("delete_all", ["destructive"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        result = await check_tool_call.run(
            "delete_all", {}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[], emitter=emitter, tenant_id="test",
            turn_signals=None,
        )
        assert result.allowed


class TestGateCorrelationPatternB:
    """Pattern B: WARN input + write-capable tool → tighten arg scanning."""

    async def test_warn_plus_write_tool_triggers_arg_scan(self):
        """WARN input + tool without 'read' tag should trigger arg scanning
        even when tool has no 'sensitive' tag."""
        tools = {"write_data": make_tool("write_data", ["internal"])}  # no 'read', no 'sensitive'
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        # Arg scanner that always blocks — proves it ran
        blocking_scanner = FakeScanner(
            "test_pii", "regex_pii",
            findings=[_finding("test_pii", "pii_leak", Severity.HIGH)],
        )

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = set()   # no injection — just a warn

        result = await check_tool_call.run(
            "write_data", {"payload": "data"}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[blocking_scanner], emitter=emitter, tenant_id="test",
            turn_signals=signals,
        )

        # Because Pattern B tightened, arg scanner ran despite no 'sensitive' tag
        assert not result.allowed
        assert "arg scan blocked" in result.deny_reason

    async def test_warn_plus_read_tool_does_not_tighten(self):
        """WARN input + read-only tool — no tightening applied."""
        tools = {"search_docs": make_tool("search_docs", ["read", "internal"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        # Blocking scanner — proves it did NOT run
        blocking_scanner = FakeScanner(
            "test_pii", "regex_pii",
            findings=[_finding("test_pii", "pii_leak", Severity.HIGH)],
        )

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN

        result = await check_tool_call.run(
            "search_docs", {"q": "x"}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[blocking_scanner], emitter=emitter, tenant_id="test",
            turn_signals=signals,
        )
        # Read-only tool, no tightening; scanner not invoked
        assert result.allowed

    async def test_allow_verdict_no_tightening(self):
        """Clean input (ALLOW) + write tool — no tightening applied."""
        tools = {"write_data": make_tool("write_data", ["internal"])}
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        agent = make_agent()
        ctx = AgentContext(agent_id="test_agent")

        blocking_scanner = FakeScanner(
            "test_pii", "regex_pii",
            findings=[_finding("test_pii", "pii_leak", Severity.HIGH)],
        )

        signals = TurnSignals()
        signals.input_verdict = ScanStatus.ALLOW    # Clean

        result = await check_tool_call.run(
            "write_data", {"payload": "data"}, ctx,
            agent_config=agent, tools=tools, policy=RuleBasedPolicy(),
            arg_scanners=[blocking_scanner], emitter=emitter, tenant_id="test",
            turn_signals=signals,
        )
        # ALLOW verdict — no tightening, scanner not invoked, gate allows
        assert result.allowed


# ── Tool result block_at adjustment ───────────────────────────────────────

class TestToolResultBlockAtAdjustment:
    """Input flagged injection + gate allowed a tool → tool_result scan
    tightens block_at by one severity level."""

    async def test_medium_finding_blocks_when_input_flagged_injection(self, tmp_path):
        """With injection in input signals, a MEDIUM tool_result finding blocks
        (block_at defaults to HIGH but shifts to MEDIUM)."""
        from harness.boundaries._scan import ScanState, run_tool_result_scan
        from harness.core.types import BoundaryName

        # Scanner produces a MEDIUM finding
        scanner = FakeScanner(
            "injection_scan", "regex_catalog",
            findings=[_finding("injection_scan", "tool_injection", Severity.MEDIUM)],
        )
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        ctx = AgentContext(agent_id="test_agent")

        # Attach signals: input had injection, gate allowed a tool
        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"tool_injection"}
        signals.gate_verdict = "allowed"
        signals.gate_tool_name = "search_docs"
        ctx._attach_signals(signals)

        from harness.boundaries._scan import ScanAction
        verdict = await run_tool_result_scan(
            "attacker embedded content", ctx,
            scanners=[scanner],
            scanner_actions=[None],
            scanner_redact_withs=[None],
            boundary_action=ScanAction.BLOCK,
            emitter=emitter,
            tenant_id="test",
            enabled=True,
            block_at=Severity.HIGH,   # would NOT block MEDIUM by default
            state=ScanState(),
        )

        # Because block_at was tightened to MEDIUM, this blocks
        assert verdict.status == ScanStatus.BLOCK

    async def test_medium_finding_passes_without_input_injection(self, tmp_path):
        """Without input injection signal, block_at stays HIGH — MEDIUM passes."""
        from harness.boundaries._scan import ScanAction, ScanState, run_tool_result_scan

        scanner = FakeScanner(
            "injection_scan", "regex_catalog",
            findings=[_finding("injection_scan", "tool_injection", Severity.MEDIUM)],
        )
        sink = RecordingSink()
        emitter = AuditEmitter([sink])
        ctx = AgentContext(agent_id="test_agent")

        # No signals attached — no adjustment
        verdict = await run_tool_result_scan(
            "some result", ctx,
            scanners=[scanner],
            scanner_actions=[None],
            scanner_redact_withs=[None],
            boundary_action=ScanAction.BLOCK,
            emitter=emitter,
            tenant_id="test",
            enabled=True,
            block_at=Severity.HIGH,
            state=ScanState(),
        )
        # MEDIUM < HIGH block_at → does not block
        assert verdict.status != ScanStatus.BLOCK


# ── Option A risk-based block at scan_output ──────────────────────────────

class TestOptionARiskBlock:
    """scan_output blocks when consolidated turn risk crosses RISK_HIGH,
    even if the output text itself is clean."""

    async def test_full_chain_causes_risk_block(self, tmp_path):
        """Simulate a full attack chain and verify scan_output blocks."""
        from harness.core.harness import SHAI

        cfg = tmp_path / "h.yaml"
        cfg.write_text(
            "version: 1\n"
            "scan_input:\n  enabled: false\n"
            "scan_output:\n  enabled: false\n"
            "policy:\n  rules: []\n"
            "audit_sinks:\n  - name: stdout\n"
        )
        h = await SHAI.from_yaml(cfg)
        # Manually inject the recording sink so we can inspect events
        rec = RecordingSink()
        h._emitter._sinks.append(rec)

        # Register a tiny agent
        agent_yaml = tmp_path / "test_agent.yaml"
        agent_yaml.write_text(
            "id: test_agent\n"
            "display_name: \"Test\"\n"
            "version: \"1.0.0\"\n"
            "allowed_tool_names:\n  - noop\n"
            "allowed_tags:\n  - read\n"
            "policy_rules: []\n"
        )
        ctx = await h.load_agent(agent_yaml)

        # Simulate a fully-loaded TurnSignals from a completed attack chain
        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"tool_injection"}
        signals.gate_verdict = "allowed"
        signals.gate_tool_name = "send_email"
        signals.tool_result_verdict = ScanStatus.BLOCK
        signals.tool_result_categories = {"tool_injection"}
        ctx._attach_signals(signals)

        # scan_output on clean text — should still block because of risk
        rec.events.clear()
        verdict = await h.scan_output("perfectly clean output", ctx)

        assert verdict.status == ScanStatus.BLOCK
        # Find the risk-block audit event
        risk_events = [
            e for e in rec.events
            if e.deny_reason and "consolidated turn risk" in e.deny_reason
        ]
        assert len(risk_events) == 1
        # extra.turn_risk should be present and above RISK_HIGH
        assert risk_events[0].extra.get("turn_risk") is not None
        assert risk_events[0].extra["turn_risk"] >= RISK_HIGH
        assert risk_events[0].extra.get("signal_source") == "consolidated"

    async def test_below_risk_high_no_forced_block(self, tmp_path):
        """A turn with elevated but not-high risk should NOT be forced to block."""
        from harness.core.harness import SHAI

        cfg = tmp_path / "h.yaml"
        cfg.write_text(
            "version: 1\n"
            "scan_input:\n  enabled: false\n"
            "scan_output:\n  enabled: false\n"
            "policy:\n  rules: []\n"
            "audit_sinks:\n  - name: stdout\n"
        )
        h = await SHAI.from_yaml(cfg)

        agent_yaml = tmp_path / "test_agent.yaml"
        agent_yaml.write_text(
            "id: test_agent\n"
            "display_name: \"Test\"\n"
            "version: \"1.0.0\"\n"
            "allowed_tool_names:\n  - noop\n"
            "allowed_tags:\n  - read\n"
            "policy_rules: []\n"
        )
        ctx = await h.load_agent(agent_yaml)

        # Set signals to a level that's above ELEVATED but below HIGH.
        # WARN + tool_injection alone lands at ~0.28 (below RISK_ELEVATED).
        # Adding the 2-family corroboration bonus pushes to ~0.33 (in-band).
        signals = TurnSignals()
        signals.input_verdict = ScanStatus.WARN
        signals.input_categories = {"tool_injection"}
        signals.input_method_families = {"regex_catalog", "structural_heuristic"}
        ctx._attach_signals(signals)

        # Verify risk is in the expected middle band
        risk = signals.compute_risk()
        assert RISK_ELEVATED < risk < RISK_HIGH

        verdict = await h.scan_output("clean output", ctx)
        # Not blocked — risk-based block only fires at RISK_HIGH
        assert verdict.status != ScanStatus.BLOCK


# ── Accumulator turn_risk integration ─────────────────────────────────────

class TestAccumulatorTurnRisk:
    """The accumulator's session score incorporates turn_risk from TurnSignals."""

    async def test_high_turn_risk_counts_as_effective_block(self, tmp_path):
        """A turn with turn_risk >= RISK_HIGH raises the accumulator score
        similarly to a real BLOCK, even if status was 'allow'."""
        pytest.importorskip("aiosqlite")
        from harness.boundaries.session_accumulator import ThreatAccumulator

        acc = ThreatAccumulator(
            db_path=str(tmp_path / "sessions.db"),
            window_size=5,
            escalation_threshold=0.99,   # very high so we test raw score
        )

        # 3 turns with status='allow' but high turn_risk
        for _ in range(3):
            await acc.record(
                "sess1", "text",
                status="allow",
                categories=[],
                density=0.0,
                turn_risk=0.75,   # above RISK_HIGH
            )

        # Session risk score should reflect the high-turn-risk contribution
        db = await acc._conn()
        async with db.execute(
            "SELECT risk_score FROM sessions WHERE session_id = 'sess1'"
        ) as cur:
            row = await cur.fetchone()
        assert row["risk_score"] > 0.30   # significantly elevated

        await acc.close()

    async def test_low_turn_risk_no_effect(self, tmp_path):
        """A turn with low turn_risk does not raise the score."""
        pytest.importorskip("aiosqlite")
        from harness.boundaries.session_accumulator import ThreatAccumulator

        acc = ThreatAccumulator(
            db_path=str(tmp_path / "sessions.db"),
            window_size=5,
        )

        for _ in range(3):
            await acc.record(
                "sess2", "text",
                status="allow",
                categories=[],
                density=0.0,
                turn_risk=0.10,   # below RISK_HIGH
            )

        db = await acc._conn()
        async with db.execute(
            "SELECT risk_score FROM sessions WHERE session_id = 'sess2'"
        ) as cur:
            row = await cur.fetchone()
        assert row["risk_score"] == 0.0    # nothing contributed

        await acc.close()


# ── Context lifecycle ─────────────────────────────────────────────────────

class TestContextLifecycle:
    """TurnSignals is attached at scan_input, cleared at scan_output."""

    def test_attach_and_read_via_property(self):
        ctx = AgentContext(agent_id="test_agent")
        assert ctx.turn_signals is None

        ts = TurnSignals()
        ctx._attach_signals(ts)
        assert ctx.turn_signals is ts

    def test_clear_removes_signals(self):
        ctx = AgentContext(agent_id="test_agent")
        ctx._attach_signals(TurnSignals())
        assert ctx.turn_signals is not None
        ctx._clear_signals()
        assert ctx.turn_signals is None

    def test_scope_subagent_does_not_propagate(self):
        """Subagents don't inherit the parent's turn_signals."""
        ctx = AgentContext(agent_id="parent")
        ctx._attach_signals(TurnSignals())
        sub_ctx = ctx.scope_subagent("child_agent", allowed_tags=["read"])
        assert sub_ctx.turn_signals is None
