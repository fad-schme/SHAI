"""Layer 6 Pattern C — result-side signal correlation.

Pattern C denies a write-capable tool call that follows a tool result which
produced findings the scan boundary did not block on. It is gated by
check_tool_call.correlate_tool_result, off by default.

These tests exercise _check_signal_correlation directly: the patterns it
implements are the unit under test, and driving them through the full gate
would couple every case to policy, registry, and audit wiring.
"""
from __future__ import annotations

import pytest

from harness.boundaries.check_tool_call import (
    _TIGHTEN_MARKER,
    _check_signal_correlation,
)
from harness.core.turn_signals import TurnSignals
from harness.core.types import ScanStatus, Severity, Transport
from harness.core.verdicts import Finding, GateDecision, ScanVerdict
from harness.tools.tool import Tool


def _tool(*tags: str) -> Tool:
    return Tool(name="t", tags=list(tags), transport=Transport.LOCAL,
                description="d")


def _verdict(*categories: str, status: ScanStatus = ScanStatus.ALLOW) -> ScanVerdict:
    return ScanVerdict(
        status=status,
        findings=[
            Finding(scanner="s", category=c, severity=Severity.LOW, detail="d")
            for c in categories
        ],
    )


def _signals_with_result(*categories: str) -> TurnSignals:
    s = TurnSignals()
    s.record_input(_verdict())                       # clean input
    s.record_tool_result(_verdict(*categories))
    return s


class TestPatternCDisabledByDefault:
    def test_no_deny_when_flag_off(self):
        signals = _signals_with_result("heuristic_anomaly")
        assert _check_signal_correlation(_tool("external_write"), signals) is None

    def test_deny_when_flag_on(self):
        signals = _signals_with_result("heuristic_anomaly")
        result = _check_signal_correlation(
            _tool("external_write"), signals, correlate_tool_result=True)
        assert isinstance(result, GateDecision)
        assert result.allowed is False
        assert "tool-result scan signal" in (result.deny_reason or "")


class TestPatternCScope:
    def test_read_only_tool_is_not_denied(self):
        """A read cannot complete an injection's objective."""
        signals = _signals_with_result("heuristic_anomaly")
        assert _check_signal_correlation(
            _tool("read"), signals, correlate_tool_result=True) is None

    def test_clean_tool_result_does_not_deny(self):
        signals = TurnSignals()
        signals.record_input(_verdict())
        signals.record_tool_result(_verdict())       # no findings
        assert _check_signal_correlation(
            _tool("external_write"), signals, correlate_tool_result=True) is None

    def test_no_tool_result_yet_does_not_deny(self):
        """The first tool call of a turn has no result to correlate against."""
        signals = TurnSignals()
        signals.record_input(_verdict())
        assert _check_signal_correlation(
            _tool("external_write"), signals, correlate_tool_result=True) is None

    def test_no_signals_object_is_safe(self):
        assert _check_signal_correlation(
            _tool("external_write"), None, correlate_tool_result=True) is None


class TestPatternCIndependentOfInputSignals:
    def test_fires_when_scan_input_was_never_called(self):
        """An integration that never calls scan_input still gets Pattern C.

        Regression guard: the layer used to return early whenever
        input_verdict was None, which short-circuited every result-side
        pattern before it could run.
        """
        signals = TurnSignals()
        signals.record_tool_result(_verdict("heuristic_anomaly"))
        assert signals.input_verdict is None
        result = _check_signal_correlation(
            _tool("external_write"), signals, correlate_tool_result=True)
        assert isinstance(result, GateDecision)
        assert result.allowed is False


class TestExistingPatternsUnaffected:
    def test_pattern_a_still_denies(self):
        signals = TurnSignals()
        signals.record_input(_verdict("prompt_injection"))
        result = _check_signal_correlation(_tool("destructive"), signals)
        assert isinstance(result, GateDecision)
        assert "input injection signal" in (result.deny_reason or "")

    def test_pattern_a_precedes_pattern_c(self):
        """Pattern A's reason must survive when both would fire."""
        signals = TurnSignals()
        signals.record_input(_verdict("prompt_injection"))
        signals.record_tool_result(_verdict("heuristic_anomaly"))
        result = _check_signal_correlation(
            _tool("destructive"), signals, correlate_tool_result=True)
        assert isinstance(result, GateDecision)
        assert "input injection signal" in (result.deny_reason or "")

    def test_pattern_b_still_tightens(self):
        signals = TurnSignals()
        signals.record_input(_verdict("x", status=ScanStatus.WARN))
        assert _check_signal_correlation(
            _tool("external_write"), signals) is _TIGHTEN_MARKER

    def test_pattern_b_tighten_not_shadowed_by_pattern_c(self):
        """A WARN input on a write-capable tool with a clean result still
        tightens rather than falling through."""
        signals = TurnSignals()
        signals.record_input(_verdict("x", status=ScanStatus.WARN))
        signals.record_tool_result(_verdict())
        assert _check_signal_correlation(
            _tool("external_write"), signals,
            correlate_tool_result=True) is _TIGHTEN_MARKER


class TestDenyReasonCarriesNoRawText:
    def test_reason_is_a_category_note_only(self):
        """Invariant 3 — deny_reason never carries scanned content."""
        signals = _signals_with_result("heuristic_anomaly")
        result = _check_signal_correlation(
            _tool("external_write"), signals, correlate_tool_result=True)
        assert isinstance(result, GateDecision)
        reason = result.deny_reason or ""
        assert "heuristic_anomaly" not in reason


@pytest.mark.parametrize("tags", [
    ("external_write",), ("destructive",), ("financial",), ("write", "internal"),
])
def test_any_non_read_tool_is_covered(tags: tuple[str, ...]):
    signals = _signals_with_result("heuristic_anomaly")
    result = _check_signal_correlation(
        _tool(*tags), signals, correlate_tool_result=True)
    assert isinstance(result, GateDecision)
