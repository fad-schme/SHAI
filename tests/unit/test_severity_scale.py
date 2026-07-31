"""Tests for SeverityScale — the shared score-to-severity derivation.

Each scanner declares its own thresholds because the scales measure different
evidence and are not comparable. What is shared is the derivation: the same
ordering, the same categorical escape hatch, the same floor semantics.
"""
from __future__ import annotations

import pytest

from harness.adapters.scanners.base import SeverityScale
from harness.adapters.scanners.heuristic_scan import HeuristicScanner
from harness.adapters.scanners.identity_spoof_scan import IdentitySpoofScanner
from harness.adapters.scanners.injection_scan import InjectionScanner
from harness.adapters.scanners.jailbreak_scan import JailbreakScanner
from harness.core.types import Severity

SCALE = SeverityScale(high=6.0, medium=3.0)
FLOORED = SeverityScale(high=5.0, medium=3.0, floor=1.0)


class TestThresholdOrdering:
    @pytest.mark.parametrize("score,expected", [
        (0.0, Severity.LOW),
        (2.9, Severity.LOW),
        (3.0, Severity.MEDIUM),
        (5.9, Severity.MEDIUM),
        (6.0, Severity.HIGH),
        (99.0, Severity.HIGH),
    ])
    def test_boundaries_are_inclusive(self, score: float, expected: Severity):
        assert SCALE.severity_for(score) is expected


class TestFloor:
    def test_below_floor_is_not_reported(self):
        assert FLOORED.severity_for(0.9) is None

    def test_at_floor_is_low(self):
        assert FLOORED.severity_for(1.0) is Severity.LOW

    def test_no_floor_always_reports(self):
        """A scanner that only scores after a concrete match wants no floor."""
        assert SCALE.severity_for(0.0) is Severity.LOW


class TestForceHigh:
    def test_force_high_overrides_a_low_score(self):
        """Categorical evidence — a catalog rule declaring severity: high —
        fires whatever the numeric total is."""
        assert SCALE.severity_for(0.0, force_high=True) is Severity.HIGH

    def test_force_high_still_respects_the_floor(self):
        """The floor decides whether anything is reported at all; force_high
        only decides how severe a reported finding is."""
        assert FLOORED.severity_for(0.5, force_high=True) is None


class TestGate:
    def test_failed_gate_suppresses_everything(self):
        assert SCALE.severity_for(99.0, gate=False) is None

    def test_failed_gate_beats_force_high(self):
        """A corroboration bar the scanner computed outranks categorical
        evidence — this is the argument that keeps a scanner from evaluating a
        gate and then forgetting to apply it."""
        assert SCALE.severity_for(99.0, force_high=True, gate=False) is None

    def test_passing_gate_is_the_default(self):
        assert SCALE.severity_for(6.0) is Severity.HIGH


class TestScannerScalesMatchShippedThresholds:
    """Pin the values lifted from the pre-refactor if/elif chains.

    These are calibrated numbers, not defaults. A change here moves what SHAI
    blocks and belongs in a security review with corpus evidence, not in a
    refactor.
    """

    def test_injection_scale(self):
        assert SeverityScale(high=6.0, medium=3.0) == InjectionScanner.SCALE
        assert InjectionScanner.SCALE.floor is None

    def test_heuristic_scale(self):
        assert SeverityScale(
            high=5.0, medium=3.0, floor=1.0) == HeuristicScanner.SCALE

    @pytest.mark.parametrize("cls", [JailbreakScanner, IdentitySpoofScanner])
    def test_catalog_subclasses_inherit_the_injection_scale(self, cls):
        """They share the scoring model and differ only in catalog."""
        assert cls.SCALE is InjectionScanner.SCALE


class TestScaleIsImmutable:
    def test_frozen(self):
        with pytest.raises(Exception):
            SCALE.high = 1.0  # type: ignore[misc]
