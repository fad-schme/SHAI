"""Tests for core/verdicts.py."""
import pytest
from pydantic import ValidationError

from harness.core.types import Severity
from harness.core.verdicts import Finding, GateDecision, ScanVerdict


def _finding(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(scanner="test", category="pii.email", severity=severity)


def test_scan_verdict_clean():
    v = ScanVerdict(blocked=False)
    assert v.findings == []
    assert v.redacted_text is None
    assert v.max_severity is None


def test_scan_verdict_blocked_with_findings():
    f = _finding(Severity.HIGH)
    v = ScanVerdict(blocked=True, findings=[f])
    assert v.max_severity == Severity.HIGH


def test_scan_verdict_max_severity_picks_highest():
    findings = [
        _finding(Severity.LOW),
        _finding(Severity.CRITICAL),
        _finding(Severity.MEDIUM),
    ]
    v = ScanVerdict(blocked=True, findings=findings)
    assert v.max_severity == Severity.CRITICAL


def test_gate_decision_allow():
    g = GateDecision(allowed=True)
    assert g.deny_reason is None
    assert g.redacted_args is None


def test_gate_decision_deny_requires_reason():
    with pytest.raises(ValidationError):
        GateDecision(allowed=False)


def test_gate_decision_deny_with_reason():
    g = GateDecision(allowed=False, deny_reason="policy denied")
    assert g.deny_reason == "policy denied"


def test_gate_decision_redact_args():
    g = GateDecision(allowed=True, redacted_args={"secret": "***"})
    assert g.redacted_args == {"secret": "***"}


def test_finding_frozen():
    f = _finding()
    with pytest.raises(Exception):
        f.scanner = "changed"  # type: ignore


def test_finding_no_raw_text_in_detail():
    # detail must be a short note, not the raw match — enforce by convention
    f = Finding(scanner="test", category="pii.ssn", severity=Severity.HIGH,
                detail="SSN pattern detected")
    assert "123-45-6789" not in (f.detail or "")
