"""Tests for core/types.py."""
import pytest

from harness.core.types import BoundaryName, Decision, Severity, Transport


def test_severity_ordering():
    assert Severity.HIGH >= Severity.HIGH
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.CRITICAL >= Severity.HIGH
    assert not (Severity.LOW >= Severity.MEDIUM)
    assert Severity.HIGH > Severity.MEDIUM
    assert not (Severity.MEDIUM > Severity.HIGH)


def test_severity_values_are_strings():
    assert Severity.HIGH == "high"
    assert Severity.CRITICAL == "critical"


def test_transport_values():
    assert Transport.LOCAL == "local"
    assert Transport.MCP == "mcp"
    assert Transport.SKILL == "skill"


def test_boundary_name_values():
    assert BoundaryName.INPUT_SCAN == "input_scan"
    assert BoundaryName.TOOL_CALL_GATE == "tool_call_gate"
    assert BoundaryName.OUTPUT_SCAN == "output_scan"


def test_decision_values():
    assert Decision.ALLOW == "allow"
    assert Decision.DENY == "deny"
    assert Decision.REDACT == "redact"
    assert Decision.BLOCKED == "blocked"
