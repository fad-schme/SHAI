"""Tests for config/schema.py."""
import pytest
from pydantic import ValidationError

from harness.config.schema import (
    BoundaryConfig,
    HarnessConfig,
)


def _minimal() -> dict:
    return {
        "scan_input":  {"enabled": False},
        "scan_output": {"enabled": False},
        "policy":      {"name": "rules"},
        "audit_sinks": [{"name": "stdout"}],
    }


def test_minimal_valid_config():
    cfg = HarnessConfig.model_validate(_minimal())
    assert cfg.policy.name == "rules"
    assert len(cfg.audit_sinks) == 1


def test_empty_audit_sinks_allowed():
    """audit_sinks defaults to [] — empty list is valid, harness falls back to stdout."""
    data = _minimal()
    data.pop("audit_sinks", None)  # omit entirely
    cfg = HarnessConfig.model_validate(data)
    assert cfg.audit_sinks == []


def test_enabled_boundary_without_scanners_rejected():
    with pytest.raises(ValidationError):
        BoundaryConfig(enabled=True, scanners=[])


def test_disabled_boundary_without_scanners_ok():
    bc = BoundaryConfig(enabled=False)
    assert not bc.enabled
    assert bc.scanners == []


def test_unknown_field_rejected():
    data = {**_minimal(), "typo_field": "oops"}
    with pytest.raises(ValidationError):
        HarnessConfig.model_validate(data)


def test_enabled_scan_with_scanners_ok():
    bc = BoundaryConfig(enabled=True, scanners=[{"name": "regex_pii"}])
    assert bc.enabled
    assert bc.scanners[0].name == "regex_pii"