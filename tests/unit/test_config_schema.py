"""Tests for config/schema.py."""
import pytest
from pydantic import ValidationError

from harness.config.schema import (
    RECOMMENDED_INPUT_SCANNERS,
    RECOMMENDED_TOOL_RESULT_SCANNERS,
    BoundaryConfig,
    HarnessConfig,
    PolicyConfig,
    ToolResultScanConfig,
)


def _minimal() -> dict:
    return {
        "scan_input":  {},
        "scan_output": {},
        "connectivity": {"token_secret": "test-connectivity-secret"},
        "session_budget": {"store": {"name": "memory"}},
        "policy":      {},
        "audit_sinks": [{"name": "stdout"}],
    }


def test_minimal_valid_config():
    cfg = HarnessConfig.model_validate(_minimal())
    assert cfg.policy.source_rules == []
    assert len(cfg.audit_sinks) == 1


def test_omitted_audit_sinks_defaults_to_stdout():
    """Omitted means stdout, declared by the schema. An explicitly empty list
    is a different fact and is rejected — see test_adapter_selection."""
    data = _minimal()
    data.pop("audit_sinks", None)  # omit entirely
    cfg = HarnessConfig.model_validate(data)
    assert [ref.name for ref in cfg.audit_sinks] == ["stdout"]


def test_empty_scanner_list_is_accepted():
    """`scanners: []` is the backstop-only posture, not a rejected config —
    a boundary cannot be switched off, so this is the quietest one gets."""
    bc = BoundaryConfig(scanners=[])
    assert bc.scanners == []


def test_omitted_scanners_get_the_recommended_list():
    assert [s.name for s in BoundaryConfig().scanners] == list(
        RECOMMENDED_INPUT_SCANNERS
    )


def test_enabled_key_is_rejected():
    """The key is gone; extra="forbid" is what tells an operator so."""
    with pytest.raises(ValidationError):
        BoundaryConfig(enabled=False, scanners=[{"name": "regex_pii"}])


def test_unknown_field_rejected():
    data = {**_minimal(), "typo_field": "oops"}
    with pytest.raises(ValidationError):
        HarnessConfig.model_validate(data)


def test_declared_scanners_replace_the_default():
    bc = BoundaryConfig(scanners=[{"name": "regex_pii"}])
    assert [s.name for s in bc.scanners] == ["regex_pii"]


def test_tool_result_scan_defaults_to_the_recommended_list():
    assert [s.name for s in ToolResultScanConfig().scanners] == list(
        RECOMMENDED_TOOL_RESULT_SCANNERS
    )


def test_tool_result_scan_accepts_scanners():
    cfg = ToolResultScanConfig(
        scanners=[{"name": "injection_scan"}, {"name": "identity_spoof_scan"}],
    )
    assert [scanner.name for scanner in cfg.scanners] == [
        "injection_scan",
        "identity_spoof_scan",
    ]


def test_forbidden_tag_combinations_parsed_as_sets():
    cfg = PolicyConfig(forbidden_tag_combinations=[["sensitive", "external_write"]])
    assert cfg.forbidden_tag_sets() == [frozenset({"sensitive", "external_write"})]


def test_forbidden_tag_combination_needs_two_distinct_tags():
    for bad in ([["sensitive"]], [["sensitive", "sensitive"]], [[]]):
        with pytest.raises(ValidationError, match="at least two distinct tags"):
            PolicyConfig(forbidden_tag_combinations=bad)
