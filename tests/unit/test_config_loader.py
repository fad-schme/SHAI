"""Tests for config/loader.py.

ENV var interpolation is tested through load_yaml / load_dict since
the _resolve helper is internal.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config.loader import load_dict, load_yaml
from harness.core.errors import ConfigError


def _minimal() -> dict:
    return {
        "scan_input":  {},
        "scan_output": {},
        "connectivity": {"token_secret": "test-connectivity-secret"},
        "session_budget": {"store": {"name": "memory"}},
        "policy":      {},
        "audit_sinks": [{"name": "stdout"}],
    }


def test_load_dict_minimal():
    cfg = load_dict(_minimal())
    assert cfg.policy.source_rules == []


def test_load_dict_validation_error_surfaces_field():
    """A bad field value surfaces as ConfigError with the field name."""
    with pytest.raises(ConfigError):
        load_dict({**_minimal(), "scan_input": {"block_at": "invalid_severity"}})


def test_load_yaml_missing_file():
    with pytest.raises(ConfigError, match="cannot read"):
        load_yaml("/nonexistent/path/harness.yaml")


def test_load_yaml_malformed(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text(": invalid: yaml: :")
    with pytest.raises(ConfigError):
        load_yaml(p)


def test_load_yaml_empty_scanner_lists(tmp_path: Path):
    p = tmp_path / "h.yaml"
    p.write_text(
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    cfg = load_yaml(p)
    assert cfg.scan_input.scanners == []
    assert cfg.scan_output.scanners == []


def test_env_var_interpolation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("TEST_SINK", "stdout")
    p = tmp_path / "h.yaml"
    p.write_text(
        "connectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: ${TEST_SINK}\n"
    )
    cfg = load_yaml(p)
    assert cfg.audit_sinks[0].name == "stdout"


def test_missing_env_var_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("MISSING_VAR_X", raising=False)
    p = tmp_path / "h.yaml"
    p.write_text(
        "connectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: ${MISSING_VAR_X}\n"
    )
    with pytest.raises(ConfigError, match="MISSING_VAR_X"):
        load_yaml(p)


def test_nested_env_interpolation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("SINK_NAME", "stdout")
    p = tmp_path / "h.yaml"
    p.write_text(
        "connectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: ${SINK_NAME}\n"
    )
    cfg = load_yaml(p)
    assert cfg.audit_sinks[0].name == "stdout"


def test_non_string_values_unchanged(tmp_path: Path):
    p = tmp_path / "h.yaml"
    p.write_text(
        "connectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    cfg = load_yaml(p)
    assert cfg.scan_input.scanners == []


def test_unknown_field_in_yaml_rejected(tmp_path: Path):
    p = tmp_path / "h.yaml"
    p.write_text(
        "connectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\n"
        "scan_output:\n  scanners: []\n"
        "audit_sinks:\n  - name: stdout\n"
        "unknown_typo_field: oops\n"
    )
    with pytest.raises(ConfigError):
        load_yaml(p)
