"""Tests for config/loader.py and config/resolution.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config.loader import load_dict, load_yaml
from harness.config.resolution import resolve_all
from harness.core.errors import ConfigError


def _minimal() -> dict:
    return {
        "scan_input":  {"enabled": False},
        "scan_output": {"enabled": False},
        "policy":      {"name": "rules"},
        "audit_sinks": [{"name": "stdout"}],
    }


def test_load_dict_minimal():
    cfg = load_dict(_minimal())
    assert cfg.policy.name == "rules"


def test_load_dict_validation_error_surfaces_field():
    with pytest.raises(ConfigError, match="audit_sinks"):
        load_dict({**_minimal(), "audit_sinks": []})


def test_load_yaml_missing_file():
    with pytest.raises(ConfigError, match="cannot read"):
        load_yaml("/nonexistent/path/harness.yaml")


def test_load_yaml_malformed(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text(": invalid: yaml: :")
    with pytest.raises(ConfigError):
        load_yaml(p)


def test_load_yaml_disabled_boundaries(tmp_path: Path):
    p = tmp_path / "h.yaml"
    p.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
    )
    cfg = load_yaml(p)
    assert not cfg.scan_input.enabled
    assert not cfg.scan_output.enabled


def test_env_var_interpolation(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_SINK", "stdout")
    result = resolve_all({"name": "${MY_SINK}"})
    assert result["name"] == "stdout"


def test_missing_env_var_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MISSING_VAR_X", raising=False)
    with pytest.raises(ConfigError, match="MISSING_VAR_X"):
        resolve_all({"key": "${MISSING_VAR_X}"})


def test_secret_substring_raises():
    with pytest.raises(ConfigError, match="substring"):
        resolve_all({"key": "prefix_secret://FOO"})


def test_nested_env_interpolation(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SINK_NAME", "stdout")
    result = resolve_all({"sinks": [{"name": "${SINK_NAME}"}]})
    assert result["sinks"][0]["name"] == "stdout"


def test_non_string_values_unchanged():
    data = {"enabled": True, "count": 42, "tags": ["a", "b"]}
    assert resolve_all(data) == data


def test_unknown_field_in_yaml_rejected(tmp_path: Path):
    p = tmp_path / "h.yaml"
    p.write_text(
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  name: rules\n"
        "audit_sinks:\n  - name: stdout\n"
        "unknown_typo_field: oops\n"
    )
    with pytest.raises(ConfigError):
        load_yaml(p)
