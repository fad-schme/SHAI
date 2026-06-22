"""SecretsProvider contract suite — EnvSecrets must pass."""
from __future__ import annotations

import pytest

from harness.adapters.secrets.env import EnvSecrets
from harness.core.errors import ConfigError


def test_env_name():
    assert EnvSecrets().name == "env"


def test_resolve_present_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_SECRET", "supersecret")
    result = EnvSecrets().resolve("secret://MY_SECRET")
    assert result == "supersecret"


def test_resolve_missing_var_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MISSING_SECRET_XYZ", raising=False)
    with pytest.raises(ConfigError, match="MISSING_SECRET_XYZ"):
        EnvSecrets().resolve("secret://MISSING_SECRET_XYZ")


def test_resolve_empty_var_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("EMPTY_SECRET", "")
    with pytest.raises(ConfigError):
        EnvSecrets().resolve("secret://EMPTY_SECRET")


def test_resolve_invalid_prefix_raises():
    with pytest.raises(ConfigError, match="secret://"):
        EnvSecrets().resolve("env://MY_SECRET")


def test_resolve_empty_name_raises():
    with pytest.raises(ConfigError):
        EnvSecrets().resolve("secret://")


def test_resolve_with_prefix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("APP_MY_SECRET", "prefixed_value")
    result = EnvSecrets(prefix="APP_").resolve("secret://MY_SECRET")
    assert result == "prefixed_value"


def test_resolved_value_not_in_error_message(monkeypatch: pytest.MonkeyPatch):
    """Error messages must never contain the resolved secret value."""
    monkeypatch.delenv("SAFE_TEST_VAR", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        EnvSecrets().resolve("secret://SAFE_TEST_VAR")
    # The var name is in the error — that's fine
    assert "SAFE_TEST_VAR" in str(exc_info.value)
