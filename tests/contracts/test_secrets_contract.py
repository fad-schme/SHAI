"""SecretsProvider contract suite — EnvVarProvider must pass."""
from __future__ import annotations

from datetime import UTC

import pytest

from harness.adapters.secrets.env import (
    EnvVarProvider,
    Secret,
    SecretNotFound,
    SecretsProviderError,
    resolve_secret_uri,
)
from harness.core.errors import ConfigError

# ── EnvVarProvider.resolve() ──────────────────────────────────────────────

def test_resolve_returns_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_SECRET", "supersecret")
    secret = EnvVarProvider().resolve("MY_SECRET")
    assert isinstance(secret, Secret)
    assert secret.value == "supersecret"


def test_resolve_present_var(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_TOKEN", "abc123")
    secret = EnvVarProvider().resolve("MY_TOKEN")
    assert secret.value == "abc123"


def test_resolve_missing_var_raises_secret_not_found(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("MISSING_XYZ", raising=False)
    with pytest.raises(SecretNotFound, match="MISSING_XYZ"):
        EnvVarProvider().resolve("MISSING_XYZ")


def test_resolve_empty_var_raises_provider_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("EMPTY_SECRET", "")
    with pytest.raises(SecretsProviderError):
        EnvVarProvider().resolve("EMPTY_SECRET")


def test_resolve_empty_reference_raises():
    with pytest.raises(ValueError):
        EnvVarProvider().resolve("")


def test_resolve_non_string_reference_raises():
    with pytest.raises(ValueError):
        EnvVarProvider().resolve(None)  # type: ignore


def test_resolved_value_not_in_repr(monkeypatch: pytest.MonkeyPatch):
    """Secret repr must never expose the value."""
    monkeypatch.setenv("REPR_TEST", "mysecretvalue")
    secret = EnvVarProvider().resolve("REPR_TEST")
    assert "mysecretvalue" not in repr(secret)
    assert "redacted" in repr(secret).lower()


def test_secret_is_expired_without_ttl():
    secret = Secret(value="x", expires_at=None)
    assert secret.is_expired() is False


def test_secret_is_expired_with_past_ttl():
    from datetime import datetime, timedelta
    past = datetime.now(UTC) - timedelta(seconds=1)
    secret = Secret(value="x", expires_at=past)
    assert secret.is_expired() is True


def test_secret_not_expired_with_future_ttl():
    from datetime import datetime, timedelta
    future = datetime.now(UTC) + timedelta(hours=1)
    secret = Secret(value="x", expires_at=future)
    assert secret.is_expired() is False


# ── Prefix mapping ────────────────────────────────────────────────────────

def test_resolve_with_prefix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("APP_MY_TOKEN", "prefixed_value")
    secret = EnvVarProvider(prefix="APP").resolve("MY_TOKEN")
    assert secret.value == "prefixed_value"


def test_empty_prefix_raises():
    with pytest.raises(ValueError):
        EnvVarProvider(prefix="")


def test_reference_with_slashes_normalised(monkeypatch: pytest.MonkeyPatch):
    """'postgres/main' maps to POSTGRES_MAIN."""
    monkeypatch.setenv("POSTGRES_MAIN", "dbpass")
    secret = EnvVarProvider().resolve("postgres/main")
    assert secret.value == "dbpass"


def test_reference_all_punctuation_raises():
    with pytest.raises(ValueError):
        EnvVarProvider().resolve("///")


# ── resolve_secret_uri() ──────────────────────────────────────────────────

def test_resolve_uri_strips_prefix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("MY_KEY", "keyvalue")
    value = resolve_secret_uri("secret://MY_KEY", EnvVarProvider())
    assert value == "keyvalue"


def test_resolve_uri_invalid_prefix_raises():
    with pytest.raises(ConfigError, match="secret://"):
        resolve_secret_uri("env://MY_KEY", EnvVarProvider())


def test_resolve_uri_empty_name_raises():
    with pytest.raises(ConfigError):
        resolve_secret_uri("secret://", EnvVarProvider())


def test_resolve_uri_missing_var_raises_config_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NOSUCHVAR", raising=False)
    with pytest.raises(ConfigError):
        resolve_secret_uri("secret://NOSUCHVAR", EnvVarProvider())


def test_resolved_value_not_in_error_message(monkeypatch: pytest.MonkeyPatch):
    """Error messages must never contain the resolved secret value."""
    monkeypatch.delenv("SAFE_TEST_VAR", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        resolve_secret_uri("secret://SAFE_TEST_VAR", EnvVarProvider())
    assert "SAFE_TEST_VAR" in str(exc_info.value)
