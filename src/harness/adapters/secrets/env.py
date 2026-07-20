"""Secrets adapter — SecretsProvider interface and EnvVarProvider.

SecretsProvider:  Abstract interface. Every secrets backend implements this.
Secret:           Value object returned by resolve() — value + TTL + version.
EnvVarProvider:   Reference implementation. Reads from environment variables.

Called only at SHAI.from_yaml() time — never on the hot path.
resolve() is synchronous: secret resolution happens once at startup.

secret:// URI convention
-------------------------
harness.yaml uses "secret://REFERENCE" to mark values that should be
resolved through the provider rather than read as literals.

  credentials:
    token: "secret://SLACK_MCP_TOKEN"

The reference portion ("SLACK_MCP_TOKEN") is passed verbatim to
SecretsProvider.resolve(). EnvVarProvider maps it to an env var name:
  "SLACK_MCP_TOKEN" → os.environ["SLACK_MCP_TOKEN"]
  "postgres/main"   → os.environ["POSTGRES_MAIN"]

Design rules
------------
- The provider returns a Secret value object. TTL is optional and advisory.
- The provider never logs the secret value.
- SecretNotFound for missing references (hard config error — do not retry).
- SecretsProviderError for transport/auth failures (may be retriable).
"""
from __future__ import annotations

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from harness.core.errors import ConfigError

log = logging.getLogger(__name__)

SECRET_URI_PREFIX = "secret://"  # nosec B105 — URI scheme prefix, not a hardcoded credential
_REF_TO_ENVVAR = re.compile(r"[^A-Za-z0-9]+")


# ── Exceptions ────────────────────────────────────────────────────────────

class SecretsProviderError(Exception):
    """Transport, auth, or misconfiguration failure. Typically retriable."""


class SecretNotFound(SecretsProviderError):
    """Reference does not exist in the backing store. Hard config error."""


# ── Value object ──────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Secret:
    """Resolved secret value with optional TTL and version metadata.

    The repr redacts the value so it never leaks through logging or test
    framework diff output.
    """

    value:      str
    expires_at: datetime | None = None
    version:    str | None      = field(default=None)

    def __repr__(self) -> str:
        return (
            f"Secret(value=<redacted len={len(self.value)}>, "
            f"expires_at={self.expires_at!r}, version={self.version!r})"
        )

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """True if the advertised TTL has passed. No expires_at → never expired."""
        if self.expires_at is None:
            return False
        return (now or datetime.now(UTC)) >= self.expires_at


# ── Interface ─────────────────────────────────────────────────────────────

class SecretsProvider(ABC):
    """Abstract interface for resolving secrets by reference.

    Implementations must be safe to share across threads and async tasks.
    Expensive work (auth handshake, client construction) belongs in
    resolve() behind whatever caching the implementation needs.
    """

    @abstractmethod
    def resolve(self, reference: str) -> Secret:
        """Resolve a reference to a Secret value object.

        Parameters
        ----------
        reference:
            Opaque identifier for the secret. Non-empty string.

        Raises
        ------
        SecretNotFound       — reference absent in the backing store.
        SecretsProviderError — transport / auth / misconfiguration failure.
        ValueError           — reference is empty or not a string.
        """


# ── Reference implementation ──────────────────────────────────────────────

class EnvVarProvider(SecretsProvider):
    """Reads secrets from environment variables.

    Reference mapping:
      "SLACK_MCP_TOKEN" → os.environ["SLACK_MCP_TOKEN"]
      "postgres/main"   → os.environ["POSTGRES_MAIN"]
      "qdrant.api-key"  → os.environ["QDRANT_API_KEY"]

    With prefix="APP":
      "SLACK_MCP_TOKEN" → os.environ["APP_SLACK_MCP_TOKEN"]

    Suitable for development and single-tenant deployments. Not suitable
    for multi-tenant production — no per-tenant scoping, no rotation
    without a process restart.

    Parameters
    ----------
    prefix:
        Optional uppercase namespace prepended to every resolved env var.
        None means no prefix. Empty string is rejected (config bug).
    default_ttl:
        Optional TTL to advertise on resolved secrets. Defaults to None
        ("no expiry guidance"). Env vars do not rotate without a restart,
        so advertising a TTL forces unnecessary re-resolution with no
        security benefit — unless the operator is doing live secret
        remounting (e.g. Kubernetes secret rotation + SIGHUP reload).
    """

    name = "env"

    def __init__(
        self,
        *,
        prefix: str | None = None,
        default_ttl: timedelta | None = None,
    ) -> None:
        if prefix is not None and not prefix:
            raise ValueError("prefix must be None or a non-empty string")
        if default_ttl is not None and default_ttl <= timedelta(0):
            raise ValueError("default_ttl must be positive when provided")

        self._prefix      = prefix.upper() if prefix else None
        self._default_ttl = default_ttl

        log.debug("EnvVarProvider initialised prefix=%s default_ttl_s=%s",
                  self._prefix,
                  int(self._default_ttl.total_seconds()) if self._default_ttl else None)

    def resolve(self, reference: str) -> Secret:
        if not isinstance(reference, str):
            raise ValueError("reference must be a string")
        if not reference.strip():
            raise ValueError("reference must be a non-empty string")

        env_name = self._to_env_name(reference)
        raw      = os.environ.get(env_name)

        if raw is None:
            log.warning("secret not found reference=%s env_name=%s",
                        reference, env_name)
            raise SecretNotFound(
                f"No environment variable {env_name!r} for reference {reference!r}"
            )
        if raw == "":
            log.warning("secret env var is empty reference=%s env_name=%s",
                        reference, env_name)
            raise SecretsProviderError(
                f"Environment variable {env_name!r} is set but empty "
                f"for reference {reference!r}"
            )

        expires_at: datetime | None = (
            datetime.now(UTC) + self._default_ttl
            if self._default_ttl else None
        )
        log.debug("secret resolved reference=%s env_name=%s expires_at=%s",
                  reference, env_name,
                  expires_at.isoformat() if expires_at else None)

        return Secret(value=raw, expires_at=expires_at)

    def _to_env_name(self, reference: str) -> str:
        normalized = _REF_TO_ENVVAR.sub("_", reference).strip("_").upper()
        if not normalized:
            raise ValueError(
                f"reference {reference!r} contains no alphanumeric characters"
            )
        return f"{self._prefix}_{normalized}" if self._prefix else normalized


# ── SHAI integration helper ───────────────────────────────────────────────

def resolve_secret_uri(uri: str, provider: SecretsProvider) -> str:
    """Resolve a secret://REFERENCE URI to its plaintext value.

    Called by config/loader.py during harness.yaml parsing.
    Raises ConfigError (not SecretNotFound) so config errors surface
    consistently alongside YAML validation errors.
    """
    if not uri.startswith(SECRET_URI_PREFIX):
        raise ConfigError(
            f"invalid secret reference {uri!r}: must start with 'secret://'",
            op="resolve_secret",
        )
    reference = uri[len(SECRET_URI_PREFIX):]
    if not reference:
        raise ConfigError(
            "invalid secret reference: name is empty after 'secret://'",
            op="resolve_secret",
        )
    try:
        secret = provider.resolve(reference)
        return secret.value
    except SecretNotFound as e:
        raise ConfigError(str(e), op="resolve_secret") from e
    except SecretsProviderError as e:
        raise ConfigError(
            f"secrets provider error for {uri!r}: {e}", op="resolve_secret"
        ) from e


__all__ = [
    "Secret",
    "SecretsProvider",
    "EnvVarProvider",
    "SecretsProviderError",
    "SecretNotFound",
    "SECRET_URI_PREFIX",
    "resolve_secret_uri",
]
