"""Load and validate harness.yaml into a HarnessConfig.

Two-pass value resolution:
  Pass 1 — ${ENV_VAR} substitution (always, no provider needed).
  Pass 2 — secret://REFERENCE resolution (only when a SecretsProvider
            is supplied; skipped when provider=None so the loader remains
            usable before the provider is instantiated).
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

import yaml
from pydantic import ValidationError

from harness.config.schema import HarnessConfig
from harness.core.errors import ConfigError

if TYPE_CHECKING:
    from harness.adapters.secrets.env import SecretsProvider

_ENV_RE    = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SECRET_RE = re.compile(r"^secret://")


def _resolve(data: Any, *, provider: "SecretsProvider | None" = None) -> Any:
    """Recursively interpolate ${ENV_VAR} and secret:// refs in string values."""
    if isinstance(data, dict):
        return {k: _resolve(v, provider=provider) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve(item, provider=provider) for item in data]
    if isinstance(data, str):
        return _resolve_string(data, provider=provider)
    return data


def _resolve_string(s: str, *, provider: "SecretsProvider | None") -> str:
    # ${ENV_VAR} substitution
    def _replace_env(m: re.Match) -> str:
        val = os.environ.get(m.group(1))
        if val is None:
            raise ConfigError(
                f"environment variable ${{{m.group(1)}}} is not set",
                op="load_yaml",
            )
        return val

    s = _ENV_RE.sub(_replace_env, s)

    # secret:// resolution
    if s.startswith("secret://"):
        if provider is None:
            # Provider not yet available — leave the URI in place.
            # harness.py will call _resolve again after building the provider.
            return s
        from harness.adapters.secrets.env import resolve_secret_uri
        return resolve_secret_uri(s, provider)

    return s


def load_yaml(
    path: str | Path,
    *,
    provider: "SecretsProvider | None" = None,
) -> HarnessConfig:
    """Read harness.yaml, resolve env vars and secret refs, validate.

    Note: secret:// resolution happens at parse time for ALL sources,
    including required: false ones. If a required: false source has
    credentials that reference missing env vars, the load will still fail.
    For optional sources in development/demo contexts, use empty string
    credentials ('') rather than secret:// references.

    provider:
        SecretsProvider to use for secret:// resolution. When None (default),
        secret:// URIs are left as-is — the caller is responsible for
        resolving them before the config is used.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read harness.yaml at {path}: {e}",
                          op="load_yaml") from e

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}", op="load_yaml") from e

    if not isinstance(data, dict):
        raise ConfigError(
            f"{path} must be a YAML mapping, got {type(data).__name__}",
            op="load_yaml",
        )

    return _validate(_resolve(data, provider=provider), source=str(path))


def load_dict(
    data: dict[str, Any],
    *,
    provider: "SecretsProvider | None" = None,
) -> HarnessConfig:
    """Construct HarnessConfig from an already-parsed dict. Used in tests."""
    return _validate(_resolve(data, provider=provider), source="<dict>")


def _validate(data: dict[str, Any], *, source: str) -> HarnessConfig:
    try:
        return HarnessConfig.model_validate(data)
    except ValidationError as e:
        first = e.errors()[0]
        loc   = " → ".join(str(x) for x in first["loc"])
        raise ConfigError(
            f"config validation failed [{source}]: {loc}: {first['msg']}",
            op="load_yaml",
        ) from e
