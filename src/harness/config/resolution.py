"""Config value interpolation — ${ENV_VAR} and secret:// refs."""
from __future__ import annotations

import os
import re
from typing import Any, Protocol

from harness.core.errors import ConfigError

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SECRET_PREFIX = "secret://"


class _SecretsProvider(Protocol):
    def resolve(self, ref: str) -> str: ...


def resolve_all(
    data: Any,
    *,
    secrets: _SecretsProvider | None = None,
) -> Any:
    """Recursively interpolate env vars and secret refs in string values.

    Operates on values only — never on dict keys.
    Missing env vars → ConfigError naming the variable.
    Substring secret references → ConfigError (prevents accidental concat).
    """
    if isinstance(data, dict):
        return {k: resolve_all(v, secrets=secrets) for k, v in data.items()}
    if isinstance(data, list):
        return [resolve_all(item, secrets=secrets) for item in data]
    if isinstance(data, str):
        return _resolve_string(data, secrets=secrets)
    return data


def _resolve_string(s: str, *, secrets: _SecretsProvider | None) -> str:
    def _replace_env(m: re.Match) -> str:
        name = m.group(1)
        val = os.environ.get(name)
        if val is None:
            raise ConfigError(
                f"environment variable ${{{name}}} is not set",
                op="config_resolution",
            )
        return val

    s = _ENV_RE.sub(_replace_env, s)

    if _SECRET_PREFIX in s:
        if not s.startswith(_SECRET_PREFIX) or s != s.strip():
            raise ConfigError(
                f"secret:// reference must be the entire string value, "
                f"not a substring: {s!r}",
                op="config_resolution",
            )
        if secrets is None:
            raise ConfigError(
                f"secret reference {s!r} found but no SecretsProvider configured",
                op="config_resolution",
            )
        return secrets.resolve(s)

    return s
