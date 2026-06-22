"""Load and validate harness.yaml into a HarnessConfig."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from harness.config.resolution import resolve_all
from harness.config.schema import HarnessConfig
from harness.core.errors import ConfigError


def load_yaml(path: str | Path) -> HarnessConfig:
    """Read harness.yaml, resolve ${ENV_VAR} refs, validate. Raises ConfigError."""
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigError(f"cannot read harness.yaml at {path}: {e}", op="load_yaml") from e

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {path}: {e}", op="load_yaml") from e

    if not isinstance(data, dict):
        raise ConfigError(
            f"{path} must be a YAML mapping, got {type(data).__name__}",
            op="load_yaml",
        )

    # Resolve ${ENV_VAR} substitutions. Secret refs resolved later in
    # Harness.from_yaml() after the SecretsProvider is instantiated.
    resolved = resolve_all(data, secrets=None)
    return _validate(resolved, source=str(path))


def load_dict(data: dict[str, Any]) -> HarnessConfig:
    """Construct HarnessConfig from an already-parsed dict. Used in tests."""
    return _validate(data, source="<dict>")


def _validate(data: dict[str, Any], *, source: str) -> HarnessConfig:
    try:
        return HarnessConfig.model_validate(data)
    except ValidationError as e:
        first = e.errors()[0]
        loc = " → ".join(str(x) for x in first["loc"])
        msg = first["msg"]
        raise ConfigError(
            f"config validation failed [{source}]: {loc}: {msg}",
            op="load_yaml",
        ) from e
