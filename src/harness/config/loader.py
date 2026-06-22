"""Load and validate harness.yaml into a HarnessConfig."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from harness.config.schema import HarnessConfig
from harness.core.errors import ConfigError

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve(data: Any) -> Any:
    """Recursively interpolate ${ENV_VAR} in string values."""
    if isinstance(data, dict):
        return {k: _resolve(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve(item) for item in data]
    if isinstance(data, str):
        def _replace(m: re.Match) -> str:
            val = os.environ.get(m.group(1))
            if val is None:
                raise ConfigError(
                    f"environment variable ${{{m.group(1)}}} is not set",
                    op="load_yaml",
                )
            return val
        return _ENV_RE.sub(_replace, data)
    return data


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

    return _validate(_resolve(data), source=str(path))


def load_dict(data: dict[str, Any]) -> HarnessConfig:
    """Construct HarnessConfig from an already-parsed dict. Used in tests."""
    return _validate(data, source="<dict>")


def _validate(data: dict[str, Any], *, source: str) -> HarnessConfig:
    try:
        return HarnessConfig.model_validate(data)
    except ValidationError as e:
        first = e.errors()[0]
        loc = " → ".join(str(x) for x in first["loc"])
        raise ConfigError(
            f"config validation failed [{source}]: {loc}: {first['msg']}",
            op="load_yaml",
        ) from e
