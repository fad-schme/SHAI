"""Load and validate harness.yaml into a HarnessConfig.

Two-pass value resolution:
  Pass 1 — ${ENV_VAR} substitution (always, no provider needed).
  Pass 2 — secret://REFERENCE resolution (only when a SecretsProvider
            is supplied; skipped when provider=None so the loader remains
            usable before the provider is instantiated).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import ValidationError

from harness.config.schema import AdapterRef, HarnessConfig
from harness.core.errors import ConfigError

if TYPE_CHECKING:
    from harness.adapters.secrets.env import SecretsProvider

log = logging.getLogger(__name__)

_ENV_RE    = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_SECRET_RE = re.compile(r"^secret://")


def _resolve(data: Any, *, provider: SecretsProvider | None = None) -> Any:
    """Recursively interpolate ${ENV_VAR} and secret:// refs in string values."""
    if isinstance(data, dict):
        return {k: _resolve(v, provider=provider) for k, v in data.items()}
    if isinstance(data, list):
        return [_resolve(item, provider=provider) for item in data]
    if isinstance(data, str):
        return _resolve_string(data, provider=provider)
    return data


def _resolve_string(s: str, *, provider: SecretsProvider | None) -> str:
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
            # No provider — leave the URI in place for a caller that resolves
            # it itself. SHAI.from_yaml always passes one, so a config it built
            # never holds an unresolved reference.
            return s
        from harness.adapters.secrets.env import resolve_secret_uri
        return resolve_secret_uri(s, provider)

    return s


def read_yaml(path: str | Path) -> dict[str, Any]:
    """Read and parse harness.yaml into a raw mapping — no resolution, no validation.

    Public because the SecretsProvider is named by the raw `secrets:` block and
    must be constructed before the config it resolves can be validated. See
    build_secrets_provider.
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

    return data


def build_secrets_provider(raw: Any) -> SecretsProvider:
    """Construct the SecretsProvider named by the raw `secrets:` block.

    Takes the *unvalidated* block because this provider is what resolves the
    secret:// URIs in the rest of the config — it cannot be built from the
    validated HarnessConfig without a cycle. Only ${ENV_VAR} is expanded here;
    a secret:// inside this block would need the provider it is defining.

    Falls back to EnvVarProvider when `secrets:` is absent, which is the
    behaviour every config had before the block existed.
    """
    from harness.adapters.secrets.env import EnvVarProvider

    ref = _secrets_ref(raw)
    if ref.name == EnvVarProvider.name:
        cls: type = EnvVarProvider
    else:
        # Fail closed: an unresolvable provider means every secret:// in the
        # config silently stays a literal string. AdapterDiscoveryError propagates.
        from harness.adapters.discovery import resolve
        cls = resolve("harness.secrets", ref.name)

    try:
        return cls(**ref.config)
    except Exception as e:
        # Type only in the message: `secrets.config` holds ${ENV_VAR}-expanded
        # credentials, and a provider outside this package can echo them into
        # its own exception text. Full detail goes to the log instead.
        log.error("secrets provider construction failed",
                  extra={"adapter_name": ref.name}, exc_info=True)
        raise ConfigError(
            f"secrets provider {ref.name!r} failed to construct: {type(e).__name__} "
            f"(see logs for detail)",
            op="load_yaml",
        ) from e


def _secrets_ref(raw: Any) -> AdapterRef:
    if not raw:
        return AdapterRef(name="env")
    if not isinstance(raw, dict):
        raise ConfigError(
            f"`secrets:` must be a mapping, got {type(raw).__name__}", op="load_yaml"
        )
    try:
        ref = AdapterRef.model_validate(_resolve(raw, provider=None))
    except ValidationError as e:
        # Field locations only — pydantic's rendered message quotes the input.
        bad = ", ".join(".".join(str(p) for p in err["loc"]) for err in e.errors())
        raise ConfigError(
            f"invalid `secrets:` block at: {bad or '<root>'}", op="load_yaml"
        ) from e

    if _holds_secret_uri(ref.config):
        raise ConfigError(
            "`secrets:` config may not contain a secret:// reference — it defines "
            "the provider that resolves them. Use ${ENV_VAR} instead.",
            op="load_yaml",
        )
    return ref


def _holds_secret_uri(data: Any) -> bool:
    if isinstance(data, dict):
        return any(_holds_secret_uri(v) for v in data.values())
    if isinstance(data, list):
        return any(_holds_secret_uri(v) for v in data)
    return isinstance(data, str) and data.startswith("secret://")


def load_yaml(
    path: str | Path,
    *,
    provider: SecretsProvider | None = None,
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
        resolving them before the config is used. The `secrets:` block is NOT
        consulted here: offline callers (`shai validate`) must be able to load
        a config whose provider they cannot reach. SHAI.from_yaml builds the
        declared provider itself and passes it in.
    """
    return _validate(_resolve(read_yaml(path), provider=provider), source=str(path))


def load_dict(
    data: dict[str, Any],
    *,
    provider: SecretsProvider | None = None,
    source: str = "<dict>",
) -> HarnessConfig:
    """Construct HarnessConfig from an already-parsed dict. Used in tests."""
    return _validate(_resolve(data, provider=provider), source=source)


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
