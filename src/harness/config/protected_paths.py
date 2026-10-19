"""The filesystem paths SHAI itself depends on.

Derived from the loaded harness config, with no operator input: the files and
directories that make SHAI's decisions trustworthy, which no agent may be
granted or reach. Resolution uses `canonicalize_path`, the same function the
gate applies to a tool's path arguments, so a symlinked state directory is
protected under its real location. A relative config path resolves against the
process working directory, which is where the adapter opens it.
"""
from __future__ import annotations

import inspect
import os
from collections.abc import Iterator
from pathlib import Path

from harness.adapters.state_store.sqlite_store import SQLiteStore
from harness.config.schema import AdapterRef, HarnessConfig
from harness.core.errors import ConfigError
from harness.core.path_scope import canonicalize_path

_SQLITE_DEFAULT_PATH = inspect.signature(SQLiteStore.__init__).parameters["path"].default


def _adapter_path(ref: AdapterRef | None) -> str | None:
    if ref is None:
        return None
    path = ref.config.get("path")
    if path is None and ref.name == "sqlite":
        return _SQLITE_DEFAULT_PATH
    return path


def _declared(config: HarnessConfig) -> Iterator[tuple[str, str | Path | None]]:
    for sink in config.audit_sinks:
        yield "audit_sinks[].config.path", _adapter_path(sink)
    yield "session.store.config.path", _adapter_path(config.session.store)
    yield "session_budget.store.config.path", _adapter_path(config.session_budget.store)
    yield "patterns_db.path", config.patterns_db.path
    yield "patterns_db.store.config.path", _adapter_path(config.patterns_db.store)
    yield "mcp_baseline.path", config.mcp_baseline.path
    yield "mcp_manifests_dir", config.mcp_manifests_dir
    yield "revocation.path", config.revocation.path


def protected_paths(
    config: HarnessConfig,
    *,
    config_path: str | Path | None = None,
    agents_dir: str | Path | None = None,
) -> tuple[str, ...]:
    """Canonical protected paths for `config`, plus the config file and agents
    directory the loader was given. An unset or empty key contributes nothing."""
    entries = [*_declared(config), ("config file", config_path), ("agents directory", agents_dir)]
    resolved: set[str] = set()
    for source, path in entries:
        if not path:
            continue
        real = canonicalize_path(os.path.abspath(path))
        if real is None:
            raise ConfigError(
                f"protected path from {source} cannot be resolved", op="protected_paths"
            )
        resolved.add(real)
    return tuple(sorted(resolved))
