"""Adapter discovery via Python entry points.

Resolves adapter names (as written in harness.yaml) to adapter classes
(registered by any installed package). This is the load-bearing mechanism
that makes the three-package layout work:

  - harness registers reference adapters under groups like "harness.scanners"
  - harness-enterprise registers production adapters under the SAME groups
  - third-party packages can register under the same groups

Entry points are enumerated once at first access and cached. Restart the
process to pick up newly installed adapters.
"""
from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

from harness.core.errors import AdapterDiscoveryError

log = logging.getLogger(__name__)

# Canonical entry-point group names
GROUPS = frozenset({
    "harness.scanners",
    "harness.policy",
    "harness.audit_sinks",
    "harness.tool_registry",
    "harness.tool_sources",
    "harness.secrets",
})

# Cache: group → {name: class}
_cache: dict[str, dict[str, type]] = {}


def _load_group(group: str) -> dict[str, type]:
    """Enumerate and load all entry points for a group. Detects name conflicts."""
    if group in _cache:
        return _cache[group]

    eps = entry_points(group=group)
    result: dict[str, type] = {}
    conflicts: dict[str, list[str]] = {}

    for ep in eps:
        if ep.name in result:
            # Collision — record both class paths for the error message
            if ep.name not in conflicts:
                conflicts[ep.name] = [result[ep.name].__module__ + "." + result[ep.name].__qualname__]
            conflicts[ep.name].append(ep.value)
        else:
            try:
                result[ep.name] = ep.load()
            except Exception as e:
                log.warning(
                    "failed to load adapter entry point",
                    extra={"group": group, "name": ep.name, "error": str(e)},
                )

    if conflicts:
        detail = "; ".join(f"{n}: {paths}" for n, paths in conflicts.items())
        raise AdapterDiscoveryError(
            f"adapter name conflicts in group '{group}': {detail}",
            op="adapter_discovery",
        )

    _cache[group] = result
    return result


def resolve(group: str, name: str) -> type:
    """Resolve an adapter name to its class.

    Raises AdapterDiscoveryError with the list of registered names on miss.
    Resolution is by NAME only — never by dotted import path.
    """
    if group not in GROUPS:
        raise AdapterDiscoveryError(
            f"unknown adapter group: {group!r}. Valid groups: {sorted(GROUPS)}",
            op="adapter_discovery",
        )

    registered = _load_group(group)
    cls = registered.get(name)
    if cls is None:
        available = sorted(registered.keys())
        raise AdapterDiscoveryError(
            f"adapter '{name}' not found in group '{group}'. "
            f"Registered: {available}",
            op="adapter_discovery",
        )

    log.debug("adapter resolved", extra={"group": group, "name": name, "class": cls.__qualname__})
    return cls


def list_registered(group: str) -> list[str]:
    """List all adapter names registered under a group. Used by CLI."""
    if group not in GROUPS:
        return []
    return sorted(_load_group(group).keys())


def clear_cache() -> None:
    """Clear the discovery cache. Used in tests that install fake entry points."""
    _cache.clear()
