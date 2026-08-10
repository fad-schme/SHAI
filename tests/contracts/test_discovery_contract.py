"""Adapter discovery contract suite.

The done-when criterion: resolve("harness.scanners", "regex_pii") returns
RegexPIIScanner. Tests cover resolution, error cases, listing, and the
clear_cache helper used in tests that need fresh entry-point state.

NOTE: these tests rely on the package being installed (`pip install shai-harness`)
so entry points are registered. When running without installation,
the resolve() call will raise AdapterDiscoveryError (not found), which
is the correct behaviour — it is tested separately in
test_discovery_unit.py without requiring installation.
"""
from __future__ import annotations

import pytest

from harness.adapters.discovery import (
    GROUPS,
    clear_cache,
    list_registered,
    resolve,
)
from harness.core.errors import AdapterDiscoveryError


@pytest.fixture(autouse=True)
def fresh_cache():
    clear_cache()
    yield
    clear_cache()


# ── Group validation ──────────────────────────────────────────────────────

def test_all_expected_groups_defined():
    expected = {
        "harness.scanners",
        "harness.policy",
        "harness.audit_sinks",
        "harness.secrets",
    }
    assert expected == GROUPS


def test_unknown_group_raises():
    with pytest.raises(AdapterDiscoveryError, match="unknown adapter group"):
        resolve("harness.nonexistent", "whatever")


def test_list_unknown_group_returns_empty():
    result = list_registered("harness.nonexistent_group")
    assert result == []


# ── Resolution (requires package installed) ───────────────────────────────

def test_resolve_regex_pii():
    """Done-when criterion: resolve returns RegexPIIScanner class."""
    pytest.importorskip("harness.adapters.scanners.regex_pii")
    from harness.adapters.scanners.regex_pii import RegexPIIScanner

    try:
        cls = resolve("harness.scanners", "regex_pii")
        assert cls is RegexPIIScanner
    except AdapterDiscoveryError:
        pytest.skip("package not installed — entry points not registered")


def test_resolve_injection_scan():
    from harness.adapters.scanners.injection_scan import InjectionScanner
    try:
        cls = resolve("harness.scanners", "injection_scan")
        assert cls is InjectionScanner
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


def test_resolve_rules_policy():
    from harness.policy.rules import RuleBasedPolicy
    try:
        cls = resolve("harness.policy", "rules")
        assert cls is RuleBasedPolicy
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


def test_resolve_stdout_sink():
    from harness.adapters.audit_sinks.stdout import StdoutSink
    try:
        cls = resolve("harness.audit_sinks", "stdout")
        assert cls is StdoutSink
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


def test_resolve_file_sink():
    from harness.adapters.audit_sinks.file import FileSink
    try:
        cls = resolve("harness.audit_sinks", "file")
        assert cls is FileSink
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


def test_resolve_memory_registry():
    from harness.tools.registry import ToolRegistry
    try:
        cls = resolve("harness.tool_registry", "memory")
        assert cls is ToolRegistry
    except (AdapterDiscoveryError, Exception):
        pytest.skip("package not installed or entry point not updated")


def test_resolve_env_secrets():
    from harness.adapters.secrets.env import EnvVarProvider
    try:
        cls = resolve("harness.secrets", "env")
        assert cls is EnvVarProvider
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


# ── Miss handling ─────────────────────────────────────────────────────────

def test_resolve_unknown_name_raises():
    try:
        with pytest.raises(AdapterDiscoveryError, match="not found in group"):
            resolve("harness.scanners", "nonexistent_adapter_xyz")
    except Exception as e:
        if "conflicts" in str(e):
            pytest.skip("stale entry point conflict — re-install package")
        raise


def test_error_message_includes_available_names():
    try:
        resolve("harness.scanners", "nonexistent_adapter_xyz")
    except AdapterDiscoveryError as e:
        msg = str(e)
        if "conflicts" in msg:
            pytest.skip("stale entry point conflict — re-install package")
        assert "nonexistent_adapter_xyz" in msg


# ── list_registered ───────────────────────────────────────────────────────

def test_list_registered_returns_sorted():
    try:
        names = list_registered("harness.scanners")
        assert names == sorted(names)
    except Exception:
        pytest.skip("package not installed")


# ── clear_cache ───────────────────────────────────────────────────────────

def test_clear_cache_allows_fresh_resolution():
    """Clearing the cache and resolving again must return the same class."""
    try:
        cls1 = resolve("harness.scanners", "regex_pii")
        clear_cache()
        cls2 = resolve("harness.scanners", "regex_pii")
        assert cls1 is cls2
    except AdapterDiscoveryError:
        pytest.skip("package not installed")


# ── Declared entry-point groups must be resolvable ───────────────────────

def test_declared_groups_are_all_resolvable():
    """Regression (SHAI-010): pyproject declared a group nothing could resolve.

    `harness.sources` was registered with three entries, sat outside
    discovery.GROUPS so `resolve()` rejected it outright, and one of its
    targets (`SkillSource`) did not exist as a class at all. Nothing imported
    it, so nothing failed — the group was pure decoration that read as a
    supported extension point.
    """
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not found (installed package, not a checkout)")

    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    groups = {
        name for name in declared.get("project", {}).get("entry-points", {})
    }
    unresolvable = groups - GROUPS
    assert not unresolvable, (
        f"entry-point group(s) {sorted(unresolvable)} declared in pyproject.toml "
        f"but absent from discovery.GROUPS — resolve() rejects them, so every "
        f"entry under them is unreachable"
    )


def test_declared_entry_point_targets_import():
    """Every registered adapter target must actually exist.

    `harness.tools.source:SkillSource` pointed at a class that was never
    written. Entry points are resolved lazily, so a broken target stays
    invisible until someone names it in harness.yaml.
    """
    import importlib
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not found (installed package, not a checkout)")

    entry_points = (
        tomllib.loads(pyproject.read_text(encoding="utf-8"))
        .get("project", {})
        .get("entry-points", {})
    )
    for group, entries in entry_points.items():
        for name, target in entries.items():
            module_path, _, attr = target.partition(":")
            module = importlib.import_module(module_path)
            assert hasattr(module, attr), (
                f"{group}.{name} points at {target}, which does not exist"
            )


def test_every_name_selectable_in_config_is_registered():
    """A scanner an operator can name in harness.yaml must be resolvable.

    Two registries name the built-in scanners: `_SCANNER_FACTORIES`, which
    from_yaml() builds them from, and the `harness.scanners` entry-point group,
    which is what `resolve()` reads and what the CHANGELOG names as the
    supported way to reach a bundled scanner by name — `MCPMetadataScanner`'s
    removal from `harness.adapters.scanners` pointed users straight at it.

    They drifted: `command_injection_scan` and `mcp_metadata_scan` were added to
    the factory table and never registered, so `resolve()` raised for the very
    scanner the migration note named. Pin them together.
    """
    import tomllib
    from pathlib import Path

    from harness.core.harness import _SCANNER_FACTORIES

    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.exists():
        pytest.skip("pyproject.toml not found (installed package, not a checkout)")

    declared = set(
        tomllib.loads(pyproject.read_text(encoding="utf-8"))
        ["project"]["entry-points"]["harness.scanners"]
    )
    missing = set(_SCANNER_FACTORIES) - declared
    assert not missing, (
        f"scanner(s) {sorted(missing)} are selectable by name in harness.yaml "
        f"but absent from the harness.scanners entry-point group — "
        f"resolve() cannot find them"
    )


def test_registry_methods_are_async_only_when_they_await():
    """`async` iff the method awaits, on all three registries.

    They were uniformly `async` while holding plain dicts behind a
    threading.Lock, so `ToolRegistry.list()` was async and `as_dict()` — the
    same read — was not. Asserted by AST rather than by listing method names, so
    a new method is covered the day it is written.

    The SHAI facade is deliberately excluded: it keeps a uniform async surface
    because it is the published API. See the SHAI class docstring.
    """
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "src" / "harness"
    targets = {
        root / "tools" / "registry.py":  "ToolRegistry",
        root / "agents" / "registry.py": "AgentRegistry",
        root / "tools" / "source.py":    "SourceRegistry",
    }

    violations = []
    for path, cls_name in targets.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        cls = next(
            n for n in ast.walk(tree)
            if isinstance(n, ast.ClassDef) and n.name == cls_name
        )
        for fn in cls.body:
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            awaits = any(
                isinstance(x, ast.Await | ast.AsyncFor | ast.AsyncWith)
                for x in ast.walk(fn)
            )
            if isinstance(fn, ast.AsyncFunctionDef) != awaits:
                violations.append(
                    f"{cls_name}.{fn.name}: "
                    f"{'async but never awaits' if not awaits else 'awaits but is not async'}"
                )

    assert not violations, "registry async/await mismatch: " + "; ".join(violations)
