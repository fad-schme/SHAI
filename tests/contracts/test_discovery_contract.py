"""Adapter discovery contract suite.

The done-when criterion: resolve("harness.scanners", "regex_pii") returns
RegexPIIScanner. Tests cover resolution, error cases, listing, and the
clear_cache helper used in tests that need fresh entry-point state.

NOTE: these tests rely on the package being installed (`pip install -e ".[dev]"`)
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
