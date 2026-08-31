"""Tests for harness.mcp.discovery — resolving declared `transport: mcp`
sources to approved manifests and building MCPSource objects. The per-call
re-check is covered separately in test_mcp_gate.py
(harness.mcp.gate.McpBaselineGate).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.config.schema import SourceConfig
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.mcp.baseline import record_baseline
from harness.mcp.discovery import build_mcp_source, resolve_mcp_sources
from harness.mcp.manifest import manifest_file_hash
from harness.tools.source import MCPSource

_SECRET = b"test-secret"
_MANIFEST = """\
id: svc
display_name: "Service"
url: "https://mcp.example.test/sse"
tags: [external]
tools:
  - name: search
    description: "Search internal documentation for a query."
    action: allow
"""


def _write(tmp_path: Path, name: str = "svc", body: str = _MANIFEST) -> Path:
    d = tmp_path / "mcp"
    d.mkdir(exist_ok=True)
    path = d / f"{name}.yaml"
    path.write_text(body)
    return path


def _source_cfg(name: str = "svc", required: bool = True) -> SourceConfig:
    return SourceConfig(name=name, transport=Transport.MCP, required=required)


def _approve(baseline_db: Path, manifest_path: Path, name: str = "svc") -> None:
    record_baseline(baseline_db, name, manifest_file_hash(manifest_path), _SECRET)


def test_undeclared_manifest_is_invisible(tmp_path: Path):
    """A manifest file sitting in mcp_manifests_dir with no sources: entry
    naming it is never resolved — dropping a file must not be enough."""
    manifest_path = _write(tmp_path)
    _approve(tmp_path / "baseline.db", manifest_path)

    resolved = resolve_mcp_sources(
        [], mcp_manifests_dir=str(manifest_path.parent),
        baseline_path=tmp_path / "baseline.db", baseline_secret=_SECRET,
    )
    assert resolved == []


def test_declared_with_approved_baseline_resolves(tmp_path: Path):
    manifest_path = _write(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    _approve(baseline_db, manifest_path)

    resolved = resolve_mcp_sources(
        [_source_cfg()], mcp_manifests_dir=str(manifest_path.parent),
        baseline_path=baseline_db, baseline_secret=_SECRET,
    )
    assert len(resolved) == 1
    assert resolved[0].manifest.id == "svc"
    assert resolved[0].file_hash == manifest_file_hash(manifest_path)


def test_declared_with_no_baseline_record_is_not_built(tmp_path: Path):
    """No PendingApprovalSource, no stub — the name is simply omitted."""
    manifest_path = _write(tmp_path)
    baseline_db = tmp_path / "baseline.db"

    resolved = resolve_mcp_sources(
        [_source_cfg()], mcp_manifests_dir=str(manifest_path.parent),
        baseline_path=baseline_db, baseline_secret=_SECRET,
    )
    assert resolved == []


def test_declared_with_stale_baseline_hash_is_not_built(tmp_path: Path):
    manifest_path = _write(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", "stale-hash", _SECRET)

    resolved = resolve_mcp_sources(
        [_source_cfg()], mcp_manifests_dir=str(manifest_path.parent),
        baseline_path=baseline_db, baseline_secret=_SECRET,
    )
    assert resolved == []


def test_required_source_with_no_manifest_file_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        resolve_mcp_sources(
            [_source_cfg(required=True)], mcp_manifests_dir=str(tmp_path / "mcp"),
            baseline_path=tmp_path / "baseline.db", baseline_secret=_SECRET,
        )


def test_optional_source_with_no_manifest_file_is_skipped(tmp_path: Path):
    resolved = resolve_mcp_sources(
        [_source_cfg(required=False)], mcp_manifests_dir=str(tmp_path / "mcp"),
        baseline_path=tmp_path / "baseline.db", baseline_secret=_SECRET,
    )
    assert resolved == []


def test_manifest_id_mismatch_raises_regardless_of_required(tmp_path: Path):
    manifest_path = _write(tmp_path, name="wrong-name")
    with pytest.raises(ConfigError):
        resolve_mcp_sources(
            [_source_cfg(name="wrong-name", required=False)],
            mcp_manifests_dir=str(manifest_path.parent),
            baseline_path=tmp_path / "baseline.db", baseline_secret=_SECRET,
        )


def test_invalid_manifest_raises(tmp_path: Path):
    d = tmp_path / "mcp"
    d.mkdir()
    (d / "svc.yaml").write_text("id: svc\n")  # missing display_name/url
    with pytest.raises(ConfigError):
        resolve_mcp_sources(
            [_source_cfg()], mcp_manifests_dir=str(d),
            baseline_path=tmp_path / "baseline.db", baseline_secret=_SECRET,
        )


def _kwargs():
    return dict(
        secrets_provider=None,
        connectivity=None,
        emitter=None,
        tenant_id="test",
        metadata_scanners=[],
        metadata_enabled=False,
        metadata_block_at=None,
        metadata_action=None,
    )


def test_build_mcp_source_builds_a_live_source(tmp_path: Path):
    manifest_path = _write(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    _approve(baseline_db, manifest_path)

    resolved = resolve_mcp_sources(
        [_source_cfg()], mcp_manifests_dir=str(manifest_path.parent),
        baseline_path=baseline_db, baseline_secret=_SECRET,
    )[0]

    source = build_mcp_source(resolved, **_kwargs())
    assert isinstance(source, MCPSource)
    assert source.name == "svc"
    assert source.tags == ["external"]
    assert "search" in source._tool_specs
