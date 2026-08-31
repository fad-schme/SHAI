"""Tests for harness.mcp.gate.McpBaselineGate — the per-tool-call MCP
manifest onboarding approval check."""
from __future__ import annotations

from pathlib import Path

from harness.mcp.baseline import record_baseline
from harness.mcp.gate import McpBaselineGate
from harness.mcp.manifest import manifest_file_hash

_SECRET = b"test-secret"
_MANIFEST = 'id: svc\ndisplay_name: "Service"\nurl: "https://mcp.example.test/sse"\n'


def _write_manifest(tmp_path: Path, body: str = _MANIFEST) -> Path:
    path = tmp_path / "svc.yaml"
    path.write_text(body)
    return path


def test_unknown_source_name_is_always_approved(tmp_path: Path):
    gate = McpBaselineGate({}, baseline_path=tmp_path / "baseline.db", secret=_SECRET)
    assert gate.check("local") == (True, None)


def test_no_baseline_record_denies_with_onboarding_message(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=tmp_path / "baseline.db", secret=_SECRET
    )
    approved, reason = gate.check("svc")
    assert not approved
    assert "needs onboarding" in reason


def test_hash_mismatch_denies_with_reonboarding_message(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", "stale-hash", _SECRET)
    gate = McpBaselineGate({"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET)
    approved, reason = gate.check("svc")
    assert not approved
    assert "re-onboarding required" in reason


def test_matching_baseline_approves(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate({"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET)
    assert gate.check("svc") == (True, None)


def test_edit_after_approval_denies_once_cache_expires(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=0,
    )
    assert gate.check("svc") == (True, None)

    manifest_path.write_text(_MANIFEST + "tags: [changed]\n")
    approved, reason = gate.check("svc")
    assert not approved
    assert "re-onboarding required" in reason


def test_reapproval_takes_effect_once_cache_expires(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=0,
    )
    approved, _ = gate.check("svc")
    assert not approved

    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    assert gate.check("svc") == (True, None)


def test_result_is_cached_within_ttl(tmp_path: Path):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=300,
    )
    assert gate.check("svc") == (True, None)

    # Edit the manifest — within the TTL window, the stale cached approval
    # still applies (this is the caching trade-off cache_ttl_seconds names).
    manifest_path.write_text(_MANIFEST + "tags: [changed]\n")
    assert gate.check("svc") == (True, None)


def test_unreadable_manifest_denies(tmp_path: Path):
    gate = McpBaselineGate(
        {"svc": tmp_path / "does_not_exist.yaml"},
        baseline_path=tmp_path / "baseline.db", secret=_SECRET,
    )
    approved, reason = gate.check("svc")
    assert not approved
    assert reason is not None


def test_baseline_read_failure_keeps_last_known_verdict(tmp_path: Path, monkeypatch):
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=0,
    )
    assert gate.check("svc") == (True, None)

    import harness.mcp.gate as gate_module

    def boom(*args, **kwargs):
        raise RuntimeError("db locked")

    monkeypatch.setattr(gate_module, "lookup_baseline", boom)
    # Read failure — the last known (approved) verdict is kept, not flipped
    # to deny, the same continuity posture RevocationStore's file read takes.
    assert gate.check("svc") == (True, None)


def test_deleted_manifest_denies_immediately_despite_a_cached_approve(tmp_path: Path):
    """Deleting the manifest is the most direct way to revoke a source, so it
    must not wait out cache_ttl_seconds behind a cached approve. The file is
    checked ahead of the cache."""
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=300,          # long TTL: a cache hit would mask this
    )
    assert gate.check("svc") == (True, None)

    manifest_path.unlink()
    approved, reason = gate.check("svc")
    assert not approved
    assert "missing" in reason


def test_restoring_a_deleted_manifest_re_verifies(tmp_path: Path):
    """The deny drops the cached verdict, so a restored file is verified again
    rather than resurrecting the stale approve.

    Restoring *different* content is not asserted here: an edit is TTL-bound
    by design (test_edit_after_approval_denies_once_cache_expires covers it
    with ttl=0), while a deletion bypasses the cache. Asserting both in one
    test would assert the edit latency away.
    """
    manifest_path = _write_manifest(tmp_path)
    baseline_db = tmp_path / "baseline.db"
    record_baseline(baseline_db, "svc", manifest_file_hash(manifest_path), _SECRET)
    gate = McpBaselineGate(
        {"svc": manifest_path}, baseline_path=baseline_db, secret=_SECRET,
        cache_ttl_seconds=300,
    )
    assert gate.check("svc") == (True, None)
    manifest_path.unlink()
    assert gate.check("svc")[0] is False

    _write_manifest(tmp_path)                       # same bytes, same hash
    assert gate.check("svc") == (True, None)
