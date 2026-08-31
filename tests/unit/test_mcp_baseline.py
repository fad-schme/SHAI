"""Tests for harness.mcp.baseline — the signed local approval store."""
from __future__ import annotations

from pathlib import Path

from harness.mcp.baseline import lookup_baseline, record_baseline

_SECRET = b"test-secret"
_OTHER_SECRET = b"other-secret"


def test_lookup_missing_db_returns_none(tmp_path: Path):
    assert lookup_baseline(tmp_path / "nope.db", "slack", _SECRET) is None


def test_record_then_lookup_roundtrips(tmp_path: Path):
    db = tmp_path / "baseline.db"
    record_baseline(db, "slack", "abc123", _SECRET)
    result = lookup_baseline(db, "slack", _SECRET)
    assert result is not None
    assert result["file_hash"] == "abc123"


def test_lookup_unknown_id_returns_none(tmp_path: Path):
    db = tmp_path / "baseline.db"
    record_baseline(db, "slack", "abc123", _SECRET)
    assert lookup_baseline(db, "github", _SECRET) is None


def test_tampered_row_fails_verification_and_reads_as_absent(tmp_path: Path):
    db = tmp_path / "baseline.db"
    record_baseline(db, "slack", "abc123", _SECRET)
    # Wrong secret simulates a row whose signature no longer verifies —
    # fail closed, same as no record at all.
    assert lookup_baseline(db, "slack", _OTHER_SECRET) is None


def test_reapproval_updates_recorded_at_keeps_hash(tmp_path: Path):
    db = tmp_path / "baseline.db"
    record_baseline(db, "slack", "abc123", _SECRET)
    first = lookup_baseline(db, "slack", _SECRET)

    record_baseline(db, "slack", "abc123", _SECRET)
    second = lookup_baseline(db, "slack", _SECRET)

    assert first["file_hash"] == second["file_hash"] == "abc123"
    assert second["recorded_at"] >= first["recorded_at"]


def test_reonboarding_with_changed_hash_overwrites(tmp_path: Path):
    db = tmp_path / "baseline.db"
    record_baseline(db, "slack", "abc123", _SECRET)
    record_baseline(db, "slack", "def456", _SECRET)
    result = lookup_baseline(db, "slack", _SECRET)
    assert result["file_hash"] == "def456"
