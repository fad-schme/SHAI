"""Tests for agents/revocation.py — the kill switch's enforcement half."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.agents.revocation import RevocationStore


@pytest.fixture
def store(tmp_path: Path) -> RevocationStore:
    return RevocationStore(tmp_path / "revoked.json", cache_ttl_seconds=0.0)


# ── Basic behaviour ───────────────────────────────────────────────────────

def test_disabled_when_no_path():
    s = RevocationStore(None)
    assert not s.enabled
    assert not s.is_revoked("anyone")
    assert s.revoked_agents() == frozenset()


def test_missing_file_is_an_empty_set_not_an_error(tmp_path):
    s = RevocationStore(tmp_path / "does-not-exist.json")
    assert s.enabled
    assert not s.is_revoked("a1")


def test_revoke_then_is_revoked(store):
    store.revoke("billing_agent", reason="anomalous spend")
    assert store.is_revoked("billing_agent")
    assert not store.is_revoked("other_agent")


def test_revoke_is_idempotent(store):
    store.revoke("a1")
    store.revoke("a1")
    assert store.revoked_agents() == frozenset({"a1"})


def test_restore_lifts_it(store):
    store.revoke("a1")
    assert store.restore("a1") is True
    assert not store.is_revoked("a1")


def test_restore_unknown_returns_false(store):
    assert store.restore("never-revoked") is False


def test_reason_is_recorded(store, tmp_path):
    store.revoke("a1", reason="leaked a key")
    entry = json.loads((tmp_path / "revoked.json").read_text())["revoked"]["a1"]
    assert entry["reason"] == "leaked a key"
    assert entry["revoked_at"]


# ── The properties that make it a kill switch ─────────────────────────────

def test_revocation_survives_a_restart(tmp_path):
    """A restart must not un-kill a killed agent."""
    path = tmp_path / "revoked.json"
    RevocationStore(path).revoke("a1")
    assert RevocationStore(path).is_revoked("a1")


def test_another_process_sees_the_revocation(tmp_path):
    """The CLI writes; the running harness reads the same file."""
    path = tmp_path / "revoked.json"
    harness_side = RevocationStore(path, cache_ttl_seconds=0.0)
    assert not harness_side.is_revoked("a1")

    RevocationStore(path).revoke("a1")          # the `shai agents revoke` process
    assert harness_side.is_revoked("a1")


def test_unreadable_file_never_resurrects_a_revoked_agent(tmp_path):
    """Failing open would be a kill switch that silently stopped working."""
    path = tmp_path / "revoked.json"
    store = RevocationStore(path, cache_ttl_seconds=0.0)
    store.revoke("a1")

    path.write_text("{ this is not json")
    assert store.is_revoked("a1")               # last known set kept
    assert store.revoked_agents() == frozenset({"a1"})


def test_unreadable_file_does_not_revoke_everyone(tmp_path):
    """Failing closed on an unreadable file would deny the whole process."""
    path = tmp_path / "revoked.json"
    path.write_text("{ not json")
    store = RevocationStore(path, cache_ttl_seconds=0.0)
    assert not store.is_revoked("anyone")


def test_malformed_revoked_key_is_a_read_error_not_a_wipe(tmp_path):
    path = tmp_path / "revoked.json"
    store = RevocationStore(path, cache_ttl_seconds=0.0)
    store.revoke("a1")
    path.write_text(json.dumps({"revoked": ["a1"]}))   # list, not object
    assert store.is_revoked("a1")


def test_cache_ttl_bounds_reads(tmp_path):
    """Within the TTL the cached set is served — the TTL is the kill latency."""
    path = tmp_path / "revoked.json"
    store = RevocationStore(path, cache_ttl_seconds=300.0)
    RevocationStore(path).revoke("a1")                 # another process
    assert not store.is_revoked("a1")                  # not yet visible

    fresh = RevocationStore(path, cache_ttl_seconds=0.0)
    assert fresh.is_revoked("a1")


def test_writer_sees_its_own_write_immediately(tmp_path):
    """A long TTL must not delay the in-process API's own revocation."""
    store = RevocationStore(tmp_path / "revoked.json", cache_ttl_seconds=3600.0)
    store.revoke("a1")
    assert store.is_revoked("a1")


def test_write_is_atomic(tmp_path):
    """A half-written file would parse as a failed read and be ignored."""
    path = tmp_path / "revoked.json"
    store = RevocationStore(path, cache_ttl_seconds=0.0)
    store.revoke("a1")
    assert json.loads(path.read_text())["revoked"].keys() == {"a1"}
    assert list(path.parent.glob("*.tmp")) == []


def test_write_creates_missing_parent_directory(tmp_path):
    store = RevocationStore(tmp_path / "state" / "nested" / "revoked.json")
    store.revoke("a1")
    assert store.is_revoked("a1")


def test_zero_ttl_reads_every_call(tmp_path):
    """0 is a valid TTL: no caching, fastest possible response."""
    path = tmp_path / "revoked.json"
    store = RevocationStore(path, cache_ttl_seconds=0)
    RevocationStore(path).revoke("a1")
    assert store.is_revoked("a1")
