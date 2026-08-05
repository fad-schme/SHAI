"""Startup attestation — the SYSTEM/STARTUP event emitted by from_yaml().

Reads events back through a FileSink because the event is emitted before
from_yaml() returns, so collect_events() cannot be attached in time.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.core.attestation import redact_url
from harness.core.errors import AuditEmissionError
from harness.core.harness import SHAI

_BASE = (
    "version: 1\n"
    "scan_input:\n"
    "  enabled: false\n"
    "scan_output:\n"
    "  enabled: false\n"
    "policy:\n"
    "  rules:\n"
    "    - id: deny_destructive\n"
    "      match:\n"
    "        tool_tags: [destructive]\n"
    "      action: deny\n"
    "      reason: destructive tools are denied\n"
    "sources:\n"
    "  - name: test_mcp\n"
    "    transport: mcp\n"
    "    url: https://user:tok@mcp.example.com/mcp?api_key=SECRET#frag\n"
    "    tags: [external]\n"
)


def _write_config(tmp_path: Path, extra: str = "") -> tuple[Path, Path]:
    log_path = tmp_path / "audit.jsonl"
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        _BASE
        + "audit_sinks:\n"
        + "  - name: file\n"
        + "    config:\n"
        + f"      path: {log_path.as_posix()}\n"
        + extra
    )
    return cfg, log_path


def _events(log_path: Path) -> list[dict]:
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


async def test_emits_exactly_one_startup_event(tmp_path: Path):
    cfg, log_path = _write_config(tmp_path)
    harness = await SHAI.from_yaml(cfg)
    await harness.close()

    events = _events(log_path)
    assert len(events) == 1
    ev = events[0]
    assert ev["boundary"] == "system"
    assert ev["decision"] == "startup"
    assert ev["agent_id"] == "__harness__"
    assert ev["finding_count"] == 0


async def test_attestation_payload_shape(tmp_path: Path):
    cfg, log_path = _write_config(tmp_path)
    harness = await SHAI.from_yaml(cfg)
    await harness.close()

    extra = _events(log_path)[0]["extra"]
    assert extra["shai_version"]
    assert extra["policy"]["rule_count"] == 1
    # Enforced at agent load, so it must be attested separately from the rule digest
    assert extra["policy"]["forbidden_tag_combinations"] == []
    assert extra["patterns_db"] is None          # disabled in this config
    assert extra["connectors"] == []             # no connector-backed source

    groups = {a["group"] for a in extra["adapters"]}
    assert groups == {"scanner", "audit_sink", "policy"}
    # Every wired component is identified by module path and source digest.
    assert all(a["module"] and len(a["sha256"]) == 64 for a in extra["adapters"])

    source = extra["sources"][0]
    assert source["name"] == "test_mcp"
    assert source["tags"] == ["external"]


async def test_source_url_carries_no_credentials(tmp_path: Path):
    """Invariant 3 — userinfo, query and fragment never reach a sink."""
    cfg, log_path = _write_config(tmp_path)
    harness = await SHAI.from_yaml(cfg)
    await harness.close()

    line = log_path.read_text()
    assert "SECRET" not in line
    assert "tok@" not in line
    assert _events(log_path)[0]["extra"]["sources"][0]["url"] == \
        "https://mcp.example.com/mcp"


async def test_digests_are_stable_and_policy_sensitive(tmp_path: Path):
    """Same config → same digest; a changed rule → a different one."""
    (tmp_path / "a").mkdir()
    cfg_a, log_a = _write_config(tmp_path / "a")

    h1 = await SHAI.from_yaml(cfg_a)
    await h1.close()
    h2 = await SHAI.from_yaml(cfg_a)
    await h2.close()

    first, second = (e["extra"]["policy"]["digest"] for e in _events(log_a))
    assert first == second

    (tmp_path / "b").mkdir()
    cfg_b, log_b = _write_config(tmp_path / "b")
    cfg_b.write_text(cfg_b.read_text().replace("destructive", "irreversible"))
    h3 = await SHAI.from_yaml(cfg_b)
    await h3.close()
    assert _events(log_b)[0]["extra"]["policy"]["digest"] != first


async def test_startup_event_is_signed_when_signing_enabled(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("TEST_AUDIT_KEY", "unit-test-signing-key")
    cfg, log_path = _write_config(
        tmp_path,
        extra="audit_signing:\n  enabled: true\n  secret: secret://TEST_AUDIT_KEY\n",
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.close()

    assert len(_events(log_path)[0]["signature"]) == 64


async def test_from_yaml_fails_when_all_sinks_fail(tmp_path: Path, monkeypatch):
    """Fail hard: a harness that cannot audit its own startup does not start."""
    from harness.adapters.audit_sinks.file import FileSink

    async def boom(self, event):
        raise OSError("disk gone")

    monkeypatch.setattr(FileSink, "emit", boom)
    cfg, _ = _write_config(tmp_path)

    with pytest.raises(AuditEmissionError):
        await SHAI.from_yaml(cfg)


def test_redact_url_handles_missing_and_bare_urls():
    assert redact_url(None) is None
    assert redact_url("https://h:8443/a/b?q=1") == "https://h:8443/a/b"
