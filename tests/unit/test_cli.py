from __future__ import annotations

from pathlib import Path

import pytest

from harness_cli.commands.audit import _read_tail
from harness_cli.main import build_parser, main

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.mark.parametrize(
    ("argv", "usage"),
    [
        (["--help"], "usage: shai "),
        (["-h"], "usage: shai "),
        (["validate", "--help"], "usage: shai validate "),
        (["agents", "--help"], "usage: shai agents "),
        (["agents", "list", "--help"], "usage: shai agents list "),
        (["harness", "--help"], "usage: shai harness "),
        (["harness", "inspect", "--help"], "usage: shai harness inspect "),
        (["harness", "graph", "--help"], "usage: shai harness graph "),
        (["audit", "--help"], "usage: shai audit "),
        (["audit", "tail", "--help"], "usage: shai audit tail "),
        (["audit", "verify", "--help"], "usage: shai audit verify "),
        (["patterns", "--help"], "usage: shai patterns "),
        (["patterns", "apply", "--help"], "usage: shai patterns apply "),
        (["patterns", "list", "--help"], "usage: shai patterns list "),
        (["patterns", "verify", "--help"], "usage: shai patterns verify "),
        (["patterns", "candidates", "--help"], "usage: shai patterns candidates "),
        (["patterns", "promote", "--help"], "usage: shai patterns promote "),
        (["patterns", "dismiss", "--help"], "usage: shai patterns dismiss "),
        (["patterns", "retire", "--help"], "usage: shai patterns retire "),
    ],
)
def test_help_is_available_at_every_command_level(
    argv: list[str],
    usage: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(argv)

    captured = capsys.readouterr()
    assert exc_info.value.code == 0
    assert usage in captured.out
    assert captured.err == ""


def test_no_arguments_prints_top_level_help(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main([])

    captured = capsys.readouterr()
    assert result == 0
    assert "usage: shai " in captured.out
    assert "Run 'shai COMMAND --help'" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    "argv",
    [
        ["validate", "--config", "harness.yaml", "--agents-dir", "agents"],
        ["agents", "list", "--agents-dir", "agents"],
        ["audit", "tail", "--file", "audit.jsonl", "--last", "50"],
        [
            "patterns",
            "apply",
            "--bundle",
            "bundle.json",
            "--db",
            "patterns.db",
            "--secret",
            "PATTERN_KEY",
        ],
        ["patterns", "list", "--db", "patterns.db"],
        ["patterns", "verify", "--db", "patterns.db", "--secret", "PATTERN_KEY"],
        ["patterns", "candidates", "--db", "patterns.db", "--status", "open", "--all"],
        ["patterns", "promote", "--db", "patterns.db", "--id", "12"],
        ["patterns", "dismiss", "--db", "patterns.db", "--id", "12"],
        ["patterns", "retire", "--db", "patterns.db", "--id", "12"],
        ["audit", "verify", "--file", "audit.jsonl", "--secret", "AUDIT_KEY"],
    ],
)
def test_documented_command_forms_parse(argv: list[str]) -> None:
    args = build_parser().parse_args(argv)

    assert callable(args.handler)


def test_validate_options_are_scoped_to_validate() -> None:
    args = build_parser().parse_args(
        [
            "validate",
            "--config",
            str(FIXTURES / "harness.yaml"),
            "--agents-dir",
            str(FIXTURES / "agents"),
        ]
    )

    assert args.command == "validate"
    assert args.config == str(FIXTURES / "harness.yaml")
    assert args.agents_dir == str(FIXTURES / "agents")


def test_agents_list_loads_fixture_agents(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(["agents", "list", "--agents-dir", str(FIXTURES / "agents")])

    captured = capsys.readouterr()
    assert result == 0
    assert "orchestrator_agent" in captured.out
    assert "research_agent" in captured.out
    assert "2 agent(s)" in captured.out
    assert captured.err == ""


def test_agents_list_requires_agents_dir() -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["agents", "list"])

    assert exc_info.value.code == 2


def test_validate_config_and_agents(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(
        [
            "validate",
            "--config",
            str(FIXTURES / "harness.yaml"),
            "--agents-dir",
            str(FIXTURES / "agents"),
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert "source_rules: 0" in captured.out
    assert "Result: 2 OK, 0 FAIL" in captured.out
    assert captured.err == ""


def test_validate_without_agents_dir_is_explicit(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(["validate", "--config", str(FIXTURES / "harness.yaml")])

    captured = capsys.readouterr()
    assert result == 0
    assert "Agent validation skipped" in captured.out
    assert captured.err == ""


def test_validate_fails_for_missing_agents_dir(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "missing"

    result = main(
        [
            "validate",
            "--config",
            str(FIXTURES / "harness.yaml"),
            "--agents-dir",
            str(missing),
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "agents directory not found" in captured.err


def test_validate_checks_inline_source_rules(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed source rule fails validation rather than loading silently."""
    config = tmp_path / "harness.yaml"
    config.write_text(
        """
scan_input:
  enabled: false
scan_output:
  enabled: false
policy:
  source_rules:
    - id: bad
      match:
        tool_names: [send]
      action: suppress
      reason: tool-scoped field on a source rule
""",
        encoding="utf-8",
    )

    result = main(["validate", "--config", str(config)])

    captured = capsys.readouterr()
    assert result == 1
    assert "tool-scoped" in captured.err


def test_read_tail_returns_only_requested_lines(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("".join(f"{index}\n" for index in range(1_000)), encoding="utf-8")

    assert _read_tail(audit_log, 3) == ["997", "998", "999"]
    assert _read_tail(audit_log, 0) == []


# ── audit verify ──────────────────────────────────────────────────────────
#
# The command answers one question — "has this trail been altered" — so the
# tests that matter are the ones where the answer is yes. A verifier that
# always says "verified" passes a happy-path test and is worthless.

_AUDIT_KEY = "SHAI_TEST_AUDIT_KEY"


def _signed_log(tmp_path: Path, secret: bytes, count: int = 3) -> Path:
    """Write a JSONL log signed exactly the way the emitter signs events."""
    import hashlib
    import hmac
    import json as _json

    path = tmp_path / "audit.jsonl"
    lines = []
    for i in range(count):
        record = {
            "agent_id": f"agent_{i}", "boundary": "tool_call_gate",
            "decision": "allow", "tenant_id": "default",
            "timestamp": f"2026-01-0{i + 1}T00:00:00Z", "duration_ms": i,
        }
        body = _json.dumps(record, sort_keys=True).encode()
        record["signature"] = hmac.new(secret, body, hashlib.sha256).hexdigest()
        lines.append(_json.dumps(record, sort_keys=True))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def test_audit_verify_accepts_an_untampered_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    log = _signed_log(tmp_path, b"correct-horse")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 0
    assert "3 verified" in capsys.readouterr().out


def test_audit_verify_detects_an_altered_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The whole point: a changed field with its original signature must fail."""
    import json as _json

    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    log = _signed_log(tmp_path, b"correct-horse")
    rows = [_json.loads(line) for line in log.read_text().splitlines()]
    rows[1]["decision"] = "deny"          # signature left untouched
    log.write_text("\n".join(_json.dumps(r, sort_keys=True) for r in rows) + "\n")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 1
    out = capsys.readouterr().out
    assert "line 2" in out and "1 mismatched" in out


def test_audit_verify_is_independent_of_key_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A record reserialized with different key order still verifies.

    Audit lines pass through log shippers and SIEM ingest, which are free to
    re-emit an object with its keys in any order. Verification canonicalises
    before hashing, so the signature covers the record's content rather than
    the byte order it happened to arrive in.
    """
    import json as _json

    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    log = _signed_log(tmp_path, b"correct-horse")
    rows = [_json.loads(line) for line in log.read_text().splitlines()]
    shuffled = [dict(reversed(list(r.items()))) for r in rows]
    assert list(shuffled[0]) != sorted(shuffled[0]), "fixture must be out of order"
    log.write_text(
        "\n".join(_json.dumps(r, sort_keys=False) for r in shuffled) + "\n",
        encoding="utf-8",
    )

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 0


def test_audit_verify_rejects_the_wrong_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_AUDIT_KEY, "not-the-key")
    log = _signed_log(tmp_path, b"correct-horse")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 1


def test_audit_verify_fails_on_unsigned_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unsigned line is a hole in the trail, not a line to skip."""
    import json as _json

    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    log = _signed_log(tmp_path, b"correct-horse")
    rows = [_json.loads(line) for line in log.read_text().splitlines()]
    stripped = [{k: v for k, v in r.items() if k != "signature"} for r in rows]
    log.write_text("\n".join(_json.dumps(r, sort_keys=True) for r in stripped) + "\n")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 1
    assert "3 unsigned" in capsys.readouterr().out


def test_audit_verify_fails_on_malformed_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    log = _signed_log(tmp_path, b"correct-horse", count=1)
    with log.open("a", encoding="utf-8") as fh:
        fh.write("this is not json\n[1, 2, 3]\n\n")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 1
    assert "2 malformed" in capsys.readouterr().out


def test_audit_verify_requires_the_secret_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The key is named, never passed — it must not land in shell history."""
    monkeypatch.delenv(_AUDIT_KEY, raising=False)
    log = _signed_log(tmp_path, b"correct-horse")

    assert main(["audit", "verify", "--file", str(log), "--secret", _AUDIT_KEY]) == 1
    assert "not set" in capsys.readouterr().err


def test_audit_verify_reports_a_missing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")

    assert main(["audit", "verify", "--file", str(tmp_path / "nope.jsonl"),
                 "--secret", _AUDIT_KEY]) == 1
    assert "file not found" in capsys.readouterr().err


def test_audit_verify_fails_on_an_empty_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Zero records verified is not the same as a verified trail."""
    monkeypatch.setenv(_AUDIT_KEY, "correct-horse")
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")

    assert main(["audit", "verify", "--file", str(empty), "--secret", _AUDIT_KEY]) == 1
    assert "no records" in capsys.readouterr().err


async def test_audit_verify_accepts_a_real_emitted_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end against FileSink output — the encoders must agree.

    The hand-built fixtures above pin the verifier's logic; this pins the
    agreement between what the emitter writes and what the verifier reads,
    which is where a canonicalisation change would silently break every
    deployed trail.
    """
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI

    monkeypatch.setenv(_AUDIT_KEY, "real-key-value")
    out = tmp_path / "real.jsonl"
    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: true\n  scanners:\n    - name: injection_scan\n"
        "scan_output:\n  enabled: false\n"
        "audit_signing:\n  enabled: true\n  secret: real-key-value\n"
        f"audit_sinks:\n  - name: file\n    config:\n      path: {out.as_posix()}\n",
        encoding="utf-8",
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.load_agent(FIXTURES / "agents" / "orchestrator_agent.yaml")
    await harness.scan_input("hello there", AgentContext(agent_id="orchestrator_agent"))
    await harness.close()

    assert main(["audit", "verify", "--file", str(out), "--secret", _AUDIT_KEY]) == 0
    assert "0 mismatched" in capsys.readouterr().out
