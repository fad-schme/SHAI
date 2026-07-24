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
        (["audit", "--help"], "usage: shai audit "),
        (["audit", "tail", "--help"], "usage: shai audit tail "),
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
    assert "policy_rules: 0" in captured.out
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


def test_validate_checks_inline_policy_rules(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = tmp_path / "harness.yaml"
    config.write_text(
        """
scan_input:
  enabled: false
scan_output:
  enabled: false
policy:
  rules:
    - id: invalid_deny
      match: {}
      action: deny
""",
        encoding="utf-8",
    )

    result = main(["validate", "--config", str(config)])

    captured = capsys.readouterr()
    assert result == 1
    assert "reason required for deny action" in captured.err


def test_read_tail_returns_only_requested_lines(tmp_path: Path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("".join(f"{index}\n" for index in range(1_000)), encoding="utf-8")

    assert _read_tail(audit_log, 3) == ["997", "998", "999"]
    assert _read_tail(audit_log, 0) == []
