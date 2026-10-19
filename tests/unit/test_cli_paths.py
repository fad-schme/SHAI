"""`shai validate` and `shai harness inspect` show the paths agents may touch and
the paths SHAI protects."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.path_scope import canonicalize_path
from harness_cli.main import main


def _config(tmp_path: Path) -> str:
    return (
        "version: 1\nconnectivity:\n  token_secret: test-connectivity-secret\n"
        "scan_input:\n  scanners: []\nscan_output:\n  scanners: []\n"
        f"audit_sinks:\n  - name: file\n    config:\n      path: '{(tmp_path / 'state' / 'audit.jsonl').as_posix()}'\n"
        f"patterns_db:\n  path: '{(tmp_path / 'state' / 'patterns.db').as_posix()}'\n"
        f"mcp_baseline:\n  path: '{(tmp_path / 'state' / 'baseline.db').as_posix()}'\n"
    )


def _agent(agent_id: str, grant: str = "", sub: str = "") -> str:
    return (
        f"id: {agent_id}\nallowed_tool_names: [read_file]\nallowed_tags: [fs]\n{grant}{sub}"
    )


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "harness.yaml").write_text(_config(tmp_path))
    (tmp_path / "agents").mkdir()
    data, out = (tmp_path / "data").as_posix(), (tmp_path / "out").as_posix()
    (tmp_path / "agents" / "a-reader.yaml").write_text(_agent(
        "reader",
        grant=f"allowed_paths:\n  read: ['{data}']\n  write: ['{out}']\n",
        sub=(f"sub_agents:\n  - id: narrow\n    allowed_tool_names: [read_file]\n"
             f"    allowed_tags: [fs]\n    allowed_paths:\n      read: ['{data}/sub']\n"),
    ))
    (tmp_path / "agents" / "b-none.yaml").write_text(_agent("nobody"))
    return tmp_path


def _run(workspace: Path, *argv: str) -> int:
    return main([*argv, "--config", str(workspace / "harness.yaml"),
                 "--agents-dir", str(workspace / "agents")])


def test_validate_lists_the_protected_set(workspace, capsys):
    assert _run(workspace, "validate") == 0
    out = capsys.readouterr().out
    assert "protected_paths:" in out
    for name in ("harness.yaml", "audit.jsonl", "patterns.db", "baseline.db", "agents"):
        assert name in out, name
    assert canonicalize_path(str(workspace / "state" / "audit.jsonl")) in out


def test_validate_omits_unset_sources(workspace, capsys):
    assert _run(workspace, "validate") == 0
    out = capsys.readouterr().out
    assert "revoked" not in out and "manifests" not in out


def test_validate_shows_each_agents_and_subagents_grants(workspace, capsys):
    assert _run(workspace, "validate") == 0
    out = capsys.readouterr().out
    data = str(workspace / "data").replace("\\", "/")
    assert f"read : {data}" in out
    assert "write: " in out
    assert "subagent narrow: read :" in out
    assert "filesystem: none" in out  # the agent with no allowed_paths


def test_validate_still_reports_the_ok_line_per_agent(workspace, capsys):
    assert _run(workspace, "validate") == 0
    out = capsys.readouterr().out
    assert "a-reader.yaml ... OK  (tools=1, sub_agents=1)" in out
    assert "b-none.yaml ... OK  (tools=1, sub_agents=0)" in out


def test_validate_fails_on_a_grant_overlapping_the_protected_set(workspace, capsys):
    (workspace / "agents" / "c-broad.yaml").write_text(_agent(
        "broad", grant=f"allowed_paths:\n  read: ['{workspace.as_posix()}']\n",
    ))
    assert _run(workspace, "validate") == 1
    captured = capsys.readouterr()
    assert "protected" in (captured.out + captured.err)
    assert "Result: 2 OK, 1 FAIL" in captured.out


def test_inspect_shows_grants_per_agent_and_subagent(workspace, capsys):
    assert _run(workspace, "harness", "inspect") == 0
    out = capsys.readouterr().out
    assert "reader" in out and "nobody" in out
    assert "read :" in out and "write:" in out
    assert "subagent narrow: read :" in out
    assert "filesystem: none" in out
