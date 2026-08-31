"""shai harness inspect / graph — offline topology view."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness_cli.main import main

_CONFIG = """\
version: 1
tenant_id: demo
scan_input:
  enabled: false
scan_output:
  enabled: false
audit_sinks:
  - name: stdout
sources:
  - name: docs
    tags: [internal]
"""

_AGENT = """\
id: analyst
allowed_tool_names: [search_docs]
allowed_tags: [internal, sensitive]
sources: [docs]
policy_rules:
  - id: deny_destructive
    match:
      tool_tags: [destructive]
    action: deny
    reason: destructive tools are denied
sub_agents:
  - id: reader
    allowed_tool_names: [search_docs]
    allowed_tags: [internal]
"""

_MANIFEST = """\
id: slack
display_name: "Slack"
url: "https://mcp.slack.com/sse?token=SHOULD_NOT_LEAK"
credentials:
  token: literal-token
tools:
  - name: send_message
    description: "Send a message"
    action: block
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "harness.yaml").write_text(_CONFIG)
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "agent-analyst.yaml").write_text(_AGENT)
    return tmp_path


@pytest.fixture
def workspace_with_manifest(workspace: Path) -> Path:
    mcp_dir = workspace / "mcp"
    mcp_dir.mkdir()
    (mcp_dir / "slack.yaml").write_text(_MANIFEST)
    config = _CONFIG.replace(
        "sources:\n  - name: docs\n    tags: [internal]\n",
        "sources:\n  - name: docs\n    tags: [internal]\n"
        "  - name: slack\n    transport: mcp\n",
    )
    (workspace / "harness.yaml").write_text(
        config + f"mcp_manifests_dir: {mcp_dir}\n"
        "mcp_baseline:\n  secret: test-secret\n"
    )
    return workspace


def _run(workspace: Path, *argv: str) -> int:
    return main([*argv, "--config", str(workspace / "harness.yaml"),
                 "--agents-dir", str(workspace / "agents")])


def test_inspect_reports_local_source_topology(workspace, capsys):
    assert _run(workspace, "harness", "inspect") == 0
    out = capsys.readouterr().out

    assert "tenant: demo" in out
    assert "0 source rules" in out
    assert "docs" in out and "internal" in out
    assert "analyst" in out


def test_inspect_reports_mcp_manifest_digest(workspace_with_manifest, capsys):
    assert _run(workspace_with_manifest, "harness", "inspect") == 0
    out = capsys.readouterr().out
    assert "mcp manifests" in out
    assert "slack" in out
    assert "digest=" in out


def test_inspect_never_prints_credentials(workspace_with_manifest, capsys):
    assert _run(workspace_with_manifest, "harness", "inspect") == 0
    captured = capsys.readouterr()
    assert "SHOULD_NOT_LEAK" not in captured.out + captured.err
    assert "literal-token" not in captured.out + captured.err


def test_graph_json_links_agent_source_tool_and_rule(workspace, capsys):
    assert _run(workspace, "harness", "graph", "--format", "json") == 0
    graph = json.loads(capsys.readouterr().out)

    types = {n["id"]: n["type"] for n in graph["nodes"]}
    assert types["agent:analyst"] == "agent"
    assert types["subagent:analyst/reader"] == "subagent"
    assert types["rule:analyst/deny_destructive"] == "rule"

    edges = {(e["from"], e["to"], e["type"]) for e in graph["edges"]}
    assert ("agent:analyst", "source:docs", "declares") in edges
    assert ("agent:analyst", "subagent:analyst/reader", "delegates") in edges
    assert ("rule:analyst/deny_destructive", "tag:destructive", "matches") in edges


def test_dot_output_is_the_default(workspace, capsys):
    assert _run(workspace, "harness", "graph") == 0
    out = capsys.readouterr().out
    assert out.startswith("digraph shai {")
    assert '"agent:analyst" -> "source:docs"' in out


def test_missing_config_exits_nonzero(tmp_path: Path, capsys):
    assert main(["harness", "inspect", "--config", str(tmp_path / "nope.yaml")]) == 1
    assert "Error:" in capsys.readouterr().err
