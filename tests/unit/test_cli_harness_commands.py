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
policy:
  rules:
    - id: deny_destructive
      match:
        tool_tags: [destructive]
      action: deny
      reason: no destructive tools
audit_sinks:
  - name: stdout
sources:
  - name: slack_primary
    connector: slack
    credentials:
      token: literal-token
  - name: slack_shadow
    transport: mcp
    url: {shadow_url}
    tags: [external]
"""

_AGENT = """\
id: analyst
allowed_tool_names: [slack_send_message, slack_list_channels]
allowed_tags: [external, sensitive]
sources: [slack_primary]
sub_agents:
  - id: reader
    allowed_tool_names: [slack_list_channels]
    allowed_tags: [external]
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Config whose second source shadows the slack connector's endpoint."""
    from harness.connectors import load_manifest

    shadow = load_manifest("slack").url + "?token=SHOULD_NOT_LEAK"
    (tmp_path / "harness.yaml").write_text(_CONFIG.format(shadow_url=shadow))
    (tmp_path / "agents").mkdir()
    (tmp_path / "agents" / "agent-analyst.yaml").write_text(_AGENT)
    return tmp_path


def _run(workspace: Path, *argv: str) -> int:
    return main([*argv, "--config", str(workspace / "harness.yaml"),
                 "--agents-dir", str(workspace / "agents")])


def test_inspect_reports_resolved_connector_topology(workspace, capsys):
    assert _run(workspace, "harness", "inspect") == 0
    out = capsys.readouterr().out

    assert "tenant: demo" in out
    assert "1 rules" in out
    assert "slack (" in out                    # connector digest line
    # Manifest values survive resolution — transport and tags come from slack.yaml
    assert "slack_primary" in out and "messaging" in out
    assert "analyst" in out


def test_inspect_never_prints_credentials(workspace, capsys):
    assert _run(workspace, "harness", "inspect") == 0
    captured = capsys.readouterr()
    assert "SHOULD_NOT_LEAK" not in captured.out + captured.err
    assert "literal-token" not in captured.out + captured.err


def test_graph_json_links_agent_source_tool_and_rule(workspace, capsys):
    assert _run(workspace, "harness", "graph", "--format", "json") == 0
    graph = json.loads(capsys.readouterr().out)

    types = {n["id"]: n["type"] for n in graph["nodes"]}
    assert types["agent:analyst"] == "agent"
    assert types["subagent:analyst/reader"] == "subagent"
    assert types["rule:global/deny_destructive"] == "rule"

    edges = {(e["from"], e["to"], e["type"]) for e in graph["edges"]}
    assert ("agent:analyst", "source:slack_primary", "declares") in edges
    assert ("agent:analyst", "subagent:analyst/reader", "delegates") in edges
    assert ("rule:global/deny_destructive", "tag:destructive", "matches") in edges
    # Tool nodes come from the connector manifest's per-tool specs
    assert any(f == "source:slack_primary" and t.startswith("tool:") and k == "exposes"
               for f, t, k in edges)


def test_graph_warns_on_colliding_endpoints(workspace, capsys):
    assert _run(workspace, "harness", "graph", "--format", "json") == 0
    captured = capsys.readouterr()

    warnings = json.loads(captured.out)["warnings"]
    assert len(warnings) == 1
    assert set(warnings[0]["sources"]) == {"slack_primary", "slack_shadow"}
    assert "?" not in warnings[0]["url"]
    assert "share one endpoint" in captured.err


def test_dot_output_is_the_default(workspace, capsys):
    assert _run(workspace, "harness", "graph") == 0
    out = capsys.readouterr().out
    assert out.startswith("digraph shai {")
    assert '"agent:analyst" -> "source:slack_primary"' in out


def test_missing_config_exits_nonzero(tmp_path: Path, capsys):
    assert main(["harness", "inspect", "--config", str(tmp_path / "nope.yaml")]) == 1
    assert "Error:" in capsys.readouterr().err
