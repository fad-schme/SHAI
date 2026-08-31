"""Tests for harness.mcp.readiness.score_readiness()."""
from __future__ import annotations

from harness.mcp.manifest import MCPArgumentSpec, MCPManifest, MCPToolSpec


def _manifest(*tools: MCPToolSpec) -> MCPManifest:
    return MCPManifest(
        id="svc", display_name="Service", url="https://mcp.example.test/sse",
        tools=list(tools),
    )


def test_empty_manifest_scores_100():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest()
    report = score_readiness(manifest)
    assert report == {"score": 100, "flags": []}


def test_well_described_tool_with_typed_args_and_timeout_scores_100():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(
        name="search",
        description="Search internal documentation for a given query string.",
        arguments=[MCPArgumentSpec(name="query", type="string")],
        timeout_seconds=30,
    ))
    report = score_readiness(manifest)
    assert report["score"] == 100
    assert report["flags"] == []


def test_missing_description_is_flagged_and_penalized():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(name="search", description=""))
    report = score_readiness(manifest)
    assert report["score"] < 100
    assert report["flags"][0]["tool_name"] == "search"
    assert "missing_description" in report["flags"][0]["flags"]


def test_short_description_is_flagged():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(name="search", description="Search."))
    report = score_readiness(manifest)
    assert "short_description" in report["flags"][0]["flags"]


def test_high_argument_count_is_flagged():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(
        name="search",
        description="Search internal documentation for a given query string.",
        arguments=[MCPArgumentSpec(name=f"arg{i}", type="string") for i in range(9)],
    ))
    report = score_readiness(manifest)
    assert "argument_count_high" in report["flags"][0]["flags"]


def test_missing_argument_type_is_flagged():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(
        name="search",
        description="Search internal documentation for a given query string.",
        arguments=[MCPArgumentSpec(name="query", type=None)],
    ))
    report = score_readiness(manifest)
    assert "missing_argument_types" in report["flags"][0]["flags"]


def test_no_timeout_hint_is_flagged():
    from harness.mcp.readiness import score_readiness
    manifest = _manifest(MCPToolSpec(
        name="search",
        description="Search internal documentation for a given query string.",
    ))
    report = score_readiness(manifest)
    assert "no_timeout_hint" in report["flags"][0]["flags"]


def test_never_participates_in_pass_fail_decision():
    """Readiness is informational only — onboard._decide() never reads it."""
    import inspect

    from harness.mcp import onboard
    source = inspect.getsource(onboard._decide)
    assert "readiness" not in source
