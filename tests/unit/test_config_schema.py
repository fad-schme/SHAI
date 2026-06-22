"""Tests for config/schema.py."""
import pytest
from pydantic import ValidationError

from harness.config.schema import (
    BoundaryConfig,
    HarnessConfig,
    ToolSourceConfig,
)
from harness.core.types import Transport


def _minimal() -> dict:
    return {
        "scan_input":  {"enabled": False},
        "scan_output": {"enabled": False},
        "policy":      {"name": "rules"},
        "audit_sinks": [{"name": "stdout"}],
    }


def test_minimal_valid_config():
    cfg = HarnessConfig.model_validate(_minimal())
    assert cfg.policy.name == "rules"
    assert len(cfg.audit_sinks) == 1
    assert cfg.tool_registry.name == "memory"
    assert cfg.secrets.name == "env"


def test_no_audit_sinks_rejected():
    data = {**_minimal(), "audit_sinks": []}
    with pytest.raises(ValidationError):
        HarnessConfig.model_validate(data)


def test_enabled_boundary_without_scanners_rejected():
    with pytest.raises(ValidationError):
        BoundaryConfig(enabled=True, scanners=[])


def test_disabled_boundary_without_scanners_ok():
    bc = BoundaryConfig(enabled=False)
    assert not bc.enabled
    assert bc.scanners == []


def test_unknown_field_rejected():
    data = {**_minimal(), "typo_field": "oops"}
    with pytest.raises(ValidationError):
        HarnessConfig.model_validate(data)


def test_mcp_source_requires_url():
    with pytest.raises(ValidationError):
        ToolSourceConfig(name="s", transport=Transport.MCP)


def test_skill_source_requires_tools():
    with pytest.raises(ValidationError):
        ToolSourceConfig(name="s", transport=Transport.SKILL)


def test_valid_mcp_source():
    s = ToolSourceConfig(
        name="slack",
        transport=Transport.MCP,
        url="https://mcp.slack.com/sse",
        credentials={"token": "secret://SLACK_TOKEN"},
    )
    assert s.url == "https://mcp.slack.com/sse"


def test_valid_skill_source():
    s = ToolSourceConfig(name="docs", transport=Transport.SKILL, tools=["search_docs"])
    assert s.tools == ["search_docs"]


def test_enabled_scan_with_scanners_ok():
    bc = BoundaryConfig(enabled=True, scanners=[{"name": "regex_pii"}])
    assert bc.enabled
    assert bc.scanners[0].name == "regex_pii"


def test_default_tool_registry_is_memory():
    cfg = HarnessConfig.model_validate(_minimal())
    assert cfg.tool_registry.name == "memory"


def test_default_secrets_is_env():
    cfg = HarnessConfig.model_validate(_minimal())
    assert cfg.secrets.name == "env"
