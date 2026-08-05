"""Tests for shai-connectors — manifest loading and SourceConfig wiring."""
from __future__ import annotations

import pytest

from harness.config.schema import SourceConfig
from harness.connectors import (
    ConnectorManifest,
    list_connectors,
    load_manifest,
    manifest_to_source_config_fields,
    resolve_source_config,
)

# ── Registry ───────────────────────────────────────────────────────────────

def test_list_connectors_returns_tier_a():
    connectors = list_connectors()
    tier_a = {"slack", "github", "notion", "jira", "gmail", "postgresql",
               "stripe", "google_drive"}
    assert tier_a.issubset(set(connectors)), (
        f"Missing Tier A connectors: {tier_a - set(connectors)}"
    )


def test_unknown_connector_raises():
    with pytest.raises(ValueError, match="Unknown connector"):
        load_manifest("does_not_exist")


def test_unknown_connector_error_lists_available():
    with pytest.raises(ValueError, match="Available"):
        load_manifest("does_not_exist")


# ── Manifest structure ─────────────────────────────────────────────────────

@pytest.mark.parametrize("connector_id", [
    "slack", "github", "notion", "jira",
    "gmail", "postgresql", "stripe", "google_drive",
])
def test_manifest_loads_and_validates(connector_id):
    m = load_manifest(connector_id)
    assert isinstance(m, ConnectorManifest)
    assert m.id == connector_id
    assert m.display_name
    assert m.url
    assert m.allowed_urls
    assert m.tools


@pytest.mark.parametrize("connector_id", [
    "slack", "github", "notion", "jira",
    "gmail", "postgresql", "stripe", "google_drive",
])
def test_manifest_write_tools_are_blocked_by_default(connector_id):
    """Tools tagged external_write must default to block or alert, not allow."""
    m = load_manifest(connector_id)
    violations = [
        t.name for t in m.tools
        if "external_write" in t.tags and t.action == "allow"
    ]
    assert not violations, (
        f"{connector_id}: external_write tools must be block/alert, "
        f"not allow: {violations}"
    )


def test_sensitive_connectors_carry_sensitive_tag():
    """Financial and email connectors must carry sensitive tag."""
    for cid in ["gmail", "stripe", "postgresql"]:
        m = load_manifest(cid)
        assert "sensitive" in m.tags, f"{cid}: missing sensitive tag"


# ── manifest_to_source_config_fields ──────────────────────────────────────

def test_manifest_to_source_config_basic():
    m = load_manifest("slack")
    fields = manifest_to_source_config_fields(m, {})
    assert fields["transport"]    == "mcp"
    assert fields["url"]          == m.url
    assert fields["allowed_urls"] == m.allowed_urls
    assert fields["tags"]         == m.tags


def test_operator_override_takes_precedence():
    m = load_manifest("slack")
    override_urls = ["https://custom-slack.example.com/*"]
    fields = manifest_to_source_config_fields(m, {"allowed_urls": override_urls})
    assert fields["allowed_urls"] == override_urls


def test_operator_required_false_overrides_manifest():
    m = load_manifest("github")
    assert m.required is True
    fields = manifest_to_source_config_fields(m, {"required": False})
    assert fields["required"] is False


# ── Caching ────────────────────────────────────────────────────────────────

def test_load_manifest_is_cached():
    m1 = load_manifest("slack")
    m2 = load_manifest("slack")
    assert m1 is m2   # lru_cache returns the same object


# ── SourceConfig integration ───────────────────────────────────────────────

def test_source_config_accepts_connector_field():
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(
        name="my_slack",
        connector="slack",
        credentials={"token": "secret://SLACK_TOKEN"},
    )
    assert cfg.connector == "slack"
    assert cfg.name == "my_slack"


def test_source_config_mcp_without_url_or_connector_raises():
    from pydantic import ValidationError

    from harness.config.schema import SourceConfig, Transport
    with pytest.raises(ValidationError, match="url is required"):
        SourceConfig(name="bad", transport=Transport.MCP)


def test_source_config_mcp_with_connector_no_url_passes():
    """connector: alone is valid — manifest provides the url."""
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(
        name="slack",
        connector="slack",
        credentials={"token": "secret://SLACK_TOKEN"},
    )
    assert cfg.connector == "slack"
    assert cfg.url is None   # url comes from manifest at from_yaml() time



# ── Per-tool tags wiring ───────────────────────────────────────────────────

def test_manifest_to_source_config_includes_tool_specs():
    m = load_manifest("slack")
    fields = manifest_to_source_config_fields(m, {})
    assert "connector_tool_specs" in fields
    specs = fields["connector_tool_specs"]
    # send_message must have external_write tag
    assert "send_message" in specs
    assert "external_write" in specs["send_message"]["tags"]
    # read_messages must have read tag
    assert "read_messages" in specs
    assert "read" in specs["read_messages"]["tags"]


def test_source_config_accepts_connector_tool_specs():
    from harness.config.schema import SourceConfig
    cfg = SourceConfig(
        name="slack",
        connector="slack",
        credentials={"token": ""},
        connector_tool_specs={
            "send_message": {"tags": ["external_write"], "action": "block"},
            "read_messages": {"tags": ["read"], "action": "allow"},
        },
    )
    assert "send_message" in cfg.connector_tool_specs


def test_all_tier_a_manifests_have_tool_specs_wired():
    """Every Tier A manifest must produce non-empty connector_tool_specs."""
    tier_a = ["slack", "github", "notion", "jira",
               "gmail", "postgresql", "stripe", "google_drive"]
    for cid in tier_a:
        m = load_manifest(cid)
        fields = manifest_to_source_config_fields(m, {})
        assert fields["connector_tool_specs"], (
            f"{cid}: connector_tool_specs is empty"
        )


def test_write_tool_specs_have_block_action():
    """External write tools in all manifests must have action: block in specs."""
    tier_a = ["slack", "github", "notion", "jira",
               "gmail", "postgresql", "stripe", "google_drive"]
    for cid in tier_a:
        m = load_manifest(cid)
        fields = manifest_to_source_config_fields(m, {})
        specs = fields["connector_tool_specs"]
        violations = [
            name for name, spec in specs.items()
            if "external_write" in spec.get("tags", [])
            and spec.get("action") == "allow"
        ]
        assert not violations, (
            f"{cid}: external_write tools with action=allow: {violations}"
        )


# ── resolve_source_config ─────────────────────────────────────────────────

def test_resolve_keeps_manifest_values_the_operator_did_not_declare():
    """SourceConfig defaults must not silently replace manifest values.

    A source declaring only `connector:` and credentials previously came back
    with transport=local and empty tags / allow-lists, because every default was
    dumped as an override — the manifest's security metadata was discarded.
    """
    src = SourceConfig(name="slack_primary", connector="slack",
                       credentials={"token": "t"})
    resolved = resolve_source_config(src)
    manifest = load_manifest("slack")

    assert resolved.transport == "mcp"
    assert resolved.url == manifest.url
    assert resolved.tags == manifest.tags
    assert resolved.allowed_urls == manifest.allowed_urls
    assert resolved.allowed_methods == manifest.allowed_methods
    assert resolved.connector == "slack"
    assert resolved.connector_tool_specs
    assert resolved.credentials == {"token": "t"}


def test_resolve_honours_explicit_operator_overrides():
    src = SourceConfig(name="slack_primary", connector="slack",
                       tags=["internal"], allowed_methods=["GET"])
    resolved = resolve_source_config(src)

    assert resolved.tags == ["internal"]
    assert resolved.allowed_methods == ["GET"]


def test_resolve_passes_through_sources_without_a_connector():
    src = SourceConfig(name="local_tools", tool_names=["a"])
    assert resolve_source_config(src) is src


def test_resolve_rejects_an_unknown_connector():
    from harness.core.errors import ConfigError

    with pytest.raises(ConfigError):
        resolve_source_config(SourceConfig(name="x", connector="not_a_connector"))
