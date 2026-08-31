"""Tests for harness.mcp.manifest — parsing, hashing, discovery."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.core.errors import ConfigError
from harness.mcp.manifest import (
    load_manifest_file,
    manifest_file_hash,
    manifest_path_for,
    resolve_manifest_credentials,
)

_VALID = """\
id: slack
display_name: "Slack"
url: "https://mcp.slack.com/sse"
allowed_urls: ["https://mcp.slack.com/*"]
tags: [external_mcp, messaging]
credentials:
  token: "literal-token"
tools:
  - name: send_message
    description: "Send a message to a channel or user"
    tags: [external_write, messaging]
    action: block
"""


def test_valid_manifest_parses(tmp_path: Path):
    path = tmp_path / "slack.yaml"
    path.write_text(_VALID)
    manifest = load_manifest_file(path)
    assert manifest.id == "slack"
    assert manifest.url == "https://mcp.slack.com/sse"
    assert manifest.tools[0].name == "send_message"
    assert manifest.tools[0].action == "block"
    assert manifest.required is True  # default


def test_missing_file_raises_config_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_manifest_file(tmp_path / "nope.yaml")


def test_missing_required_field_names_it(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("id: slack\ndisplay_name: Slack\n")  # no url
    with pytest.raises(ConfigError, match="url"):
        load_manifest_file(path)


def test_not_a_mapping_raises(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError, match="mapping"):
        load_manifest_file(path)


def test_invalid_yaml_raises(tmp_path: Path):
    path = tmp_path / "bad.yaml"
    path.write_text("id: [unterminated\n")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_manifest_file(path)


def test_hash_is_sha256_over_raw_bytes(tmp_path: Path):
    import hashlib
    path = tmp_path / "slack.yaml"
    path.write_text(_VALID)
    assert manifest_file_hash(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_hash_changes_with_any_byte_change(tmp_path: Path):
    path = tmp_path / "slack.yaml"
    path.write_text(_VALID)
    before = manifest_file_hash(path)
    path.write_text(_VALID + "\n")
    after = manifest_file_hash(path)
    assert before != after


def test_manifest_path_for_resolves_by_convention(tmp_path: Path):
    assert manifest_path_for("slack", tmp_path) == tmp_path / "slack.yaml"


def test_manifest_path_for_ignores_files_not_matching_a_declared_name(tmp_path: Path):
    (tmp_path / "slack.yaml").write_text(_VALID)
    # A file for a name nothing declares is never resolved to — the caller
    # only ever asks for the name it was told to look up.
    assert manifest_path_for("github", tmp_path) == tmp_path / "github.yaml"
    assert not manifest_path_for("github", tmp_path).exists()


def test_resolve_manifest_credentials_expands_env_var(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("SLACK_TOKEN_TEST", "xoxb-secret")
    path = tmp_path / "slack.yaml"
    path.write_text(_VALID.replace(
        'token: "literal-token"', 'token: "${SLACK_TOKEN_TEST}"'
    ))
    manifest = load_manifest_file(path)
    resolved = resolve_manifest_credentials(manifest, provider=None)
    assert resolved["token"] == "xoxb-secret"
