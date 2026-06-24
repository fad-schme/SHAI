"""harness.connectors — connector manifest registry.

A ConnectorManifest is a pre-built, security-reviewed configuration for a
well-known MCP server. Operators reference a connector by name in harness.yaml
instead of hand-configuring every field:

    sources:
      - connector: slack           # loads the manifest
        credentials:
          token: "secret://SLACK_BOT_TOKEN"
      - connector: github
        credentials:
          token: "secret://GITHUB_TOKEN"

The manifest supplies: url, allowed_urls, allowed_methods, tags, and the
per-tool security metadata (which tools carry sensitive/external_write tags,
which tools trigger scan_tool_result). The operator only needs to supply
credentials and optionally override any field.

Manifests ship inside the shai package under harness/connectors/manifests/.
Each connector is a YAML file named <connector_id>.yaml.
"""
from __future__ import annotations

import importlib.resources
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


# ── Manifest schema ────────────────────────────────────────────────────────

class ConnectorToolSpec(BaseModel, frozen=True):
    """Security metadata for one tool exposed by the connector."""
    name:        str
    tags:        list[str]         = Field(default_factory=list)
    action:      str               = "allow"   # allow | block | alert
    description: str               = ""


class ConnectorManifest(BaseModel, frozen=True):
    """Pre-built security configuration for a well-known MCP server.

    Fields map directly to SourceConfig — the manifest is merged with
    any operator overrides declared alongside `connector:` in harness.yaml.

    scan_tool_result_on lists tool names that should have scan_tool_result
    applied to their output — these are tools that return external content
    that may contain indirect injection payloads.
    """
    id:                  str
    display_name:        str
    categories:          list[str]          = Field(default_factory=list)
    url:                 str
    allowed_urls:        list[str]          = Field(default_factory=list)
    allowed_methods:     list[str]          = Field(default_factory=lambda: ["GET", "POST"])
    tags:                list[str]          = Field(default_factory=list)
    tools:               list[ConnectorToolSpec] = Field(default_factory=list)
    scan_tool_result_on: list[str]          = Field(default_factory=list)
    auth:                dict[str, Any]     = Field(default_factory=dict)
    required:            bool               = True
    notes:               str                = ""


# ── Manifest registry ──────────────────────────────────────────────────────

_MANIFESTS_DIR = Path(__file__).parent / "manifests"


@lru_cache(maxsize=None)
def load_manifest(connector_id: str) -> ConnectorManifest:
    """Load and validate a connector manifest by id.

    Raises ValueError if the connector is not found.
    Results are cached — manifests are immutable at runtime.
    """
    path = _MANIFESTS_DIR / f"{connector_id}.yaml"
    if not path.exists():
        available = [p.stem for p in _MANIFESTS_DIR.glob("*.yaml")]
        raise ValueError(
            f"Unknown connector '{connector_id}'. "
            f"Available: {sorted(available)}"
        )
    with path.open() as f:
        data = yaml.safe_load(f)
    return ConnectorManifest.model_validate(data)


def list_connectors() -> list[str]:
    """Return all available connector ids."""
    if not _MANIFESTS_DIR.exists():
        return []
    return sorted(p.stem for p in _MANIFESTS_DIR.glob("*.yaml"))


def manifest_to_source_config_fields(
    manifest: ConnectorManifest,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Merge a manifest with operator overrides into SourceConfig fields.

    The operator can override any manifest field by declaring it alongside
    `connector:` in harness.yaml. Credentials are always operator-supplied.

    Returns a dict suitable for SourceConfig.model_validate().
    """
    fields: dict[str, Any] = {
        "transport":      "mcp",
        "url":            manifest.url,
        "allowed_urls":   manifest.allowed_urls,
        "allowed_methods": manifest.allowed_methods,
        "tags":           manifest.tags,
        "required":       manifest.required,
    }
    # Operator overrides take precedence
    fields.update({k: v for k, v in overrides.items() if v is not None})
    return fields
