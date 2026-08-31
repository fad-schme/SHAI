"""MCP manifest — the external, user-authored source of truth for one MCP
source's existence, connection, tool set, tool descriptions, and tool policy.

Replaces the old harness.connectors bundled-manifest mechanism: a manifest is
a plain YAML file the operator owns, outside the package. It is never
discovered by scanning a directory — it is declared under `sources:` in
harness.yaml (`transport: mcp`, by name) and resolved by convention at
`<mcp_manifests_dir>/<name>.yaml` (see harness.mcp.discovery). Its raw bytes
are hashed and the hash is what `shai mcp onboard` approves and
harness.mcp.gate.McpBaselineGate checks on every check_tool_call for that
source — not once at startup.

Schema
------
    id: slack
    display_name: "Slack"
    url: "https://mcp.slack.com/sse"
    allowed_urls: ["https://mcp.slack.com/*"]
    allowed_methods: [GET, POST]
    tags: [external_mcp, messaging]
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
    required: true
    tools:
      - name: send_message
        description: "Send a message to a channel or user"
        tags: [external_write, messaging]
        action: block   # enforced — compiles to a deny rule the gate evaluates
                        # ahead of every operator rule (see MCPToolSpec.action)
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

from harness.core.errors import ConfigError


class MCPArgumentSpec(BaseModel, frozen=True, extra="forbid"):
    """Manifest's declared shape for one tool argument — optional, informs
    the readiness heuristic (harness.mcp.readiness) only. Never enforced.
    """
    name: str
    type: str | None = None


class MCPToolSpec(BaseModel, frozen=True, extra="forbid"):
    """Manifest's declared shape for one tool — the authoritative registration
    content once the manifest passes onboarding (see harness.mcp.reconciliation).

    action is the operator's per-tool policy for this tool, and it is
    enforced. There is still exactly one enforcement path: at startup
    `action: block` compiles to an ordinary deny RuleConfig that the existing
    PolicyEngine layer evaluates (harness.mcp.discovery.compile_manifest_rules),
    placed ahead of every operator rule — agent-scoped and global alike — so a
    hash-approved manifest denial cannot be weakened by a local rule.
    `action: allow` compiles to no rule at all: it is the absence of a
    restriction, not an affirmative grant, so an operator rule denying the
    tool still denies. The manifest adds denials; it never removes them.

    arguments/timeout_seconds are optional and purely informational — read
    only by the readiness heuristic (harness.mcp.readiness), never by
    registration or the approval gate.
    """
    name:            str
    description:     str = ""
    tags:            list[str] = Field(default_factory=list)
    action:          Literal["allow", "block"] = "allow"
    arguments:       list[MCPArgumentSpec] = Field(default_factory=list)
    timeout_seconds: int | None = None


class MCPManifest(BaseModel, frozen=True, extra="forbid"):
    """One MCP source, entirely as declared by the operator."""
    id:              str
    display_name:    str
    url:             str
    allowed_urls:    list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=lambda: ["GET", "POST"])
    tags:            list[str] = Field(default_factory=list)
    credentials:     dict[str, str] = Field(default_factory=dict)
    required:        bool = True
    tools:           list[MCPToolSpec] = Field(default_factory=list)


def manifest_file_hash(path: str | Path) -> str:
    """SHA-256 hex digest over the manifest file's raw bytes.

    This, not a parsed/re-serialized form, is what onboarding approves and
    the gate compares on every call — any byte-level change to the file (a
    reordered key, a trailing space) is a change to what was approved.
    """
    data = Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def load_manifest_file(path: str | Path) -> MCPManifest:
    """Parse and validate one manifest file.

    Raises ConfigError naming exactly what's missing or invalid — no
    interactive prompting, no partial/best-effort parse.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"MCP manifest not found: {p}", op="load_manifest")

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in manifest {p}: {e}", op="load_manifest") from e

    if not isinstance(raw, dict):
        raise ConfigError(
            f"manifest {p} must be a YAML mapping, got {type(raw).__name__}",
            op="load_manifest",
        )

    try:
        return MCPManifest.model_validate(raw)
    except ValidationError as e:
        bad = ", ".join(".".join(str(p_) for p_ in err["loc"]) for err in e.errors())
        raise ConfigError(
            f"manifest {p} is missing or has invalid field(s): {bad}",
            op="load_manifest",
        ) from e


def manifest_path_for(name: str, mcp_manifests_dir: str | Path) -> Path:
    """The manifest path a declared `transport: mcp` source resolves to, by
    convention: `<mcp_manifests_dir>/<name>.yaml`. `mcp_manifests_dir` is
    never scanned — a name with no `sources:` entry naming it is invisible
    to the harness, whether or not a file happens to sit here.
    """
    return Path(mcp_manifests_dir) / f"{name}.yaml"


def resolve_manifest_credentials(
    manifest: MCPManifest, *, provider: Any | None
) -> dict[str, str]:
    """Resolve secret:// / ${ENV_VAR} references in a manifest's credentials.

    Manifest files are read straight off disk — outside harness.yaml's own
    load_dict()/load_yaml() resolution pass — so credentials need the same
    two-pass resolution applied explicitly here.
    """
    from harness.config.loader import resolve_secret_refs
    return resolve_secret_refs(dict(manifest.credentials), provider=provider)
