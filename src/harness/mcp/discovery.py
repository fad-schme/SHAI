"""mcp/discovery.py — startup manifest resolution for declared MCP sources.

Called once from SHAI.from_yaml(). An MCP source must be declared under
`sources:` in harness.yaml (`transport: mcp`, by name) — see
`config.schema.SourceConfig`. Its manifest is resolved by convention at
`<mcp_manifests_dir>/<name>.yaml`, parsed, hashed, and checked against the
signed baseline store. Only a name whose current hash matches an approved
baseline record is built into a live `MCPSource`; an unapproved or
hash-mismatched name is not built at all — no `PendingApprovalSource`, no
stub of any kind. An agent that declares that source name later hits
`SourceRegistry`'s ordinary "source not registered" path, honouring the
declared `required` flag exactly as any other missing source does (see
`harness.tools.source.SourceRegistry.activate`).

`harness.mcp.gate.McpBaselineGate` re-checks the baseline on every call for a
source that *was* built — that is what catches a manifest edited after
startup without needing a restart. A manifest that was never onboarded never
reaches that check at all, because no source was built for it in the first
place.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness.agents.agent_config import RuleConfig, RuleMatchConfig
from harness.core.errors import ConfigError
from harness.core.types import Transport
from harness.mcp.baseline import lookup_baseline
from harness.mcp.manifest import (
    MCPManifest,
    load_manifest_file,
    manifest_file_hash,
    manifest_path_for,
    resolve_manifest_credentials,
)
from harness.tools.source import MCPSource, MCPSourceParams

if TYPE_CHECKING:
    from harness.adapters.secrets.env import SecretsProvider
    from harness.audit.emitter import AuditEmitter
    from harness.config.schema import SourceConfig
    from harness.connectivity.config import ConnectivityConfig
    from harness.core.types import ScanAction, Severity

log = logging.getLogger(__name__)


class ResolvedManifest:
    """One declared `transport: mcp` source resolved to a parsed, hashed
    manifest with a matching, approved baseline record — ready to be built
    into a live MCPSource.
    """

    def __init__(self, path: Path, manifest: MCPManifest, file_hash: str) -> None:
        self.path      = path
        self.manifest  = manifest
        self.file_hash = file_hash


def resolve_mcp_sources(
    sources: list[SourceConfig],
    *,
    mcp_manifests_dir: str,
    baseline_path: str | Path,
    baseline_secret: bytes,
) -> list[ResolvedManifest]:
    """Resolve every `transport: mcp` entry in `sources` to its approved
    manifest.

    A declared name with no manifest file at all is a load error — same
    `required` handling as any other missing source (SourceRegistry.activate):
    required=True raises ConfigError immediately, required=False logs and is
    skipped. A manifest that exists but has no matching, approved baseline
    record is neither an error nor built — it is simply omitted from the
    returned list, so a later reference to that source name falls through to
    the ordinary "source not registered" handling instead.

    A manifest whose `id` doesn't match the declared `sources:` name is a
    load error regardless of `required` — the mismatch means the harness
    cannot tell which name the built source would register under.
    """
    out: list[ResolvedManifest] = []
    for src_cfg in sources:
        if src_cfg.transport != Transport.MCP:
            continue

        path = manifest_path_for(src_cfg.name, mcp_manifests_dir)
        if not path.is_file():
            if src_cfg.required:
                raise ConfigError(
                    f"MCP source '{src_cfg.name}' declared with transport: mcp "
                    f"has no manifest at {path}",
                    op="mcp_discovery",
                )
            log.warning(
                "optional MCP source manifest not found — skipped",
                extra={"source": src_cfg.name, "path": str(path)},
            )
            continue

        manifest = load_manifest_file(path)
        if manifest.id != src_cfg.name:
            raise ConfigError(
                f"MCP manifest at {path} declares id '{manifest.id}', "
                f"which does not match sources: entry '{src_cfg.name}'",
                op="mcp_discovery",
            )

        file_hash = manifest_file_hash(path)
        baseline = lookup_baseline(baseline_path, src_cfg.name, baseline_secret)
        if baseline is None or baseline["file_hash"] != file_hash:
            log.info(
                "MCP source has no approved baseline — not built",
                extra={"source": src_cfg.name, "path": str(path)},
            )
            continue

        out.append(ResolvedManifest(path, manifest, file_hash))
    return out


def build_mcp_source(
    resolved: ResolvedManifest,
    *,
    secrets_provider: SecretsProvider | None,
    connectivity: ConnectivityConfig | None,
    emitter: AuditEmitter | None,
    tenant_id: str,
    metadata_scanners: list[Any],
    metadata_enabled: bool,
    metadata_block_at: Severity | None,
    metadata_action: ScanAction | None,
) -> MCPSource:
    """One resolved, approved manifest → a live MCPSource."""
    manifest = resolved.manifest
    credentials = resolve_manifest_credentials(manifest, provider=secrets_provider)
    # `action` is deliberately absent here — it is compiled into policy rules
    # by compile_manifest_rules(), not carried into registration a second time.
    tool_specs = {
        t.name: {"description": t.description, "tags": list(t.tags)}
        for t in manifest.tools
    }
    params = MCPSourceParams(
        manifest.id,
        manifest.url,
        tags=manifest.tags,
        credentials=credentials,
        allowed_urls=manifest.allowed_urls,
        allowed_methods=manifest.allowed_methods,
        tool_specs=tool_specs,
    )
    return MCPSource(
        params,
        connectivity=connectivity,
        emitter=emitter,
        tenant_id=tenant_id,
        metadata_scanners=metadata_scanners,
        metadata_enabled=metadata_enabled,
        metadata_block_at=metadata_block_at,
        metadata_action=metadata_action,
    )


def compile_manifest_rules(manifest: MCPManifest) -> list[RuleConfig]:
    """One manifest's per-tool `action` → policy rules for that source.

    `action: block` becomes a deny RuleConfig; `action: allow` becomes
    nothing. The caller places these ahead of every operator rule for the
    source they came from, and `_evaluate_rules` is first-match-wins — so a
    manifest denial cannot be overridden, while a manifest `allow` leaves an
    operator rule denying the same tool fully in force. Compiling `allow`
    into an allow-rule would invert that: a hash-approved manifest could
    silently un-deny a tool the operator's own policy denies.

    Rules are already scoped to their source by the caller's keying, so the
    match is the tool name alone.
    """
    return [
        RuleConfig(
            id=f"mcp:{manifest.id}:{t.name}",
            match=RuleMatchConfig(tool_names=[t.name]),
            action="deny",
            reason=(
                f"tool '{t.name}' is declared action: block in the "
                f"'{manifest.id}' MCP manifest"
            ),
        )
        for t in manifest.tools
        if t.action == "block"
    ]
