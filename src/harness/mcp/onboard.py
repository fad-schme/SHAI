"""mcp/onboard.py — `shai mcp onboard <manifest> --config <harness.yaml>`.

One run: parse/validate the manifest → connect live and fetch tools/list →
scan the manifest's own declared tool text (MCPMetadataScanner +
PromptDefenseScanner) → tool reconciliation against the live response →
aggregate into exactly one AuditEvent(boundary=MCP_SOURCE_ONBOARDING) →
on a clean pass, auto-record the baseline (harness.mcp.baseline) — running
the command *is* the operator's trust action, no separate flag.

Readiness (harness.mcp.readiness) and protocol posture (harness.mcp.posture)
ride along on the same event as pure governance signal — see the assertion
in _decide() that neither participates in the pass/fail decision.

Failure before scanning (manifest not found/invalid, connection or
tools/list failure) raises ConfigError/MCPInvocationError and is not
recorded here — there is nothing to scan yet, so no audit event is emitted
for it (the CLI reports the error and exits non-zero).
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel

from harness.adapters.scanners.mcp_metadata_scanner import MCPMetadataScanner
from harness.adapters.scanners.prompt_defense_scanner import PromptDefenseScanner
from harness.core.context import AgentContext
from harness.core.events import AuditEvent, now_ms
from harness.core.types import BoundaryName, Decision, Severity
from harness.core.verdicts import Finding
from harness.mcp.baseline import record_baseline
from harness.mcp.manifest import (
    MCPManifest,
    load_manifest_file,
    manifest_file_hash,
    resolve_manifest_credentials,
)
from harness.mcp.posture import protocol_posture
from harness.mcp.readiness import score_readiness
from harness.mcp.reconciliation import ReconciliationResult, reconcile
from harness.tools.source import MCPSource, MCPSourceParams

if TYPE_CHECKING:
    from harness.adapters.secrets.env import SecretsProvider
    from harness.audit.emitter import AuditEmitter
    from harness.config.schema import HarnessConfig

ONBOARD_AGENT_ID_PREFIX = "mcp_onboard"


class OnboardResult(BaseModel, frozen=True):
    """What `shai mcp onboard` decided — returned for the CLI to render and
    for tests to assert on directly, independent of the emitted AuditEvent.
    """
    passed:              bool
    manifest_id:         str
    file_hash:            str
    finding_categories:   list[str] = []
    max_severity:         Severity | None = None
    reconciliation:       ReconciliationResult
    readiness:            dict
    protocol_posture:     dict
    baseline_recorded:    bool = False


async def _fetch_live_tools(manifest: MCPManifest, *, provider: SecretsProvider | None) -> list[dict]:
    """Connect to the manifest's url and return the raw tools/list response.

    Reuses MCPSource's own connect/JSON-RPC machinery rather than
    reimplementing the protocol — this is a real connection, made and torn
    down once, never registered with a SourceRegistry.
    """
    credentials = resolve_manifest_credentials(manifest, provider=provider)
    params = MCPSourceParams(
        manifest.id, manifest.url,
        credentials=credentials,
        allowed_urls=manifest.allowed_urls,
        allowed_methods=manifest.allowed_methods,
    )
    source = MCPSource(params)
    try:
        await source._connect()
        response = await source._post({
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": "tools/list",
            "params": {},
        })
        source._check_jsonrpc_error(response, "tools/list")
        return response.get("result", {}).get("tools", [])
    finally:
        await source.close()


async def _scan_declared_tools(manifest: MCPManifest) -> list[Finding]:
    """Scan the manifest's own declared tool name/description — never the
    live response (Invariant: manifest is authoritative for what's judged)."""
    metadata_scanner = MCPMetadataScanner()
    defense_scanner = PromptDefenseScanner()

    findings: list[Finding] = []
    for tool in manifest.tools:
        tool_dict = {"name": tool.name, "description": tool.description}
        metadata_result = await metadata_scanner.scan_tool(tool_dict, source_name=manifest.id)
        defense_result = await defense_scanner.scan_tool(tool_dict, source_name=manifest.id)
        findings.extend(metadata_result.findings)
        findings.extend(defense_result.findings)
    return findings


def _decide(
    findings: list[Finding],
    reconciliation: ReconciliationResult,
    *,
    block_at: Severity,
) -> bool:
    """True if onboarding passes. Readiness and protocol posture never reach
    this function — they are informational only, attached to the audit event
    separately and never consulted here."""
    scanner_blocked = any(f.severity >= block_at for f in findings)
    return not scanner_blocked and not reconciliation.fails_onboarding


async def run_onboarding(
    manifest_path: str | Path,
    *,
    config: HarnessConfig,
    provider: SecretsProvider | None,
    emitter: AuditEmitter,
) -> OnboardResult:
    """Run one onboarding pass. Raises ConfigError / MCPInvocationError for
    everything before the scan step (manifest parse, connect, tools/list) —
    those are not recorded as an audit event; there is nothing to scan yet.
    """
    start = now_ms()
    manifest = load_manifest_file(manifest_path)
    file_hash = manifest_file_hash(manifest_path)

    live_tools = await _fetch_live_tools(manifest, provider=provider)

    findings = await _scan_declared_tools(manifest)
    reconciliation = reconcile(manifest, live_tools)
    readiness = score_readiness(manifest)
    posture = protocol_posture(manifest)

    block_at = config.scan_mcp_metadata.block_at
    passed = _decide(findings, reconciliation, block_at=block_at)

    max_severity = max((f.severity for f in findings), key=lambda s: s._index()) if findings else None
    finding_categories = sorted({f.category for f in findings})

    deny_reason = None
    if not passed:
        reasons = []
        if any(f.severity >= block_at for f in findings):
            reasons.append(f"scanner finding(s) reached block_at={block_at}")
        if reconciliation.fails_onboarding:
            reasons.append("tool description reconciliation mismatch")
        deny_reason = "mcp onboarding refused: " + "; ".join(reasons)

    decision = (
        Decision.BLOCKED if not passed
        else Decision.WARN if findings
        else Decision.ALLOW
    )

    ctx = AgentContext(agent_id=f"{ONBOARD_AGENT_ID_PREFIX}:{manifest.id}")
    await emitter.emit(AuditEvent.build(
        boundary=BoundaryName.MCP_SOURCE_ONBOARDING,
        decision=decision,
        ctx=ctx,
        tenant_id=config.tenant_id,
        duration_ms=now_ms() - start,
        adapters=[MCPMetadataScanner.name, PromptDefenseScanner.name],
        finding_count=len(findings),
        max_severity=max_severity,
        deny_reason=deny_reason,
        extra={
            "manifest_id": manifest.id,
            "file_hash": file_hash,
            "finding_categories": finding_categories,
            "reconciliation": {
                "absent": reconciliation.absent,
                "undeclared": reconciliation.undeclared,
                "description_mismatches": reconciliation.description_mismatches,
            },
            "readiness": readiness,
            "protocol_posture": posture,
        },
    ))

    baseline_recorded = False
    if passed:
        record_baseline(
            config.mcp_baseline.path, manifest.id, file_hash,
            config.mcp_baseline.secret.encode(),
        )
        baseline_recorded = True

    return OnboardResult(
        passed=passed,
        manifest_id=manifest.id,
        file_hash=file_hash,
        finding_categories=finding_categories,
        max_severity=max_severity,
        reconciliation=reconciliation,
        readiness=readiness,
        protocol_posture=posture,
        baseline_recorded=baseline_recorded,
    )
