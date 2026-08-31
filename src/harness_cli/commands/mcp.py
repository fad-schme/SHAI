"""shai mcp onboard — parse, connect, scan, and decide on one MCP manifest.

  shai mcp onboard <path-to-manifest> --config <harness.yaml>

The only path to approving an MCP manifest: a clean pass auto-records the
manifest's hash into the signed baseline store (harness.mcp.baseline). A
source declared under `sources:` (transport: mcp) with no approved manifest
is never built at all — this command is what gets it connected and its
tools registered on the harness's next start. Once built, the baseline is
also what the gate checks on every check_tool_call for that source
(harness.mcp.gate.McpBaselineGate), so a manifest edited after startup
denies further calls without needing a restart. See harness.mcp.onboard for
the full pipeline.
"""
from __future__ import annotations

import argparse
import asyncio

from harness.core.errors import ConfigError, HarnessError, MCPInvocationError
from harness_cli.console import console


async def _run(args: argparse.Namespace) -> int:
    from harness.config.loader import build_secrets_provider, load_dict, read_yaml
    from harness.core import wiring
    from harness.core.errors import AuditEmissionError

    try:
        raw = read_yaml(args.config)
        provider = build_secrets_provider(raw.get("secrets"))
        config = load_dict(raw, provider=provider, source=str(args.config))
    except (ConfigError, ValueError) as e:
        console.error(f"error: {e}")
        return 1

    if not config.mcp_baseline.secret:
        console.error(
            "error: mcp_baseline.secret is not set in "
            f"{args.config} — required to record an onboarding approval"
        )
        return 1

    sinks = wiring._build_sinks(config.audit_sinks)
    signing_secret = (
        config.audit_signing.secret.encode() if config.audit_signing.enabled else None
    )
    from harness.audit.emitter import AuditEmitter
    emitter = AuditEmitter(sinks, signing_secret=signing_secret)

    from harness.mcp.onboard import run_onboarding

    try:
        result = await run_onboarding(
            args.manifest, config=config, provider=provider, emitter=emitter,
        )
    except (ConfigError, MCPInvocationError, HarnessError) as e:
        console.error(f"error: {e}")
        return 1
    except AuditEmissionError as e:
        console.error(f"error: could not record onboarding decision: {e}")
        return 1

    console.write(f"manifest:   {result.manifest_id}")
    console.write(f"file_hash:  {result.file_hash}")
    console.write(f"findings:   {len(result.finding_categories)}"
                  + (f"  categories={result.finding_categories}" if result.finding_categories else ""))
    if result.max_severity:
        console.write(f"max_severity: {result.max_severity}")
    rec = result.reconciliation
    if rec.absent:
        console.write(f"warning: declared tool(s) not live: {rec.absent}")
    if rec.undeclared:
        console.write(f"info: live tool(s) not declared (never registered): {rec.undeclared}")
    if rec.description_mismatches:
        console.error(f"reconciliation mismatch: {rec.description_mismatches}")
    console.write(f"readiness:  {result.readiness['score']}/100")
    console.write(f"protocol:   {result.protocol_posture}")

    if result.passed:
        console.write(f"PASS — baseline recorded for '{result.manifest_id}'")
        return 0

    console.error(f"FAIL — '{result.manifest_id}' not approved; nothing recorded")
    return 1


def cmd_mcp_onboard(args: argparse.Namespace) -> int:
    return asyncio.run(_run(args))
