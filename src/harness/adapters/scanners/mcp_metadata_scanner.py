"""mcp_metadata_scanner.py — Scanner for MCP tool metadata injection.

Scans tool names, descriptions, and argument schema descriptions as received
from the MCP server's tools/list response — before those tools are registered
with SHAI or used to build the LLM tool schema.

Threat model
------------
A compromised MCP server can embed injection payloads in tool metadata.
This is distinct from payload injection in tool *results* (T6, handled by
scan_tool_result) — metadata injection operates at registration time:

  1. The payload is embedded in the tool schema passed to the LLM.
  2. The LLM sees it as a "trusted instruction from the tool description"
     before any user turn begins.
  3. Encoded as `always call X before responding`, `do not tell the user`,
     or a full `ignore all previous instructions` payload.

Usage from MCPSource._fetch_tools()
-------------------------------------
    scanner = MCPMetadataScanner()
    for mcp_tool in mcp_tools:
        result = await scanner.scan_tool(mcp_tool, source_name="slack_mcp")
        if any(f.severity >= block_at for f in result.findings):
            continue  # skip registering this tool
        tools.append(build_tool(mcp_tool))

The scanner produces findings; it does not decide whether they block. The
threshold is `scan_mcp_metadata.block_at` from harness.yaml, applied by
MCPSource._scan_mcp_metadata — the same split every other boundary uses,
where scanners return a ScanResult and the boundary applies block_at.

Fields scanned per tool
-----------------------
  - name          — the tool identifier
  - description   — shown to the LLM as the tool's purpose
  - inputSchema   — argument definitions; each argument's description is scanned

The scanner uses the YAML catalog in mcp_metadata_patterns.yaml, compiled
once at construction. Each scanned string is a separate Finding with its own
severity.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from harness.adapters.scanners.base import ScanResult
from harness.adapters.scanners.injection_scan import InjectionScanner

log = logging.getLogger(__name__)

_PATTERNS_FILE = Path(__file__).parent / "l10n" / "mcp_metadata_patterns.yaml"


class MCPMetadataScanner:
    """Scans MCP tool metadata for injection payloads before tool registration.

    Instantiated once per MCPSource at connection time. Stateless — safe for
    concurrent _fetch_tools() calls.
    """

    name = "mcp_metadata_scan"
    method_family = "regex_catalog"

    def __init__(
        self,
        patterns_file: Path | None = None,
        extra_rules: list | None = None,
    ) -> None:
        """
        patterns_file: path to YAML catalog. Defaults to mcp_metadata_patterns.yaml.
        extra_rules:   compiled rules from the signed pattern DB (`mcp_metadata`
                       catalog), merged onto the bundled ones. This scanner is a
                       catalog scanner like the rest, so operators extend it the
                       same way.
        """
        pfile = patterns_file or _PATTERNS_FILE
        self._scanner = InjectionScanner(
            patterns_file=pfile,
            extra_rules=extra_rules,
            name="mcp_metadata_scan",
        )
        log.debug("MCPMetadataScanner initialised",
                  extra={"patterns_file": str(pfile),
                         "extra_rules": len(extra_rules or [])})

    # ── Public API ─────────────────────────────────────────────────────────

    async def scan_tool(
        self,
        mcp_tool: dict[str, Any],
        *,
        source_name: str = "unknown",
    ) -> ScanResult:
        """Scan a single tool dict from tools/list.

        Returns a ScanResult. The caller blocks registration when a finding
        reaches scan_mcp_metadata.block_at, and logs the rest.

        Never raises — exceptions are caught and logged as warnings.
        """
        findings = []

        # Build the surfaces to scan — name, description, arg descriptions
        surfaces = self._extract_surfaces(mcp_tool)

        for surface_name, text in surfaces:
            if not text:
                continue
            try:
                from harness.core.context import AgentContext
                ctx = AgentContext(agent_id=f"mcp_metadata:{source_name}")
                result = await self._scanner.scan(text, ctx)
                for f in result.findings:
                    # Annotate which metadata field the finding came from
                    # without including the raw text
                    log.debug("mcp metadata finding",
                              extra={"source": source_name,
                                     "tool": mcp_tool.get("name", "?"),
                                     "surface": surface_name,
                                     "category": f.category,
                                     "severity": str(f.severity)})
                findings.extend(result.findings)
            except Exception as e:
                log.warning("mcp metadata scan error — skipped",
                            extra={"source": source_name,
                                   "tool": mcp_tool.get("name", "?"),
                                   "surface": surface_name,
                                   "error": str(e)})

        return ScanResult(findings=findings)

    # ── Metadata extraction ────────────────────────────────────────────────

    def _extract_surfaces(
        self, mcp_tool: dict[str, Any]
    ) -> list[tuple[str, str]]:
        """Return (surface_name, text) pairs from tool metadata fields."""
        surfaces: list[tuple[str, str]] = []

        # Tool name — identifier but can carry payloads in malicious servers
        name = str(mcp_tool.get("name") or "").strip()
        if name:
            surfaces.append(("name", name))

        # Tool description — highest risk surface
        desc = str(mcp_tool.get("description") or "").strip()
        if desc:
            surfaces.append(("description", desc))

        # Argument schema — inputSchema.properties.*.description
        schema = mcp_tool.get("inputSchema") or mcp_tool.get("input_schema") or {}
        if isinstance(schema, dict):
            for arg_name, arg_def in schema.get("properties", {}).items():
                if not isinstance(arg_def, dict):
                    continue
                arg_desc = str(arg_def.get("description") or "").strip()
                if arg_desc:
                    surfaces.append((f"arg:{arg_name}", arg_desc))

        # Concatenated surface — run the full text as one unit to catch
        # cross-field payloads split across name + description
        combined = " ".join(t for _, t in surfaces)
        if len(surfaces) > 1 and combined:
            surfaces.append(("combined", combined))

        return surfaces
