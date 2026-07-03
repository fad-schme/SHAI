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
        finding = await scanner.scan_tool(mcp_tool, source_name="slack_mcp")
        if finding:
            log.warning("mcp tool blocked — metadata injection detected",
                        extra={"tool": mcp_tool["name"], "finding": finding})
            continue  # skip registering this tool
        tools.append(build_tool(mcp_tool))

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

import json
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

    def __init__(
        self,
        patterns_file: Path | None = None,
        block_at_severity: str = "medium",
    ) -> None:
        """
        patterns_file: path to YAML catalog. Defaults to mcp_metadata_patterns.yaml.
        block_at_severity: 'low' | 'medium' | 'high'. Findings at or above this
            severity cause the tool to be blocked from registration.
            Default: 'medium' — conservative for metadata (almost no legitimate
            content looks like an injection in tool descriptions).
        """
        pfile = patterns_file or _PATTERNS_FILE
        self._scanner = InjectionScanner(
            patterns_file=pfile,
            name="mcp_metadata_scan",
        )
        self._block_severities = self._severities_at_or_above(block_at_severity)
        log.debug("MCPMetadataScanner initialised",
                  extra={"patterns_file": str(pfile),
                         "block_at": block_at_severity})

    # ── Public API ─────────────────────────────────────────────────────────

    async def scan_tool(
        self,
        mcp_tool: dict[str, Any],
        *,
        source_name: str = "unknown",
    ) -> ScanResult:
        """Scan a single tool dict from tools/list.

        Returns a ScanResult. The caller should:
          - block registration if result.findings contains any finding at
            or above block_at_severity
          - log all findings regardless of block decision

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

    def should_block(self, result: ScanResult) -> bool:
        """Return True if any finding meets or exceeds block_at_severity."""
        from harness.core.types import Severity
        return any(
            f.severity in self._block_severities
            for f in result.findings
        )

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

    @staticmethod
    def _severities_at_or_above(threshold: str) -> frozenset:
        """Return the set of Severity values at or above threshold."""
        from harness.core.types import Severity
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH]
        names = {s.value if hasattr(s, "value") else str(s): s for s in order}
        threshold_sev = names.get(threshold.lower(), Severity.MEDIUM)
        idx = order.index(threshold_sev)
        return frozenset(order[idx:])
