"""Integration test — from_yaml() with an MCP source no longer crashes.

Regression test for the NameError where lines 269-271 in harness.py
referenced `instance._mcp_metadata_scanners` before `instance` was
constructed. The fix uses local variables that hold the same values.

The MCP source won't connect during construction — MCPSource._connect()
is lazy — so no mock server is needed.
"""
from __future__ import annotations

from pathlib import Path

import pytest


async def test_from_yaml_with_mcp_source_does_not_crash(tmp_path: Path):
    """from_yaml() completes when harness.yaml declares an MCP source."""
    cfg = tmp_path / "harness.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n"
        "  enabled: false\n"
        "scan_output:\n"
        "  enabled: false\n"
        "policy:\n"
        "  rules: []\n"
        "audit_sinks:\n"
        "  - name: stdout\n"
        "sources:\n"
        "  - name: test_mcp\n"
        "    transport: mcp\n"
        "    url: http://localhost:9999/mcp\n"
        "    tags:\n"
        "      - external\n"
    )

    from harness.core.harness import SHAI

    # This used to raise NameError: name 'instance' is not defined
    harness = await SHAI.from_yaml(cfg)

    # Verify the source was registered
    source = await harness.get_source("test_mcp")
    assert source.name == "test_mcp"

    # Verify MCP metadata scanner config was wired correctly
    assert source._scan_mcp_metadata_enabled is True
    assert len(source._mcp_metadata_scanners) > 0  # default mcp_metadata_scan

    await harness.close()
