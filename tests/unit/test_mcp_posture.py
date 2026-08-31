"""Tests for harness.mcp.posture.protocol_posture()."""
from __future__ import annotations

from harness.mcp.manifest import MCPManifest
from harness.mcp.posture import protocol_posture


def _manifest(url: str, credentials: dict | None = None) -> MCPManifest:
    return MCPManifest(
        id="svc", display_name="Service", url=url,
        credentials=credentials or {},
    )


def test_https_scheme_reported():
    posture = protocol_posture(_manifest("https://mcp.example.test/sse"))
    assert posture["scheme"] == "https"


def test_http_scheme_reported():
    posture = protocol_posture(_manifest("http://mcp.example.test/sse"))
    assert posture["scheme"] == "http"


def test_credentials_configured_true():
    posture = protocol_posture(_manifest(
        "https://mcp.example.test/sse", credentials={"token": "secret://X"}
    ))
    assert posture["credentials_configured"] is True


def test_credentials_configured_false():
    posture = protocol_posture(_manifest("https://mcp.example.test/sse"))
    assert posture["credentials_configured"] is False
