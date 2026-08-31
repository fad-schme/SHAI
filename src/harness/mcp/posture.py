"""mcp/posture.py — protocol posture facts for onboarding's AuditEvent.

Derived entirely from fields already in the manifest — no live network call.
Gives the operator a recorded, informed basis for trusting a server's
posture without SHAI attempting to enforce or fix anything about a
third-party server. Purely informational, like readiness — never part of
the block_at pass/fail decision.

No live unauthenticated-request probing here, deliberately: that carries a
different risk profile (an active request against a third-party server) and
would need its own separate approval.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from harness.mcp.manifest import MCPManifest


def protocol_posture(manifest: MCPManifest) -> dict:
    """{"scheme": "https"|"http"|..., "credentials_configured": bool}."""
    scheme = urlsplit(manifest.url).scheme or None
    return {
        "scheme": scheme,
        "credentials_configured": bool(manifest.credentials),
    }
