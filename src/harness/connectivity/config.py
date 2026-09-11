"""ConnectivityConfig — operator config for the connectivity layer.

Declared in harness.yaml under `connectivity:`, which is required: the layer
is always on. check_tool_call() issues a signed DispatchToken on every allow
decision, every MCP connect-phase request carries a connect token, and every
MCPSource runs its traffic through ShaiTransport, which enforces the
manifest's allowed_urls/allowed_methods, validates tokens and emits
NetworkAuditEvents.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ConnectivityConfig(BaseModel, frozen=True, extra="forbid"):
    """Connectivity layer configuration.

    token_secret:
        HMAC-SHA256 signing key for dispatch tokens. Resolved via secret:// at
        from_yaml() time. Required: every allowed call is minted a token.

    token_ttl_seconds:
        Token lifetime. Short by design — one gate decision, one dispatch.
        Default 15 seconds.

    token_policy:
        What ShaiTransport does with a request that carries no dispatch
        token. Every legitimate request carries one, so an untokened request
        is one SHAI did not authorise.

        strict: refuse it, with a denied NetworkAuditEvent (default)
        audit:  forward it and record an allowed NetworkAuditEvent with no
                token_id, so every untokened request stays visible

    gateway_url:
        Reserved for future sidecar gateway integration. Not used in Phase 1.
    """
    token_secret:       str     = Field(min_length=1)
    token_ttl_seconds:  int     = Field(default=15, ge=1, le=300)
    token_policy:       Literal["strict", "audit"] = "strict"
    gateway_url:        str     = ""   # reserved
