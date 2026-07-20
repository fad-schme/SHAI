"""ConnectivityConfig — operator config for the connectivity layer.

Declared in harness.yaml under `connectivity:`. Disabled by default.
When enabled, check_tool_call() issues a signed DispatchToken on every
allow decision. MCPSource.call() attaches the token to outbound requests
via ShaiTransport, which also enforces allowed_urls and emits
NetworkAuditEvents.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator


class ConnectivityConfig(BaseModel, frozen=True, extra="forbid"):
    """Connectivity layer configuration.

    enabled:
        When False (default), no tokens are issued and MCPSource uses the
        default httpx transport. Zero overhead, zero behaviour change.
        When True, token issuance and ShaiTransport enforcement are active.

    token_secret:
        HMAC-SHA256 signing key. Resolved via secret:// at from_yaml() time.
        Required when enabled=True.

    token_ttl_seconds:
        Token lifetime. Short by design — one gate decision, one dispatch.
        Default 15 seconds.

    no_token_policy:
        What ShaiTransport does when a request carries no dispatch token.
        Applies to non-tool-call requests (SSE connection, MCP initialize,
        tools/list) which legitimately have no token.

        strict:    reject requests with no token (use only for tool/call
                   endpoints — not suitable for SSE/init traffic)
        permissive: allow requests with no token (default — SSE and init
                   calls do not carry tokens by design)
        audit_only: allow and log — useful during rollout

    gateway_url:
        Reserved for future sidecar gateway integration. Not used in Phase 1.
    """
    enabled:            bool    = False
    token_secret:       str     = ""
    token_ttl_seconds:  int     = Field(default=15, ge=1, le=300)
    no_token_policy:    Literal["strict", "permissive", "audit_only"] = "permissive"
    gateway_url:        str     = ""   # reserved

    @model_validator(mode="after")
    def _secret_required_when_enabled(self) -> ConnectivityConfig:
        if self.enabled and not self.token_secret:
            raise ValueError(
                "connectivity.token_secret is required when connectivity.enabled=true. "
                "Set it to a secret:// URI resolving to a strong random key."
            )
        return self
