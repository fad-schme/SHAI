"""SHAI connectivity layer.

Phase 1: Token issuance
  DispatchToken, sign_token, verify_token, encode_token — dispatch token
  ConnectivityConfig — harness.yaml connectivity: block

Phase 2: In-process egress enforcement
  ShaiTransport      — httpx transport hook, wired into MCPSource
  NetworkAuditEvent  — audit event emitted per outbound tool call
"""
from harness.connectivity.config import ConnectivityConfig
from harness.connectivity.token import (
    DispatchToken,
    TokenError,
    default_allowed_urls,
    encode_token,
    matches_allowed_url,
    sign_token,
    verify_token,
)
from harness.connectivity.transport import NetworkAuditEvent, ShaiTransport

__all__ = [
    "ConnectivityConfig",
    "DispatchToken",
    "TokenError",
    "default_allowed_urls",
    "encode_token",
    "matches_allowed_url",
    "sign_token",
    "verify_token",
    "NetworkAuditEvent",
    "ShaiTransport",
]
