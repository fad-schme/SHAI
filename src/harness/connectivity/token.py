"""Dispatch token — signed assertion that SHAI authorised a tool call.

Issued by check_tool_call() on every GateDecision(allowed=True) when
connectivity.enabled=True. Carried on outbound requests as the
X-Shai-Token header. Validated by ShaiTransport before forwarding.

Format: base64url-encoded JSON — no external library dependency.
Signature: HMAC-SHA256 over all payload fields (sort_keys=True).

The token is not a bearer credential. It does not grant access to the
destination directly. It is a signed, time-limited assertion that:
  - agent {agent_id} in tenant {tenant_id}
  - was granted permission to call tool {tool_name} from source {source_name}
  - and may reach {allowed_urls} using {allowed_methods}
  - before {expires_at}

token_id is a UUID that acts as both identifier and nonce. The ShaiTransport
nonce store (Phase 2+) keys on token_id to prevent replay within the TTL window.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

# ── Token dataclass ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class DispatchToken:
    """Signed, time-limited authorisation token for one tool call.

    All fields except signature are included in the HMAC payload.
    signature is computed over all other fields and appended.
    """
    version:         int              # always 1 — allows future format migration
    token_id:        str              # UUID v4 — unique per gate decision, acts as nonce
    agent_id:        str
    sub_agent_id:    str | None
    tenant_id:       str
    tool_name:       str
    source_name:     str              # which MCPSource owns this tool
    allowed_urls:    list[str]        # URL prefix patterns — e.g. ["https://slack.com/api/*"]
    allowed_methods: list[str]        # HTTP methods — e.g. ["GET", "POST"]
    issued_at:       datetime
    expires_at:      datetime
    signature:       str              # HMAC-SHA256 hex digest — always last field


# ── URL matching ────────────────────────────────────────────────────────────

def matches_allowed_url(url: str, patterns: list[str]) -> bool:
    """Return True if url matches any pattern in patterns.

    Patterns use suffix wildcard only: "https://slack.com/api/*"
    matches any URL starting with "https://slack.com/api/".
    Exact match (no wildcard) is also supported.

    An empty patterns list → False (no destinations allowed).
    """
    for pattern in patterns:
        if pattern.endswith("/*"):
            prefix = pattern[:-1]   # strip the *
            if url.startswith(prefix):
                return True
        elif url == pattern:
            return True
    return False


def default_allowed_urls(source_url: str) -> list[str]:
    """Derive the default allowed_urls from a source URL.

    https://mcp.slack.com/sse  →  ["https://mcp.slack.com/*"]
    """
    # Strip path — allow anything on the same host/scheme
    from urllib.parse import urlparse
    parsed = urlparse(source_url)
    base = f"{parsed.scheme}://{parsed.netloc}/*"
    return [base]


# ── Signing ────────────────────────────────────────────────────────────────

def _payload(token: DispatchToken) -> bytes:
    """Deterministic JSON of all fields except signature."""
    data: dict[str, Any] = {
        "version":         token.version,
        "token_id":        token.token_id,
        "agent_id":        token.agent_id,
        "sub_agent_id":    token.sub_agent_id,
        "tenant_id":       token.tenant_id,
        "tool_name":       token.tool_name,
        "source_name":     token.source_name,
        "allowed_urls":    token.allowed_urls,
        "allowed_methods": token.allowed_methods,
        "issued_at":       token.issued_at.isoformat(),
        "expires_at":      token.expires_at.isoformat(),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def sign_token(
    *,
    agent_id:        str,
    sub_agent_id:    str | None,
    tenant_id:       str,
    tool_name:       str,
    source_name:     str,
    allowed_urls:    list[str],
    allowed_methods: list[str],
    secret:          bytes,
    ttl_seconds:     int = 15,
) -> DispatchToken:
    """Issue a new signed DispatchToken.

    Args:
        secret: HMAC-SHA256 key — resolved from connectivity.token_secret.
        ttl_seconds: token lifetime. Short by design; default 15s.

    Returns a frozen DispatchToken with signature set.
    """
    now        = datetime.now(UTC)
    token_id   = str(uuid.uuid4())

    token = DispatchToken(
        version=1,
        token_id=token_id,
        agent_id=agent_id,
        sub_agent_id=sub_agent_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        source_name=source_name,
        allowed_urls=list(allowed_urls),
        allowed_methods=list(allowed_methods),
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        signature="",   # placeholder — replaced below
    )

    sig = hmac.new(secret, _payload(token), hashlib.sha256).hexdigest()

    # Return token with real signature (dataclass is frozen — use replace pattern)
    import dataclasses
    return dataclasses.replace(token, signature=sig)


def encode_token(token: DispatchToken) -> str:
    """Encode a DispatchToken to a base64url string for the X-Shai-Token header."""
    data: dict[str, Any] = {
        "version":         token.version,
        "token_id":        token.token_id,
        "agent_id":        token.agent_id,
        "sub_agent_id":    token.sub_agent_id,
        "tenant_id":       token.tenant_id,
        "tool_name":       token.tool_name,
        "source_name":     token.source_name,
        "allowed_urls":    token.allowed_urls,
        "allowed_methods": token.allowed_methods,
        "issued_at":       token.issued_at.isoformat(),
        "expires_at":      token.expires_at.isoformat(),
        "signature":       token.signature,
    }
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


class TokenError(Exception):
    """Raised by verify_token() on any validation failure."""


def verify_token(encoded: str, secret: bytes) -> DispatchToken:
    """Decode and verify a token string from X-Shai-Token.

    Raises TokenError on:
    - malformed base64 or JSON
    - missing required fields
    - HMAC signature mismatch
    - expired token

    Does NOT check nonce uniqueness — that is the transport/gateway's job.
    """
    try:
        raw  = base64.urlsafe_b64decode(encoded.encode() + b"==")
        data = json.loads(raw)
    except Exception as e:
        raise TokenError(f"malformed token: {e}") from e

    required = {
        "version", "token_id", "agent_id", "tenant_id",
        "tool_name", "source_name", "allowed_urls", "allowed_methods",
        "issued_at", "expires_at", "signature",
    }
    missing = required - data.keys()
    if missing:
        raise TokenError(f"token missing fields: {missing}")

    claimed_sig = data.pop("signature")

    # Verify signature over payload without the signature field
    payload_bytes = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    expected_sig  = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, claimed_sig):
        raise TokenError("signature mismatch")

    try:
        issued_at  = datetime.fromisoformat(data["issued_at"])
        expires_at = datetime.fromisoformat(data["expires_at"])
    except ValueError as e:
        raise TokenError(f"invalid datetime field: {e}") from e

    if datetime.now(UTC) > expires_at:
        raise TokenError(
            f"token expired at {expires_at.isoformat()} "
            f"(token_id={data['token_id']})"
        )

    return DispatchToken(
        version=data["version"],
        token_id=data["token_id"],
        agent_id=data["agent_id"],
        sub_agent_id=data.get("sub_agent_id"),
        tenant_id=data["tenant_id"],
        tool_name=data["tool_name"],
        source_name=data["source_name"],
        allowed_urls=data["allowed_urls"],
        allowed_methods=data["allowed_methods"],
        issued_at=issued_at,
        expires_at=expires_at,
        signature=claimed_sig,
    )
