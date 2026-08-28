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
nonce store keys on token_id to prevent replay within the TTL window.
"""
from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

from harness.connectivity.scope import canonicalize_host
from harness.core.signing import claims_of, decode, encode, sign

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

@lru_cache(maxsize=512)
def _canonicalize_url(url: str) -> str | None:
    """Rebuild url with its host canonicalized, leaving scheme, port, path,
    query, and fragment untouched — so the prefix/exact matching below keeps
    comparing what it always compared, on everything except the host.

    Returns None (deny) if the host fails to canonicalize (see
    canonicalize_host) or the URL carries a malformed port.

    Cached: matches_allowed_url calls this on the same small set of
    allowlist patterns on every dispatch, same rationale as
    connectivity.scope._parse_network caching CIDR parses.
    """
    canonical_host = canonicalize_host(url)
    if canonical_host is None:
        return None

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None

    netloc_host = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    netloc = f"{netloc_host}:{port}" if port is not None else netloc_host
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def matches_allowed_url(url: str, patterns: list[str]) -> bool:
    """Return True if url matches any pattern in patterns.

    Patterns use suffix wildcard only: "https://slack.com/api/*"
    matches any URL starting with "https://slack.com/api/".
    Exact match (no wildcard) is also supported.

    Both url and each pattern have their host canonicalized before
    comparison (lowercased, IDNA-encoded, IP-literal forms normalized) so
    a case or encoding difference that resolves to the same destination
    isn't judged as a mismatch — see connectivity.scope.canonicalize_host.
    A url whose host fails to canonicalize is denied outright; it never
    falls back to a raw-string comparison. A pattern that fails to
    canonicalize is skipped, not treated as a wildcard match.

    An empty patterns list → False (no destinations allowed).
    """
    canonical_url = _canonicalize_url(url)
    if canonical_url is None:
        return False

    for pattern in patterns:
        canonical_pattern = _canonicalize_url(pattern)
        if canonical_pattern is None:
            continue
        if canonical_pattern.endswith("/*"):
            prefix = canonical_pattern[:-1]   # strip the *
            if canonical_url.startswith(prefix):
                return True
        elif canonical_url == canonical_pattern:
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
#
# Envelope mechanics — canonical encoding, HMAC, base64url, expiry — live in
# harness.core.signing and are shared with the approval grant. Only the field
# set and the error type are this module's.

# The signed field set, declared once. Signing, encoding, and verification all
# derive from this — three hand-maintained copies had to agree exactly or
# signatures silently stopped verifying, which is the failure `canonical_json`
# was introduced to end for audit events.
_SIGNED_FIELDS: tuple[str, ...] = (
    "version", "token_id", "agent_id", "sub_agent_id", "tenant_id",
    "tool_name", "source_name", "allowed_urls", "allowed_methods",
    "issued_at", "expires_at",
)


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

    # Frozen dataclass — replace rather than mutate.
    return dataclasses.replace(
        token, signature=sign(claims_of(token, _SIGNED_FIELDS), secret)
    )


def encode_token(token: DispatchToken) -> str:
    """Encode a DispatchToken to a base64url string for the X-Shai-Token header."""
    return encode(claims_of(token, _SIGNED_FIELDS), token.signature)


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
    data = decode(
        encoded,
        secret=secret,
        fields=_SIGNED_FIELDS,
        error=TokenError,
        noun="token",
        # Carries into the transport's deny_reason, which is where an expired
        # token is correlated back to the gate event that issued it.
        id_field="token_id",
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
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        signature=data["signature"],
    )
