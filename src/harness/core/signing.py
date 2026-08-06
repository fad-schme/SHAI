"""Signed envelope — the one HMAC-SHA256 assertion format SHAI issues.

Two things travel between processes as signed assertions: the dispatch token
that says the gate authorised a call (`connectivity/token.py`) and the approval
grant that says a human authorised one (`core/approval.py`). They are different
claims with the same envelope, and they were built twice — two `_claims`, two
`_canonical`, two sign/encode/verify triples that had to stay byte-identical in
behaviour without sharing a line. A hardening fix landed in one of them.

The envelope is: canonical JSON of the claims, HMAC-SHA256 over exactly those
bytes, base64url of the claims plus the signature. Every envelope is
time-limited — `issued_at` and `expires_at` are part of the format, not of the
individual claim sets.

Callers supply their signed field tuple, their exception type, and a noun for
error messages. What they do not supply is any part of the crypto.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

# Present in every envelope: an assertion with no expiry is a standing licence.
ISSUED_AT = "issued_at"
EXPIRES_AT = "expires_at"
_TIME_FIELDS = (ISSUED_AT, EXPIRES_AT)


def canonical(claims: dict[str, Any]) -> bytes:
    """The one encoding the HMAC covers.

    Signing and verification share it, so an envelope re-encodes byte-for-byte
    to what was signed. Compact separators and sorted keys are load-bearing:
    they make the encoding a function of the claims alone.
    """
    return json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()


def claims_of(obj: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    """Read the signed fields off a frozen dataclass, datetimes as ISO 8601."""
    claims: dict[str, Any] = {f: getattr(obj, f) for f in fields}
    for f in _TIME_FIELDS:
        if f in claims:
            claims[f] = claims[f].isoformat()
    return claims


def sign(claims: dict[str, Any], secret: bytes) -> str:
    """HMAC-SHA256 hex digest over the canonical encoding of the claims."""
    return hmac.new(secret, canonical(claims), hashlib.sha256).hexdigest()


def encode(claims: dict[str, Any], signature: str) -> str:
    """base64url of the claims carrying their signature — the wire form."""
    return base64.urlsafe_b64encode(canonical({**claims, "signature": signature})).decode()


def decode(
    encoded: str,
    *,
    secret: bytes,
    fields: tuple[str, ...],
    error: type[Exception],
    noun: str,
    id_field: str | None = None,
) -> dict[str, Any]:
    """Decode, verify, and return the claims of one envelope.

    Checks in order: well-formed base64/JSON, a JSON object, every signed field
    plus `signature` present, HMAC match, parsable timestamps, not expired.
    Raises `error` on the first failure. Binding — whether this envelope
    authorises *this* call — is the caller's, since only it knows the call.

    `id_field` names the claim carrying the envelope's identifier; when given,
    the expiry message quotes it. That message is the only place the identifier
    reaches the audit trail on this path — the denial is recorded before the
    envelope is trusted enough to read fields off — so a correlatable expiry
    denial depends on it.

    Returns the claims with `issued_at` / `expires_at` as aware datetimes and
    `signature` included, ready to build the caller's dataclass from.
    """
    try:
        raw = base64.urlsafe_b64decode(encoded.encode() + b"==")
        data = json.loads(raw)
    except Exception as e:
        raise error(f"malformed {noun}: {e}") from e

    if not isinstance(data, dict):
        raise error(f"malformed {noun}: not an object")

    missing = (set(fields) | {"signature"}) - data.keys()
    if missing:
        raise error(f"{noun} missing fields: {sorted(missing)}")

    claimed_sig = data.pop("signature")

    # Re-encode whatever remains, not just the fields expected: a field smuggled
    # into the envelope changes the bytes and must fail the comparison.
    if not hmac.compare_digest(sign(data, secret), claimed_sig):
        raise error(f"{noun} signature mismatch")

    try:
        for f in _TIME_FIELDS:
            data[f] = datetime.fromisoformat(data[f])
    except (ValueError, TypeError) as e:
        raise error(f"invalid datetime field: {e}") from e

    if datetime.now(UTC) > data[EXPIRES_AT]:
        ident = f" ({id_field}={data[id_field]})" if id_field else ""
        raise error(f"{noun} expired at {data[EXPIRES_AT].isoformat()}{ident}")

    data["signature"] = claimed_sig
    return data
