"""Security: dispatch token signing and validation.

Documents and tests the HMAC-SHA256 token interface described in
docs/connectivity.md. The token is not yet issued by the harness
(planned for harness-connectivity), but the signing logic is defined
here and tested independently.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

import pytest


# ── Reference implementation (from docs/connectivity.md) ─────────────────

SECRET = b"test-shared-secret-not-for-production"


def _sign(payload: dict, secret: bytes) -> str:
    body = json.dumps(payload, sort_keys=True).encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def make_token(
    agent_id: str,
    tool_name: str,
    allowed_destinations: list[str],
    *,
    sub_agent_id: str | None = None,
    ttl_seconds: int = 10,
    secret: bytes = SECRET,
) -> dict:
    payload = {
        "agent_id": agent_id,
        "sub_agent_id": sub_agent_id,
        "tool_name": tool_name,
        "allowed_destinations": allowed_destinations,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "ttl_seconds": ttl_seconds,
    }
    payload["signature"] = _sign({k: v for k, v in payload.items()}, secret)
    return payload


def verify_token(token: dict, secret: bytes = SECRET) -> tuple[bool, str]:
    """Return (valid, reason). reason is non-empty on failure."""
    try:
        token = dict(token)
        sig = token.pop("signature", None)
        if not sig:
            return False, "missing signature"

        expected = _sign(token, secret)
        if not hmac.compare_digest(sig, expected):
            return False, "signature mismatch"

        issued = datetime.fromisoformat(token["issued_at"])
        age = (datetime.now(timezone.utc) - issued).total_seconds()
        if age > token["ttl_seconds"]:
            return False, f"token expired (age={age:.1f}s ttl={token['ttl_seconds']}s)"

        return True, ""
    except Exception as e:
        return False, str(e)


# ── Tests ─────────────────────────────────────────────────────────────────

def test_valid_token_verifies():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    valid, reason = verify_token(token)
    assert valid, reason


def test_token_carries_correct_fields():
    token = make_token(
        "orchestrator", "search_docs",
        ["https://docs.internal"],
        sub_agent_id="research_sub",
        ttl_seconds=15,
    )
    assert token["agent_id"] == "orchestrator"
    assert token["sub_agent_id"] == "research_sub"
    assert token["tool_name"] == "search_docs"
    assert token["ttl_seconds"] == 15
    assert "issued_at" in token
    assert "signature" in token


def test_tampered_agent_id_rejected():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    token["agent_id"] = "attacker"
    valid, reason = verify_token(token)
    assert not valid
    assert "mismatch" in reason


def test_tampered_tool_name_rejected():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    token["tool_name"] = "send_email"
    valid, reason = verify_token(token)
    assert not valid


def test_tampered_destinations_rejected():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    token["allowed_destinations"] = ["https://evil.example.com"]
    valid, reason = verify_token(token)
    assert not valid


def test_missing_signature_rejected():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    del token["signature"]
    valid, reason = verify_token(token)
    assert not valid
    assert "missing" in reason


def test_wrong_secret_rejected():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"],
                        secret=b"correct-secret")
    valid, reason = verify_token(token, secret=b"wrong-secret")
    assert not valid


def test_expired_token_rejected():
    """Token with ttl_seconds=0 is immediately expired."""
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"],
                        ttl_seconds=0)
    # Sleep 0.01s to ensure age > 0
    time.sleep(0.01)
    valid, reason = verify_token(token)
    assert not valid
    assert "expired" in reason


def test_hmac_timing_safe():
    """Signature comparison must use hmac.compare_digest, not ==."""
    import inspect
    src = inspect.getsource(verify_token)
    assert "hmac.compare_digest" in src, \
        "verify_token must use hmac.compare_digest to prevent timing attacks"


def test_token_is_json_serialisable():
    token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    serialised = json.dumps(token)
    assert len(serialised) > 0


def test_subagent_token_distinct_from_parent():
    """A subagent token must have sub_agent_id set and a different signature."""
    parent_token = make_token("orchestrator", "search_docs", ["https://docs.internal"])
    child_token  = make_token("orchestrator", "search_docs", ["https://docs.internal"],
                               sub_agent_id="research_sub")
    assert parent_token["signature"] != child_token["signature"]
    assert child_token["sub_agent_id"] == "research_sub"
    assert parent_token.get("sub_agent_id") is None


def test_allowed_destinations_scope_is_per_token():
    """Each token scopes exactly which destinations the tool may reach."""
    token_a = make_token("orchestrator", "fetch_doc",
                          ["https://docs.internal", "https://api.internal"])
    token_b = make_token("orchestrator", "fetch_doc", ["https://docs.internal"])

    assert token_a["signature"] != token_b["signature"]
    assert len(token_a["allowed_destinations"]) == 2
    assert len(token_b["allowed_destinations"]) == 1
