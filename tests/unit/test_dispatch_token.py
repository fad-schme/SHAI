"""Tests for connectivity/token.py — dispatch token issuance and verification."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from harness.connectivity.token import (
    DispatchToken,
    TokenError,
    default_allowed_urls,
    encode_token,
    matches_allowed_url,
    sign_token,
    verify_token,
)

SECRET = b"test-secret-do-not-use-in-production"


# ── Helpers ───────────────────────────────────────────────────────────────

def _token(**overrides) -> DispatchToken:
    defaults = dict(
        agent_id="orchestrator_agent",
        sub_agent_id=None,
        tenant_id="test-tenant",
        tool_name="search_docs",
        source_name="slack_mcp",
        allowed_urls=["https://slack.com/api/*"],
        allowed_methods=["GET", "POST"],
        secret=SECRET,
        ttl_seconds=15,
    )
    defaults.update(overrides)
    return sign_token(**defaults)


# ── sign + encode + verify roundtrip ─────────────────────────────────────

def test_sign_verify_roundtrip():
    tok = _token()
    encoded = encode_token(tok)
    decoded = verify_token(encoded, SECRET)

    assert decoded.agent_id    == "orchestrator_agent"
    assert decoded.tenant_id   == "test-tenant"
    assert decoded.tool_name   == "search_docs"
    assert decoded.source_name == "slack_mcp"
    assert decoded.allowed_urls    == ["https://slack.com/api/*"]
    assert decoded.allowed_methods == ["GET", "POST"]
    assert decoded.version     == 1
    assert decoded.token_id    == tok.token_id


def test_sub_agent_id_preserved():
    tok     = _token(sub_agent_id="research_sub")
    decoded = verify_token(encode_token(tok), SECRET)
    assert decoded.sub_agent_id == "research_sub"


def test_none_sub_agent_id_preserved():
    tok     = _token(sub_agent_id=None)
    decoded = verify_token(encode_token(tok), SECRET)
    assert decoded.sub_agent_id is None


def test_each_token_has_unique_id():
    t1 = _token()
    t2 = _token()
    assert t1.token_id != t2.token_id


def test_version_is_1():
    tok = _token()
    assert tok.version == 1


# ── Expiry ────────────────────────────────────────────────────────────────

def test_expired_token_raises():
    tok     = _token(ttl_seconds=1)
    encoded = encode_token(tok)
    # Manually create an expired token by patching expires_at in the raw JSON
    import dataclasses
    expired = dataclasses.replace(
        tok,
        expires_at=datetime.now(UTC) - timedelta(seconds=60),
        signature="",
    )
    import hashlib
    import hmac as _hmac

    from harness.connectivity.token import _payload
    sig = _hmac.new(SECRET, _payload(expired), hashlib.sha256).hexdigest()
    expired = dataclasses.replace(expired, signature=sig)
    with pytest.raises(TokenError, match="expired"):
        verify_token(encode_token(expired), SECRET)


def test_valid_token_not_yet_expired():
    tok     = _token(ttl_seconds=30)
    encoded = encode_token(tok)
    decoded = verify_token(encoded, SECRET)    # must not raise
    assert decoded.token_id == tok.token_id


# ── Tampering ─────────────────────────────────────────────────────────────

def test_wrong_secret_raises():
    tok     = _token()
    encoded = encode_token(tok)
    with pytest.raises(TokenError, match="signature"):
        verify_token(encoded, b"wrong-secret")


def test_tampered_payload_raises():
    import base64
    import json
    tok     = _token()
    encoded = encode_token(tok)
    raw     = base64.urlsafe_b64decode(encoded.encode() + b"==")
    data    = json.loads(raw)
    data["agent_id"] = "evil_agent"
    tampered = base64.urlsafe_b64encode(
        json.dumps(data, sort_keys=True).encode()
    ).decode()
    with pytest.raises(TokenError, match="signature"):
        verify_token(tampered, SECRET)


def test_malformed_base64_raises():
    with pytest.raises(TokenError, match="malformed"):
        verify_token("not-valid-base64!!!", SECRET)


def test_missing_field_raises():
    import base64
    import json
    tok     = _token()
    encoded = encode_token(tok)
    raw     = base64.urlsafe_b64decode(encoded.encode() + b"==")
    data    = json.loads(raw)
    del data["tool_name"]
    broken = base64.urlsafe_b64encode(
        json.dumps(data, sort_keys=True).encode()
    ).decode()
    with pytest.raises(TokenError, match="missing"):
        verify_token(broken, SECRET)


# ── URL matching ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("url,patterns,expected", [
    # wildcard prefix
    ("https://slack.com/api/chat.postMessage", ["https://slack.com/api/*"], True),
    ("https://slack.com/api/",                 ["https://slack.com/api/*"], True),
    ("https://evil.com/api/chat",              ["https://slack.com/api/*"], False),
    # exact match
    ("https://slack.com/api/auth",             ["https://slack.com/api/auth"], True),
    ("https://slack.com/api/auth2",            ["https://slack.com/api/auth"], False),
    # empty patterns
    ("https://slack.com/api/anything",         [], False),
    # multiple patterns — first match wins
    ("https://evil.com/path",  ["https://slack.com/*", "https://evil.com/*"], True),
    # no wildcard at end — treated as exact
    ("https://slack.com/api",  ["https://slack.com/api"], True),
    ("https://slack.com/api/x", ["https://slack.com/api"], False),
])
def test_matches_allowed_url(url, patterns, expected):
    assert matches_allowed_url(url, patterns) == expected


# ── default_allowed_urls ──────────────────────────────────────────────────

def test_default_allowed_urls_from_source_url():
    urls = default_allowed_urls("https://mcp.slack.com/sse")
    assert urls == ["https://mcp.slack.com/*"]


def test_default_allowed_urls_strips_path():
    urls = default_allowed_urls("https://api.example.com/v1/mcp")
    assert urls == ["https://api.example.com/*"]


# ── Gate integration: token issued when connectivity enabled ─────────────

async def test_gate_issues_token_when_connectivity_enabled(tmp_path):
    """check_tool_call returns dispatch_token when connectivity.enabled."""
    import os

    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport

    os.environ["SHAI_TEST_TOKEN_SECRET"] = "a-strong-test-secret-1234567890ab"

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        "connectivity:\n"
        "  enabled: true\n"
        "  token_secret: 'secret://SHAI_TEST_TOKEN_SECRET'\n"
        "  token_ttl_seconds: 15\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_a\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent)
    ctx  = AgentContext(agent_id="agent_a")
    gate = await harness.check_tool_call("search_docs", {"query": "test"}, ctx)

    assert gate.allowed
    assert gate.dispatch_token is not None

    # Token must be verifiable
    secret = b"a-strong-test-secret-1234567890ab"
    tok    = verify_token(gate.dispatch_token, secret)
    assert tok.agent_id   == "agent_a"
    assert tok.tool_name  == "search_docs"
    assert tok.tenant_id  == "default"
    assert tok.version    == 1

    await harness.close()
    del os.environ["SHAI_TEST_TOKEN_SECRET"]


async def test_gate_no_token_when_connectivity_disabled(tmp_path):
    """check_tool_call returns no dispatch_token when connectivity.enabled=false."""
    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n  rules: []\n"
        # no connectivity block — defaults to disabled
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_b\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent)
    ctx  = AgentContext(agent_id="agent_b")
    gate = await harness.check_tool_call("search_docs", {"query": "test"}, ctx)

    assert gate.allowed
    assert gate.dispatch_token is None

    await harness.close()


async def test_gate_denied_carries_no_token(tmp_path):
    """Denied gate decisions must never carry a dispatch token."""
    import os

    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport

    os.environ["SHAI_TEST_TOKEN_SECRET2"] = "another-strong-secret-xyz987654321"

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "policy:\n"
        "  rules:\n"
        "    - id: deny_all\n"
        "      match: {}\n"
        "      action: deny\n"
        "      reason: 'all denied'\n"
        "connectivity:\n"
        "  enabled: true\n"
        "  token_secret: 'secret://SHAI_TEST_TOKEN_SECRET2'\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_c\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent)
    ctx  = AgentContext(agent_id="agent_c")
    gate = await harness.check_tool_call("search_docs", {}, ctx)

    assert not gate.allowed
    assert gate.dispatch_token is None

    await harness.close()
    del os.environ["SHAI_TEST_TOKEN_SECRET2"]


async def test_connectivity_config_requires_secret_when_enabled(tmp_path):
    """ConnectivityConfig raises on enabled=True with empty token_secret."""
    from pydantic import ValidationError

    from harness.connectivity.config import ConnectivityConfig

    with pytest.raises((ValidationError, ValueError)):
        ConnectivityConfig(enabled=True, token_secret="")
