"""Tests for ShaiTransport — in-process egress enforcement."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from harness.connectivity.config import ConnectivityConfig
from harness.connectivity.token import encode_token, sign_token
from harness.connectivity.transport import NetworkAuditEvent, ShaiTransport
from harness.core.errors import NetworkPolicyError

SECRET  = b"test-secret-transport-phase2"
TENANT  = "test-tenant"
AGENT   = "orchestrator_agent"
SOURCE  = "slack_mcp"
ALLOWED = ["https://mcp.slack.com/*", "https://slack.com/api/*"]
METHODS = ["GET", "POST"]


# ── Helpers ────────────────────────────────────────────────────────────────

def _config(**overrides) -> ConnectivityConfig:
    defaults = dict(
        enabled=True,
        token_secret="test-secret-transport-phase2",
        token_ttl_seconds=15,
        no_token_policy="permissive",
    )
    defaults.update(overrides)
    return ConnectivityConfig(**defaults)


def _transport(
    allowed_urls=None,
    allowed_methods=None,
    config=None,
    emitter=None,
    inner=None,
) -> ShaiTransport:
    mock_inner   = inner or AsyncMock(spec=httpx.AsyncBaseTransport)
    mock_emitter = emitter or AsyncMock()
    mock_emitter.emit = AsyncMock()
    return ShaiTransport(
        source_name=SOURCE,
        allowed_urls=ALLOWED if allowed_urls is None else allowed_urls,
        allowed_methods=METHODS if allowed_methods is None else allowed_methods,
        agent_id=AGENT,
        sub_agent_id=None,
        tenant_id=TENANT,
        emitter=mock_emitter,
        connectivity=config or _config(),
        inner=mock_inner,
    )


def _request(
    url: str = "https://mcp.slack.com/message",
    method: str = "POST",
    token: str | None = None,
) -> httpx.Request:
    r = httpx.Request(method, url)
    if token:
        r.extensions["shai_dispatch_token"] = token
    return r


def _token(**overrides) -> str:
    defaults = dict(
        agent_id=AGENT,
        sub_agent_id=None,
        tenant_id=TENANT,
        tool_name="search_docs",
        source_name=SOURCE,
        allowed_urls=ALLOWED,
        allowed_methods=METHODS,
        secret=SECRET,
        ttl_seconds=15,
    )
    defaults.update(overrides)
    return encode_token(sign_token(**defaults))


def _response(status=200, content=b'{"result": "ok"}') -> httpx.Response:
    return httpx.Response(status_code=status, content=content)


# ── URL enforcement ────────────────────────────────────────────────────────

async def test_allowed_url_passes():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner)
    req = _request("https://mcp.slack.com/message")
    await t.handle_async_request(req)   # must not raise


async def test_denied_url_raises():
    t = _transport()
    req = _request("https://evil.com/steal")
    with pytest.raises(NetworkPolicyError, match="not in allowed_urls"):
        await t.handle_async_request(req)


async def test_denied_url_emits_audit_event():
    emitter = AsyncMock()
    emitter.emit = AsyncMock()
    t = _transport(emitter=emitter)
    req = _request("https://evil.com/steal")
    with pytest.raises(NetworkPolicyError):
        await t.handle_async_request(req)
    emitter.emit.assert_called_once()
    event = emitter.emit.call_args[0][0]
    assert event.status == "denied"
    assert "allowed_urls" in event.deny_reason


async def test_empty_allowed_urls_permits_any():
    """Empty allowed_urls = no URL restriction (local tools, test scenarios)."""
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(allowed_urls=[])
    req = _request("https://anywhere.com/api")
    await t.handle_async_request(req)   # must not raise


# ── Method enforcement ────────────────────────────────────────────────────

async def test_allowed_method_passes():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner)
    req = _request(method="GET")
    await t.handle_async_request(req)


async def test_denied_method_raises():
    t = _transport(allowed_methods=["GET"])
    req = _request("https://mcp.slack.com/message", method="DELETE")
    with pytest.raises(NetworkPolicyError, match="not in allowed_methods"):
        await t.handle_async_request(req)


async def test_method_check_is_case_insensitive():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(allowed_methods=["get", "post"], inner=inner)
    req = _request(method="POST")
    await t.handle_async_request(req)   # must not raise


# ── Token injection ───────────────────────────────────────────────────────

async def test_token_injected_as_header():
    captured: list[httpx.Request] = []

    async def capture(req):
        captured.append(req)
        return _response()

    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(side_effect=capture)
    t = _transport(inner=inner)

    tok = _token()
    req = _request(token=tok)
    await t.handle_async_request(req)

    assert captured, "inner transport was not called"
    assert "x-shai-token" in captured[0].headers or \
           "X-Shai-Token" in captured[0].headers


async def test_no_token_permissive_passes():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(config=_config(no_token_policy="permissive"), inner=inner)
    req = _request()  # no token
    await t.handle_async_request(req)   # must not raise


async def test_no_token_strict_raises():
    t = _transport(config=_config(no_token_policy="strict"))
    req = _request()  # no token
    with pytest.raises(NetworkPolicyError, match="no_token_policy=strict"):
        await t.handle_async_request(req)


async def test_tampered_token_raises():
    t = _transport()
    req = _request(token="not.a.valid.token")
    with pytest.raises(NetworkPolicyError, match="invalid dispatch token"):
        await t.handle_async_request(req)


# ── NetworkAuditEvent emission ────────────────────────────────────────────

async def test_network_audit_event_emitted_on_allowed_tool_call():
    emitter = AsyncMock()
    emitter.emit = AsyncMock()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=emitter, inner=inner)

    tok = _token()
    req = _request(token=tok)
    await t.handle_async_request(req)

    emitter.emit.assert_called_once()
    event = emitter.emit.call_args[0][0]
    assert isinstance(event, NetworkAuditEvent)
    assert event.event_type   == "network_egress"
    assert event.status       == "allowed"
    assert event.source_name  == SOURCE
    assert event.agent_id     == AGENT
    assert event.tenant_id    == TENANT
    assert event.tool_name    == "search_docs"
    assert event.token_id     is not None
    assert event.deny_reason  is None


async def test_no_audit_event_for_tokenless_requests():
    """SSE and init requests carry no token — no NetworkAuditEvent emitted."""
    emitter = AsyncMock()
    emitter.emit = AsyncMock()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=emitter, inner=inner)

    req = _request()  # no token — simulates SSE or init call
    await t.handle_async_request(req)

    emitter.emit.assert_not_called()


async def test_network_audit_event_json_serialisable():
    event = NetworkAuditEvent(
        timestamp    = datetime.now(timezone.utc),
        event_type   = "network_egress",
        token_id     = "uuid-1234",
        source_name  = SOURCE,
        agent_id     = AGENT,
        sub_agent_id = None,
        tenant_id    = TENANT,
        tool_name    = "search_docs",
        destination  = "https://mcp.slack.com/message",
        method       = "POST",
        status       = "allowed",
        deny_reason  = None,
        bytes_sent   = 256,
        bytes_recv   = 1024,
        duration_ms  = 42,
    )
    import json
    parsed = json.loads(event.model_dump_json())
    assert parsed["event_type"]  == "network_egress"
    assert parsed["token_id"]    == "uuid-1234"
    assert parsed["bytes_sent"]  == 256


# ── Token_id SIEM correlation ─────────────────────────────────────────────

async def test_token_id_matches_issued_token():
    from harness.connectivity.token import sign_token, encode_token

    tok_obj = sign_token(
        agent_id="orchestrator_agent",
        sub_agent_id=None,
        tenant_id=TENANT,
        tool_name="search_docs",
        source_name=SOURCE,
        allowed_urls=ALLOWED,
        allowed_methods=METHODS,
        secret=SECRET,
    )
    encoded = encode_token(tok_obj)

    emitter = AsyncMock()
    emitter.emit = AsyncMock()
    inner   = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=emitter, inner=inner)

    req = _request(token=encoded)
    await t.handle_async_request(req)

    event = emitter.emit.call_args[0][0]
    assert event.token_id == tok_obj.token_id
