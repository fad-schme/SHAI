"""Tests for ShaiTransport — in-process egress enforcement.

The inner httpx transport is mocked deliberately: it is the seam to the real
network. The AuditEmitter is not — it is SHAI's own code and runs in-memory,
so emission is asserted against a real emitter and a real sink.
"""
from __future__ import annotations

import asyncio
import io
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.audit.emitter import AuditEmitter
from harness.connectivity.config import ConnectivityConfig
from harness.connectivity.token import encode_token, sign_token
from harness.connectivity.transport import ShaiTransport
from harness.core.errors import NetworkPolicyError
from harness.core.events import NetworkAuditEvent
from tests.conftest import RecordingSink

SECRET  = b"test-secret-transport-phase2"
TENANT  = "test-tenant"
AGENT   = "orchestrator_agent"
SOURCE  = "slack_mcp"
ALLOWED = ["https://mcp.slack.com/*", "https://slack.com/api/*"]
METHODS = ["GET", "POST"]


# ── Helpers ────────────────────────────────────────────────────────────────

def _config(**overrides) -> ConnectivityConfig:
    defaults = dict(
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
    # The inner transport is mocked — it is the seam to the real network.
    # The emitter is not: it is SHAI's own code and runs in-memory.
    mock_inner = inner or AsyncMock(spec=httpx.AsyncBaseTransport)
    return ShaiTransport(
        source_name=SOURCE,
        allowed_urls=ALLOWED if allowed_urls is None else allowed_urls,
        allowed_methods=METHODS if allowed_methods is None else allowed_methods,
        agent_id=AGENT,
        sub_agent_id=None,
        tenant_id=TENANT,
        emitter=emitter or AuditEmitter([RecordingSink()]),
        connectivity=config or _config(),
        inner=mock_inner,
    )


def _request(
    url: str = "https://mcp.slack.com/message",
    method: str = "POST",
    token: str | None = None,
    rpc_method: str | None = "tools/call",
) -> httpx.Request:
    # A POST carries a JSON-RPC body, as MCPSource sends it: a token's purpose
    # is bound to the JSON-RPC method it may carry.
    body = ({"jsonrpc": "2.0", "id": "1", "method": rpc_method, "params": {}}
            if method == "POST" and rpc_method else None)
    r = httpx.Request(method, url, json=body)
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
        purpose="tool_call",
        secret=SECRET,
        ttl_seconds=15,
    )
    defaults.update(overrides)
    return encode_token(sign_token(**defaults))


def _connect_token(**overrides) -> str:
    return _token(purpose="connect", tool_name=None, **overrides)


def _network(response: httpx.Response | None = None) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: response or httpx.Response(200, json={}))


def _response(status=200, content=b'{"result": "ok"}') -> httpx.Response:
    return httpx.Response(status_code=status, content=content)


# ── MCPSource → ShaiTransport wiring ───────────────────────────────────────
#
# A real MCPSource whose client runs through a real ShaiTransport. Only the
# inner transport, the network, is mocked. _post is exercised as written:
# patching it away is how a dropped token went unnoticed.

def _wired_source(seen: list[httpx.Request], sink: RecordingSink):
    from harness.tools.source import MCPSource, MCPSourceParams

    def network(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "1", "result": {}})

    async def no_connect(*_, **__) -> str:
        raise AssertionError("the client is wired directly; nothing connects")

    src = MCPSource(
        MCPSourceParams(
            SOURCE, "https://mcp.slack.com", allowed_urls=ALLOWED, allowed_methods=METHODS,
        ),
        connectivity=_config(), emitter=AuditEmitter([sink]), mint_connect_token=no_connect,
    )
    src._client = httpx.AsyncClient(
        base_url="https://mcp.slack.com",
        transport=_transport(emitter=AuditEmitter([sink]),
                             inner=httpx.MockTransport(network)),
    )
    src._session_id = "sess"
    src._connected = True
    return src


async def test_mcp_source_call_carries_dispatch_token_to_the_wire():
    """Regression: MCPSource._post took dispatch_token and never attached it,
    so every real tool call reached ShaiTransport untokened."""
    from harness.connectivity.token import verify_token

    seen: list[httpx.Request] = []
    sink = RecordingSink()
    src = _wired_source(seen, sink)
    token = _token()

    await src.call("search_docs", {"q": "x"}, dispatch_token=token)

    assert seen[0].headers.get("X-Shai-Token") == token
    events = [e for e in sink.events if isinstance(e, NetworkAuditEvent)]
    assert len(events) == 1
    assert events[0].status == "allowed"
    assert events[0].token_id == verify_token(token, SECRET).token_id
    await src.close()


async def test_mcp_source_call_refuses_replayed_token():
    from harness.core.errors import ConfigError

    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink())
    token = _token()
    await src.call("search_docs", {}, dispatch_token=token)

    # _post reports every request failure as ConfigError; the policy refusal
    # is its cause.
    with pytest.raises(ConfigError) as exc:
        await src.call("search_docs", {}, dispatch_token=token)
    assert isinstance(exc.value.__cause__, NetworkPolicyError)
    assert len(seen) == 1
    await src.close()


async def test_mcp_source_call_refuses_token_for_another_source():
    from harness.core.errors import ConfigError

    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink())

    with pytest.raises(ConfigError) as exc:
        await src.call("search_docs", {}, dispatch_token=_token(source_name="other_mcp"))
    assert isinstance(exc.value.__cause__, NetworkPolicyError)
    assert seen == []
    await src.close()


async def test_mcp_source_call_without_token_sends_no_token_header():
    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink())

    await src.call("search_docs", {})

    assert "X-Shai-Token" not in seen[0].headers
    await src.close()


def test_runtime_mcp_source_requires_a_connect_minter():
    """Outside onboarding, a source with no connect minter could only send
    untokened connect requests. It is refused at construction instead."""
    from harness.core.errors import ConfigError
    from harness.tools.source import MCPSource, MCPSourceParams

    with pytest.raises(ConfigError, match="connect"):
        MCPSource(
            MCPSourceParams(SOURCE, "https://mcp.slack.com", allowed_urls=ALLOWED),
            connectivity=_config(), emitter=AuditEmitter([RecordingSink()]),
        )


# ── Token purpose: connect vs tool_call ────────────────────────────────────

@pytest.mark.parametrize("url,method,rpc_method", [
    ("https://mcp.slack.com/sse",     "GET",  None),
    ("https://mcp.slack.com/message", "POST", "initialize"),
    ("https://mcp.slack.com/message", "POST", "notifications/initialized"),
    ("https://mcp.slack.com/message", "POST", "tools/list"),
])
async def test_connect_token_accepted_for_connect_phase_requests(url, method, rpc_method):
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())

    await t.handle_async_request(
        _request(url=url, method=method, rpc_method=rpc_method, token=_connect_token())
    )

    assert [e.status for e in sink.events] == ["allowed"]


async def test_connect_token_refused_on_tool_call():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())

    with pytest.raises(NetworkPolicyError, match="purpose"):
        await t.handle_async_request(_request(token=_connect_token()))
    assert [e.status for e in sink.events] == ["denied"]


@pytest.mark.parametrize("url,method,rpc_method", [
    ("https://mcp.slack.com/message", "POST", "initialize"),
    ("https://mcp.slack.com/sse",     "GET",  None),
])
async def test_tool_call_token_refused_on_connect_requests(url, method, rpc_method):
    t = _transport(inner=_network())

    with pytest.raises(NetworkPolicyError, match="purpose"):
        await t.handle_async_request(
            _request(url=url, method=method, rpc_method=rpc_method, token=_token())
        )


class _EndlessSSE(httpx.AsyncByteStream):
    """An SSE stream as a real MCP server serves it: it never ends."""

    async def __aiter__(self):
        yield b"event: endpoint\ndata: /message?sessionId=abc\n\n"
        await asyncio.Event().wait()


async def test_tokened_sse_get_returns_without_reading_the_stream():
    """The transport buffers a tokened response to count bytes_recv. An SSE
    stream never ends, so buffering it would hang the connect forever."""
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]),
                   inner=_network(httpx.Response(200, stream=_EndlessSSE())))

    response = await asyncio.wait_for(
        t.handle_async_request(_request(
            url="https://mcp.slack.com/sse", method="GET", rpc_method=None,
            token=_connect_token(),
        )),
        timeout=2,
    )

    assert response.status_code == 200
    assert [e.status for e in sink.events] == ["allowed"]


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
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]))
    req = _request("https://evil.com/steal")
    with pytest.raises(NetworkPolicyError):
        await t.handle_async_request(req)
    assert len(sink.events) == 1
    event = sink.events[0]
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
    sink  = RecordingSink()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=AuditEmitter([sink]), inner=inner)

    tok = _token()
    req = _request(token=tok)
    await t.handle_async_request(req)

    assert len(sink.events) == 1
    event = sink.events[0]
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
    sink  = RecordingSink()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=AuditEmitter([sink]), inner=inner)

    req = _request()  # no token — simulates SSE or init call
    await t.handle_async_request(req)

    assert sink.events == []


async def test_network_event_reaches_sink_as_jsonl():
    """Real AuditEmitter + real StdoutSink — the path production actually takes.

    Asserting the emitter was *called* is not enough: the event has to survive
    serialization. When NetworkAuditEvent was a dataclass it never did, and the
    failure was swallowed by _emit's log-and-continue.
    """
    buf     = io.StringIO()
    emitter = AuditEmitter([StdoutSink(stream=buf)])
    inner   = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=emitter, inner=inner)

    await t.handle_async_request(_request(token=_token()))

    data = json.loads(buf.getvalue().strip())
    assert data["event_type"]  == "network_egress"
    assert data["status"]      == "allowed"
    assert data["source_name"] == SOURCE
    assert data["tool_name"]   == "search_docs"
    assert data["token_id"]


# ── Token_id SIEM correlation ─────────────────────────────────────────────

async def test_token_id_matches_issued_token():
    """The SIEM join key must survive serialization, not merely reach the emitter.

    token_id is what joins this event to the gate AuditEvent that authorised
    the call, so it has to be present on the written line.
    """
    tok_obj = sign_token(
        agent_id="orchestrator_agent",
        sub_agent_id=None,
        tenant_id=TENANT,
        tool_name="search_docs",
        source_name=SOURCE,
        purpose="tool_call",
        allowed_urls=ALLOWED,
        allowed_methods=METHODS,
        secret=SECRET,
    )
    encoded = encode_token(tok_obj)

    buf     = io.StringIO()
    emitter = AuditEmitter([StdoutSink(stream=buf)])
    inner   = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=emitter, inner=inner)

    await t.handle_async_request(_request(token=encoded))

    data = json.loads(buf.getvalue().strip())
    assert data["token_id"] == tok_obj.token_id


# ── Token binding checks ───────────────────────────────────────────────────

async def test_token_wrong_source_denied():
    """Token issued for 'slack_mcp' must not pass on 'github_mcp' transport."""
    t = _transport()  # source_name = SOURCE = "slack_mcp"
    # Token claims source_name = "github_mcp"
    tok = _token(source_name="github_mcp")
    req = _request(token=tok)
    with pytest.raises(NetworkPolicyError, match="source_name"):
        await t.handle_async_request(req)


async def test_token_wrong_source_emits_audit_event():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]))
    tok = _token(source_name="github_mcp")
    req = _request(token=tok)
    with pytest.raises(NetworkPolicyError):
        await t.handle_async_request(req)
    event = sink.events[0]
    assert event.status == "denied"
    assert "source_name" in event.deny_reason


async def test_token_url_binding_denied():
    """Token with allowed_urls scoped to Slack must not reach GitHub."""
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(
        allowed_urls=["https://api.github.com/*"],
        inner=inner,
    )
    # Token allows only Slack URLs
    tok = _token(
        allowed_urls=["https://mcp.slack.com/*"],
        allowed_methods=["GET", "POST"],
    )
    req = _request(url="https://api.github.com/repos", token=tok)
    with pytest.raises(NetworkPolicyError, match="token.allowed_urls"):
        await t.handle_async_request(req)


async def test_token_method_binding_denied():
    """Token that allows only GET must block a POST request."""
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner)
    tok = _token(allowed_methods=["GET"])   # POST not permitted
    req = _request(method="POST", token=tok)
    with pytest.raises(NetworkPolicyError, match="token.allowed_methods"):
        await t.handle_async_request(req)


async def test_token_replay_denied():
    """Same token used twice must be rejected on the second use."""
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner)
    tok = _token()

    # First use — allowed
    req1 = _request(token=tok)
    await t.handle_async_request(req1)

    # Second use — replay denied
    req2 = _request(token=tok)
    with pytest.raises(NetworkPolicyError, match="replay"):
        await t.handle_async_request(req2)


async def test_different_tokens_not_confused():
    """Two distinct tokens on the same transport are both allowed."""
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner)

    tok1 = _token()
    tok2 = _token()   # different token_id via new sign_token call
    assert tok1 != tok2

    await t.handle_async_request(_request(token=tok1))
    await t.handle_async_request(_request(token=tok2))
    assert inner.handle_async_request.call_count == 2


async def test_token_binding_checks_order():
    """Source binding fires before URL binding — wrong source caught first."""
    t = _transport()
    # Token with wrong source AND wrong url — source check fires first
    tok = _token(
        source_name="wrong_source",
        allowed_urls=["https://evil.com/*"],
    )
    req = _request(token=tok)
    with pytest.raises(NetworkPolicyError, match="source_name"):
        await t.handle_async_request(req)
