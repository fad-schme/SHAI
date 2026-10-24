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
from harness.core.context import AgentContext
from harness.core.errors import AuditEmissionError, NetworkPolicyError
from harness.core.events import NetworkAuditEvent
from tests.conftest import RecordingSink

SECRET  = b"test-secret-transport-phase2"
TENANT  = "test-tenant"
AGENT   = "orchestrator_agent"
SOURCE  = "slack_mcp"
ALLOWED = ["https://mcp.slack.com/*", "https://slack.com/api/*"]
METHODS = ["GET", "POST"]
CALLER  = AgentContext(agent_id=AGENT)


# ── Helpers ────────────────────────────────────────────────────────────────

def _config(**overrides) -> ConnectivityConfig:
    defaults = dict(
        token_secret="test-secret-transport-phase2",
        token_ttl_seconds=15,
        token_policy="strict",
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
    tool_name: str | None = "search_docs",
    params: dict | None = None,
    caller: AgentContext | None = CALLER,
) -> httpx.Request:
    # A POST carries a JSON-RPC body, as MCPSource sends it: a token's purpose
    # is bound to the JSON-RPC method it may carry, and a tool-call token to the
    # tool name in params.name.
    if params is None:
        params = ({"name": tool_name, "arguments": {}}
                  if rpc_method == "tools/call" and tool_name is not None else {})
    body = ({"jsonrpc": "2.0", "id": "1", "method": rpc_method, "params": params}
            if method == "POST" and rpc_method else None)
    r = httpx.Request(method, url, json=body)
    if token:
        r.extensions["shai_dispatch_token"] = token
    if caller is not None:
        r.extensions["shai_caller"] = caller
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

def _wired_source(
    seen: list[httpx.Request], sink: RecordingSink, *,
    config: ConnectivityConfig | None = None,
    allowed_urls: list[str] | None = None,
    status: int = 200,
):
    from harness.tools.source import MCPSource, MCPSourceParams

    def network(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json={"jsonrpc": "2.0", "id": "1", "result": {}})

    async def no_connect(*_, **__) -> str:
        raise AssertionError("the client is wired directly; nothing connects")

    src = MCPSource(
        MCPSourceParams(
            SOURCE, "https://mcp.slack.com", allowed_urls=ALLOWED, allowed_methods=METHODS,
        ),
        connectivity=config or _config(), emitter=AuditEmitter([sink]),
        mint_connect_token=no_connect,
    )
    src._client = httpx.AsyncClient(
        base_url="https://mcp.slack.com",
        transport=_transport(emitter=AuditEmitter([sink]), config=config or _config(),
                             allowed_urls=allowed_urls,
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

    await src.call("search_docs", {"q": "x"}, ctx=CALLER, dispatch_token=token)

    assert seen[0].headers.get("X-Shai-Token") == token
    events = [e for e in sink.events if isinstance(e, NetworkAuditEvent)]
    assert len(events) == 1
    assert events[0].status == "allowed"
    assert events[0].token_id == verify_token(token, SECRET).token_id
    await src.close()


async def test_mcp_source_call_refuses_replayed_token():
    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink())
    token = _token()
    await src.call("search_docs", {}, ctx=CALLER, dispatch_token=token)

    # A policy refusal reaches the caller as itself, not wrapped in ConfigError.
    with pytest.raises(NetworkPolicyError):
        await src.call("search_docs", {}, ctx=CALLER, dispatch_token=token)
    assert len(seen) == 1
    await src.close()


async def test_mcp_source_call_refuses_token_for_another_source():
    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink())

    with pytest.raises(NetworkPolicyError):
        await src.call("search_docs", {}, ctx=CALLER, dispatch_token=_token(source_name="other_mcp"))
    assert seen == []
    await src.close()


async def test_mcp_source_call_to_a_destination_outside_allowed_urls_raises_policy_error():
    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink(), allowed_urls=["https://other.example.test/*"])

    with pytest.raises(NetworkPolicyError, match="allowed_urls"):
        await src.call("search_docs", {}, ctx=CALLER, dispatch_token=_token())
    assert seen == []
    await src.close()


async def test_mcp_source_call_server_error_is_still_a_config_error():
    """Only the policy refusal is unwrapped: a broken server keeps being
    reported as it always was."""
    from harness.core.errors import ConfigError

    seen: list[httpx.Request] = []
    src = _wired_source(seen, RecordingSink(), status=500)

    with pytest.raises(ConfigError, match="POST /message failed"):
        await src.call("search_docs", {}, ctx=CALLER, dispatch_token=_token())
    assert len(seen) == 1
    await src.close()


async def test_mcp_source_call_without_token_sends_no_token_header():
    seen: list[httpx.Request] = []
    # Under the strict default an untokened call is refused; audit lets it
    # reach the wire so the absent header can be checked.
    src = _wired_source(seen, RecordingSink(), config=_config(token_policy="audit"))

    await src.call("search_docs", {}, ctx=CALLER)

    assert "X-Shai-Token" not in seen[0].headers
    await src.close()


# ── token_policy: strict | audit ───────────────────────────────────────────

def test_token_policy_defaults_to_strict():
    assert ConnectivityConfig(token_secret="t").token_policy == "strict"


async def test_audit_forwards_an_untokened_request_and_records_it():
    """Forwarding an untokened request without a record is what the removed
    policies did. audit forwards and records it: every untokened request is
    in the trail, marked by the missing token_id."""
    sink = RecordingSink()
    t = _transport(config=_config(token_policy="audit"),
                   emitter=AuditEmitter([sink]), inner=_network())

    response = await t.handle_async_request(_request())

    assert response.status_code == 200
    assert len(sink.events) == 1
    assert sink.events[0].status == "allowed"
    assert sink.events[0].token_id is None


@pytest.mark.parametrize("policy", ["strict", "audit"])
async def test_a_valid_token_is_handled_the_same_under_either_policy(policy):
    sink = RecordingSink()
    t = _transport(config=_config(token_policy=policy),
                   emitter=AuditEmitter([sink]), inner=_network())

    await t.handle_async_request(_request(token=_token()))

    assert [e.status for e in sink.events] == ["allowed"]
    assert sink.events[0].token_id is not None


async def test_audit_does_not_relax_the_url_check():
    t = _transport(config=_config(token_policy="audit"), inner=_network())

    with pytest.raises(NetworkPolicyError, match="allowed_urls"):
        await t.handle_async_request(_request("https://evil.com/steal"))


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


# ── Token tool binding: a tool-call token authorises one tool ──────────────

async def test_tool_call_token_passes_for_its_own_tool():
    sink = RecordingSink()
    inner = _network()
    t = _transport(emitter=AuditEmitter([sink]), inner=inner)

    await t.handle_async_request(_request(token=_token(), tool_name="search_docs"))

    assert [e.status for e in sink.events] == ["allowed"]


async def test_tool_call_token_refused_for_another_tool_and_not_burned():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())
    token = _token()

    with pytest.raises(NetworkPolicyError, match="search_docs.*delete_all"):
        await t.handle_async_request(_request(token=token, tool_name="delete_all"))

    denied = [e for e in sink.events if isinstance(e, NetworkAuditEvent)]
    assert [e.status for e in denied] == ["denied"]
    assert denied[0].tool_name == "search_docs"
    assert denied[0].token_id

    # The nonce was not consumed: the same token passes on its own tool.
    await t.handle_async_request(_request(token=token, tool_name="search_docs"))
    assert [e.status for e in sink.events] == ["denied", "allowed"]


@pytest.mark.parametrize("params", [{}, {"name": 7}, {"name": None}, {"arguments": {}}])
async def test_tool_call_token_refused_when_body_has_no_readable_tool_name(params):
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())
    token = _token()

    with pytest.raises(NetworkPolicyError, match="no readable tool"):
        await t.handle_async_request(_request(token=token, params=params))
    assert [e.status for e in sink.events] == ["denied"]

    await t.handle_async_request(_request(token=token))   # not burned


async def test_tool_binding_refusal_carries_no_argument_value():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())
    req = _request(token=_token(), params={"name": "delete_all",
                                           "arguments": {"secret": "hunter2-value"}})

    with pytest.raises(NetworkPolicyError) as exc:
        await t.handle_async_request(req)

    assert "hunter2-value" not in str(exc.value)
    assert all("hunter2-value" not in (e.deny_reason or "") for e in sink.events)


async def test_mcp_source_call_refuses_token_issued_for_another_tool():
    seen: list[httpx.Request] = []
    sink = RecordingSink()
    src = _wired_source(seen, sink)

    with pytest.raises(NetworkPolicyError, match="search_docs.*other_tool"):
        await src.call("other_tool", {"q": "x"}, ctx=CALLER, dispatch_token=_token())

    assert seen == []
    events = [e for e in sink.events if isinstance(e, NetworkAuditEvent)]
    assert [e.status for e in events] == ["denied"]
    assert events[0].tool_name == "search_docs"
    await src.close()


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
    # audit lets the untokened request through, so only the URL check is tested.
    t = _transport(inner=inner, config=_config(token_policy="audit"))
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


async def test_empty_allowed_urls_refuses_every_request():
    """The URL check runs on every request; an empty allow-list refuses each one."""
    sink = RecordingSink()
    t = _transport(allowed_urls=[], config=_config(token_policy="audit"),
                   emitter=AuditEmitter([sink]), inner=_network())
    with pytest.raises(NetworkPolicyError, match="allowed_urls"):
        await t.handle_async_request(_request("https://mcp.slack.com/message"))
    assert [e.status for e in sink.events] == ["denied"]


async def test_token_with_empty_allowed_urls_is_refused_at_url_binding():
    t = _transport(inner=_network())
    with pytest.raises(NetworkPolicyError, match="token.allowed_urls"):
        await t.handle_async_request(_request(token=_token(allowed_urls=[])))


# ── Method enforcement ────────────────────────────────────────────────────

async def test_allowed_method_passes():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(inner=inner, config=_config(token_policy="audit"))
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
    t = _transport(allowed_methods=["get", "post"], inner=inner,
                   config=_config(token_policy="audit"))
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


async def test_no_token_strict_raises():
    t = _transport(config=_config(token_policy="strict"))
    req = _request()  # no token
    with pytest.raises(NetworkPolicyError, match="token_policy=strict"):
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


async def test_strict_records_the_untokened_request_it_refuses():
    """Every untokened request is in the trail under either policy: strict
    refuses it with a denied event, audit forwards it with an allowed one."""
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=_network())

    with pytest.raises(NetworkPolicyError):
        await t.handle_async_request(_request())

    assert len(sink.events) == 1
    assert sink.events[0].status == "denied"
    assert sink.events[0].token_id is None


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


# ── Every request ends with exactly one event; an outage is never swallowed ──

class _FailingSink:
    name = "failing"

    async def emit(self, event):
        raise OSError("sink down: https://secret.example/?q=hidden")

    async def close(self):
        pass


def _failing_inner(exc: BaseException):
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(side_effect=exc)
    return inner


async def test_connect_error_emits_one_failed_event_and_reraises():
    sink = RecordingSink()
    exc = httpx.ConnectError("boom to https://mcp.slack.com/message?token=hunter2")
    t = _transport(emitter=AuditEmitter([sink]), inner=_failing_inner(exc))
    tok = _token()
    with pytest.raises(httpx.ConnectError) as info:
        await t.handle_async_request(_request(token=tok))
    assert info.value is exc
    assert len(sink.events) == 1
    event = sink.events[0]
    assert event.status == "failed"
    assert event.deny_reason == "ConnectError"
    assert event.token_id is not None
    # The token was consumed by the attempt: replaying it is refused (and audited).
    with pytest.raises(NetworkPolicyError):
        await t.handle_async_request(_request(token=tok))
    assert len(sink.events) == 2


async def test_read_error_while_buffering_body_emits_one_failed_event():
    class _Broken(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"abc"
            raise httpx.ReadError("cut off at https://mcp.slack.com/x?k=v")

    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(
        return_value=httpx.Response(200, stream=_Broken()),
    )
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=inner)
    with pytest.raises(httpx.ReadError):
        await t.handle_async_request(_request(token=_token()))
    assert len(sink.events) == 1
    assert sink.events[0].status == "failed"
    assert sink.events[0].deny_reason == "ReadError"
    assert sink.events[0].bytes_recv == 3


async def test_cancelled_request_emits_one_failed_event_and_reraises():
    sink = RecordingSink()
    started = asyncio.Event()

    async def hang(request):
        started.set()
        await asyncio.sleep(60)

    inner = AsyncMock()
    inner.handle_async_request = hang
    t = _transport(emitter=AuditEmitter([sink]), inner=inner)
    task = asyncio.ensure_future(t.handle_async_request(_request(token=_token())))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(sink.events) == 1
    assert sink.events[0].status == "failed"
    assert sink.events[0].deny_reason == "cancelled"


async def test_total_sink_outage_on_an_allowed_request_raises_and_returns_no_response():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=AuditEmitter([_FailingSink()]), inner=inner)
    with pytest.raises(AuditEmissionError):
        await t.handle_async_request(_request(token=_token()))


async def test_total_sink_outage_on_a_failed_request_raises_audit_emission_error():
    t = _transport(emitter=AuditEmitter([_FailingSink()]),
                   inner=_failing_inner(httpx.ConnectError("x")))
    with pytest.raises(AuditEmissionError):
        await t.handle_async_request(_request(token=_token()))


def _refusal_requests():
    good = _token()
    return {
        "url": lambda: _request(url="https://evil.example/x", token=good),
        "method": lambda: _request(method="DELETE", token=good),
        "token": lambda: _request(token="not-a-token"),
        "no_token": lambda: _request(),
    }


@pytest.mark.parametrize("kind", ["url", "method", "token", "no_token"])
async def test_total_sink_outage_on_a_refusal_raises_audit_emission_error(kind):
    t = _transport(emitter=AuditEmitter([_FailingSink()]))
    with pytest.raises(AuditEmissionError):
        await t.handle_async_request(_refusal_requests()[kind]())


async def test_total_sink_outage_on_a_replay_refusal_raises_audit_emission_error():
    good_sink = RecordingSink()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    tok = _token()
    t = _transport(emitter=AuditEmitter([good_sink]), inner=inner)
    await t.handle_async_request(_request(token=tok))
    t._emitter = AuditEmitter([_FailingSink()])
    with pytest.raises(AuditEmissionError):
        await t.handle_async_request(_request(token=tok))


async def test_one_failing_sink_out_of_two_does_not_stop_the_request():
    sink = RecordingSink()
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(return_value=_response())
    t = _transport(emitter=AuditEmitter([_FailingSink(), sink]), inner=inner)
    response = await t.handle_async_request(_request(token=_token()))
    assert response.status_code == 200
    assert len(sink.events) == 1
    assert sink.events[0].status == "allowed"


async def test_failure_records_carry_no_exception_message_or_url_query(caplog):
    sink = RecordingSink()
    exc = httpx.ConnectError("secret-message https://mcp.slack.com/m?token=hunter2")
    t = _transport(emitter=AuditEmitter([sink]), inner=_failing_inner(exc))
    with caplog.at_level("DEBUG"), pytest.raises(httpx.ConnectError):
        await t.handle_async_request(_request(token=_token()))
    dumped = sink.events[0].model_dump_json()
    assert "secret-message" not in dumped
    assert "hunter2" not in sink.events[0].deny_reason
    assert "secret-message" not in caplog.text
    assert "hunter2" not in caplog.text


async def test_one_event_per_request_on_an_untokened_audit_failure():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), config=_config(token_policy="audit"),
                   inner=_failing_inner(httpx.ConnectError("x")))
    with pytest.raises(httpx.ConnectError):
        await t.handle_async_request(_request())
    assert len(sink.events) == 1
    assert sink.events[0].status == "failed"
    assert sink.events[0].token_id is None


# ── The caller: tokens bind the agent, and events carry it ─────────────────

AGENT_B = AgentContext(agent_id="second_agent", sub_agent_id="sub_b")
WRONG_AGENT = "token was issued for another agent"


async def _ok_inner():
    inner = AsyncMock()
    inner.handle_async_request = AsyncMock(side_effect=lambda r: _response())
    return inner


async def test_token_presented_by_its_own_caller_is_allowed_and_attributed():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=await _ok_inner())
    await t.handle_async_request(_request(token=_token()))
    assert [(e.status, e.agent_id, e.sub_agent_id) for e in sink.events] == [
        ("allowed", AGENT, None),
    ]


async def test_token_presented_by_another_agent_is_denied_not_burned():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=await _ok_inner())
    tok = _token()
    with pytest.raises(NetworkPolicyError) as info:
        await t.handle_async_request(_request(token=tok, caller=AGENT_B))
    assert str(info.value) == WRONG_AGENT
    denied = sink.events[0]
    assert (denied.status, denied.deny_reason) == ("denied", WRONG_AGENT)
    assert (denied.agent_id, denied.sub_agent_id) == ("second_agent", "sub_b")
    assert AGENT not in denied.deny_reason and "sub_b" not in denied.deny_reason

    # The refusal did not consume the nonce: its own agent can still use it.
    await t.handle_async_request(_request(token=tok))
    assert sink.events[1].status == "allowed"
    assert sink.events[1].agent_id == AGENT
    assert len(sink.events) == 2


async def test_token_with_a_subagent_is_denied_when_the_caller_has_none():
    t = _transport(inner=await _ok_inner())
    with pytest.raises(NetworkPolicyError, match=WRONG_AGENT):
        await t.handle_async_request(_request(token=_token(sub_agent_id="sub_b")))


async def test_token_without_a_subagent_is_denied_for_a_subagent_caller():
    t = _transport(inner=await _ok_inner())
    caller = AgentContext(agent_id=AGENT, sub_agent_id="sub_b")
    with pytest.raises(NetworkPolicyError, match=WRONG_AGENT):
        await t.handle_async_request(_request(token=_token(), caller=caller))


async def test_token_for_another_tenant_is_denied():
    t = _transport(inner=await _ok_inner())
    with pytest.raises(NetworkPolicyError, match=WRONG_AGENT):
        await t.handle_async_request(_request(token=_token(tenant_id="other-tenant")))


async def test_request_with_no_caller_is_denied_and_audited():
    sink = RecordingSink()
    t = _transport(emitter=AuditEmitter([sink]), inner=await _ok_inner())
    with pytest.raises(NetworkPolicyError, match="no caller"):
        await t.handle_async_request(_request(token=_token(), caller=None))
    assert len(sink.events) == 1
    assert sink.events[0].status == "denied"


async def test_a_caller_that_is_not_an_agent_context_is_refused():
    t = _transport(inner=await _ok_inner())
    req = _request(token=_token())
    req.extensions["shai_caller"] = {"agent_id": AGENT}
    with pytest.raises(NetworkPolicyError, match="no caller"):
        await t.handle_async_request(req)


@pytest.mark.parametrize("first", ["a", "b"])
async def test_two_agents_sharing_one_source_are_each_attributed(first):
    sink = RecordingSink()
    seen: list[httpx.Request] = []
    src = _wired_source(seen, sink)
    calls = {
        "a": (CALLER, _token()),
        "b": (AGENT_B, _token(agent_id="second_agent", sub_agent_id="sub_b")),
    }
    order = [first, "b" if first == "a" else "a"]
    for key in order:
        ctx, tok = calls[key]
        await src.call("search_docs", {}, ctx=ctx, dispatch_token=tok)
    attributed = [(e.status, e.agent_id, e.sub_agent_id) for e in sink.events]
    expected = {"a": ("allowed", AGENT, None), "b": ("allowed", "second_agent", "sub_b")}
    assert attributed == [expected[k] for k in order]


async def test_a_source_call_with_another_agents_token_is_refused():
    sink = RecordingSink()
    src = _wired_source([], sink)
    with pytest.raises(NetworkPolicyError, match=WRONG_AGENT):
        await src.call("search_docs", {}, ctx=AGENT_B, dispatch_token=_token())
    assert sink.events[0].agent_id == "second_agent"


async def test_connect_phase_requests_are_attributed_to_the_loading_agent():
    sink = RecordingSink()
    seen: list[httpx.Request] = []
    src = _wired_source(seen, sink)
    loader = AgentContext(agent_id="loader", sub_agent_id="sub_l")
    src._agent_ctx = loader

    async def mint(ctx, *, method, destination):
        assert ctx is loader
        return _connect_token(agent_id="loader", sub_agent_id="sub_l")

    src._mint_connect_token = mint
    await src._initialize_session()
    assert sink.events, "the handshake sent no requests"
    assert {(e.agent_id, e.sub_agent_id, e.status) for e in sink.events} == {
        ("loader", "sub_l", "allowed"),
    }
