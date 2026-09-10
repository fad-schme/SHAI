"""Tests for connectivity/token.py — dispatch token issuance and verification."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from harness.connectivity.token import (
    DispatchToken,
    TokenError,
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
    """A token whose signature is valid but whose expiry has passed is refused.

    Signed here rather than via sign_token() because that always issues from
    `now` — the case under test is a correctly signed token that has aged out,
    not a tampered one.
    """
    import dataclasses

    from harness.connectivity.token import _SIGNED_FIELDS
    from harness.core.signing import claims_of, sign

    tok     = _token(ttl_seconds=1)
    expired = dataclasses.replace(
        tok, expires_at=datetime.now(UTC) - timedelta(seconds=60), signature="",
    )
    expired = dataclasses.replace(
        expired, signature=sign(claims_of(expired, _SIGNED_FIELDS), SECRET)
    )
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


# ── URL matching: canonicalization hardening (SHAI-scope-canonicalization) ─

def test_matches_allowed_url_is_case_insensitive_on_host():
    assert matches_allowed_url(
        "https://SLACK.COM/api/x", ["https://slack.com/api/*"]
    )
    assert matches_allowed_url(
        "https://slack.com/api/x", ["https://SLACK.COM/api/*"]
    )


def test_matches_allowed_url_denies_userinfo_smuggling():
    """A userinfo-bearing URL is denied outright — it never falls back to a
    raw-string comparison against either the pre-@ or post-@ substring."""
    assert not matches_allowed_url(
        "https://good.test@slack.com.evil.test/api/x",
        ["https://slack.com/api/*"],
    )
    # Even when the post-@ host would otherwise match the allowlist.
    assert not matches_allowed_url(
        "https://x@slack.com/api/y", ["https://slack.com/api/*"]
    )


def test_matches_allowed_url_denies_malformed_url_without_raw_fallback():
    """A url that fails to canonicalize is denied, never compared as a raw
    string — even against a pattern that would trivially string-match it."""
    assert not matches_allowed_url("not a url", ["not a url"])


def test_matches_allowed_url_skips_uncanonicalizable_pattern():
    """A malformed allowlist entry is skipped, not treated as matching
    everything and not treated as denying everything else in the list."""
    assert matches_allowed_url(
        "https://slack.com/api/x", ["not a pattern", "https://slack.com/api/*"]
    )


def test_matches_allowed_url_preserves_port_and_query():
    assert matches_allowed_url(
        "https://SLACK.COM:8443/api/x?q=1", ["https://slack.com:8443/api/*"]
    )
    assert not matches_allowed_url(
        "https://slack.com:9999/api/x", ["https://slack.com:8443/api/*"]
    )


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
        "connectivity:\n"
        "  enabled: true\n"
        "  token_secret: 'secret://SHAI_TEST_TOKEN_SECRET2'\n"
    )
    # The deny now comes from the agent's own rules — global policy no longer
    # arbitrates tool calls. What is under test is unchanged: a denied gate
    # decision carries no dispatch token.
    agent = tmp_path / "agent.yaml"
    agent.write_text("""id: agent_c
allowed_tool_names:
  - search_docs
allowed_tags:
  - read
policy_rules:
  - id: deny_all
    match: {}
    action: deny
    reason: all denied
""", encoding="utf-8")
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


# ── token_id joins the gate event to the network event (SHAI-007) ─────────

async def test_gate_event_carries_the_token_id_it_issued(tmp_path):
    """Regression (SHAI-007): AuditEvent.token_id was structurally always null.

    The gate emitted its allow event, then the facade minted the token
    afterwards — so the field documented as the SIEM join key with
    NetworkAuditEvent never held a value, and the join had only a right-hand
    side. The token is now minted before the event is built.
    """
    import os

    from harness import SHAI, Tool
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import AgentContext
    from harness.core.types import Transport
    from tests.conftest import RecordingSink

    os.environ["SHAI_TEST_TOKEN_SECRET"] = "a-strong-test-secret-1234567890ab"
    try:
        cfg = tmp_path / "h.yaml"
        cfg.write_text(
            "version: 1\n"
            "scan_input:\n  enabled: false\n"
            "scan_output:\n  enabled: false\n"
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
        sink = RecordingSink()
        harness._emitter = AuditEmitter([sink])
        await harness.register_tools([
            Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
        ])
        await harness.load_agent(agent)

        ctx  = AgentContext(agent_id="agent_a")
        gate = await harness.check_tool_call("search_docs", {"q": "x"}, ctx)
        assert gate.allowed and gate.dispatch_token

        gate_events = [e for e in sink.events if e.boundary == "tool_call_gate"]
        assert len(gate_events) == 1
        event = gate_events[0]

        assert event.token_id, "gate event carries no token_id — the join is broken"
        # The id on the event must be the id inside the token handed to the caller.
        issued = verify_token(gate.dispatch_token, b"a-strong-test-secret-1234567890ab")
        assert event.token_id == issued.token_id
        assert gate.source_name is not None
        await harness.close()
    finally:
        del os.environ["SHAI_TEST_TOKEN_SECRET"]


async def test_no_token_id_when_connectivity_disabled(tmp_path):
    """Connectivity off issues no token, so the field stays null."""
    from harness import SHAI, Tool
    from harness.audit.emitter import AuditEmitter
    from harness.core.context import AgentContext
    from harness.core.types import Transport
    from tests.conftest import RecordingSink

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_a\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    sink = RecordingSink()
    harness._emitter = AuditEmitter([sink])
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent)

    gate = await harness.check_tool_call("search_docs", {}, AgentContext(agent_id="agent_a"))
    assert gate.allowed
    assert gate.dispatch_token is None
    assert sink.events[0].token_id is None
    await harness.close()


async def test_denied_call_mints_no_token(tmp_path):
    """issue_token runs on the allow path only — a refusal signs nothing."""
    import os

    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport

    os.environ["SHAI_TEST_TOKEN_SECRET"] = "a-strong-test-secret-1234567890ab"
    try:
        cfg = tmp_path / "h.yaml"
        cfg.write_text(
            "version: 1\n"
            "scan_input:\n  enabled: false\n"
            "scan_output:\n  enabled: false\n"
            "connectivity:\n"
            "  enabled: true\n"
            "  token_secret: 'secret://SHAI_TEST_TOKEN_SECRET'\n"
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

        # Not in allowed_tool_names — denied at L1, before any token work.
        gate = await harness.check_tool_call("other_tool", {}, AgentContext(agent_id="agent_a"))
        assert not gate.allowed
        assert gate.dispatch_token is None
        await harness.close()
    finally:
        del os.environ["SHAI_TEST_TOKEN_SECRET"]


# ── The token is bound to the source's manifest ──────────────────────────

CONNECTIVITY_SECRET = b"test-connectivity-secret"


async def _declared_mcp_harness(tmp_path, monkeypatch, manifest_extra: str,
                                *, agent_tools: tuple[str, ...] = ("remote_read",)):
    """Connectivity on, one declared and approved MCP source whose manifest
    carries manifest_extra. Connect and tool fetch are stubbed: minting is
    under test, not the wire."""
    from harness.audit.emitter import AuditEmitter
    from harness.core.harness import SHAI
    from harness.core.types import Transport
    from harness.mcp.baseline import record_baseline
    from harness.mcp.manifest import manifest_file_hash
    from harness.tools.source import MCPSource
    from harness.tools.tool import Tool
    from tests.conftest import RecordingSink

    async def fake_connect(self):
        self._connected = True

    async def fake_fetch_tools(self):
        return [Tool(name="remote_read", tags=["read"], transport=Transport.MCP,
                     source_name=self.name)]

    monkeypatch.setattr(MCPSource, "_connect", fake_connect)
    monkeypatch.setattr(MCPSource, "_fetch_tools", fake_fetch_tools)

    mcp_dir = tmp_path / "mcp"
    mcp_dir.mkdir()
    baseline_db = tmp_path / "baseline.db"
    manifest_path = mcp_dir / "remote_mcp.yaml"
    manifest_path.write_text(
        "id: remote_mcp\ndisplay_name: \"remote\"\n"
        "url: \"https://mcp.example.com/sse\"\n" + manifest_extra
    )
    record_baseline(baseline_db, "remote_mcp", manifest_file_hash(manifest_path), b"test-secret")

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "sources:\n  - name: remote_mcp\n    transport: mcp\n"
        f"mcp_manifests_dir: {mcp_dir}\n"
        f"mcp_baseline:\n  path: {baseline_db}\n  secret: test-secret\n"
        "connectivity:\n  enabled: true\n"
        f"  token_secret: {CONNECTIVITY_SECRET.decode()}\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_m\n"
        "sources:\n  - remote_mcp\n"
        "allowed_tool_names:\n" + "".join(f"  - {t}\n" for t in agent_tools) +
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    sink = RecordingSink()
    harness._emitter = AuditEmitter([sink])
    ctx = await harness.load_agent(agent)
    return harness, ctx, sink


async def test_token_for_declared_mcp_source_carries_manifest_allow_lists(tmp_path, monkeypatch):
    """Regression: minting read url/allowed_urls/allowed_methods off the
    harness.yaml SourceConfig, which declares an MCP source by name only, so
    every allowed call to a declared MCP source raised AttributeError out of
    check_tool_call with no audit event."""
    harness, ctx, sink = await _declared_mcp_harness(
        tmp_path, monkeypatch,
        'allowed_urls: ["https://mcp.example.com/api/*"]\nallowed_methods: [POST]\n',
    )

    gate = await harness.check_tool_call("remote_read", {}, ctx)

    assert gate.allowed
    tok = verify_token(gate.dispatch_token, CONNECTIVITY_SECRET)
    assert tok.source_name == "remote_mcp"
    assert tok.allowed_urls == ["https://mcp.example.com/api/*"]
    assert tok.allowed_methods == ["POST"]
    gate_events = [e for e in sink.events if e.boundary == "tool_call_gate"]
    assert len(gate_events) == 1
    assert gate_events[0].token_id == tok.token_id
    await harness.close()


async def test_mcp_manifest_without_allowed_urls_denies_instead_of_minting(tmp_path, monkeypatch):
    """A token bound to no destinations would pass ShaiTransport's URL binding
    unchecked. With nothing to bind, the call is refused with one gate event."""
    harness, ctx, sink = await _declared_mcp_harness(tmp_path, monkeypatch, "")

    gate = await harness.check_tool_call("remote_read", {}, ctx)

    assert not gate.allowed
    assert gate.dispatch_token is None
    assert "allowed_urls" in gate.deny_reason
    gate_events = [e for e in sink.events if e.boundary == "tool_call_gate"]
    assert len(gate_events) == 1
    assert gate_events[0].token_id is None
    await harness.close()


async def test_gate_token_reaches_shai_transport_and_joins_the_network_event(tmp_path, monkeypatch):
    """End to end: check_tool_call → dispatch_remote → the declared MCPSource
    → ShaiTransport. The network event carries the token_id of the gate
    event that authorised it. Only the network under ShaiTransport is mocked."""
    import httpx

    from harness.connectivity.transport import ShaiTransport
    from harness.core.events import NetworkAuditEvent
    from harness.integrations.base import dispatch_remote

    harness, ctx, sink = await _declared_mcp_harness(
        tmp_path, monkeypatch, 'allowed_urls: ["https://mcp.example.com/*"]\n',
    )
    source = await harness.get_source("remote_mcp")
    seen: list[httpx.Request] = []

    def network(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": "1", "result": {}})

    # The transport _connect would build for this source, over a mocked network.
    source._client = httpx.AsyncClient(
        base_url="https://mcp.example.com",
        transport=ShaiTransport(
            source_name="remote_mcp",
            allowed_urls=["https://mcp.example.com/*"],
            allowed_methods=["GET", "POST"],
            agent_id=ctx.agent_id,
            sub_agent_id=None,
            tenant_id=harness._tenant_id,
            emitter=harness._emitter,
            connectivity=harness._connectivity,
            inner=httpx.MockTransport(network),
        ),
    )
    source._session_id = "sess"

    gate = await harness.check_tool_call("remote_read", {}, ctx)
    await dispatch_remote(harness, "remote_read", {}, gate)

    assert seen[0].headers.get("X-Shai-Token") == gate.dispatch_token
    gate_event = next(e for e in sink.events if e.boundary == "tool_call_gate")
    net_events = [e for e in sink.events if isinstance(e, NetworkAuditEvent)]
    assert len(net_events) == 1
    assert net_events[0].status == "allowed"
    assert net_events[0].token_id == gate_event.token_id
    await harness.close()


async def test_local_tool_named_after_mcp_source_gets_no_destinations(tmp_path, monkeypatch):
    """Whether a token binds a manifest is decided by the tool's transport,
    the same test the pre-gate check uses, not by its source_name. A local
    tool whose source_name names an MCP source must not be minted a token
    that source's ShaiTransport would accept."""
    from harness.core.types import Transport
    from harness.tools.tool import Tool

    harness, ctx, _ = await _declared_mcp_harness(
        tmp_path, monkeypatch,
        'allowed_urls: ["https://mcp.example.com/api/*"]\n',
        agent_tools=("remote_read", "local_lookalike"),
    )
    await harness.register_tools([
        Tool(name="local_lookalike", tags=["read"], transport=Transport.LOCAL,
             source_name="remote_mcp"),
    ])

    gate = await harness.check_tool_call("local_lookalike", {}, ctx)

    assert gate.allowed
    tok = verify_token(gate.dispatch_token, CONNECTIVITY_SECRET)
    assert tok.allowed_urls == []
    assert tok.allowed_methods == []
    await harness.close()


async def test_local_tool_token_carries_no_destinations(tmp_path):
    """A local tool has no network target: its token binds no URL and no
    method, so it can never pass ShaiTransport's checks."""
    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport

    cfg = tmp_path / "h.yaml"
    cfg.write_text(
        "version: 1\n"
        "scan_input:\n  enabled: false\n"
        "scan_output:\n  enabled: false\n"
        "connectivity:\n  enabled: true\n"
        f"  token_secret: {CONNECTIVITY_SECRET.decode()}\n"
    )
    agent = tmp_path / "agent.yaml"
    agent.write_text(
        "id: agent_l\n"
        "allowed_tool_names:\n  - search_docs\n"
        "allowed_tags:\n  - read\n"
    )
    harness = await SHAI.from_yaml(cfg)
    await harness.register_tools([
        Tool(name="search_docs", tags=["read"], transport=Transport.LOCAL)
    ])
    await harness.load_agent(agent)

    gate = await harness.check_tool_call("search_docs", {}, AgentContext(agent_id="agent_l"))

    tok = verify_token(gate.dispatch_token, CONNECTIVITY_SECRET)
    assert tok.allowed_urls == []
    assert tok.allowed_methods == []
    await harness.close()
