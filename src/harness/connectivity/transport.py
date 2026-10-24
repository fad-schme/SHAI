"""ShaiTransport — httpx transport hook for in-process egress enforcement.

Sits inside MCPSource's httpx.AsyncClient. Every outbound HTTP request
from an MCP source passes through it. Per request:

  0. Read the calling AgentContext from request.extensions["shai_caller"];
     a request that states none is refused
  1. Read dispatch token from request.extensions["shai_dispatch_token"]
  2. Enforce allowed_urls  — NetworkPolicyError if destination not permitted
  3. Enforce allowed_methods — NetworkPolicyError if method not permitted
  4. Inject X-Shai-Token header when token is present
  5. Forward to inner transport (real TCP/TLS connection)
  6. Emit NetworkAuditEvent to AuditEmitter (same sinks as AuditEvent):
     one per request — status allowed, denied, or failed (the forward raised
     or was cancelled). A total audit outage raises AuditEmissionError.

NetworkAuditEvent is distinguished from AuditEvent by event_type="network_egress".
It carries token_id as the join key for SIEM correlation with the gate AuditEvent.

Design decisions:
  - No sidecar, no Docker, no external process required
  - Works on laptop, Lambda, container — any Python deployment
  - Covers all MCPSource HTTP traffic: SSE connection, initialize, tools/call
  - Connect-phase requests (SSE, initialize, tools/list) carry a connect
    token; only the onboarding connection runs untokened, and it is audited
  - URL and method enforcement applies to ALL requests including SSE
  - requires: httpx (now a core shai dependency)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx

from harness.connectivity.token import (
    NonceStore,
    TokenError,
    matches_allowed_url,
    verify_token,
)
from harness.core.context import AgentContext
from harness.core.errors import AuditEmissionError, NetworkPolicyError
from harness.core.events import NetworkAuditEvent

if TYPE_CHECKING:
    from harness.audit.emitter import AuditEmitter
    from harness.connectivity.config import ConnectivityConfig

log = logging.getLogger(__name__)

# The request extension that carries the calling AgentContext, next to the
# dispatch token's "shai_dispatch_token".
CALLER_EXTENSION = "shai_caller"

# The JSON-RPC methods of the MCP session handshake: all a connect token may
# carry besides the SSE GET.
_CONNECT_RPC_METHODS = frozenset({"initialize", "notifications/initialized", "tools/list"})


def _jsonrpc_body(request: httpx.Request) -> dict | None:
    """The JSON-RPC object a POST body carries, None for anything else."""
    if request.method != "POST":
        return None
    try:
        body = json.loads(request.content)
    except (ValueError, httpx.RequestNotRead):
        return None
    return body if isinstance(body, dict) else None


def _jsonrpc_method(request: httpx.Request) -> str | None:
    """The JSON-RPC method a POST body names, None for anything else."""
    body = _jsonrpc_body(request)
    method = body.get("method") if body is not None else None
    return method if isinstance(method, str) else None


def _called_tool_name(request: httpx.Request) -> str | None:
    """The tool a tools/call body names (params.name), None when unreadable."""
    body = _jsonrpc_body(request)
    params = body.get("params") if body is not None else None
    name = params.get("name") if isinstance(params, dict) else None
    return name if isinstance(name, str) else None


def _purpose_permits(purpose: str, http_method: str, rpc_method: str | None) -> bool:
    """A connect token opens the session; a tool-call token carries one
    tools/call. Neither passes as the other."""
    if purpose == "connect":
        return http_method == "GET" or rpc_method in _CONNECT_RPC_METHODS
    return http_method == "POST" and rpc_method == "tools/call"


# ── ShaiTransport ──────────────────────────────────────────────────────────

class ShaiTransport(httpx.AsyncBaseTransport):
    """In-process httpx transport that enforces SHAI connectivity policy.

    Wraps the default httpx transport. Installed on the AsyncClient inside
    MCPSource._connect() for every MCP source.

    onboarding=True marks the `shai mcp onboard` connection. It produces the
    approval tokens are minted from, so it has none: it is exempt from the
    token check only. The URL and method checks still apply, and every one of
    its requests is audited.

    Replay: one NonceStore per transport, so per source. A token is bound to
    one source, so it can only ever be consumed here.
    """

    def __init__(
        self,
        *,
        source_name:     str,
        allowed_urls:    list[str],
        allowed_methods: list[str],
        tenant_id:       str,
        emitter:         AuditEmitter,
        connectivity:    ConnectivityConfig,
        onboarding:      bool = False,
        inner:           httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._source_name     = source_name
        self._allowed_urls    = allowed_urls
        self._allowed_methods = [m.upper() for m in allowed_methods]
        self._tenant_id       = tenant_id
        self._emitter         = emitter
        self._connectivity    = connectivity
        self._onboarding      = onboarding
        self._inner           = inner or httpx.AsyncHTTPTransport()
        self._nonces          = NonceStore()

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        """Validate, optionally inject token header, forward, then audit."""
        start_ms  = int(time.monotonic() * 1000)
        url_str   = str(request.url)
        method    = request.method.upper()
        token_raw = request.extensions.get("shai_dispatch_token")
        token_id  = None
        tool_name = None

        # ── 0. Caller — who is making this request. Every event carries the
        #    caller's identity, never one fixed when the transport was built,
        #    because one source serves every agent that declares it. ─────────
        caller = request.extensions.pop(CALLER_EXTENSION, None)
        if isinstance(caller, AgentContext):
            agent_id, sub_agent_id = caller.agent_id, caller.sub_agent_id
        else:
            caller, agent_id, sub_agent_id = None, "unknown", None
        if caller is None:
            deny_reason = "request states no caller"
            await self._emit(
                agent_id=agent_id, sub_agent_id=sub_agent_id,
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        # ── 1. URL enforcement ────────────────────────────────────────────
        if not matches_allowed_url(url_str, self._allowed_urls):
            deny_reason = (
                f"destination '{url_str}' is not in allowed_urls for "
                f"source '{self._source_name}'"
            )
            await self._emit(
                agent_id=agent_id, sub_agent_id=sub_agent_id,
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        # ── 2. Method enforcement ─────────────────────────────────────────
        if self._allowed_methods and method not in self._allowed_methods:
            deny_reason = (
                f"method '{method}' is not in allowed_methods for "
                f"source '{self._source_name}'"
            )
            await self._emit(
                agent_id=agent_id, sub_agent_id=sub_agent_id,
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        # ── 3. Token validation — signature, binding, nonce ──────────────
        if token_raw:
            try:
                secret = self._connectivity.token_secret.encode()
                token  = verify_token(token_raw, secret)
            except TokenError as e:
                deny_reason = f"invalid dispatch token: {e}"
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=None, tool_name=None,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason) from e

            token_id  = token.token_id
            tool_name = token.tool_name

            # ── 3a. Source binding — token must be for this source ────────
            if token.source_name != self._source_name:
                deny_reason = (
                    f"token source_name '{token.source_name}' does not match "
                    f"transport source '{self._source_name}'"
                )
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # ── Caller binding — a token authorises the agent, subagent and
            #    tenant it was issued to. Checked before the nonce is consumed,
            #    so a token presented by the wrong caller is refused, not
            #    burned. No identifier value appears in the reason. ──────────
            if (token.agent_id != agent_id
                    or token.sub_agent_id != sub_agent_id
                    or token.tenant_id != self._tenant_id):
                deny_reason = "token was issued for another agent"
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # ── Purpose binding — checked before the nonce is consumed, so a
            #    token presented on the wrong request is refused, not burned ─
            if not _purpose_permits(token.purpose, method, _jsonrpc_method(request)):
                deny_reason = (
                    f"token purpose '{token.purpose}' does not permit this "
                    f"{method} request for source '{self._source_name}'"
                )
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # ── Tool binding — a tool-call token authorises the one tool it
            #    was issued for; checked before the nonce is consumed ──────
            if token.purpose == "tool_call":
                called = _called_tool_name(request)
                if called != token.tool_name:
                    deny_reason = (
                        f"token was issued for tool '{token.tool_name}', "
                        f"request names "
                        f"{'no readable tool' if called is None else repr(called)} "
                        f"for source '{self._source_name}'"
                    )
                    await self._emit(
                        agent_id=agent_id, sub_agent_id=sub_agent_id,
                        token_id=token_id, tool_name=tool_name,
                        destination=url_str, method=method,
                        status="denied", deny_reason=deny_reason,
                        bytes_sent=0, bytes_recv=0,
                        duration_ms=int(time.monotonic() * 1000) - start_ms,
                    )
                    raise NetworkPolicyError(deny_reason)

            # ── 3b. URL binding — request must match token's allowed_urls ─
            if not matches_allowed_url(url_str, token.allowed_urls):
                deny_reason = (
                    f"destination '{url_str}' not in token.allowed_urls "
                    f"for source '{self._source_name}'"
                )
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # ── 3c. Method binding — request method must match token's list
            if token.allowed_methods and method not in [m.upper() for m in token.allowed_methods]:
                deny_reason = (
                    f"method '{method}' not in token.allowed_methods "
                    f"for source '{self._source_name}'"
                )
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # ── 3d. Nonce check — prevent replay within TTL window ────────
            deny_reason = self._nonces.consume(token_id, token.expires_at)
            if deny_reason:
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason)

            # Inject token as X-Shai-Token header
            request.headers["X-Shai-Token"] = token_raw
            log.debug("shai token injected",
                      extra={"source": self._source_name,
                             "token_id": token_id,
                             "destination": url_str})

        elif self._onboarding:
            # The onboarding connection has no approval to mint a token from.
            # It is exempt from the token check only; step 5 audits it.
            pass

        # B105 fires on the "strict" literal; it is a policy name, not a password.
        elif self._connectivity.token_policy == "strict":  # nosec B105
            deny_reason = (
                f"no dispatch token on request to '{url_str}' "
                f"(token_policy=strict)"
            )
            await self._emit(
                agent_id=agent_id, sub_agent_id=sub_agent_id,
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        else:
            # token_policy=audit: forwarded, and recorded in step 5 with
            # token_id=None so the untokened request stays visible.
            log.warning("untokened request forwarded (token_policy=audit)",
                        extra={"source": self._source_name, "method": method,
                               "tenant_id": self._tenant_id})

        # ── 4. Forward to inner transport ─────────────────────────────────
        # Remove the extension so httpx doesn't try to serialise it
        request.extensions.pop("shai_dispatch_token", None)

        # Every request that reaches this point ends with exactly one event:
        # allowed after a response is read, failed if the attempt raises or is
        # cancelled first. A token's nonce is consumed above, so an attempt that
        # left no record would be a used token missing from the trail.
        recorded = (token_id is not None or self._onboarding
                    or self._connectivity.token_policy == "audit")
        # The SSE GET is a stream that never ends: it passes through unread,
        # bytes_recv=0. Buffering it to count bytes would hang the connect
        # forever. Every other recorded response is buffered and re-attached.
        streamed = method == "GET"
        bytes_recv = 0
        content = b""
        try:
            response = await self._inner.handle_async_request(request)
            if recorded and not streamed:
                chunks: list[bytes] = []
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                    bytes_recv += len(chunk)
                content = b"".join(chunks)
        except asyncio.CancelledError:
            if recorded:
                await self._emit_failed(
                    "cancelled", agent_id, sub_agent_id, token_id, tool_name, url_str, method,
                    len(request.content), bytes_recv, start_ms,
                )
            raise
        except Exception as exc:
            if recorded:
                # The exception type only: its message can echo the URL or
                # content (Invariant 3).
                await self._emit_failed(
                    type(exc).__name__, agent_id, sub_agent_id, token_id, tool_name, url_str, method,
                    len(request.content), bytes_recv, start_ms,
                )
            raise

        # ── 5. Emit NetworkAuditEvent — every tokened request, every
        #    untokened one forwarded under audit, and every request of the
        #    onboarding connection. AuditEmissionError propagates: a response
        #    whose record cannot be written is not returned. ───────────────
        if recorded:
            try:
                await self._emit(
                    agent_id=agent_id, sub_agent_id=sub_agent_id,
                    token_id=token_id, tool_name=tool_name,
                    destination=url_str, method=method,
                    status="allowed", deny_reason=None,
                    bytes_sent=len(request.content),
                    bytes_recv=len(content),
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
            except AuditEmissionError:
                await response.aclose()
                raise
            if not streamed:
                response = httpx.Response(
                    status_code=response.status_code,
                    headers=response.headers,
                    content=content,
                    request=request,
                )

        return response

    async def _emit_failed(
        self, reason: str, agent_id: str, sub_agent_id: str | None,
        token_id: str | None, tool_name: str | None,
        destination: str, method: str, bytes_sent: int, bytes_recv: int,
        start_ms: int,
    ) -> None:
        await self._emit(
            agent_id=agent_id, sub_agent_id=sub_agent_id,
            token_id=token_id, tool_name=tool_name,
            destination=destination, method=method,
            status="failed", deny_reason=reason,
            bytes_sent=bytes_sent, bytes_recv=bytes_recv,
            duration_ms=int(time.monotonic() * 1000) - start_ms,
        )

    async def _emit(
        self, *, agent_id: str, sub_agent_id: str | None, token_id: str | None, tool_name: str | None,
        destination: str, method: str, status: str, deny_reason: str | None,
        bytes_sent: int, bytes_recv: int, duration_ms: int,
    ) -> None:
        event = NetworkAuditEvent(
            timestamp    = datetime.now(UTC),
            event_type   = "network_egress",
            token_id     = token_id,
            source_name  = self._source_name,
            agent_id     = agent_id,
            sub_agent_id = sub_agent_id,
            tenant_id    = self._tenant_id,
            tool_name    = tool_name,
            destination  = destination,
            method       = method,
            status       = status,
            deny_reason  = deny_reason,
            bytes_sent   = bytes_sent,
            bytes_recv   = bytes_recv,
            duration_ms  = duration_ms,
        )
        # No catch-all: the emitter absorbs a single sink failure itself and
        # raises AuditEmissionError only when every sink failed. That error
        # reaches the caller, so a request is never allowed or refused without
        # a record.
        await self._emitter.emit(event)

    async def aclose(self) -> None:
        await self._inner.aclose()
