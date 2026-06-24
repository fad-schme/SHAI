"""ShaiTransport — httpx transport hook for in-process egress enforcement.

Sits inside MCPSource's httpx.AsyncClient. Every outbound HTTP request
from an MCP source passes through it. Per request:

  1. Read dispatch token from request.extensions["shai_dispatch_token"]
  2. Enforce allowed_urls  — NetworkPolicyError if destination not permitted
  3. Enforce allowed_methods — NetworkPolicyError if method not permitted
  4. Inject X-Shai-Token header when token is present
  5. Forward to inner transport (real TCP/TLS connection)
  6. Emit NetworkAuditEvent to AuditEmitter (same sinks as AuditEvent)

NetworkAuditEvent is distinguished from AuditEvent by event_type="network_egress".
It carries token_id as the join key for SIEM correlation with the gate AuditEvent.

Design decisions:
  - No sidecar, no Docker, no external process required
  - Works on laptop, Lambda, container — any Python deployment
  - Covers all MCPSource HTTP traffic: SSE connection, initialize, tools/call
  - Non-tool-call requests (SSE, init) carry no token → no NetworkAuditEvent
    emitted for them by default (no_token_policy=permissive for these)
  - URL and method enforcement applies to ALL requests including SSE
  - requires: httpx (now a core shai dependency)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import httpx

from harness.connectivity.token import (
    TokenError,
    matches_allowed_url,
    verify_token,
)
from harness.core.errors import NetworkPolicyError

if TYPE_CHECKING:
    from harness.audit.emitter import AuditEmitter
    from harness.connectivity.config import ConnectivityConfig

log = logging.getLogger(__name__)


# ── NetworkAuditEvent ──────────────────────────────────────────────────────

@dataclass(frozen=True)
class NetworkAuditEvent:
    """Audit event emitted per outbound HTTP request from an MCP source.

    event_type="network_egress" distinguishes these from boundary AuditEvents.
    token_id is the join key with the gate AuditEvent in the SIEM:

        SELECT gate.*, net.*
        FROM audit_events gate
        JOIN network_audit_events net ON gate.token_id = net.token_id
        WHERE gate.agent_id = 'orchestrator_agent'

    Written to the same AuditEmitter sinks as AuditEvent (file, stdout, etc.).
    """
    timestamp:    datetime
    event_type:   str           # always "network_egress"
    token_id:     str | None    # DispatchToken.token_id — join key with AuditEvent
    source_name:  str           # MCPSource.name
    agent_id:     str
    sub_agent_id: str | None
    tenant_id:    str
    tool_name:    str | None    # None for SSE/init requests
    destination:  str           # full URL
    method:       str
    status:       str           # "allowed" | "denied"
    deny_reason:  str | None
    bytes_sent:   int
    bytes_recv:   int
    duration_ms:  int

    def model_dump_json(self) -> str:
        """Emit as JSON for AuditEmitter sinks (matches AuditEvent interface)."""
        import json
        return json.dumps({
            "timestamp":    self.timestamp.isoformat(),
            "event_type":   self.event_type,
            "token_id":     self.token_id,
            "source_name":  self.source_name,
            "agent_id":     self.agent_id,
            "sub_agent_id": self.sub_agent_id,
            "tenant_id":    self.tenant_id,
            "tool_name":    self.tool_name,
            "destination":  self.destination,
            "method":       self.method,
            "status":       self.status,
            "deny_reason":  self.deny_reason,
            "bytes_sent":   self.bytes_sent,
            "bytes_recv":   self.bytes_recv,
            "duration_ms":  self.duration_ms,
        }, default=str)


# ── ShaiTransport ──────────────────────────────────────────────────────────

class ShaiTransport(httpx.AsyncBaseTransport):
    """In-process httpx transport that enforces SHAI connectivity policy.

    Wraps the default httpx transport. Installed on the AsyncClient inside
    MCPSource._connect() when connectivity.enabled=True.

    Thread/task safety: stateless per request. Multiple concurrent MCP
    calls are safe — each request is independently validated.
    """

    def __init__(
        self,
        *,
        source_name:     str,
        allowed_urls:    list[str],
        allowed_methods: list[str],
        agent_id:        str,
        sub_agent_id:    str | None,
        tenant_id:       str,
        emitter:         "AuditEmitter",
        connectivity:    "ConnectivityConfig",
        inner:           httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._source_name     = source_name
        self._allowed_urls    = allowed_urls
        self._allowed_methods = [m.upper() for m in allowed_methods]
        self._agent_id        = agent_id
        self._sub_agent_id    = sub_agent_id
        self._tenant_id       = tenant_id
        self._emitter         = emitter
        self._connectivity    = connectivity
        self._inner           = inner or httpx.AsyncHTTPTransport()

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

        # ── 1. URL enforcement ────────────────────────────────────────────
        if self._allowed_urls and not matches_allowed_url(url_str, self._allowed_urls):
            deny_reason = (
                f"destination '{url_str}' is not in allowed_urls for "
                f"source '{self._source_name}'"
            )
            await self._emit(
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
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        # ── 3. Token handling ─────────────────────────────────────────────
        if token_raw:
            # Verify signature and extract metadata for the audit event
            try:
                secret = self._connectivity.token_secret.encode()
                token  = verify_token(token_raw, secret)
                token_id  = token.token_id
                tool_name = token.tool_name
            except TokenError as e:
                deny_reason = f"invalid dispatch token: {e}"
                await self._emit(
                    token_id=None, tool_name=None,
                    destination=url_str, method=method,
                    status="denied", deny_reason=deny_reason,
                    bytes_sent=0, bytes_recv=0,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                )
                raise NetworkPolicyError(deny_reason) from e

            # Inject token as X-Shai-Token header
            request.headers["X-Shai-Token"] = token_raw
            log.debug("shai token injected",
                      extra={"source": self._source_name,
                             "token_id": token_id,
                             "destination": url_str})

        elif self._connectivity.no_token_policy == "strict":
            # strict mode: reject requests with no token
            # (not suitable for SSE/init — use permissive for those)
            deny_reason = (
                f"no dispatch token on request to '{url_str}' "
                f"(no_token_policy=strict)"
            )
            await self._emit(
                token_id=None, tool_name=None,
                destination=url_str, method=method,
                status="denied", deny_reason=deny_reason,
                bytes_sent=0, bytes_recv=0,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
            )
            raise NetworkPolicyError(deny_reason)

        # ── 4. Forward to inner transport ─────────────────────────────────
        # Remove the extension so httpx doesn't try to serialise it
        request.extensions.pop("shai_dispatch_token", None)

        response    = await self._inner.handle_async_request(request)
        duration_ms = int(time.monotonic() * 1000) - start_ms

        # ── 5. Emit NetworkAuditEvent (only for tool calls with a token) ──
        if token_id is not None:
            content = await response.aread()
            await self._emit(
                token_id=token_id, tool_name=tool_name,
                destination=url_str, method=method,
                status="allowed", deny_reason=None,
                bytes_sent=len(request.content),
                bytes_recv=len(content),
                duration_ms=duration_ms,
            )
            # Re-attach body so the caller can read it
            response = httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=content,
                request=request,
            )

        return response

    async def _emit(
        self, *, token_id: str | None, tool_name: str | None,
        destination: str, method: str, status: str, deny_reason: str | None,
        bytes_sent: int, bytes_recv: int, duration_ms: int,
    ) -> None:
        event = NetworkAuditEvent(
            timestamp    = datetime.now(timezone.utc),
            event_type   = "network_egress",
            token_id     = token_id,
            source_name  = self._source_name,
            agent_id     = self._agent_id,
            sub_agent_id = self._sub_agent_id,
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
        try:
            await self._emitter.emit(event)  # type: ignore[arg-type]
        except Exception as e:
            log.error("failed to emit NetworkAuditEvent",
                      extra={"source": self._source_name, "error": str(e)})

    async def aclose(self) -> None:
        await self._inner.aclose()
