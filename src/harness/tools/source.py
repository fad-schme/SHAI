"""ToolSource implementations and SourceRegistry.

ToolSource:     Protocol every source adapter must satisfy.
SourceRegistry: Concrete registry. activate() builds an agent's tool set from
                its declared sources — called once at load_agent() time.

Implementations
---------------
LocalSource:    Returns a named subset of already-registered tools.
                No network; no external dependencies.

MCPSource:      Connects to an MCP server over SSE, discovers its tool catalog,
                and exposes a call() method for tool invocation.
                Requires: httpx>=0.27  (included in shai core)

Transport routing
-----------------
Tool.transport tells the caller (agent dispatch layer) how to invoke the tool:
  LOCAL  → call the Python callable already registered in the agent's runtime
  MCP    → call MCPSource.call(tool_name, arguments) on the source that owns it

The harness gates; it does not dispatch. MCPSource.call() is the production
dispatch path for MCP tools — callers hold a reference to the source object
returned by SHAI.get_source(name) and call it directly.
"""
from __future__ import annotations

import asyncio
import json
import logging

import httpx
import time
import uuid
from typing import TYPE_CHECKING, Any, AsyncIterator, Iterable, Protocol

from harness.core.errors import ConfigError, MCPInvocationError
from harness.core.types import Transport
from harness.tools.registry import ToolRegistry
from harness.tools.tool import Tool

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.policy.engine import PolicyEngine

log = logging.getLogger(__name__)


# ── ToolSource Protocol ───────────────────────────────────────────────────

class ToolSource(Protocol):
    """Interface every source adapter must satisfy."""

    name:      str
    transport: str
    tags:      list[str]

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        """Return tools available from this source for this agent context.

        Called once at load_agent() time — not per turn.
        Must be idempotent: calling load() again returns the same tools.
        """
        ...

    async def close(self) -> None:
        """Release any held connections or resources. Called at SHAI.close()."""
        ...


# ── SourceRegistry ────────────────────────────────────────────────────────

class SourceRegistry:
    """Concrete registry for ToolSource objects.

    Satisfies SHAIRegistry[ToolSource] structurally.
    activate() is the main entry point — called by SHAI.load_agent() to
    build the merged tool set for an agent from its declared sources.
    """

    def __init__(self, policy: "PolicyEngine") -> None:
        self._sources: dict[str, ToolSource] = {}
        self._policy  = policy

    async def register(self, item: ToolSource) -> bool:
        """True = newly registered. False = same object already registered.
        Raises ConfigError on name collision with a different object.
        """
        existing = self._sources.get(item.name)
        if existing is None:
            self._sources[item.name] = item
            log.debug("source registered", extra={"source": item.name})
            return True
        if existing is item:
            return False
        raise ConfigError(
            f"source '{item.name}' already registered with a different object",
            op="register_source",
        )

    async def deregister(self, item: ToolSource) -> bool:
        """True = removed. False = was not registered."""
        if item.name in self._sources:
            del self._sources[item.name]
            log.debug("source deregistered", extra={"source": item.name})
            return True
        return False

    async def register_many(self, items: Iterable[ToolSource]) -> None:
        for item in items:
            await self.register(item)

    async def get(self, name: str) -> ToolSource:
        """Raises ConfigError on miss."""
        source = self._sources.get(name)
        if source is None:
            raise ConfigError(
                f"source '{name}' not registered. "
                f"Known sources: {sorted(self._sources)}",
                op="source_lookup",
            )
        return source

    async def list(self) -> list[ToolSource]:
        return list(self._sources.values())

    async def activate(
        self,
        ctx: "AgentContext",
        source_names: list[str],
        required_flags: dict[str, bool] | None = None,
    ) -> list[Tool]:
        """Activate declared sources and return their merged tool list.

        Called once at load_agent() time.

        Failure handling — controlled per source by required_flags:

        required=True (default):
            Missing source (not registered) → raises ConfigError immediately.
            Failed load (source.load() raised) → raises ConfigError immediately.
            The agent is not considered usable without it.

        required=False:
            Missing source → logged at WARNING, skipped.
            Failed load → logged at ERROR, skipped.
            Use for optional enrichment sources where degraded operation
            is acceptable (e.g. a telemetry or analytics source).

        Policy-suppressed sources are always skipped regardless of required flag —
        suppression is an intentional operator decision, not a failure.
        """
        if required_flags is None:
            required_flags = {}

        tasks: list[tuple[str, bool, asyncio.Task]] = []

        for name in source_names:
            is_required = required_flags.get(name, True)
            source = self._sources.get(name)
            if source is None:
                if is_required:
                    from harness.core.errors import ConfigError as _CE
                    raise _CE(
                        f"source '{name}' declared by agent '{ctx.agent_id}' "
                        f"is not registered in the harness. "                        f"Add it to config.sources or set required: false.",
                        op="source_activate",
                    )
                log.warning("optional source not registered — skipped",
                            extra={"source": name, **ctx.to_log_fields()})
                continue

            decision = await self._policy.evaluate_source(source, ctx)
            if not decision.active:
                log.info("source suppressed by policy",
                         extra={"source": name, "reason": decision.reason,
                                **ctx.to_log_fields()})
                continue

            tasks.append((name, is_required, asyncio.create_task(source.load(ctx))))

        if not tasks:
            return []

        results = await asyncio.gather(
            *[t for _, _, t in tasks],
            return_exceptions=True,
        )

        tools: list[Tool] = []
        for (src_name, is_req, _), result in zip(tasks, results):
            if isinstance(result, Exception):
                if is_req:
                    from harness.core.errors import ConfigError as _CE
                    raise _CE(
                        f"source '{src_name}' failed to load: {result}",
                        op="source_activate",
                    )
                log.error("optional source load failed — skipped",
                          extra={"source": src_name, "error": str(result),
                                 **ctx.to_log_fields()})
            else:
                tools.extend(result)
                log.debug("source activated",
                          extra={"source": src_name, "tools": len(result),
                                 **ctx.to_log_fields()})

        return tools

    async def close(self) -> None:
        """Close all registered sources. Called from SHAI.close()."""
        results = await asyncio.gather(
            *[s.close() for s in self._sources.values()],
            return_exceptions=True,
        )
        for source, result in zip(self._sources.values(), results):
            if isinstance(result, Exception):
                log.warning("source close failed",
                            extra={"source": source.name, "error": str(result)})


# ── LocalSource ───────────────────────────────────────────────────────────

class LocalSource:
    """Returns a named subset of already-registered local tools.

    tool_names:  explicit list of tool names to include. If empty, all
                 tools in the registry are returned (filtered by tags).
    tags:        additional tags applied to all returned tools.
    """

    transport = Transport.LOCAL

    def __init__(
        self,
        registry: ToolRegistry,
        name: str = "local",
        tool_names: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> None:
        self.name       = name
        self.tags       = list(tags or [])
        self._registry  = registry
        self._tool_names = list(tool_names or [])

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        if self._tool_names:
            candidates: list[Tool] = []
            for tname in self._tool_names:
                try:
                    candidates.append(await self._registry.get(tname))
                except Exception:
                    log.warning("local source: tool not found — skipped",
                                extra={"tool": tname, "source": self.name})
        else:
            candidates = await self._registry.list()

        # Apply subagent tag filter if present
        if ctx.allowed_tags is not None:
            allowed = set(ctx.allowed_tags)
            candidates = [t for t in candidates
                          if not (set(t.tags) - allowed)]

        # Merge source-level tags onto each tool
        if self.tags:
            tools = []
            for t in candidates:
                combined = sorted(set(t.tags) | set(self.tags))
                tools.append(t.model_copy(update={"tags": combined}))
        else:
            tools = candidates

        return tools

    async def close(self) -> None:
        pass  # No resources to release



# ── SkillSource ───────────────────────────────────────────────────────────

class SkillSource:
    """A named, explicitly-listed subset of already-registered local tools.

    Identical to LocalSource with a fixed tool_names list and
    transport=Transport.SKILL, which signals to policy rules that these tools
    originate from a skill bundle rather than raw local registration.

    Use LocalSource when you want all-or-filtered local tools.
    Use SkillSource when you want a named, curated subset.
    """

    transport = Transport.SKILL

    def __init__(
        self,
        name: str,
        tool_names: list[str],
        registry: ToolRegistry,
        tags: list[str] | None = None,
    ) -> None:
        self.name        = name
        self.tags        = list(tags or [])
        self._tool_names = list(tool_names)
        self._registry   = registry

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        tools: list[Tool] = []
        for tname in self._tool_names:
            try:
                tool = await self._registry.get(tname)
            except Exception:
                log.warning("skill tool not found — skipped",
                            extra={"tool": tname, "source": self.name})
                continue

            # Apply subagent tag filter if present
            if ctx.allowed_tags is not None:
                if set(tool.tags) - set(ctx.allowed_tags):
                    continue

            # Merge source-level tags onto the tool
            if self.tags:
                combined = sorted(set(tool.tags) | set(self.tags))
                tool = tool.model_copy(update={"tags": combined})

            tools.append(tool)

        log.debug("skill source loaded",
                  extra={"source": self.name,
                         "requested": len(self._tool_names),
                         "returned": len(tools)})
        return tools

    async def close(self) -> None:
        pass  # No resources to release


# ── MCPSource ─────────────────────────────────────────────────────────────

class MCPSource:
    """Connects to an MCP server, discovers its tool catalog, and provides
    tool invocation via the MCP JSON-RPC protocol over SSE.

    MCP protocol reference: https://spec.modelcontextprotocol.io

    Lifecycle
    ---------
    1. Constructed at SHAI.from_yaml() with URL, credentials, and tags.
    2. load(ctx) connects, initialises the session, and fetches the tool list.
       Returns list[Tool] with transport=MCP. Called once per agent at
       load_agent() time.
    3. call(tool_name, arguments) sends a tools/call request and returns the
       result. Called by the agent dispatch layer when executing an MCP tool.
       Not called by the harness itself.
    4. close() tears down the connection. Called from SHAI.close().

    Connection model
    ----------------
    The MCP SSE transport opens a persistent GET /sse connection for receiving
    server-sent events, and sends JSON-RPC requests via POST /message.
    A session_id returned by the server in the SSE stream is included in
    every POST to correlate requests with the session.

    Requires httpx>=0.27 (included in shai core).

    Error handling
    --------------
    Connection failures at load() time raise ConfigError — a broken MCP
    source at startup is a configuration error, not a runtime error.
    Invocation failures at call() time raise MCPInvocationError so the
    agent dispatch layer can handle them gracefully.
    """

    transport = Transport.MCP

    # Timeouts
    CONNECT_TIMEOUT_S = 10.0
    REQUEST_TIMEOUT_S = 30.0
    SSE_READ_TIMEOUT_S = 60.0

    def __init__(
        self,
        name: str,
        url: str,
        credentials:     dict[str, str] | None = None,
        tags:            list[str] | None = None,
        allowed_urls:    list[str] | None = None,
        allowed_methods: list[str] | None = None,
    ) -> None:
        self.name  = name
        self.tags  = list(tags or [])
        self._url  = url.rstrip("/")
        self._creds: dict[str, str] = credentials or {}

        # Connectivity — populated when connectivity.enabled in harness.yaml
        self._allowed_urls:         list[str] = list(allowed_urls or [])
        self._allowed_methods:      list[str] = list(allowed_methods or [])
        self._connectivity:         Any = None   # ConnectivityConfig — set by harness
        self._emitter:              Any = None   # AuditEmitter — set by harness
        self._tenant_id:            str = "default"
        self._agent_ctx:            Any = None   # AgentContext — set at load() time
        # Connector manifest enforcement
        self._connector_tool_specs: dict = {}    # tool_name → {tags, action}
        self._scan_tool_result_on:  set  = set() # tool names requiring scan_tool_result

        self._client: httpx.AsyncClient | None = None
        self._session_id: str | None = None
        self._tools: list[Tool] = []
        self._lock = asyncio.Lock()
        self._connected = False

    # ── Public API ────────────────────────────────────────────────────────

    async def load(self, ctx: "AgentContext") -> list[Tool]:
        """Connect to MCP server and fetch its tool catalog.

        Idempotent — returns cached tools if already connected.
        Raises ConfigError on connection or protocol failure.
        """
        async with self._lock:
            if self._connected:
                return list(self._tools)
            self._agent_ctx = ctx   # used by ShaiTransport for audit events
            await self._connect()
            self._tools = await self._fetch_tools()
            self._connected = True
            log.info("mcp source connected",
                     extra={"source": self.name, "tools": len(self._tools),
                            "url": self._url})
            return list(self._tools)

    async def call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        dispatch_token: str | None = None,
    ) -> Any:
        """Invoke a tool on the MCP server. Returns the tool result.

        dispatch_token:
            When connectivity.enabled, pass gate.dispatch_token here.
            ShaiTransport will attach it as X-Shai-Token on the outbound
            request and emit a NetworkAuditEvent. When None, no token header
            is added (default — no-op when connectivity is disabled).

        Raises MCPInvocationError on server-side errors.
        Raises ConfigError if the source is not connected.
        """
        if not self._connected or self._client is None:
            raise ConfigError(
                f"MCP source '{self.name}' is not connected; "
                "call load() before invoking tools",
                op="mcp_call",
            )

        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments,
            },
        }

        response = await self._post(payload, dispatch_token=dispatch_token)
        self._check_jsonrpc_error(response, tool_name)

        result = response.get("result", {})
        log.debug("mcp tool invoked",
                  extra={"source": self.name, "tool": tool_name})
        return result

    async def close(self) -> None:
        """Close the HTTP client and reset connection state."""
        self._connected = False
        self._session_id = None
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception as e:
                log.warning("mcp source close error",
                            extra={"source": self.name, "error": str(e)})
            finally:
                self._client = None

    # ── Connection ────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        """Open the HTTP client, establish the SSE session, and initialise."""
        headers = self._build_headers()

        transport: httpx.AsyncBaseTransport | None = None
        if (self._connectivity is not None
                and self._connectivity.enabled
                and self._emitter is not None):
            from harness.connectivity.transport import ShaiTransport
            transport = ShaiTransport(
                source_name=self.name,
                allowed_urls=self._allowed_urls,
                allowed_methods=self._allowed_methods,
                agent_id=self._agent_ctx.agent_id if self._agent_ctx else "unknown",
                sub_agent_id=self._agent_ctx.sub_agent_id if self._agent_ctx else None,
                tenant_id=self._tenant_id or "default",
                emitter=self._emitter,
                connectivity=self._connectivity,
            )

        self._client = httpx.AsyncClient(
            base_url=self._url,
            headers=headers,
            timeout=httpx.Timeout(
                connect=self.CONNECT_TIMEOUT_S,
                read=self.SSE_READ_TIMEOUT_S,
                write=self.REQUEST_TIMEOUT_S,
                pool=self.CONNECT_TIMEOUT_S,
            ),
            transport=transport,
        )

        try:
            self._session_id = await self._open_sse_session()
            await self._initialize_session()
        except ConfigError:
            await self.close()
            raise
        except Exception as e:
            await self.close()
            raise ConfigError(
                f"MCP source '{self.name}' failed to connect to {self._url}: {e}",
                op="mcp_connect",
            ) from e

    async def _open_sse_session(self) -> str:
        """Open GET /sse and read the endpoint event to get the session_id.

        The MCP SSE transport sends an 'endpoint' event containing the
        message endpoint URL, which includes the session_id as a query param.
        """
        try:
            async with self._client.stream("GET", "/sse") as response:
                if response.status_code != 200:
                    raise ConfigError(
                        f"MCP source '{self.name}': SSE endpoint returned "
                        f"HTTP {response.status_code}",
                        op="mcp_connect",
                    )
                async for event_type, data in _parse_sse(response):
                    if event_type == "endpoint":
                        # data is the message endpoint path, e.g. /message?sessionId=abc
                        session_id = _extract_session_id(data)
                        if not session_id:
                            raise ConfigError(
                                f"MCP source '{self.name}': endpoint event "
                                f"contained no sessionId: {data!r}",
                                op="mcp_connect",
                            )
                        log.debug("mcp sse session established",
                                  extra={"source": self.name,
                                         "session_id": session_id})
                        return session_id
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(
                f"MCP source '{self.name}': SSE connection failed: {e}",
                op="mcp_connect",
            ) from e

        raise ConfigError(
            f"MCP source '{self.name}': SSE stream ended without endpoint event",
            op="mcp_connect",
        )

    async def _initialize_session(self) -> None:
        """Send MCP initialize request and await the initialized notification."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "shai",
                    "version": "0.1.0",
                },
            },
        }
        response = await self._post(payload)
        self._check_jsonrpc_error(response, "initialize")

        # Send initialized notification (no response expected)
        await self._notify("notifications/initialized", {})
        log.debug("mcp session initialised", extra={"source": self.name})

    # ── Tool catalog ──────────────────────────────────────────────────────

    async def _fetch_tools(self) -> list[Tool]:
        """Fetch the tool list from the MCP server and convert to SHAI Tools."""
        request_id = str(uuid.uuid4())
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/list",
            "params": {},
        }
        response = await self._post(payload)
        self._check_jsonrpc_error(response, "tools/list")

        mcp_tools = response.get("result", {}).get("tools", [])
        tools: list[Tool] = []
        for mcp_tool in mcp_tools:
            tool_name = mcp_tool.get("name", "").strip()
            if not tool_name:
                log.warning("mcp tool with empty name skipped",
                            extra={"source": self.name})
                continue
            description = mcp_tool.get("description") or None
            # Merge source-level tags with per-tool tags from connector manifest
            spec      = self._connector_tool_specs.get(tool_name, {})
            spec_tags = spec.get("tags", [])
            tool_tags = sorted(set(self.tags) | set(spec_tags) | {"mcp"})
            tools.append(Tool(
                name=tool_name,
                tags=tool_tags,
                transport=Transport.MCP,
                description=description,
            ))

        log.debug("mcp tools fetched",
                  extra={"source": self.name, "count": len(tools)})
        return tools

    # ── JSON-RPC helpers ──────────────────────────────────────────────────

    async def _post(self, payload: dict, dispatch_token: str | None = None) -> dict:
        """POST a JSON-RPC request to /message?sessionId=<session_id>."""
        params = {"sessionId": self._session_id} if self._session_id else {}
        try:
            response = await self._client.post(
                "/message",
                json=payload,
                params=params,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise ConfigError(
                f"MCP source '{self.name}': POST /message failed: {e}",
                op="mcp_request",
            ) from e

    async def _notify(self, method: str, params: dict) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        payload = {"jsonrpc": "2.0", "method": method, "params": params}
        params_q = {"sessionId": self._session_id} if self._session_id else {}
        try:
            await self._client.post("/message", json=payload, params=params_q)
        except Exception as e:
            log.debug("mcp notification failed",
                      extra={"source": self.name, "method": method,
                             "error": str(e)})

    def _check_jsonrpc_error(self, response: dict, method: str) -> None:
        """Raise MCPInvocationError if the response contains a JSON-RPC error."""
        error = response.get("error")
        if error:
            code    = error.get("code", -1)
            message = error.get("message", "unknown error")
            raise MCPInvocationError(
                source=self.name,
                tool=method,
                code=code,
                message=message,
            )

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers from credentials dict.

        Credential key conventions:
          'Authorization' → used as-is
          'token'         → 'Authorization: Bearer <value>'
          any other key   → passed as a custom header
        """
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream, application/json",
        }
        for key, value in self._creds.items():
            if key.lower() == "authorization":
                headers["Authorization"] = value
            elif key.lower() == "token":
                headers["Authorization"] = f"Bearer {value}"
            else:
                headers[key] = value
        return headers


# ── SSE parsing helpers ───────────────────────────────────────────────────

async def _parse_sse(
    response: Any,
) -> AsyncIterator[tuple[str, str]]:
    """Parse a Server-Sent Events stream from an httpx streaming response.

    Yields (event_type, data) tuples.
    Skips comment lines (starting with ':').
    Handles multi-line data fields by joining with newlines.
    """
    event_type = "message"
    data_lines: list[str] = []

    async for line in response.aiter_lines():
        line = line.rstrip("\r")

        if line.startswith(":"):
            continue  # SSE comment

        if not line:
            # Empty line = dispatch event
            if data_lines:
                yield event_type, "\n".join(data_lines)
            event_type = "message"
            data_lines = []
            continue

        if line.startswith("event:"):
            event_type = line[6:].strip()
        elif line.startswith("data:"):
            data_lines.append(line[5:].strip())
        # id: and retry: fields are intentionally ignored


def _extract_session_id(endpoint_data: str) -> str | None:
    """Extract sessionId from the endpoint event data.

    The MCP spec sends the message endpoint as the data field, e.g.:
      /message?sessionId=abc123
    """
    import urllib.parse
    # endpoint_data may be a path+query or a full URL
    try:
        parsed = urllib.parse.urlparse(endpoint_data)
        qs = urllib.parse.parse_qs(parsed.query)
        ids = qs.get("sessionId") or qs.get("session_id")
        if ids:
            return ids[0]
    except Exception:
        pass
    return None
