# Tools and Sources Reference

A tool source activates a set of tools for an agent. Sources are declared in
`harness.yaml` under `sources:` and in each `agent-xx.yaml` under `sources:`.
They are activated at `load_agent()` time — not per turn.

---

## Lifecycle

```
await SHAI.from_yaml(path)
  └── constructs SourceRegistry
  └── registers MCPSource or LocalSource for each config.sources entry

await harness.load_agent(path)
  └── AgentRegistry.load(path)
  └── SourceRegistry.activate(ctx, cfg.sources)
        ├── PolicyEngine.evaluate_source(source, ctx)  ← suppress check
        ├── source.load(ctx) [concurrent]
        └── ToolRegistry.register(tool)                ← merge into shared store
  └── _resolve_tools(cfg)   ← filter to allowed_tool_names
```

Tools from sources are merged into the shared `ToolRegistry` and filtered to
the agent's `allowed_tool_names`. The result is stored in
`_agent_tools[agent_id]` and read lock-free on every subsequent turn.

**Call `load_agent()` once per deployment** (not per-turn). The returned
`AgentContext` is lightweight — create multiple for concurrent turns:

```python
ctx = await harness.load_agent("config/agents/my_agent.yaml")

# Run many turns concurrently with the same ctx
await asyncio.gather(
    run_turn(harness, ctx, "question 1"),
    run_turn(harness, ctx, "question 2"),
)
```

---

## Tool descriptor

```python
from harness import Tool
from harness.core.types import Transport

Tool(
    name="search_docs",
    tags=["read", "internal"],
    transport=Transport.LOCAL,   # LOCAL | SKILL | MCP
    description="Search internal docs.",  # optional
)
```

**`tags` matter for:**
- `allowed_tags` gate (L2) — subagent capability enforcement
- Policy rule matching (`tool_tags: [external_write]`)
- Arg scanning (`scan_args_for_tags: [sensitive]`)

**Common tag conventions:**

| Tag | Meaning |
|---|---|
| `read` | Read-only operation |
| `write` | Writes data somewhere |
| `external_write` | Writes to an external service |
| `internal` | Accesses internal systems only |
| `sensitive` | Args/results may contain PII — arg scanner runs |
| `external_mcp` | Tool comes from an external MCP source |
| `messaging` | Sends or reads messages |
| `database` | Accesses a database |

---

## Where tools live

There is **one** tool registry. It holds every tool regardless of transport —
local Python callables and tools discovered from an MCP server sit in the
same store, keyed by name. There is no separate MCP registry, and connector
manifests are not a registry: they are static config, read once at
`from_yaml()`.

Three distinct things, easy to conflate:

| | What it is | Populated by |
|---|---|---|
| Tool registry | The canonical store of `Tool` descriptors, name-unique across all transports | `register_tools()` and `load_agent()` |
| Per-agent tool set | `{tool_name: (source_name, Tool)}`, filtered to the agent's `allowed_tool_names` — what the gate reads | `load_agent()` |
| `SourceRegistry` | The sources that *produce* tools | `from_yaml()` |

How an MCP tool arrives:

1. `MCPSource.load()` calls `tools/list`, scans each entry's metadata, and
   builds a `Tool` whose tags are the union of the source's tags, the
   connector manifest's per-tool tags, and `mcp`. This is the only point
   where manifest metadata enters — a remote server's own tool listing
   carries no security metadata SHAI would trust.
2. `load_agent()` registers those tools in the same registry as local ones.
   When a tool name already exists with different tags, the enriched
   variant is kept as a per-agent override instead, so one agent's source
   tags never rewrite another agent's canonical definition.
3. The per-agent set is resolved once, with overrides applied last. The
   gate therefore knows each tool's owning source without a lookup.

**Consequence for offline tooling:** tool names for a hand-configured MCP
source exist only after a live `tools/list`, and local tool names only
after the application calls `register_tools()`. `shai harness graph` can
draw the tool layer only for connector-backed sources and agent
`allowed_tool_names`.

---

## register_tools()

Registers tools with the harness. Must be called before `load_agent()` for
locally-implemented tools.

```python
await harness.register_tools([
    Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    Tool(name="send_email",  tags=["external_write"],   transport=Transport.LOCAL),
])
```

Also accepts `ShaiTool` instances from the `@shai_tool` decorator — preferred
when using integrations (LangChain, LangGraph):

```python
from harness.integrations.langchain import shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str:
    """Search internal documentation."""
    return _impl(query)

await harness.register_tools([search_docs])
```

**Re-registration is idempotent** — same name + same tags + same transport =
no error. Different tags for the same name = `ConfigError`.

### @shai_tool decorator

Single definition for frameworks + SHAI:

```python
from harness.integrations.langchain import shai_tool  # or langgraph, etc.

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str:
    """Search internal documentation."""
    return _search(query)

@shai_tool(tags=["external_write", "sensitive"])
async def send_email(to: str, subject: str, body: str) -> str:
    """Send an email."""
    return await _send(to, subject, body)

tools = [search_docs, send_email]

# Same list works everywhere:
gated = await wrap_tools(tools, harness=harness, ctx=ctx)   # LangChain
tool_node = await HarnessToolNode.create(tools, harness, ctx)  # LangGraph
await harness.register_tools(tools)                           # direct
```

**`@shai_tool` creates a `ShaiTool`** — a Python callable that satisfies both
SHAI's `Tool` interface and LangChain's `BaseTool` interface.

---

## Connector manifests (recommended)

Use a pre-built connector manifest to avoid hand-configuring `url`,
`allowed_urls`, `tags`, and tool specs:

```yaml
sources:
  - name: slack
    connector: slack          # loads url, allowed_urls, tags, tool specs
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
```

→ See `connectors.md` for the list of available connectors.

Fields you declare override the manifest; fields you leave out keep the
manifest's value, so a source naming only `connector:` and `credentials:`
still gets its transport, url, tags, allow-lists, and per-tool specs.
Credentials are always operator-supplied — never from the manifest.

---

## Declaring sources in agent-xx.yaml

```yaml
sources:
  - docs_local
  - slack_mcp
```

Sources not found in the `SourceRegistry` are logged and skipped — not a
hard error.

### Source required flag

```yaml
required: true   # default — ConfigError at load_agent() if source fails
required: false  # skipped with WARNING log — agent continues without it
```

**Policy suppression always skips** (never raises), regardless of `required`.

---

## LocalSource (`transport: local` and `transport: skill`)

Returns tools registered via `harness.register_tools()`. If `tool_names` is
specified, only those tools are returned. Source-level `tags` are merged
onto each returned tool.

For subagent contexts (`ctx.allowed_tags is not None`), tools with tags
outside `allowed_tags` are excluded before return.

```yaml
sources:
  - name: read_tools
    transport: local
    tool_names: [search_docs, fetch_doc]   # omit for all registered tools
    tags: [internal]
```

`transport: skill` uses the same class and behaves identically — it marks a
curated bundle rather than raw local registration, and the source reports
the transport it was declared with.

```yaml
sources:
  - name: docs_skill
    transport: skill
    tool_names: [search_docs, fetch_doc]
    tags: [skill, read, internal]
```

**A policy rule matching `transport:` reads the *tool's* transport, not the
source's.** A rule targeting `[skill]` matches only tools registered with
`Transport.SKILL` — declaring `transport: skill` on the source does not
stamp it onto the tools it returns.

---

## MCPSource (`transport: mcp`)

Connects to a remote MCP server over SSE (Server-Sent Events), runs the
JSON-RPC initialize handshake, and fetches the tool catalog with
`tools/list`. Returned tools are stamped `transport=Transport.MCP`.

```yaml
sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
    tags: [external_mcp, messaging]
    allowed_urls:
      - "https://mcp.slack.com/*"
      - "https://slack.com/api/*"
    allowed_methods: [GET, POST]
    required: true
```

### Connection protocol

1. `GET /sse` — open persistent SSE stream
2. Read `endpoint` event — extract `sessionId` from the URL query parameter
3. `POST /message?sessionId=<id>` with `{"method": "initialize", ...}`
4. `POST /message` with `{"method": "notifications/initialized"}`
5. `POST /message` with `{"method": "tools/list"}` — parse tool descriptors
6. Return `list[Tool]` with `transport=Transport.MCP` and source `tags`
   merged in

### Credentials

```yaml
credentials:
  token: "secret://SLACK_MCP_TOKEN"     # → Authorization: Bearer <value>
  # Authorization: "Bearer literal"      # used as-is
  # X-Custom-Header: "value"             # arbitrary headers
```

### Tool invocation after gating

The harness gates; it does not dispatch. After `check_tool_call` approves,
call `source.call()` directly:

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    source = await harness.get_source("slack_mcp")
    result = await source.call(
        tool_name,
        gate.redacted_args or args,
        dispatch_token=gate.dispatch_token,   # when connectivity.enabled
    )
    tverdict = await harness.scan_tool_result(result, ctx)
    safe_result = tverdict.redacted_text or result
```

`MCPInvocationError` is raised if the server returns a JSON-RPC error. It
carries `source`, `tool`, `code`, and `message` attributes.

### Close

`SHAI.close()` calls `source_registry.close()`, which closes the
`httpx.AsyncClient` on each MCPSource. Always call `await harness.close()`
at process shutdown.

---

## Policy-based source suppression

`PolicyEngine.evaluate_source(source, ctx)` is called for every source
before loading. A `suppress` rule deactivates the source for that agent:

```yaml
- id: suppress_mcp_for_untrusted
  match:
    source_tags: [external_mcp]
    agent_ids: [untrusted_agent]
  action: suppress
  reason: "external MCP not permitted for untrusted_agent"
```

Suppressed sources produce no tools and no audit event — suppression is
logged at INFO level only.

---

## Writing a custom ToolSource

```python
from harness.tools.tool import Tool
from harness.core.types import Transport
from harness.core.context import AgentContext

class MySource:
    name      = "my_source"
    transport = Transport.LOCAL
    tags: list[str] = ["my_tag"]

    async def load(self, ctx: AgentContext) -> list[Tool]:
        # Return tools. Apply ctx.allowed_tags filter for subagent safety.
        ...

    async def close(self) -> None:
        # Release connections. Called from SHAI.close().
        ...
```

`SourceRegistry.register()` takes any object satisfying the `ToolSource`
protocol (`name`, `transport`, `tags`, `load()`, `close()`) — there is no
config-driven or entry-point discovery for custom sources; construct the
instance and register it directly where the harness is wired up.
