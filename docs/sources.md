# Tool Sources

A tool source activates a set of tools for an agent. Sources are declared in `harness.yaml` under `sources:` and in each `agent-xx.yaml` under `sources:`. They are activated at `load_agent()` time — not per turn.

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

Tools from sources are merged into the shared `ToolRegistry` and filtered to the agent's `allowed_tool_names`. The result is stored in `_agent_tools[agent_id]` and read lock-free on every subsequent turn.

---

## Declaring sources in harness.yaml

```yaml
sources:
  - name: docs_local
    transport: local
    tool_names: [search_docs, fetch_doc]   # omit for all registered tools
    tags: [internal]

  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_MCP_TOKEN"
    tags: [external_mcp, messaging]
```

## Declaring sources in agent-xx.yaml

```yaml
sources:
  - docs_local
  - slack_mcp
```

Sources not found in the `SourceRegistry` are logged and skipped — not a hard error.

---

## LocalSource (`transport: local`)

Returns tools registered via `harness.register_tools()`. If `tool_names` is specified, only those tools are returned. Source-level `tags` are merged onto each returned tool.

For subagent contexts (`ctx.allowed_tags is not None`), tools with tags outside `allowed_tags` are excluded before return.

```yaml
sources:
  - name: read_tools
    transport: local
    tool_names: [search_docs, fetch_doc]
    tags: [internal]
```

---

## SkillSource (`transport: skill`)

A named, explicitly-listed subset of registered tools. `transport=Transport.SKILL` distinguishes skill-sourced tools from raw local tools in policy rules and audit events.

```yaml
sources:
  - name: docs_skill
    transport: skill
    tool_names: [search_docs, fetch_doc]
    tags: [skill, read, internal]
```

```yaml
# Policy rule that targets skill tools specifically
- id: audit_skill_calls
  match:
    transport: [skill]
  action: allow
```

---

## MCPSource (`transport: mcp`)

Connects to an MCP server over SSE (Server-Sent Events), runs the JSON-RPC initialize handshake, and fetches the tool catalog with `tools/list`. Returned tools are stamped `transport=Transport.MCP`.

**Requires `pip install shai[mcp]`** (`httpx>=0.27`). If httpx is absent, `load()` raises `ConfigError` with a clear install message.

### Connection protocol

1. `GET /sse` — open persistent SSE stream
2. Read `endpoint` event — extract `sessionId` from the URL query parameter
3. `POST /message?sessionId=<id>` with `{"method": "initialize", ...}`
4. `POST /message` with `{"method": "notifications/initialized"}`
5. `POST /message` with `{"method": "tools/list"}` — parse tool descriptors
6. Return `list[Tool]` with `transport=Transport.MCP` and source `tags` merged in

### Credentials

```yaml
credentials:
  token: "secret://SLACK_MCP_TOKEN"     # → Authorization: Bearer <value>
  # Authorization: "Bearer literal"      # used as-is
  # X-Custom-Header: "value"             # arbitrary headers
```

### Tool invocation after gating

The harness gates; it does not dispatch. After `check_tool_call` approves, call `source.call()` directly:

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    source = await harness.get_source("slack_mcp")
    result = await source.call(tool_name, gate.redacted_args or args)
    tverdict = await harness.scan_tool_result(result, ctx)
    safe_result = tverdict.redacted_text or result
```

`MCPInvocationError` is raised if the server returns a JSON-RPC error. It carries `source`, `tool`, `code`, and `message` attributes.

### Close

`SHAI.close()` calls `source_registry.close()` which closes the `httpx.AsyncClient` on each MCPSource. Always call `await harness.close()` at process shutdown.

---

## Policy-based source suppression

`PolicyEngine.evaluate_source(source, ctx)` is called for every source before loading. A `suppress` rule deactivates the source for that agent:

```yaml
- id: suppress_mcp_for_untrusted
  match:
    source_tags: [external_mcp]
    agent_ids: [untrusted_agent]
  action: suppress
  reason: "external MCP not permitted for untrusted_agent"
```

Suppressed sources produce no tools and no audit event — suppression is logged at INFO level only.

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

Register in `pyproject.toml`:

```toml
[project.entry-points."harness.sources"]
my_source = "my_package.sources:MySource"
```
