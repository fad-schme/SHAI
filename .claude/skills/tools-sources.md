# Tools and Sources Reference

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

**Re-registration is idempotent** — same name + same tags + same transport = no error.
Different tags for the same name = `ConfigError`.

---

## load_agent()

Activates sources, resolves tools, returns `AgentContext`.

```python
ctx = await harness.load_agent("config/agents/orchestrator.yaml")
```

**What happens:**
1. Loads and validates the YAML
2. Activates declared sources (`activate()`) — connects to MCP servers
3. Merges source tools into the tool registry
4. Filters to `allowed_tool_names`
5. Returns `AgentContext`

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

## Sources

### LocalSource

Returns tools registered via `register_tools()`. Optionally filtered to
an explicit `tool_names` list.

```yaml
sources:
  - name: docs_local
    transport: local
    tool_names: [search_docs, fetch_doc]   # omit for all registered tools
    tags: [internal]                       # merged onto every returned tool
```

### SkillSource

Named subset of registered tools. `transport=Transport.SKILL` in policy rules.

```yaml
sources:
  - name: docs_skill
    transport: skill
    tool_names: [search_docs]
    tags: [skill, read]
```

### MCPSource

Connects to a remote MCP server over SSE.

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

**Connection protocol:**
1. `GET /sse` — opens SSE stream, receives `endpoint` event with `sessionId`
2. `POST /message?sessionId=...` — `initialize` handshake
3. `POST /message` — `tools/list` — fetches tool catalog
4. Tools returned with `transport=Transport.MCP` + source tags merged in

**Tool invocation — after `check_tool_call` approves:**

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    source = await harness.get_source("slack_mcp")
    result = await source.call(
        tool_name,
        gate.redacted_args or args,
        dispatch_token=gate.dispatch_token,   # when connectivity.enabled
    )
```

The harness gates; it does not dispatch. You dispatch via `source.call()`.

---

## @shai_tool decorator

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

**`@shai_tool` creates a `ShaiTool`** — a Python callable that satisfies
both SHAI's `Tool` interface and LangChain's `BaseTool` interface.

---

## Source required flag

```yaml
required: true   # default — ConfigError at load_agent() if source fails
required: false  # skipped with WARNING log — agent continues without it
```

**Policy suppression always skips** (never raises), regardless of `required`.

---

## Custom ToolSource

Implement the protocol and register via entry points:

```python
class MySource:
    name      = "my_source"
    transport = Transport.LOCAL
    tags: list[str] = ["custom"]

    async def load(self, ctx: AgentContext) -> list[Tool]:
        return [Tool(name="my_tool", tags=self.tags, transport=self.transport)]

    async def close(self) -> None:
        pass
```

```toml
[project.entry-points."harness.sources"]
my_source = "my_package.sources:MySource"
```
