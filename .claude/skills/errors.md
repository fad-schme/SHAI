# Errors Reference

---

## Exception hierarchy

```
HarnessError
├── ConfigError               — invalid YAML, bad schema, missing file, unknown connector
├── AdapterDiscoveryError     — entry point not found or name collision
├── AgentNotRegisteredError   — agent_id not in AgentRegistry
├── AgentConflictError        — same agent_id, different content
├── SubAgentNotDeclaredError  — sub_agent_id not in parent's sub_agents
├── ToolNotRegisteredError    — tool name not in ToolRegistry
├── PolicyEvaluationError     — policy engine internal failure (not a normal deny)
├── AuditEmissionError        — all audit sinks failed simultaneously
├── NetworkPolicyError        — ShaiTransport blocked an outbound MCP request
├── SecretNotFound            — secret:// reference not in environment
└── MCPInvocationError        — MCP server returned a JSON-RPC error
```

All errors carry structured context attributes (`agent_id`, `op`, `boundary`, etc.)
for log formatters.

---

## Common errors and fixes

### `ConfigError: source 'X': url is required for mcp transport`

```yaml
# Wrong
sources:
  - name: my_source
    transport: mcp
    # url is missing AND no connector: field

# Fix A — add url
sources:
  - name: my_source
    transport: mcp
    url: "https://my-mcp-server.com/sse"

# Fix B — use a connector manifest
sources:
  - name: slack
    connector: slack
    credentials:
      token: "..."
```

### `ConfigError: Unknown connector 'X'. Available: [...]`

The connector id doesn't match any manifest in `harness/connectors/manifests/`.

```python
from harness.connectors import list_connectors
print(list_connectors())
# ['github', 'gmail', 'google_drive', 'jira', 'notion', 'postgresql', 'slack', 'stripe']
```

### `SecretNotFound: No environment variable 'SLACK_BOT_TOKEN'`

A `secret://SLACK_BOT_TOKEN` reference in harness.yaml requires the env var
to be set at `from_yaml()` time — even for `required: false` sources.

```bash
export SLACK_BOT_TOKEN="xoxb-..."
```

For dev with no real token, use `""` instead of `secret://...`:
```yaml
credentials:
  token: ""   # empty — no real API calls made
```

### `ConfigError: agent config validation failed: policy_rules → X → match → source_name`

`source_name` is not a valid match field in `RuleMatchConfig`.
Valid fields: `tool_tags`, `tool_names`, `transport`, `agent_ids`, `sub_agent_ids`, `source_tags`.

```yaml
# Wrong
policy_rules:
  - id: allow_slack
    match:
      source_name: [slack]   # ← doesn't exist
    action: allow

# Fix — use tool_names instead
policy_rules:
  - id: allow_slack_read
    match:
      tool_names: [list_channels, read_messages, search_messages]
    action: allow
```

### `TypeError: 'AuditEvent' object is not subscriptable`

`collect_events()` returns `list[AuditEvent]` — Pydantic model instances,
not dicts. Use attribute access:

```python
# Wrong
ev["boundary"]
ev.get("decision")

# Correct
ev.boundary      # BoundaryName enum
str(ev.boundary) # "tool_call_gate"
ev.decision      # Decision enum
ev.tool_name     # str | None
```

### `AttributeError: 'ScanVerdict' object has no attribute 'finding_count'`

`ScanVerdict` has `findings: list[Finding]` — not `finding_count`.
`AuditEvent` has `finding_count: int`.

```python
# ScanVerdict
len(verdict.findings)       # number of findings
verdict.max_severity        # highest severity
verdict.findings[0].category  # first finding category

# AuditEvent
ev.finding_count             # integer
ev.max_severity              # str | None
```

### `MCPInvocationError: MCP invocation error [slack_mcp] tool=X code=-32600`

The MCP server returned a JSON-RPC error. Attributes available:
```python
except MCPInvocationError as e:
    print(e.source)   # "slack_mcp"
    print(e.tool)     # "search_messages"
    print(e.code)     # -32600 (JSON-RPC error code)
    print(e.message)  # error message from the server
```

### `NetworkPolicyError: token source_name 'github' does not match transport source 'slack_mcp'`

A dispatch token issued for one source was presented to a different source's
transport. Tokens are bound to their source at issuance time.

### `NetworkPolicyError: token_id 'X' has already been used (replay prevented)`

Same token used twice. Tokens are one-time-use within their TTL window.
Each `check_tool_call` → `source.call()` must use a fresh gate decision.

---

## Boundary methods never raise

`scan_input`, `check_tool_call`, `scan_tool_result`, `scan_output`, `scan_file`
never raise — they always return a verdict. Exceptions inside scanners are
logged and treated as empty findings.

The only exception is `AuditEmissionError` — raised when ALL configured
audit sinks fail simultaneously. Individual sink failures are swallowed.

---

## Error in from_yaml vs load_agent

| Error | When | Meaning |
|---|---|---|
| `ConfigError` at `from_yaml()` | Parse/validate | YAML is malformed, unknown connector, bad schema |
| `ConfigError` at `load_agent()` | Source connect | Required MCP source failed to connect |
| `AgentNotRegisteredError` | Per-turn | `check_tool_call` called before `load_agent()` |
