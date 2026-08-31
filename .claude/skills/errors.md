# Errors Reference

---

## Exception hierarchy

```
HarnessError
├── ConfigError               — invalid YAML, bad schema, missing file, invalid MCP manifest
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

### `ConfigError: MCP source 'X' declared with transport: mcp has no manifest at ...`

```yaml
# harness.yaml
mcp_manifests_dir: ./mcp/
mcp_baseline:
  secret: "secret://SHAI_MCP_BASELINE_KEY"
sources:
  - name: my_source
    transport: mcp
```

A `transport: mcp` entry declares only `name`/`transport` (plus `tags`/
`required`) — no `url` or `credentials` on the `sources:` entry itself; a
manifest with those fields at `mcp/my_source.yaml` is what the name
resolves to by convention:

```yaml
# mcp/my_source.yaml
id: my_source
display_name: "My Source"
url: "https://my-mcp-server.com/sse"
credentials:
  token: "secret://MY_SOURCE_TOKEN"
```

If the file is missing at that path and the entry's `required` is `true`
(the default), this is a startup `ConfigError`; with `required: false` it's
a WARNING and the source is skipped. Once the manifest exists, approve it —
the only path to letting calls through:

```bash
shai mcp onboard mcp/my_source.yaml --config config/harness.yaml
```

### A declared MCP source is silently absent from the built harness

Not an exception at `from_yaml()` — a `transport: mcp` entry with a manifest
file that has no matching, approved baseline record (or a hash mismatch) is
simply not built into a live source: no stub, no "pending approval" object.
An agent that references that source name then hits the ordinary
`source 'X' not registered` handling (`SourceRegistry.activate()`),
honouring the source's `required` flag exactly like any other missing
source.

### `check_tool_call` denies: "needs onboarding" / "re-onboarding required"

Not an exception — only reachable for a source that *was* built (valid
baseline at startup). This is a normal gate denial
(`GateDecision.allowed=False`, `boundary=tool_call_gate`, `decision=deny`,
checked on every call by `harness.mcp.gate.McpBaselineGate`) for a manifest
edited since its last approval — the hash no longer matches the baseline
record (message says "re-onboarding required" in that case). Run the
command the message names; the denial clears within one
`mcp_baseline.cache_ttl_seconds`.

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
`from_yaml()` raises the same error when the startup attestation cannot be
written.

---

## Error in from_yaml vs load_agent

| Error | When | Meaning |
|---|---|---|
| `ConfigError` at `from_yaml()` | Parse/validate | YAML is malformed, invalid MCP manifest, bad schema |
| `AuditEmissionError` at `from_yaml()` | Startup attestation | Every sink rejected the `system`/`startup` event — construction fails rather than running unaudited |
| `ConfigError` at `load_agent()` | Source connect | Required MCP source failed to connect |
| `AgentNotRegisteredError` | Per-turn | `check_tool_call` called before `load_agent()` |
