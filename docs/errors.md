# Errors

The exceptions you'll see when SHAI refuses to load a config, refuses a tool call, or a scanner or audit sink misbehaves. Every SHAI exception inherits from `HarnessError` — if you want a single top-level catch, use that.

## The hierarchy

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

Every error carries structured context on it — `agent_id`, `op`, `boundary`, `tool_name`, whatever's relevant. Format them in your logs the way you'd format `ValueError.args`.

## The five you'll actually hit

### `ConfigError` at startup

The most common. Something in `harness.yaml` or an agent file didn't validate. The message names the field.

```
ConfigError: source 'slack_mcp': url is required for mcp transport
```

Fix by supplying `url:` or switching to a `connector:` reference. See [configuration.md](configuration.md) or [connectors.md](connectors.md).

```
ConfigError: Unknown connector 'slac'. Available: [github, gmail, google_drive, jira, notion, postgresql, slack, stripe]
```

Typo. `list_connectors()` prints the current set:

```python
from harness.connectors import list_connectors
print(list_connectors())
```

### `AgentNotRegisteredError` on a boundary call

You called a boundary method with an `AgentContext` whose `agent_id` was never loaded.

```python
ctx = AgentContext(agent_id="my_agent")   # constructed by hand — not loaded
await harness.scan_input(text, ctx)
# AgentNotRegisteredError: agent 'my_agent' is not registered in this harness
```

Always construct `ctx` via `await harness.load_agent(...)` — that path registers it. Hand-constructed contexts are for advanced use only (e.g. background jobs that legitimately don't map to a loaded agent — you register those explicitly).

### `ToolNotRegisteredError` on `check_tool_call`

The LLM proposed a tool name that isn't in the tool registry. Either you forgot to `register_tools()` for it, or the LLM hallucinated. Both are worth logging — the second case is often the tell for a jailbreak attempt.

The gate emits a `deny` audit event for this before raising, so your audit trail sees it either way.

### `NetworkPolicyError` from `ShaiTransport`

Only relevant when `connectivity.enabled: true`. Raised when the transport refuses to send a request — the URL isn't in the token's `allowed_urls`, the method isn't allowed, the source binding is wrong, the nonce was already spent, or the token has expired.

The exception carries the reason:

```
NetworkPolicyError: request refused: url 'https://attacker.example/exfil' not in allowed_urls for token issued to source 'slack'
```

Log it and treat it as a security event. A `NetworkPolicyError` on a tool that shouldn't have made outbound calls at all is a strong signal something is compromised.

### `SecretNotFound` at startup

You have `secret://SOME_KEY` in the config but `SOME_KEY` isn't in the environment.

```
SecretNotFound: environment variable 'SLACK_BOT_TOKEN' is not set
```

Fix in your process manager or `.env` file. SHAI does not fall back to defaults for missing secrets — the config is an explicit declaration of what needs to be present.

## Errors you should almost never see

- `PolicyEvaluationError` — the policy engine failed internally. This is a bug, not a configuration issue. File it.
- `AuditEmissionError` — every audit sink failed simultaneously. If a single sink fails, SHAI keeps trying the others; this only fires when all of them are dead. File it, and check the sinks in the meantime.
- `AdapterDiscoveryError` — the entry-point machinery couldn't resolve a plugin. Usually a broken install.

## Boundary errors are audit events, not exceptions

The boundaries themselves — `scan_input`, `check_tool_call`, `scan_tool_result`, `scan_output`, `scan_file` — **never raise on a policy decision.** They return a verdict. If input contained PII, you get `verdict.blocked`, not an exception. If the gate denied, you get `gate.allowed = False`, not an exception.

Exceptions from a boundary method mean something structural is wrong: unknown agent, unknown tool, config corruption. The security decision itself is always a value your code inspects.

This is deliberate. You should never wrap a boundary call in `try/except` for the security decision — the verdict is the security decision, and it's already structured. Reserve `except HarnessError` for genuine structural failures.

## What next

- [testing.md](testing.md) — how to write tests that assert on deny reasons
- [`.claude/skills/errors.md`](../.claude/skills/errors.md) — every exception class with full context attributes
