# SHAI Quickstart

## What SHAI does

SHAI sits between your agent and its tools. It:
- Scans user input before it reaches the LLM
- Gates every tool call through a policy engine
- Scans tool results before they re-enter the LLM context
- Scans the LLM response before it reaches the user
- Emits one structured audit event per boundary call, always

```
user text → Ingress Scan → LLM → Tool Governance → tool → Tool Stream Control → LLM → Egress Scan → response
```

SHAI does **not** own the LLM loop. The agent decides when to call the LLM
and when to dispatch tools. SHAI governs what's allowed.

---

## Minimal working example

### 1. Install

```bash
pip install shai
```

### 2. `config/harness.yaml`

```yaml
version: 1
tenant_id: "my-app"

scan_input:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii
    - name: injection_scan

scan_output:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii

scan_tool_result:
  enabled: true
  block_at: high

policy:
  rules:
    - id: allow_local
      match:
        transport: [local]
      action: allow

audit_sinks:
  - name: file
    config:
      path: ./logs/audit.jsonl
```

### 3. `config/agents/my_agent.yaml`

```yaml
id: my_agent
allowed_tool_names: [search_docs, send_email]
allowed_tags: [read, internal, external_write]

policy_rules:
  - id: deny_write
    match:
      tool_tags: [external_write]
    action: deny
    reason: "external writes require approval"
  - id: allow_read
    match:
      tool_tags: [read]
    action: allow
```

### 4. Agent code

```python
import asyncio
from harness import SHAI, Tool
from harness.core.types import Transport

async def main():
    # Build once at startup
    harness = await SHAI.from_yaml("config/harness.yaml")

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write"],   transport=Transport.LOCAL),
    ])

    ctx = await harness.load_agent("config/agents/my_agent.yaml")

    # Per-turn
    user_text = "What's the vacation policy?"

    verdict = await harness.scan_input(user_text, ctx)
    if verdict.blocked:
        return "Input rejected."

    # ... call LLM, get tool_call ...
    tool_name = "search_docs"
    tool_args = {"query": "vacation policy"}

    gate = await harness.check_tool_call(tool_name, tool_args, ctx)
    if not gate.allowed:
        return f"Tool call denied: {gate.deny_reason}"

    # Dispatch the tool yourself
    result = await my_tool_dispatch(tool_name, gate.redacted_args or tool_args)

    tverdict = await harness.scan_tool_result(result, ctx, tool_name=tool_name)
    safe_result = tverdict.redacted_text or result

    # ... call LLM again with safe_result ...

    out_verdict = await harness.scan_output(llm_response, ctx)
    return out_verdict.redacted_text or llm_response

asyncio.run(main())
```

---

## Key patterns

### `scan_tool_result` takes an optional `tool_name`

```python
# Always correct — scans every result
tverdict = await harness.scan_tool_result(result, ctx)

# Better when using connectors — connector manifests declare
# which tools need scanning; others skip with a disabled audit event
tverdict = await harness.scan_tool_result(result, ctx, tool_name="search_docs")
```

### `collect_events()` for display/testing

```python
with harness.collect_events() as events:
    gate    = await harness.check_tool_call(name, args, ctx)
    verdict = await harness.scan_tool_result(result, ctx)
# events: list[AuditEvent] — populated after the block
for ev in events:
    print(ev.boundary, ev.decision)
```

### Always `await harness.close()` at shutdown

```python
await harness.close()   # flushes audit sinks, closes MCP connections
```

---

## What SHAI protects automatically

**At tool registration** — `MCPMetadataScanner` scans every tool name, description, and argument schema received from an MCP server's `tools/list` response. Tools carrying injection payloads in their metadata are blocked before registration.

## What gets audited

Every call to any boundary method emits exactly one `AuditEvent`.
No raw text ever appears in the event — only metadata.

```json
{
  "boundary": "tool_call_gate",
  "decision": "deny",
  "tool_name": "send_email",
  "deny_reason": "external writes require approval",
  "agent_id": "my_agent",
  "tenant_id": "my-app"
}
```

→ See `05-verdicts-events.md` for the full field reference.
