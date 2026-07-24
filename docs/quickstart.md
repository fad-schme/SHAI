# Quickstart

Five minutes from `pip install` to a working, gated agent.

## What you'll build

An agent that takes a question, calls one tool, and returns a response — with SHAI wrapping every step.

- Input is scanned for PII, prompt injection, and jailbreak attempts before the LLM sees it.
- The proposed tool call has to survive a deterministic policy gate before it runs — the LLM cannot argue past this.
- The tool's return value is scanned for indirect injection before it re-enters the LLM's context. (This is the boundary most frameworks miss.)
- The final response is scanned for PII leakage before it reaches the user.
- Every decision writes a signed audit event.

```
user → scan_input → LLM → check_tool_call → tool → scan_tool_result → LLM → scan_output → response
                                                                                ↓
                                                                    signed audit event stream
```

SHAI does not own your LLM loop. Your agent still decides when to call the LLM and when to dispatch tools. SHAI decides what's allowed.

## 1 — Install

```bash
pip install shai
```

Requires Python 3.11+.

## 2 — Configure the harness

`config/harness.yaml`:

```yaml
version: 1
tenant_id: "my-app"

scan_input:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii
    - name: injection_scan
    - name: jailbreak_scan
    - name: identity_spoof_scan
    - name: heuristic_scan

scan_output:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii

scan_tool_result:
  enabled: true
  block_at: high
  scanners:
    - name: injection_scan
    - name: identity_spoof_scan   # catches fabricated-approval in poisoned tool results

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

`block_at: high` means only HIGH-severity findings block. Medium and low still appear in the audit trail but don't stop the turn — you want the log to reflect what the scanners saw, not just what warranted blocking.

## 3 — Configure the agent

`config/agents/my_agent.yaml`:

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

Agent rules stack on top of harness rules — they don't replace them. Agent rules are evaluated first; the first `deny` wins. So even though the harness allows all local tools, `send_email` is denied for this agent because its `external_write` tag matches an agent-scoped `deny`.

## 4 — Wire it up

```python
import asyncio
from harness import SHAI, Tool
from harness.core.types import Transport


async def main():
    # Build once at startup — expensive, keep out of the hot path.
    harness = await SHAI.from_yaml("config/harness.yaml")

    # Register tools. Tags drive policy matching.
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write"],   transport=Transport.LOCAL),
    ])

    # Load the agent — returns an AgentContext you carry through the turn.
    ctx = await harness.load_agent("config/agents/my_agent.yaml")

    # ── Per-turn ──
    user_text = "What's the vacation policy?"

    # Boundary 1: scan input before the LLM sees it.
    verdict = await harness.scan_input(user_text, ctx)
    if verdict.blocked:
        return "I can't process that message."

    # Boundary 2: gate the tool call.
    # (In real code you'd call your LLM here and read tool_calls off its response.)
    tool_name = "search_docs"
    tool_args = {"query": "vacation policy"}

    gate = await harness.check_tool_call(tool_name, tool_args, ctx)
    if not gate.allowed:
        return f"Tool call denied: {gate.deny_reason}"

    # Dispatch the tool yourself. SHAI does not run tools for you.
    result = await my_tool_dispatch(tool_name, gate.redacted_args or tool_args)

    # Boundary 3: scan the result before it re-enters the LLM context.
    tverdict = await harness.scan_tool_result(result, ctx, tool_name=tool_name)
    safe_result = tverdict.redacted_text or result

    # ... call LLM again with safe_result to get the final response ...

    # Boundary 4: scan the response before it reaches the user.
    out_verdict = await harness.scan_output(llm_response, ctx)
    return out_verdict.redacted_text or llm_response


asyncio.run(main())
```

## 5 — Look at the audit trail

`./logs/audit.jsonl` now has one JSON object per boundary call:

```json
{
  "boundary": "tool_call_gate",
  "decision": "deny",
  "tool_name": "send_email",
  "deny_reason": "external writes require approval",
  "agent_id": "my_agent",
  "tenant_id": "my-app",
  "timestamp_ms": 1730000000000,
  "signature": "…"
}
```

What's **not** there: no raw user text, no LLM output, no matched substrings. Structured metadata only. This is deliberate — the audit trail is safe to ship to a SIEM without leaking the content it was watching.

## Handy patterns

**`collect_events()` for tests and debugging** — grab events for one turn in-process instead of tailing a file:

```python
with harness.collect_events() as events:
    gate     = await harness.check_tool_call(name, args, ctx)
    tverdict = await harness.scan_tool_result(result, ctx)
# events: list[AuditEvent] — populated after the with-block
```

**Always close on shutdown**:

```python
await harness.close()   # flushes audit sinks, closes MCP connections
```

Without this, the last few audit events may not make it to disk and any active MCP sessions time out rather than close cleanly.

## What SHAI protects automatically without any code

- **At MCP tool registration** — every tool name, description, and argument schema received from an MCP server's `tools/list` response is scanned by `MCPMetadataScanner`. Tools carrying injection payloads in their own metadata are refused registration before any agent could invoke them.
- **On every scan boundary** — content is first normalized (base64, hex, URL, rot13, homoglyphs, fragment reassembly) so pattern scanners can't be bypassed by encoding.

## What next

- [concepts.md](concepts.md) — the mental model: five boundaries, trust envelope, how verdicts flow through a turn
- [configuration.md](configuration.md) — every field in `harness.yaml` and `agent.yaml`, policy rules explained
- [integrations.md](integrations.md) — LangGraph, LangChain, Anthropic SDK, CrewAI, PydanticAI, OpenAI Agents
- Detailed schema lookup — [`.claude/skills/`](../.claude/skills/)
