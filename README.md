# SHAI — Secure Harness AI

**Production-grade security control plane for AI agents.**

Your agent calls tools. Some send emails, write files, query databases, and talk to external APIs. The LLM decides which to call and what arguments to pass. You do not get to review that decision before it executes.

SHAI sits between your agent and its tools. Every piece of text the LLM touches is scanned. Every tool call passes through a governance gate. Every decision is logged. You stay in control.

---

## Install

```bash
pip install shai
```

Requires Python 3.11+.

---

## Security Core

```
user text ──► Ingress Scan ──► LLM ──► Tool Governance ──► tool ──► Tool Stream Control ──► LLM ──► Egress Scan ──► response
                                                                ▲
                                              MCP Governance runs at connection time
```

### Ingress Scan

Runs on every user message before it reaches the LLM. Configurable scanners, all combinable:

| Scanner | What it catches | Config name |
|---|---|---|
| `InjectionScanner` | Direct prompt injection, jailbreak attempts, role override, encoded payloads | `injection_scan` |
| `RegexPIIScanner` | SSN, credit card, email, phone, IBAN, API keys (Stripe, GitHub, AWS, Slack), UUIDs | `regex_pii` |
| `FileScanner` | MIME type, extension, size, PDF JS, EXIF, ZIP macros — then doc-tuned injection scan on extracted text | `file_scanner` |

Actions per scanner: `block` · `alert` · `redact` (with configurable `redact_with` placeholder). `block_at` severity threshold per boundary.

```yaml
scan_input:
  enabled: true
  block_at: high
  action: block
  scanners:
    - name: injection_scan
      action: block
    - name: regex_pii
      action: redact
      redact_with: "[REDACTED]"

scan_file:
  enabled: true
  block_at: high
  max_size_mb: 50
```

---

### Tool Governance

Four-layer gate on every tool call. First denial at any layer wins. Cannot be disabled.

| Layer | What it enforces | Bypassable? |
|---|---|---|
| **L0 — Rate Limiter** | Sliding-window token bucket: global budget + per-tool budget per agent | No |
| **L1 — Name Gate** | Tool must be in `allowed_tool_names` — hard pre-policy gate | No |
| **L2 — Tag Scope** | Tool tags must be ⊆ `allowed_tags` — subagent capability enforcement | No |
| **L3 — Policy Engine** | YAML rule intersection: subagent → parent → global. Actions: allow · deny · redact args | By design |
| **L4 — Arg Scanning** | PII scanner on tool arguments for tools tagged `sensitive` | Configurable |

One `GateDecision` returned: `allowed`, `deny_reason`, `redacted_args`, `source_name`, `dispatch_token`.

```yaml
check_tool_call:
  rate_limit:
    enabled: true
    window_seconds: 60
    max_calls_per_window: 60
    max_calls_per_tool: 20
  arg_scanners:
    - name: regex_pii
  scan_args_for_tags: [sensitive]

policy:
  rules:
    - id: allow_local
      match:
        transport: [local, skill]
      action: allow
    - id: deny_mcp_default
      match:
        transport: [mcp]
      action: deny
      reason: "MCP requires explicit agent-level allow"
```

---

### Tool Stream Control

Runs on every tool result before it re-enters the LLM context. Prevents T6 indirect injection:

| Scanner | What it catches | Config name |
|---|---|---|
| `InjectionScanner` (doc-tuned) | Injection payloads embedded in API responses, database rows, document content | `injection_scan_doc` |

Connector manifests declare `scan_tool_result_on` — only tools with T6 risk are scanned when using connectors. Pass `tool_name=` to activate this optimisation.

```yaml
scan_tool_result:
  enabled: true
  block_at: high
  action: block
```

---

### Egress Scan

Runs on every LLM response before it reaches the user:

| Scanner | What it catches | Config name |
|---|---|---|
| `RegexPIIScanner` | PII leakage in responses, data exfiltration via output | `regex_pii` |

```yaml
scan_output:
  enabled: true
  block_at: high
  action: block
  scanners:
    - name: regex_pii
      action: redact
      redact_with: "[REDACTED:{category}]"
```

---

### MCP Governance

Runs at MCP source connection time — before any tool is registered with SHAI:

| Scanner | What it catches | Config name |
|---|---|---|
| `MCPMetadataScanner` | Injection payloads in tool names, descriptions, and argument schemas from `tools/list` | `mcp_metadata_scan` |

`block_at` defaults to `medium` — metadata injection is high signal, almost no legitimate content triggers it.

```yaml
scan_mcp_metadata:
  enabled: true
  block_at: medium
  action: block
  scanners:
    - name: mcp_metadata_scan
```

---

## SHAI Gateway

### Connector Manifests

8 Tier A cloud connectors ship pre-configured with `url`, `allowed_urls`, `allowed_methods`, per-tool tags, blocked external-write tools, and `scan_tool_result_on` declarations. One line replaces ~15 lines of manual config:

```yaml
# Instead of hand-configuring every field:
sources:
  - name: slack
    connector: slack
    credentials:
      token: "secret://SLACK_BOT_TOKEN"

  - name: github
    connector: github
    credentials:
      token: "secret://GITHUB_TOKEN"
```

Available: `slack` · `github` · `notion` · `jira` · `gmail` · `postgresql` · `stripe` · `google_drive`

Each connector manifest enforces: write tools blocked by default, read tool results scanned for injection, correct tag assignments for policy rules to fire correctly.

---

### Dispatch Tokens

HMAC-signed, source-bound, one-time-use, short-TTL (default 15s). Issued by Tool Governance on every allowed gate decision when `connectivity.enabled: true`. Carry `agent_id`, `tool_name`, `source_name`, `allowed_urls`, `allowed_methods`.

```yaml
connectivity:
  enabled: true
  token_secret: "secret://SHAI_TOKEN_SECRET"
  token_ttl_seconds: 15
  no_token_policy: permissive
```

---

### ShaiTransport

In-process `httpx` transport hook installed on every `MCPSource`. Enforces per request:

1. URL envelope — destination must match `allowed_urls`
2. Method — must match `allowed_methods`
3. Token signature — HMAC-SHA256 verified
4. Source binding — `token.source_name` must match the transport's source
5. URL binding — request URL must match `token.allowed_urls`
6. Method binding — request method must match `token.allowed_methods`
7. Nonce — `token_id` consumed as one-time use, replay prevented

Emits `NetworkAuditEvent` per call. `token_id` joins with the gate `AuditEvent` for full SIEM correlation.

---

## Observability

### Audit Trail

One structured event per boundary call, always. No raw text ever — no user input, LLM output, tool arguments, or matched substrings in any field.

```json
{
  "boundary":    "tool_call_gate",
  "decision":    "deny",
  "tool_name":   "send_email",
  "deny_reason": "external writes require approval",
  "agent_id":    "orchestrator",
  "tenant_id":   "platform-prod",
  "duration_ms": 1,
  "audit_tags":  {"team": "platform", "env": "prod"}
}
```

Optional HMAC-SHA256 signing per event:

```yaml
audit_signing:
  enabled: true
  secret: "secret://AUDIT_SIGNING_KEY"

audit_sinks:
  - name: file
    config:
      path: ./logs/audit.jsonl
```

`collect_events()` for in-process collection without affecting sinks:

```python
with harness.collect_events() as events:
    gate    = await harness.check_tool_call(name, args, ctx)
    verdict = await harness.scan_tool_result(result, ctx, tool_name=name)
# events: list[AuditEvent], populated after the block
```

---

## Capabilities

### Subagent Scoping

Declare subagents inside the parent YAML. Capabilities are always a strict subset of the parent — enforced at `load_agent()` time, not per turn:

```yaml
# config/agents/orchestrator.yaml
id: orchestrator
allowed_tool_names: [search_docs, send_email, list_inbox]
allowed_tags: [read, internal, external_write]

sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]     # ⊆ parent
    allowed_tags: [read, internal]        # ⊆ parent — no external_write
```

```python
ctx       = await harness.load_agent("config/agents/orchestrator.yaml")
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")
# send_email → denied at L1 — not in research_sub.allowed_tool_names
```

### Framework Integrations

Single `@shai_tool` decorator — define once, works across all frameworks:

```python
from harness.integrations.langchain import shai_tool

@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str: ...

@shai_tool(tags=["external_write", "sensitive"])
async def send_email(to: str, subject: str, body: str) -> str: ...

tools = [search_docs, send_email]
```

| Framework | Integration | How |
|---|---|---|
| LangGraph | `HarnessToolNode` | Drop-in for `ToolNode` |
| LangChain Agent Loop | `ShaiMiddleware` | `create_agent(middleware=[middleware])` |
| LangChain classic | `wrap_tools()` | Returns gated `BaseTool` wrappers |
| Anthropic SDK | `gated_dispatch` | Manual loop with gate + dispatch |
| CrewAI | `wrap_tools()` | Same pattern as LangChain |
| PydanticAI | `harness_tool` + `add_harness_middleware` | Decorator + middleware |
| OpenAI Agents | `make_before_tool_hook` | Hook-based integration |

---

## Quick start

**`config/harness.yaml`:**

```yaml
version: 1
tenant_id: "my-deployment"

scan_input:
  enabled: true
  block_at: high
  scanners:
    - name: injection_scan
    - name: regex_pii
      action: redact
      redact_with: "***"

scan_tool_result:
  enabled: true
  block_at: high

scan_mcp_metadata:
  enabled: true
  block_at: medium
  scanners:
    - name: mcp_metadata_scan

scan_output:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii

policy:
  rules:
    - id: allow_local
      match:
        transport: [local, skill]
      action: allow
    - id: deny_mcp_default
      match:
        transport: [mcp]
      action: deny

audit_sinks:
  - name: file
    config:
      path: ./logs/audit.jsonl
```

**`config/agents/my_agent.yaml`:**

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

**Agent code:**

```python
import asyncio
from harness import SHAI, Tool
from harness.core.types import Transport

async def main():
    harness = await SHAI.from_yaml("config/harness.yaml")

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write"],   transport=Transport.LOCAL),
    ])
    ctx = await harness.load_agent("config/agents/my_agent.yaml")

    # Ingress Scan
    verdict = await harness.scan_input(user_text, ctx)
    if verdict.blocked:
        return "Input rejected"

    # Tool Governance
    gate = await harness.check_tool_call("search_docs", {"query": "report"}, ctx)
    if not gate.allowed:
        return gate.deny_reason

    # Dispatch — your code
    result = await dispatch("search_docs", gate.redacted_args or {"query": "report"})

    # Tool Stream Control
    tv = await harness.scan_tool_result(result, ctx, tool_name="search_docs")
    safe_result = tv.redacted_text or result

    # Egress Scan
    out = await harness.scan_output(llm_response, ctx)
    return out.redacted_text or llm_response

asyncio.run(main())
```

---

## OWASP Agentic AI Coverage

| OWASP Threat | Coverage | SHAI Control |
|---|---|---|
| **T1** Goal/Instruction Hijacking | Full | Ingress Scan `injection_scan`, L1 name gate, MCP Governance `mcp_metadata_scan` |
| **T2** Tool Misuse | Full | Tool Governance L1–L4, rate limiter |
| **T3** Uncontrolled Agent Actions | Full | Tool Governance L1–L3, subagent scoping, source suppression |
| **T4** Resource Overload | Full | Rate Limiter — global + per-tool sliding window |
| **T5** Prompt Injection (direct) | Full | Ingress Scan `injection_scan` — 17-rule catalog |
| **T6** Indirect Prompt Injection | Full | Tool Stream Control `injection_scan_doc`, MCP Governance `mcp_metadata_scan` |
| **T8** Repudiation & Untraceability | Full | HMAC-signed audit trail, one event per boundary |
| **T9** Privilege Escalation | Full | Subagent capability gate (L2), policy intersection (L3) |
| **T11** Sensitive Data Exposure | Full | Ingress/Egress Scan `regex_pii`, arg scanning (L4) |
| **T16** Data Exfiltration | Partial | Egress Scan `regex_pii`, ShaiTransport for MCP egress |
| **T17** Supply Chain | Full | MCP Governance `mcp_metadata_scan`, FileScanner, source suppression, secret resolution |

*T16 partial: full closure requires `shai-gateway` for non-MCP traffic (planned).*

---

## Enterprise (planned)

**`shai-gateway`** — external HTTPS proxy for non-MCP traffic. L7 policy rules per source/agent. Closes T16 fully.

**`shai-inference-router`** — LLM credential isolation, model allowlist per agent, per-agent inference rate limits.

**`shai-local-connectors`** — managed local MCP processes: Apple Notes, Obsidian, SQLite, filesystem. `allowed_paths` enforcement at I/O level.

**Tier B/C Connectors** — Teams, GitLab, Linear, Confluence, Supabase, AWS, Cloudflare, WhatsApp, Google Calendar, Docker, Zapier, Brave Search.

**Enterprise Providers** — HashiCorp Vault, AWS KMS, GCP Secret Manager.

---

## Documentation

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component map, construction sequence, concurrency model |
| [docs/boundaries.md](docs/boundaries.md) | Boundary contracts, gate layers, audit invariants |
| [docs/agents.md](docs/agents.md) | agent-xx.yaml schema, subagent model, registry lifecycle |
| [docs/sources.md](docs/sources.md) | Source lifecycle, LocalSource, SkillSource, MCPSource, connector manifests |
| [docs/policy.md](docs/policy.md) | Rule grammar, intersection model, combinators |
| [docs/audit-schema.md](docs/audit-schema.md) | AuditEvent field reference, NetworkAuditEvent, SIEM queries |
| [docs/connectivity.md](docs/connectivity.md) | Dispatch tokens, ShaiTransport, NetworkAuditEvent |
| [docs/adapters.md](docs/adapters.md) | Writing and registering custom scanners, sinks, sources |
| [docs/concurrency.md](docs/concurrency.md) | Threading model, concurrent turn isolation |

---

## Packages

| Package | License | Description |
|---|---|---|
| `shai` | Apache-2.0 | Security Core + SHAI Gateway + Observability + Capabilities |
| `shai-gateway` | Apache-2.0 | External egress enforcement — planned |

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
