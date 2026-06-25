# CLAUDE.md

This file is the canonical guide for AI assistants working in the `shai`
repository. Read it before making any change. The live codebase is the
authoritative source — when this file conflicts with the code, the code wins.

---

## 1. What this project is

`shai` (package name `harness`) is a Python SDK that owns the **security
control plane** around an agent's LLM loop. The agent owns the loop — when
to call the LLM, when to dispatch tools, when to stop. SHAI governs the
security boundaries around that loop.

```
user text → scan_input → LLM → check_tool_call → tool → scan_tool_result → LLM → scan_output → response
```

**What SHAI is not:**
- No LLM client. No agent loop. No memory primitives.
- No tool execution — the harness gates; the agent dispatches.
- No network-level enforcement — that is the planned `shai-connectivity` layer.

---

## 2. Public API

```python
from harness import SHAI, Tool, AgentContext
from harness.core.types import Transport, ScanAction, ScanStatus

# Construction — async
harness = await SHAI.from_yaml("config/harness.yaml")

# Startup
await harness.register_tools([
    Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    Tool(name="send_email",  tags=["external_write"],   transport=Transport.LOCAL),
])
ctx = await harness.load_agent("config/agents/my_agent.yaml")

# Per-turn — in order
verdict  = await harness.scan_input(text, ctx)          # ScanVerdict
gate     = await harness.check_tool_call(name, args, ctx)  # GateDecision
result   = await source.call(name, args)                # agent dispatches
tverdict = await harness.scan_tool_result(result, ctx)  # ScanVerdict
verdict  = await harness.scan_output(text, ctx)         # ScanVerdict

# Subagent scoping — synchronous pure function
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")

# Source access (for MCP dispatch after gate)
source = await harness.get_source("slack_mcp")

# Shutdown
await harness.close()
```

**Wire types:**

- `ScanVerdict`: `status: ScanStatus` (ALLOW/WARN/BLOCK), `findings: list[Finding]`,
  `redacted_text: str | None`. Also `.blocked` and `.warned` as bool properties.
- `GateDecision`: `allowed: bool`, `deny_reason: str | None`, `redacted_args: dict | None`
- `Finding`: `scanner: str`, `category: str`, `severity: Severity`, `detail: str | None`
- `AgentContext`: `agent_id: str`, `sub_agent_id: str | None`, `allowed_tags: list[str] | None`
- `Tool`: `name: str`, `tags: list[str]`, `transport: Transport`, `description: str | None`

All facade methods are `async def` except `scope_context_for_subagent` (sync pure).

---

## 3. harness.yaml schema (current)

```yaml
version: 1
tenant_id: "my-deployment"

scan_input:
  enabled: true
  block_at: high
  action: block          # block | alert | redact
  scanners:
    - name: regex_pii
      action: redact     # per-scanner override
      redact_with: "***"
    - name: injection_scan
      action: block

scan_output:
  enabled: true
  block_at: high
  action: block
  scanners:
    - name: regex_pii

scan_tool_result:
  enabled: true
  block_at: high
  action: block

scan_mcp_metadata:
  enabled: true
  block_at: medium    # default — metadata injection is high signal
  action: block
  scanners:
    - name: mcp_metadata_scan  # MCPMetadataScanner, mcp_metadata_patterns.yaml

scan_file:
  enabled: false
  block_at: high
  action: block
  max_size_mb: 50

check_tool_call:
  rate_limit:
    enabled: true
    window_seconds: 60
    max_calls_per_window: 60
    max_calls_per_tool: 20
  arg_scanners:
    - name: regex_pii
  scan_args_for_tags:
    - sensitive

# Inline policy rules — no external rules file
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
      reason: "MCP requires explicit agent-level allow rule"

audit_sinks:                 # optional — defaults to stdout
  - name: file
    config:
      path: ./logs/audit.jsonl
  - name: stdout

audit_signing:
  enabled: false
  secret: "secret://AUDIT_SIGNING_KEY"

sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_MCP_TOKEN"
    tags: [external_mcp, messaging]
    required: true           # default — failure raises ConfigError at startup
  - name: docs_local
    transport: local
    tool_names: [search_docs]
    tags: [internal]
    required: false          # optional — failure skips, not fatal
```

**Removed fields** (do not add back): `tool_registry`, `secrets`, `agents.directory`,
`tool_sources`, `logging`, `allowed_extensions`. These were removed deliberately.

**Policy** is always inline (`policy.rules`). There is no `rules_path` or external
policy file. `policy.name` does not exist on `PolicyConfig`.

---

## 4. agent-xx.yaml schema (current)

```yaml
id: orchestrator_agent
display_name: "Orchestrator"
version: "1.0.0"

allowed_tool_names: [search_docs, send_email]
allowed_tags: [read, internal, external_write]

sources:
  - slack_mcp              # must be registered in harness.yaml sources

policy_rules:
  - id: deny_external_write
    match:
      tool_tags: [external_write]
    action: deny
    reason: "requires explicit approval"
  - id: allow_read
    match:
      tool_tags: [read]
    action: allow

audit_tags:
  team: platform
  env: prod

sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]   # must be ⊆ parent
    allowed_tags: [read, internal]      # must be ⊆ parent
    policy_rules:
      - id: read_only
        match:
          tool_tags: [external_write]
        action: deny
        reason: "research_sub is read-only"
```

---

## 5. Architecture

### check_tool_call — four layers

```
Pre-gate: agent registered? → deny-with-audit if not (never raises)
L1:       tool.name in allowed_tool_names? → deny
L2:       tool.tags ⊆ ctx.allowed_tags? (subagents only) → deny
L3:       policy intersection (subagent → parent → global rules) → deny/allow/redact
L4:       arg scanning for tools tagged in scan_args_for_tags → deny
```

**Invariant:** exactly one AuditEvent per call, on every code path including
pre-gate failure. Never raises — always returns `GateDecision`.

### scan actions (block / alert / redact)

Each scan boundary has a `action:` field. Each scanner in `scanners:` can
override with its own `action:` and `redact_with:` on the `AdapterRef`.

- `block`  — `ScanStatus.BLOCK`, `Decision.BLOCKED`. Hard stop.
- `alert`  — `ScanStatus.WARN`, `Decision.WARN`. Content passes, audit flags it.
- `redact` — Scanner's `redacted_text` applied unconditionally (not gated by
             `block_at`). `ScanStatus.ALLOW`. Falls back to block if scanner
             returns no `redacted_text`.

### source tag overrides

`_source_overrides: dict[agent_id, dict[tool_name, Tool]]` — per-agent.
When a source enriches a tool with additional tags that conflict with the
registry, the enriched variant is stored here, not re-registered globally.
`_resolve_tools()` applies overrides on top of registry for that agent only.

### source required flag

`SourceConfig.required: bool = True` — fail-safe default.
- `required=True`: missing or failed source raises `ConfigError` at `load_agent()`.
- `required=False`: logs and skips.
- Policy suppression always skips regardless of `required` (intentional, not failure).

### Audit invariants

- Exactly one `AuditEvent` per boundary call, on every code path.
- `disabled=True` → `decision=allow`, `finding_count=0`.
- `decision=deny` → only on `tool_call_gate`.
- `decision=blocked` / `decision=warn` → only on scan boundaries.
- No raw user text, LLM output, or matched substrings in any audit field.
- `tenant_id` from config, never from caller.

---

## 6. Source tree

```
src/harness/
├── core/
│   ├── harness.py        ← SHAI facade (single public entry point)
│   ├── context.py        ← AgentContext
│   ├── events.py         ← AuditEvent
│   ├── verdicts.py       ← ScanVerdict (status: ScanStatus), GateDecision, Finding
│   ├── types.py          ← BoundaryName, Decision, ScanAction, ScanStatus, Severity, Transport
│   └── errors.py         ← exception hierarchy
├── boundaries/
│   ├── _scan.py          ← shared scan pipeline (block/alert/redact logic)
│   └── check_tool_call.py← four-layer gate
├── agents/
│   ├── agent_config.py   ← AgentConfig, SubAgentConfig, RuleConfig
│   └── registry.py       ← AgentRegistry
├── tools/
│   ├── tool.py           ← Tool descriptor
│   ├── registry.py       ← ToolRegistry
│   └── source.py         ← ToolSource, SourceRegistry, LocalSource, SkillSource, MCPSource
├── policy/
│   ├── engine.py         ← PolicyEngine Protocol
│   └── rules.py          ← RuleBasedPolicy(rules=[...]) — no rules_path
├── audit/
│   └── emitter.py        ← AuditEmitter (fan-out + optional HMAC signing)
├── config/
│   ├── schema.py         ← HarnessConfig, SourceConfig, BoundaryConfig, PolicyConfig
│   └── loader.py         ← load_yaml (env-var + secret:// resolution)
├── adapters/
│   ├── scanners/
│   │   ├── regex_pii.py           ← 7 categories incl. secret.credential
│   │   ├── injection_scan.py      ← YAML-rule (17 rules)
│   │   ├── file_scanner.py
│   │   ├── rate_limiter.py
│   │   ├── injection_patterns.yaml
│   │   └── patterns_for_doc.yaml
│   ├── audit_sinks/stdout.py, file.py
│   ├── secrets/env.py             ← EnvVarProvider, Secret
│   └── discovery.py
├── integrations/
│   ├── anthropic_sdk.py, langgraph.py, langchain.py
│   ├── crewai.py, pydantic_ai.py, openai_agents.py
│   └── HarnessToolNode            ← gate + dispatch + scan_tool_result
└── py.typed
```

---

## 7. Design constraints

**No backwards compatibility.** Dev phase. Remove obsolete paths rather than
preserve them. No alias classes, no deprecated wrappers.

**No silent failures in core flows.** The pre-gate wraps `agent_registry.get()`
in try/except to emit an audit event — but it still denies, it does not swallow.

**Simplify before extending.** One canonical path per boundary. No parallel
variants.

**Configuration over code.** All behavioral choices in `harness.yaml` or
`agent-xx.yaml`. Policy is inline YAML, not Python.

**All facade methods async** except `scope_context_for_subagent`.

**All Protocol methods async.** Reference adapters with no I/O implement
async methods that return immediately.

**Logging field names** (consistent across all modules):
`tenant_id`, `agent_id`, `sub_agent_id`, `boundary`, `decision`,
`adapter_name`, `source`, `tool`, `op`, `error`.
Do not use `name` as a log extra key — it is reserved by Python's `LogRecord`.

---

## 8. Where to look first

- `SESSION_STATE.md` — current project state, completed work, open items.
- `ARCHITECTURE.md` — full component map, construction sequence, hot path.
- `README.md` — OWASP coverage table, scanner descriptions, quick start.
- `docs/` — per-topic deep dives (boundaries, agents, sources, policy, audit).
- `harness.yaml.example` — canonical reference configuration.
- `examples/shai_demo.py` — 10 scenarios, no external deps.
- `examples/langgraph_agent.py` — LangGraph + Ollama working example.
