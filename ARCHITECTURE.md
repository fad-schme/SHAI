# SHAI Architecture

**Secure Harness AI** is a security control plane for production AI agents. It sits between agent code and tool dispatch, enforcing policy, scanning content, and emitting a tamper-evident audit trail on every call.

---

## System overview

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
                                                               ▲
                                                    (MCP / local / skill)
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely. No per-turn state — every turn is stateless from the harness perspective.

---

## Source tree

```
src/
├── harness/
│   ├── core/
│   │   ├── harness.py        ← SHAI facade — the single public entry point
│   │   ├── context.py        ← AgentContext — identity envelope for every call
│   │   ├── events.py         ← AuditEvent — structured output of every boundary
│   │   ├── verdicts.py       ← ScanVerdict, GateDecision, Finding
│   │   ├── types.py          ← BoundaryName, Decision, Severity, Transport enums
│   │   └── errors.py         ← exception hierarchy
│   ├── boundaries/
│   │   ├── _scan.py          ← shared scan pipeline (run_scan, run_file_scan, run_tool_result_scan)
│   │   └── check_tool_call.py← four-layer gate implementation
│   ├── agents/
│   │   ├── agent_config.py   ← AgentConfig, SubAgentConfig, RuleConfig schemas
│   │   └── registry.py       ← AgentRegistry (load, reload, deregister)
│   ├── tools/
│   │   ├── tool.py           ← Tool descriptor (name, tags, transport, description)
│   │   ├── registry.py       ← ToolRegistry (register, deregister, list)
│   │   └── source.py         ← ToolSource protocol, SourceRegistry, LocalSource, SkillSource, MCPSource
│   ├── policy/
│   │   ├── engine.py         ← PolicyEngine protocol, PolicyDecision, SourceDecision
│   │   └── rules.py          ← RuleBasedPolicy — YAML rule evaluator
│   ├── audit/
│   │   └── emitter.py        ← AuditEmitter — fan-out + optional HMAC signing
│   ├── config/
│   │   ├── schema.py         ← HarnessConfig, SourceConfig, BoundaryConfig, etc.
│   │   └── loader.py         ← load_yaml — env-var + secret:// resolution
│   ├── adapters/
│   │   ├── scanners/
│   │   │   ├── base.py           ← Scanner protocol, ScanResult
│   │   │   ├── regex_pii.py      ← PII scanner (email, phone, SSN, credit card)
│   │   │   ├── injection_scan.py ← YAML-rule injection scanner
│   │   │   ├── file_scanner.py   ← structural file scanner
│   │   │   ├── rate_limiter.py   ← sliding-window rate limiter for check_tool_call
│   │   │   ├── injection_patterns.yaml   ← 17-rule injection catalog
│   │   │   └── patterns_for_doc.yaml     ← 9-rule catalog for tool result scanning
│   │   ├── audit_sinks/
│   │   │   ├── stdout.py         ← StdoutSink (JSONL to stdout)
│   │   │   └── file.py           ← FileSink (rotating JSONL file)
│   │   ├── secrets/
│   │   │   └── env.py            ← EnvVarProvider — resolves secret:// URIs from env
│   │   └── discovery.py          ← entry-point discovery and caching
│   └── integrations/
│       ├── anthropic_sdk.py  ← gated_dispatch, run_turn, make_tool_result_from_denial
│       ├── langgraph.py      ← HarnessToolNode
│       ├── langchain.py      ← wrap_tool, wrap_tools
│       ├── crewai.py         ← wrap_tool, wrap_tools
│       ├── pydantic_ai.py    ← harness_tool decorator, add_harness_middleware
│       └── openai_agents.py  ← make_before_tool_hook, wrap_tool
└── harness_cli/
    ├── main.py
    └── commands/
        ├── validate.py       ← shai validate
        ├── agents.py         ← shai agents list
        └── audit.py          ← shai audit tail
```

---

## SHAI facade

`SHAI` (`core/harness.py`) is the only public entry point. It is constructed once via `await SHAI.from_yaml(path)` and held for the lifetime of the process.

### Construction sequence (`from_yaml`)

```
load_yaml(path)          ← first pass: resolve ${ENV_VAR}
EnvVarProvider()         ← build secrets provider
load_yaml(path, provider) ← second pass: resolve secret:// URIs
_build_scanners(...)     ← input, output, arg scanners
_build_file_scanners(...)← file scanner with embedded InjectionScanner
RuleBasedPolicy(...)     ← policy engine
ToolRegistry()           ← shared tool store
AgentRegistry()          ← agent config store
SourceRegistry(policy)   ← source adapter store
  └── register MCPSource or LocalSource for each config.sources entry
RateLimiter(...)         ← if rate_limit.enabled
AuditEmitter(sinks, signing_secret) ← fan-out + optional HMAC
```

Everything is built once. No lazy initialisation on the hot path.

### Hot path (per turn)

```python
# Startup
harness = await SHAI.from_yaml("harness.yaml")
await harness.register_tools([...])
ctx = await harness.load_agent("agents/my_agent.yaml")

# Per turn
verdict  = await harness.scan_input(text, ctx)
gate     = await harness.check_tool_call(name, args, ctx)
result   = await source.call(name, args)          # agent dispatches
tverdict = await harness.scan_tool_result(result, ctx)
verdict  = await harness.scan_output(response, ctx)
```

No registry lookups on the hot path. Tools and agent config are resolved once at `load_agent()` and stored in `_agent_tools[agent_id]`. Every subsequent turn reads from that dict directly.

---

## Boundaries

### scan_input / scan_output / scan_tool_result

All three share one implementation (`boundaries/_scan.py → run_scan`). The differences are the `BoundaryName` enum value and the scanner list used.

**Pipeline:**

1. If disabled: emit `AuditEvent(disabled=True, decision=allow)`, return `ScanVerdict(blocked=False)`.
2. Run all scanners concurrently via `asyncio.gather`. Per-scanner exceptions are logged and treated as empty findings — the pipeline never raises on scanner failure.
3. Aggregate findings. Any finding at or above `block_at` severity sets `blocked=True`.
4. Emit exactly one `AuditEvent`. No raw text in any field.
5. Return `ScanVerdict`.

### check_tool_call

Four layers, strict order. Exactly one `AuditEvent` emitted regardless of which layer fires.

| Layer | Check | Can policy override? |
|---|---|---|
| Pre-gate | Agent registered in harness? | No |
| L1 | `tool_name` in `allowed_tool_names`? | No |
| L2 | `tool.tags ⊆ ctx.allowed_tags`? (subagent only) | No |
| L3 | Intersection policy (subagent rules → parent rules → global rules) | By design |
| L4 | Arg scanning for `sensitive`-tagged tools | Configurable |

L1 is the hard boundary. No policy rule can grant access to a tool not in `allowed_tool_names`. If the LLM requests a tool the agent was never declared to use, L1 fires before policy runs.

---

## Tool sources

Sources declare where tools come from and are activated at `load_agent()` time — not per turn.

```
SHAI.load_agent(path)
  └── AgentRegistry.load(path)         ← parse and validate agent YAML
  └── SourceRegistry.activate(ctx, cfg.sources)
        ├── PolicyEngine.evaluate_source(source, ctx)  ← suppress check
        ├── source.load(ctx) [concurrent]              ← fetch tools
        └── ToolRegistry.register(tool)                ← merge into shared store
  Missing required source or failed load → ConfigError (fail-safe default)
  Missing optional source (required: false) → logged and skipped
  └── _resolve_tools(cfg)              ← filter to allowed_tool_names
```

### LocalSource (`transport: local`)

Returns tools registered via `harness.register_tools()`. Optionally filtered to an explicit `tool_names` list. Applies `ctx.allowed_tags` filter for subagent contexts.

### SkillSource (`transport: skill`)

A named, curated subset of registered tools. `transport=Transport.SKILL` enables transport-based policy rules to distinguish skill tools from raw local tools.

### MCPSource (`transport: mcp`)

Connects to an MCP server via SSE, runs the JSON-RPC initialize handshake, fetches the tool catalog with `tools/list`, and exposes `call(tool_name, args)` for dispatch. Tools are stamped `transport=Transport.MCP`.

Requires `pip install shai[mcp]` (adds `httpx>=0.27`). If httpx is absent, `load()` raises `ConfigError` with a clear install message.

By default (`required: true`) a failed MCP connection at `load_agent()` time raises `ConfigError` — the agent is not usable without it. Set `required: false` in `SourceConfig` for optional sources where degraded operation is acceptable.

**Lifecycle:**
1. Constructed at `from_yaml()` from `config.sources`.
2. `load(ctx)` connects and fetches tools — called once per agent at `load_agent()`.
3. `call(name, args)` dispatches tool calls. Not called by the harness — called by the agent dispatch layer after `check_tool_call` approves.
4. `close()` tears down the HTTP client. Called from `SHAI.close()`.

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    source = await harness.get_source("my_mcp_server")
    result = await source.call(tool_name, gate.redacted_args or args)
```

**Transport routing** — `Tool.transport` tells the dispatch layer how to invoke the tool:
- `LOCAL` / `SKILL` → Python callable in the agent's runtime
- `MCP` → `source.call()` via MCPSource

---

## Policy engine

`RuleBasedPolicy` implements the intersection model:

1. Subagent rules + parent rules evaluated first (in that order)
2. Global rules from `rules_path` evaluated second
3. First match anywhere wins and returns immediately
4. No match → `PolicyDecision(action="allow")`

`evaluate_source()` checks `suppress` rules against `source.tags` and `ctx.agent_id` / `ctx.sub_agent_id`. Default: `SourceDecision(active=True)`.

**Rule actions:** `allow`, `deny`, `redact`, `suppress`
**Match fields:** `tool_names`, `tool_tags`, `transport`, `agent_ids`, `sub_agent_ids`, `source_tags`, `any`, `all`, `not`

---

## Audit system

`AuditEmitter` fans out to all configured sinks concurrently. Individual sink failures are logged and swallowed. If all sinks fail, `AuditEmissionError` is raised.

**Optional HMAC-SHA256 signing (R3):** when `audit_signing.enabled: true`, each event is signed before emission. The signature covers all non-null fields except `signature` itself, serialised as deterministic JSON (`sort_keys=True`). Verification: recompute the HMAC and compare to `event.signature`.

**AuditEvent invariants:**
- Exactly one event per boundary call, on every code path
- No raw user text, LLM output, tool arguments, or scanner-matched substrings in any field
- `decision=deny` → `deny_reason` is non-null
- `decision=blocked` → only on scan boundaries, never on `tool_call_gate`
- `disabled=True` → `decision=allow`, `finding_count=0`
- `tenant_id` from `HarnessConfig`, never from the caller

---

## Security controls (OWASP Agentic AI Threats)

See the full coverage table in `README.md`.

### R1 — Rate limiter (`adapters/scanners/rate_limiter.py`)

Sliding-window token bucket. Two independent counters per `agent_id`: global call budget and per-tool budget. Both must pass. Thread-safe via `threading.Lock`. Resets on `deregister_agent()`.

### R2 — Tool result scanning

`scan_tool_result()` runs `patterns_for_doc.yaml` against every tool return value before it re-enters the LLM context. Detects indirect prompt injection embedded in document content, search results, or API responses.

### R3 — Audit event signing

HMAC-SHA256 over deterministic JSON of each `AuditEvent`. Key resolved via `EnvVarProvider` at startup. Provides tamper-evidence for the audit trail.

---

## Concurrency model

One `SHAI` instance, many concurrent turns.

`ToolRegistry` uses a `threading.Lock` for writes (startup only) and lock-free dict reads for the hot path. `AgentRegistry` uses the same pattern.

`_agent_tools[agent_id]` is populated at `load_agent()` and read lock-free on every turn. No per-turn mutation.

`RateLimiter` uses a single `threading.Lock` held only for deque operations — O(1) amortised. Never held across I/O.

`AuditEmitter` uses `asyncio.gather` for concurrent sink fan-out.

`SourceRegistry.activate()` uses `asyncio.gather` for concurrent source loading.

---

## Secrets

`EnvVarProvider` resolves `secret://VAR_NAME` URIs: `VAR_NAME` → normalise separators to `_`, uppercase, prepend optional prefix. Resolution is synchronous and called once at `from_yaml()` time.

`Secret` is a frozen dataclass with `value`, `expires_at`, and `version`. `is_expired()` checks wall-clock time. The value is never included in `repr()` or error messages.

Enterprise providers (Vault, AWS KMS, GCP Secret Manager) swap in by replacing `EnvVarProvider()` in `from_yaml()`.

---

## Adapter discovery

Python entry points under six groups:

| Group | Interface |
|---|---|
| `harness.scanners` | `Scanner` protocol |
| `harness.policy` | `PolicyEngine` protocol |
| `harness.audit_sinks` | `AuditSink` protocol |
| `harness.sources` | `ToolSource` protocol |
| `harness.secrets` | `SecretsProvider` ABC |

Entry points are loaded once on first access and cached. Name collisions within a group raise `AdapterDiscoveryError` at startup — never silently resolved.

---

## Error hierarchy

```
HarnessError
├── ConfigError                  ← invalid YAML, bad schema, missing file
├── AdapterDiscoveryError        ← entry point not found or name collision
├── AgentNotRegisteredError      ← agent_id not in AgentRegistry
├── AgentConflictError           ← same agent_id, different content
├── SubAgentNotDeclaredError     ← sub_agent_id not in parent's sub_agents
├── ToolNotRegisteredError       ← tool name not in ToolRegistry
├── PolicyEvaluationError        ← engine failure (not a normal deny)
├── AuditEmissionError           ← all sinks failed
└── MCPInvocationError           ← MCP server returned JSON-RPC error
```

All errors carry structured context fields (`agent_id`, `op`, `boundary`, etc.) as attributes for log formatters.


## Known limitations and roadmap

### Tool identity is global-by-name (0.2.x)

`ToolRegistry` is keyed by `tool_name` alone. Transport and source tags are
stamped at source activation time. If two sources provide a tool with the same
name, the registry holds one variant; the per-agent `_source_overrides` dict
holds the other. Policy rules that match on `transport` or `source_tags` will
evaluate against whichever variant was resolved at `load_agent()` time, not
against the source the dispatch call actually came from.

**Current mitigation:** `ToolRegistry.register()` raises `ConfigError` on
same-name conflict with different definitions, surfacing the ambiguity at
startup.

**Planned fix (0.2.x):** Composite tool identity `(source_name, tool_name)`
at the agent resolution layer. The LLM call interface is unchanged; the gate
resolves the source internally and evaluates policy against the
source-specific `Tool` object.

### shai-connectivity (planned)

Network-layer enforcement via dispatch tokens. See `docs/connectivity.md`.


### shai-connectors — manifest registry (0.2.x)

Curated YAML manifests that wrap community MCP servers with correct SHAI
security configuration: tool tags, `allowed_urls`, scan policies, auth
schemas. Operators reference a connector by name instead of hand-configuring
source entries.

```yaml
sources:
  - connector: slack
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
```

Initial set: Slack, WhatsApp, Gmail, GitHub, Notion, Linear, Jira,
Google Drive, Microsoft Teams. Manifests ship in `shai-connectors`;
MCP servers come from the community or service-hosted endpoints.

### shai-local-connectors — local service MCP servers (0.2.x)

Lightweight MCP servers for locally-installed services that have no hosted
MCP: Apple Notes, Obsidian, SQLite, filesystem. Distributed as
`shai-local-connectors`. Pre-wired with `allowed_urls: []` (no outbound
network), `allowed_paths` scoping, and `sensitive` tags on write tools.
Local process lifecycle managed by the harness (`load_agent` / `close()`).

### MCPSource live tests

`MCPSource` SSE connection and JSON-RPC handshake are tested with mocks only.
