# SHAI Architecture

**Secure Harness AI** is a security control plane for production AI agents. It enforces four security boundaries around every agent turn, governs tool calls through a four-layer gate, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► Ingress Scan ──► LLM ──► Tool Governance ──► tool ──► Tool Stream Control ──► LLM ──► Egress Scan ──► response
                                                                ▲
                                              MCP Governance runs at connection time (tools/list)
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely. No per-turn state — every boundary call is stateless from the harness perspective.

---

## Security Core

### Ingress Scan — `scan_input`, `scan_file`

Runs on every user message before it reaches the LLM. Scanners run concurrently. Per-scanner exceptions are logged as empty findings — the pipeline never raises.

**Scanners:** `InjectionScanner` (`injection_patterns.yaml`, 17 rules) · `RegexPIIScanner` (7 categories) · `FileScanner` (structural + doc-tuned injection scan on extracted text)

**Actions:** `block` · `alert` · `redact`

### Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Four layers in strict order. First denial wins. Exactly one `AuditEvent` per call on every code path including pre-gate failure. Never raises.

| Layer | Check | Bypassable? |
|---|---|---|
| **L0** | Rate limiter — sliding-window token bucket | No |
| **L1** | `tool_name` in `allowed_tool_names` | No — hard pre-policy |
| **L2** | `tool.tags ⊆ ctx.allowed_tags` (subagents only) | No — capability gate |
| **L3** | Policy intersection: subagent → parent → global | By design |
| **L4** | Arg scanning for `sensitive`-tagged tools | Configurable |

Returns `GateDecision(allowed, deny_reason, redacted_args, source_name, dispatch_token)`.

### Tool Stream Control — `scan_tool_result`

Runs on every tool result before it re-enters the LLM context. Uses `InjectionScanner` with `patterns_for_doc.yaml` (doc-tuned, lower false-positive rate for structured content). Pass `tool_name=` to activate connector manifest `scan_tool_result_on` optimisation — only declared T6-risk tools are scanned.

### Egress Scan — `scan_output`

Runs on every LLM response before it reaches the user. `RegexPIIScanner` by default. Catches data egress and PII leakage.

### MCP Governance — `scan_mcp_metadata`

Runs at MCP source connection time, before any tool is registered. `MCPMetadataScanner` scans tool names, descriptions, and argument schemas from the `tools/list` response. `block_at: medium` default — metadata injection is high signal.

**Why medium not high:** almost no legitimate content in tool descriptions looks like `"ignore all previous instructions"`. The other boundaries use `high` because false positives on user text are costly; tool metadata has much better signal-to-noise.

---

## SHAI Gateway

### Connector Manifests

8 Tier A cloud connectors (`slack`, `github`, `notion`, `jira`, `gmail`, `postgresql`, `stripe`, `google_drive`) ship with `url`, `allowed_urls`, `allowed_methods`, per-tool tags, blocked external-write tools, and `scan_tool_result_on` declarations. Loaded via `connector:` in `harness.yaml`. Operator supplies only credentials.

### Dispatch Tokens — `connectivity/token.py`

`DispatchToken`: HMAC-signed (HS256), source-bound, short-TTL, one-time-use. Issued by Tool Governance on every allowed gate decision when `connectivity.enabled`. Fields: `token_id` (UUID, nonce), `agent_id`, `tool_name`, `source_name`, `allowed_urls`, `allowed_methods`, `expires_at`.

### ShaiTransport — `connectivity/transport.py`

`httpx.AsyncBaseTransport` subclass installed on every `MCPSource` client when `connectivity.enabled`. Per-request enforcement chain:

```
URL envelope → method → token signature → source binding → URL binding → method binding → nonce check
    → X-Shai-Token header injection → forward → NetworkAuditEvent
```

Raises `NetworkPolicyError` on any violation. Emits `NetworkAuditEvent` with `token_id` join key for SIEM correlation with the gate `AuditEvent`.

---

## Observability

### Audit Trail — `audit/emitter.py`

`AuditEmitter` fans out to configured sinks (file, stdout, custom). Optional HMAC-SHA256 signing per event. `collect_events()` context manager for in-process collection without affecting sinks.

**Invariants:**
- Exactly one `AuditEvent` per boundary call, on every code path
- No raw text in any field — no user input, LLM output, args, or matched substrings
- `decision=deny` only on `tool_call_gate`
- `decision=blocked`/`warn` only on scan boundaries
- `disabled=True` → `decision=allow`, `finding_count=0`
- `tenant_id` from config, never from caller

`NetworkAuditEvent` (`event_type="network_egress"`) written to same sinks. `token_id` joins with gate event.

---

## Capabilities

### Subagent Scoping — `core/context.py`, `agents/agent_config.py`

`scope_context_for_subagent(ctx, sub_agent_id)` returns `AgentContext` with narrowed `allowed_tool_names` and `allowed_tags`. Validated at `load_agent()` — subagent cannot exceed parent. Pure synchronous function, no I/O.

### Framework Integrations — `integrations/`

`@shai_tool` decorator creates a `ShaiTool` satisfying both SHAI and framework tool interfaces. One definition, used across all integrations.

| Integration | Class/Function | Boundary coverage |
|---|---|---|
| LangGraph | `HarnessToolNode` | Gate + dispatch + Tool Stream Control |
| LangChain Agent Loop | `ShaiMiddleware` | All four boundaries via `abefore_agent`, `awrap_tool_call`, `aafter_agent` |
| LangChain classic | `wrap_tools()` | Gate per call |
| Anthropic SDK | `gated_dispatch` | Gate + dispatch |
| CrewAI / PydanticAI / OpenAI Agents | `wrap_tools()` / hooks | Gate per call |

---

## Construction sequence

`from_yaml(path)` builds SHAI in one async call:

```
load_yaml() → resolve ${ENV_VAR} → resolve secret:// → validate HarnessConfig
    → build scanners (Ingress, Egress, Tool Stream, MCP Governance, arg scanners)
    → build policy (RuleBasedPolicy from inline rules)
    → build AuditEmitter (sinks + optional signing key)
    → build SourceRegistry (MCPSource per mcp source, LocalSource per local)
    → stamp connectivity config + emitter + metadata scanners onto each MCPSource
    → collect scan_tool_result_on from connector manifests
    → return SHAI instance
```

`load_agent(path)` per agent:

```
load + validate agent YAML → AgentRegistry.load()
    → SourceRegistry.activate(ctx, agent.sources) → MCPSource.load() per MCP source
        → MCPSource._connect() → SSE + initialize + tools/list
        → MCPSource._scan_mcp_metadata() per tool → skip if blocked
        → Tool objects built with composite identity (source_name, Tool)
    → _resolve_tools() → {tool_name: (source_name, Tool)} per agent
    → return AgentContext
```

---

## Source tree

```
src/harness/
├── core/
│   ├── harness.py         ← SHAI facade — single public entry point
│   ├── context.py         ← AgentContext
│   ├── events.py          ← AuditEvent, NetworkAuditEvent
│   ├── verdicts.py        ← ScanVerdict, GateDecision, Finding
│   ├── types.py           ← BoundaryName, Decision, Severity, Transport enums
│   └── errors.py          ← exception hierarchy
├── boundaries/
│   ├── _scan.py           ← shared scan pipeline (block/alert/redact logic)
│   └── check_tool_call.py ← Tool Governance four-layer gate
├── agents/
│   ├── agent_config.py    ← AgentConfig, SubAgentConfig, RuleConfig
│   └── registry.py        ← AgentRegistry
├── tools/
│   ├── tool.py            ← Tool descriptor
│   ├── registry.py        ← ToolRegistry
│   └── source.py          ← ToolSource, SourceRegistry, LocalSource, SkillSource, MCPSource
├── policy/
│   ├── engine.py          ← PolicyEngine protocol
│   └── rules.py           ← RuleBasedPolicy
├── audit/
│   └── emitter.py         ← AuditEmitter — fan-out + collect_events() + signing
├── config/
│   ├── schema.py          ← HarnessConfig, BoundaryConfig, MCPMetadataScanConfig, ...
│   └── loader.py          ← load_yaml — env-var + secret:// resolution
├── connectivity/
│   ├── config.py          ← ConnectivityConfig
│   ├── token.py           ← DispatchToken, sign_token, verify_token
│   └── transport.py       ← ShaiTransport, NetworkAuditEvent, NetworkPolicyError
├── connectors/
│   ├── __init__.py        ← ConnectorManifest, load_manifest, list_connectors
│   └── manifests/         ← 8 Tier A YAML manifests
│       slack.yaml, github.yaml, notion.yaml, jira.yaml
│       gmail.yaml, postgresql.yaml, stripe.yaml, google_drive.yaml
├── adapters/
│   ├── scanners/
│   │   ├── base.py                    ← Scanner protocol, ScanResult
│   │   ├── regex_pii.py               ← RegexPIIScanner
│   │   ├── injection_scan.py          ← InjectionScanner
│   │   ├── file_scanner.py            ← FileScanner
│   │   ├── rate_limiter.py            ← RateLimiter
│   │   ├── mcp_metadata_scanner.py    ← MCPMetadataScanner
│   │   ├── injection_patterns.yaml    ← 17-rule catalog (Ingress Scan)
│   │   ├── patterns_for_doc.yaml      ← 9-rule catalog (Tool Stream Control)
│   │   └── mcp_metadata_patterns.yaml ← 8-rule catalog (MCP Governance)
│   ├── audit_sinks/
│   │   ├── stdout.py
│   │   └── file.py
│   ├── secrets/
│   │   └── env.py          ← EnvVarProvider
│   └── discovery.py        ← entry-point discovery
├── integrations/
│   ├── base.py             ← ShaiTool, @shai_tool decorator
│   ├── langgraph.py        ← HarnessToolNode
│   ├── langchain.py        ← wrap_tools, ShaiMiddleware
│   ├── anthropic_sdk.py    ← gated_dispatch, make_tool_result_from_denial
│   ├── crewai.py
│   ├── pydantic_ai.py
│   └── openai_agents.py
└── py.typed
```

---

## Known limitations and roadmap

### Composite tool identity — current state

`ToolRegistry` is keyed by `(source_name, tool_name)` pairs. `_agent_tools` carries `(source_name, Tool)` tuples. `GateDecision.source_name` is set on every allowed decision. Tool name conflicts across sources still raise `ConfigError` at `load_agent()` time — the registry surfaces ambiguity at startup.

### T16 partial coverage

`ShaiTransport` enforces the URL envelope for MCP tool calls. Raw socket traffic from non-MCP tools is uncontrolled until `shai-gateway` ships. `RegexPIIScanner` on `scan_output` provides application-layer T16 coverage.

### shai-local-connectors

Local connector manifests are not in `shai` core — a manifest without its MCP server process is misleading. Package boundary: `shai-local-connectors` ships manifests + managed subprocess per connector. `load_manifest()` will be extended to check entry points registered by the installed package.

### Enterprise providers

`EnvVarProvider` is the only `SecretsProvider` implementation. Vault, AWS KMS, GCP Secret Manager are enterprise scope.
