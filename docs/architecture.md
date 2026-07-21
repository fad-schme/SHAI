# Architecture

**Secure Harness AI** is a security control plane for production AI agents. It enforces security boundaries around every agent turn, governs tool calls through a pre-gate + four-layer stack, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
                                            ▲
                              MCP Governance runs at connection time (tools/list)
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely.

---

## Repository layout

```
src/harness/
├── __init__.py                        public exports: SHAI, Tool, AgentContext, verdicts
├── core/
│   ├── harness.py                     SHAI facade — the only public entry point
│   ├── context.py                     AgentContext (identity envelope)
│   ├── verdicts.py                    GateDecision, ScanVerdict
│   ├── events.py                      AuditEvent, NetworkAuditEvent
│   ├── types.py                       enums: BoundaryName, Decision, Severity, Transport
│   └── errors.py                      HarnessError hierarchy
├── boundaries/
│   ├── check_tool_call.py             four-layer tool gate (L1–L4)
│   ├── session_budget.py              DoS budget enforcer (R2): step, token, fan-out, loop
│   └── _scan.py                       scan_input, scan_output, scan_tool_result, scan_file
├── adapters/
│   ├── scanners/
│   │   ├── injection_scan.py          InjectionScanner — 17-rule YAML catalog
│   │   ├── regex_pii.py               RegexPIIScanner — 7 PII categories
│   │   ├── file_scanner.py            FileScanner — MIME, macros, size gate
│   │   ├── mcp_metadata_scanner.py    MCPMetadataScanner — tool description injection
│   │   ├── rate_limiter.py            RateLimiter — sliding-window (R1)
│   │   └── base.py                    Scanner Protocol
│   ├── audit_sinks/                   stdout, rotating file
│   ├── secrets/                       EnvVarProvider
│   └── discovery.py                   entry-point adapter loader
├── agents/
│   ├── agent_config.py                AgentConfig, SubAgentConfig, RuleConfig
│   └── registry.py                    AgentRegistry
├── audit/
│   └── emitter.py                     AuditEmitter + HMAC signing
├── config/
│   ├── schema.py                      HarnessConfig, all sub-configs including ExecutionBudgetConfig
│   └── loader.py                      YAML loader + secret resolution
├── policy/
│   ├── engine.py                      PolicyEngine Protocol + RuleBasedPolicy
│   └── rules.py                       rule evaluation
├── tools/
│   ├── registry.py                    ToolRegistry
│   ├── source.py                      LocalSource, MCPSource, SourceRegistry
│   └── tool.py                        Tool dataclass
├── connectivity/
│   ├── config.py                      ConnectivityConfig
│   ├── token.py                       DispatchToken (HMAC-signed)
│   └── transport.py                   ShaiTransport (httpx)
├── connectors/                        bundled connector manifests (Slack, GitHub, …)
└── integrations/                      LangGraph, LangChain, Anthropic SDK, CrewAI, PydanticAI, OpenAI Agents
```

---

## Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Two pre-gate controls run before the four policy layers. First denial wins. Exactly one `AuditEvent` per call on every code path.

### Execution order

```
R1: Rate limiter      — sliding-window token bucket (RateLimiter)
R2: Session budget    — step counter, token burn-down, fan-out, loop detection (SessionBudget)
    Pre-gate          — agent registered?
L1: allowed_tool_names hard gate
L2: allowed_tags subagent capability gate
L3: intersection policy (subagent → parent → global)
L4: arg scanning (sensitive-tagged tools only)
```

### Session Budget — `boundaries/session_budget.py`

`SessionBudget` is a thread-safe, per-session enforcer for DoS / Unbounded Consumption (OWASP T4). One instance per SHAI facade, keyed by `(agent_id, session_id)`. All controls are opt-in via `None` defaults.

| Control | Trigger |
|---|---|
| **Step counter** | `state.steps >= max_steps` — blocks before the call is recorded |
| **Token burn-down** | `state.tokens + cost > max_tokens_per_session` — cost = `tokens_consumed × tool_cost_weights.get(tool, 1)` |
| **Per-prompt fan-out** | `state.prompt_calls >= max_tool_calls_per_prompt` — resets when `prompt_id` changes |
| **Loop detection** | Jaccard similarity ≥ `loop_similarity_threshold` against last `loop_detection_window` fingerprints |

Fingerprints are `frozenset` of `"key=value"` strings (values truncated at 128 chars). `loop_detection_window=0` (default) disables loop detection.

Config lives in `harness.yaml` under `check_tool_call.execution_budget:`. Per-agent overrides in `agent-xx.yaml` under `limits:` are merged on top of global defaults at `load_agent()` time. Invalid agent overrides fall back to global defaults with a warning log.

Budget state is cleaned up in `deregister_agent()` via `session_budget.reset(agent_id)`.

---

## Scan boundaries

### Ingress Scan — `scan_input`, `scan_file`

Runs before the LLM. Scanners run concurrently via `asyncio.gather`. Per-scanner exceptions produce empty findings — pipeline never raises. Disable-able; emits `disabled=True` event when off.

**Scanners:** `InjectionScanner` (17 rules) · `RegexPIIScanner` (7 categories) · `FileScanner` (size gate, MIME, macros, extracted text scan)

### Tool Stream Control — `scan_tool_result`

Runs before tool results re-enter the LLM context. Uses `patterns_for_doc.yaml` (9 rules, doc-tuned). Disabled by default. Closes the ClawJacked-style indirect injection vector.

### Egress Scan — `scan_output`

Mirrors ingress. Catches PII leakage and data exfiltration in the LLM's final response.

### MCP Governance — `scan_mcp_metadata`

Runs at MCP connection time before any tool is registered. Scans tool names, descriptions, and argument schemas. `block_at: medium` default — metadata injection has a near-zero false-positive rate.

---

## Audit trail

Every boundary call emits exactly one `AuditEvent` to `AuditEmitter`, which fans out to all configured sinks. Emission is structural — boundary code cannot return without emitting.

**Invariants:**
- Exactly one event per boundary call, on every code path
- No raw text in any field (no user input, LLM output, args, or matched substrings)
- `disabled=True` → `decision=allow`, `finding_count=0`
- `tenant_id` stamped from config, never from the caller
- Events are optionally HMAC-SHA256 signed and tamper-evident

---

## Adapter extension points

| Protocol | Reference impl | Production impl (enterprise) |
|---|---|---|
| `Scanner` | Regex PII, injection patterns | Purview, Nightfall, Lakera |
| `PolicyEngine` | YAML rule evaluator | OPA bundle loader, Cedar |
| `AuditSink` | stdout JSONL, rotating file | Splunk, Sentinel, Elastic, S3+WORM |
| `ToolRegistry` | In-memory dict | Redis, central registry |
| `SecretsProvider` | Env vars | Vault, AWS KMS, GCP Secret Manager |

Adapters are discovered via Python entry points and selected by name in `harness.yaml`.
