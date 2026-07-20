# SHAI Architecture

**Secure Harness AI** is a security control plane for production AI agents. It enforces five security boundaries around every agent turn, governs tool calls through a six-layer gate, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► Ingress Scan ──► LLM ──► Tool Governance ──► tool ──► Tool Stream Control ──► LLM ──► Egress Scan ──► response
                                                                ▲
                                              MCP Governance runs at connection time (tools/list)
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely.

---

## Design principle

Security risks in LLM-enabled systems should be treated as **expected operational conditions**, not exceptional events. The correct question is not "how do we make the model never misbehave?" but "how do we build a system that survives the model misbehaving?"

This shifts enforcement downstream — to deterministic code that evaluates what the agent *proposes to do*, independently of why it proposed it. The model's job is to be useful. SHAI's job is to ensure that when the model fails — or is turned against you — the failure stops at the gate.

---

## Security Core

### Ingress Scan — `scan_input`, `scan_file`

Runs on every user message before it reaches the LLM. Scanners run concurrently. Per-scanner exceptions are logged as empty findings — the pipeline never raises.

**Pre-processing — normalization (`core/normalize.py`):** Before any scanner runs, the input is canonicalized into one or more plaintext *views* — the surface form plus any decoded variants (base64, hex, URL, rot13, unicode homoglyphs, fragment reassembly). Scanners match against all views. Raw text the agent sees is never mutated. Configured under `normalization:` in `harness.yaml`; enabled by default.

**Scanners:** `HeuristicScanner` (always on, structural anomaly detection) · `InjectionScanner` (`injection_patterns.yaml`, 17 rules) · `JailbreakScanner` (`jailbreak_patterns.yaml`, 6 rules) · `IdentitySpoofScanner` (`identity_spoof_patterns.yaml`, 4 rules) · `RegexPIIScanner` (7 categories) · `FileScanner` (structural + doc-tuned injection scan on extracted text)

**HeuristicScanner (0.2.0):** Always prepended to every scan boundary. Not configurable. Four sub-scores: entropy analysis (Shannon entropy > 4.5 bits/char catches base64 blobs and obfuscated payloads), instruction density (ratio of control tokens to total — injection attempts > 8%), language coherence (bigram divergence detects register shifts), structural markers (embedded `<|system|>`, `[INST]`, `{"role":}`). Each 0–2, summed: ≥5 HIGH, ≥3 MEDIUM, ≥1 LOW.

**Ensemble severity promotion (0.2.0):** Runs unconditionally after all scanners complete. Maps severity to weight (LOW=1, MEDIUM=3, HIGH=6), sums per category across scanners. When sum ≥ 4.0 and 2+ distinct scanners contributed → promotes to HIGH. Two independent MEDIUM signals become HIGH even though neither alone would trigger `block_at: high`.

**Incremental pattern database (0.2.0):** Built-in YAML patterns ship with the package. Supplemental patterns are stored in a signed SQLite database (`patterns_db` in config). Each row is HMAC-SHA256 verified at startup. Verified rules are compiled and passed to `InjectionScanner` as `extra_rules`. Distributed via signed bundles: `shai patterns apply --bundle <file>`. Tampered rows are skipped.

**Error handling (0.2.0):** Per-boundary `on_error` config controls scanner failure behavior: `fail_closed` (default, BLOCK), `fail_open` (empty findings), `degrade` (WARN). Per-scanner circuit breaker (CLOSED → OPEN → HALF_OPEN, exponential backoff, cap 5 min). Scanner failures and circuit trips emit `boundary=SYSTEM`, `decision=DEGRADED` audit events.

| Scanner | Category prefix | What it catches | Languages |
|---|---|---|---|
| `injection_scan` | `prompt_injection`, `tool_injection`, `obfuscation`, … | Data-boundary attacks: tool coercion, exfiltration, context spoofing, encoded payloads (17 EN rules) | EN + FR, ES, DE, ZH |
| `jailbreak_scan` | `jailbreak.*` | Guardrail-integrity attacks: persona override, instruction override, refusal suppression, prompt extraction, mode activation (6 EN rules) | EN + FR, ES, DE, ZH |
| `identity_spoof_scan` | `identity_spoof.*` | Agentic identity spoofing: claimed orchestrator/system authority, peer privilege escalation, tool-result authority injection (4 EN rules) | EN + FR, ES, DE, ZH |
| `regex_pii` | `pii.*`, `secret.*`, `network.*` | PII and credential patterns with optional redaction | EN (Unicode-aware) |

**Multilingual pattern catalogs (`l10n/`):** Three scanners ship multilingual variants in
`src/harness/adapters/scanners/l10n/`. Pattern files follow the naming convention
`<scanner>_patterns.l10n.yaml`. Each l10n file covers the highest-threat rule families
per language. `patterns_for_doc.yaml` (tool result scanning) and `mcp_metadata_patterns.yaml`
are English-only — MCP metadata is typically ASCII and tool result content is
language-independent at the structural level.

**L10n coverage per scanner:**

| Rule family | FR | ES | DE | ZH |
|---|---|---|---|---|
| Injection: instruction override | ✅ | ✅ | ✅ | ✅ |
| Injection: jailbreak/persona | ✅ | ✅ | ✅ | ✅ |
| Injection: config/prompt leakage | ✅ | ✅ | ✅ | ✅ |
| Injection: tool coercion | ✅ | ✅ | ✅ | ⚠️ missing |
| Jailbreak: all 4 families | ✅ | ✅ | ✅ | ✅ |
| Identity spoof: all 3 families | ✅ | ✅ | ✅ | ✅ |

ZH `tool_coercion` is the one known gap — all other languages have it. Tracked as a backlog item.

**Actions:** `block` · `alert` · `redact`

**Session accumulator pre-check:** Before scanners run, `scan_input` checks the cross-turn threat accumulator. An escalated session is blocked immediately — scanners never run.

### Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Six layers in strict order. First denial wins. Exactly one `AuditEvent` per call on every code path. Never raises.

| Layer | Check | Bypassable? |
|---|---|---|
| **R1** | Rate limiter — sliding-window token bucket | No |
| **R2** | Session budget — step counter, token burn-down, per-prompt fan-out, loop detection | No |
| **L1** | `tool_name` in `allowed_tool_names` | No — hard pre-policy |
| **L2** | Argument rules — deterministic parameter constraints | No |
| **L3** | Irreversibility gate — blast-radius enforcement | No |
| **L4** | `tool.tags ⊆ ctx.allowed_tags` (subagents only) | No — capability gate |
| **L5** | Policy intersection: subagent → parent → global | By design |
| **L6** | Arg scanning for `sensitive`-tagged tools | Configurable |

Returns `GateDecision(allowed, deny_reason, redacted_args, source_name, dispatch_token)`.

#### L2 — Argument Rules

`ArgumentRule` declarations on a `Tool` encode typed, deterministic constraints that are evaluated before the policy engine. First violation denies the call regardless of context.

```python
Tool(
    name="approve_payment",
    tags=["financial"],
    argument_rules=[
        ArgumentRule(arg="amount",      max_value=50_000),
        ArgumentRule(arg="vendor",      allowlist=["acme_corp", "globex"]),
        ArgumentRule(arg="destination", pattern=r"^https://pay\.internal/"),
    ],
)
```

The gate does not ask *why* the LLM proposed the action. It checks the argument value against a closed set of rules. This is the correct architecture: detecting a cleverly disguised injection is open-ended; checking whether `amount > 50000` is a closed problem.

Available constraint fields on `ArgumentRule`: `max_value`, `min_value`, `allowlist`, `pattern`, `required`.

Implemented in `boundaries/argument_policy.py`. Raises `ArgumentViolationError` on first violation; `check_tool_call` converts this to `_deny()`.

#### L3 — Irreversibility Gate

Every tool carries an `Irreversibility` tier classifying its blast radius. Evaluated after argument rules, before the subagent tag gate.

| Tier | Behaviour |
|---|---|
| `REVERSIBLE` | Default. No extra check. |
| `SENSITIVE` | Denied unless `ctx.human_approved=True` |
| `IRREVERSIBLE` | Denied unless `ctx.human_approved=True` |

```python
Tool(name="delete_record", tags=["destructive"],
     irreversibility=Irreversibility.IRREVERSIBLE)
```

The agent sets `ctx.human_approved=True` on `AgentContext` after obtaining explicit human confirmation. SHAI enforces the signal's presence — not how it was obtained.

Implemented in `boundaries/argument_policy.py`. Raises `IrreversibleActionError` when blocked; `check_tool_call` converts this to `_deny()`.

#### Session Budget — `boundaries/session_budget.py`

`SessionBudget` enforces per-session execution limits as a pre-gate check (R2). Keyed by `(agent_id, session_id)`.

| Control | Config key | Description |
|---|---|---|
| Step counter | `max_steps` | Hard ceiling on total tool invocations per session |
| Token burn-down | `max_tokens_per_session` | Cumulative token budget; `tool_cost_weights` multiplies cost per tool |
| Per-prompt fan-out | `max_tool_calls_per_prompt` | Resets when `prompt_id` changes. Distinct from rate limiting — catches amplification within one request |
| Loop detection | `loop_detection_window` / `loop_similarity_threshold` | Jaccard similarity check over a rolling fingerprint window |

Configured globally in `harness.yaml` under `check_tool_call.execution_budget:`, with per-agent overrides in `agent-xx.yaml` under `limits:`.

```yaml
check_tool_call:
  execution_budget:
    max_steps: 30
    max_tokens_per_session: 50000
    max_tool_calls_per_prompt: 10
    tool_cost_weights:
      web_search: 3
      database_query: 2
    loop_detection_window: 5
    loop_similarity_threshold: 0.95
```

**Fan-out vs rate limit distinction:** Rate limiting controls frequency over time (N requests per minute). Fan-out limiting controls amplification within a single request (N tool calls per user turn). A single prompt that induces 200 tool calls bypasses rate limiting entirely — it is one request. Fan-out catches it.

#### Session Threat Accumulator — `boundaries/session_accumulator.py`

Detects crescendo attacks: multi-turn escalation where each turn stays below per-turn thresholds but the session pattern is clearly adversarial. Runs as a pre-check in `scan_input`.

SQLite-backed (`aiosqlite`). Risk scores persist across process restarts. Keyed by `ctx.conversation_id` when set, falls back to `ctx.agent_id`.

**Score formula:** `min(1.0, block_rate × 0.60 + warn_rate × 0.25 + reframe_bonus × 0.30)`

When score ≥ `escalation_threshold`: emit audit event with `extra.signals=["session_escalation"]` and return `ScanVerdict(BLOCK)` or `ScanVerdict(WARN)` per `on_escalation` config.

```yaml
session:
  enabled: true
  escalation_threshold: 0.70
  window_size: 10
  reframe_similarity: 0.72
  on_escalation: block
```

### Tool Stream Control — `scan_tool_result`

Runs on every tool result before it re-enters the LLM context. This is the boundary that catches indirect prompt injection — malicious instructions embedded in documents, search results, emails, or API responses the agent reads.

Most security frameworks miss this boundary entirely. SHAI treats tool results as untrusted content. Uses `InjectionScanner` with `patterns_for_doc.yaml` (doc-tuned, lower false-positive rate for structured content).

```yaml
scan_tool_result:
  enabled: true
  block_at: high
```

### Egress Scan — `scan_output`

Runs on every LLM response before it reaches the user. `RegexPIIScanner` by default. Catches data egress and PII leakage.

### MCP Governance — `scan_mcp_metadata`

Runs at MCP source connection time, before any tool is registered. `MCPMetadataScanner` scans tool names, descriptions, and argument schemas from the `tools/list` response. `block_at: medium` default.

---

## SHAI Gateway

### Connector Manifests

8 Tier A cloud connectors (`slack`, `github`, `notion`, `jira`, `gmail`, `postgresql`, `stripe`, `google_drive`) ship with `url`, `allowed_urls`, `allowed_methods`, per-tool tags, blocked external-write tools, and `scan_tool_result_on` declarations.

### Dispatch Tokens — `connectivity/token.py`

`DispatchToken`: HMAC-signed (HS256), source-bound, short-TTL. Issued by Tool Governance on every allowed gate decision when `connectivity.enabled`. Fields: `token_id` (UUID, nonce), `agent_id`, `tool_name`, `source_name`, `allowed_urls`, `allowed_methods`, `expires_at`.

### ShaiTransport — `connectivity/transport.py`

`httpx.AsyncBaseTransport` subclass installed on every `MCPSource` client. Per-request enforcement:

```
URL envelope → method → token signature → source binding → URL binding → method binding → nonce check
    → X-Shai-Token header injection → forward → NetworkAuditEvent
```

---

## Observability

### Audit Trail — `audit/emitter.py`

`AuditEmitter` fans out to configured sinks (file, stdout, custom). Optional HMAC-SHA256 signing per event. `collect_events()` context manager for in-process collection.

**Invariants:**
- Exactly one `AuditEvent` per boundary call, on every code path
- No raw text in any field
- `decision=deny` only on `tool_call_gate` — deny reason includes violation type (argument rule, irreversibility, policy)
- `decision=blocked`/`warn` only on scan boundaries
- `disabled=True` → `decision=allow`, `finding_count=0`
- `tenant_id` from config, never from caller

Argument rule violations and irreversibility blocks produce structured `deny_reason` strings parseable by SIEM queries:
- `"argument rule violation on 'approve_payment': argument 'amount' value 1200000 exceeds max 50000"`
- `"tool 'delete_record' is irreversible and requires human_approved=True on AgentContext"`

---

## Capabilities

### AgentContext — `core/context.py`

Identity envelope passed on every boundary call. Pydantic `BaseModel`, frozen.

| Field | Type | Purpose |
|---|---|---|
| `agent_id` | `str` | Identifies the agent. Required. |
| `sub_agent_id` | `str \| None` | Set by `scope_context_for_subagent`. |
| `allowed_tags` | `list[str] \| None` | Narrowed capability scope for subagents. |
| `conversation_id` | `str \| None` | Session key for threat accumulator. Falls back to `agent_id`. |
| `human_approved` | `bool` | Set by agent after explicit human confirmation. Required by `SENSITIVE` and `IRREVERSIBLE` tools. |

### Subagent Scoping

`scope_context_for_subagent(ctx, sub_agent_id)` returns `AgentContext` with narrowed capability set. Validated at `load_agent()` — subagent cannot exceed parent. Pure synchronous function, no I/O.

### Framework Integrations — `integrations/`

| Integration | Class/Function | Boundary coverage |
|---|---|---|
| LangGraph | `HarnessToolNode` | Gate + dispatch + Tool Stream Control |
| LangChain Agent Loop | `ShaiMiddleware` | All five boundaries |
| LangChain classic | `wrap_tools()` | Gate per call |
| Anthropic SDK | `gated_dispatch` | Gate + dispatch |
| CrewAI / PydanticAI / OpenAI Agents | `wrap_tools()` / hooks | Gate per call |
