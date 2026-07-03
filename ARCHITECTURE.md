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

**Pre-processing — normalization (`core/normalize.py`):** Before any scanner runs, the input is canonicalized into one or more plaintext *views* — the surface form plus any decoded variants (base64, hex, URL, rot13, unicode homoglyphs, fragment reassembly). Scanners match against all views. Raw text the agent sees is never mutated. Configured under `normalization:` in `harness.yaml`; enabled by default.

**Scanners:** `InjectionScanner` (`injection_patterns.yaml`, 17 rules) · `JailbreakScanner` (`jailbreak_patterns.yaml`, 6 rules) · `IdentitySpoofScanner` (`identity_spoof_patterns.yaml`, 4 rules) · `RegexPIIScanner` (7 categories) · `FileScanner` (structural + doc-tuned injection scan on extracted text)

| Scanner | Category prefix | What it catches |
|---|---|---|
| `injection_scan` | `prompt_injection`, `tool_injection`, `obfuscation`, … | Data-boundary attacks: tool coercion, exfiltration, context spoofing, encoded payloads |
| `jailbreak_scan` | `jailbreak.*` | Guardrail-integrity attacks: persona override, instruction override, refusal suppression, prompt extraction, mode activation |
| `identity_spoof_scan` | `identity_spoof.*` | Agentic identity spoofing: claimed orchestrator/system authority, peer privilege escalation, tool-result authority injection |
| `regex_pii` | `pii.*`, `secret.*`, `network.*` | PII and credential patterns with optional redaction |

**Actions:** `block` · `alert` · `redact`

**Session accumulator pre-check:** Before scanners run, `scan_input` checks the cross-turn threat accumulator (see below). An escalated session is blocked immediately — scanners never run.

### Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Runs pre-gate checks then four layers in strict order. First denial wins. Exactly one `AuditEvent` per call on every code path including pre-gate failure. Never raises.

| Layer | Check | Bypassable? |
|---|---|---|
| **R1** | Rate limiter — sliding-window token bucket | No |
| **R2** | Session budget — step counter, token burn-down, per-prompt fan-out, loop detection | No |
| **L1** | `tool_name` in `allowed_tool_names` | No — hard pre-policy |
| **L2** | `tool.tags ⊆ ctx.allowed_tags` (subagents only) | No — capability gate |
| **L3** | Policy intersection: subagent → parent → global | By design |
| **L4** | Arg scanning for `sensitive`-tagged tools | Configurable |

Returns `GateDecision(allowed, deny_reason, redacted_args, source_name, dispatch_token)`.

#### Session Budget — `boundaries/session_budget.py`

`SessionBudget` enforces per-session execution limits before the four-layer gate runs. One instance per SHAI facade, keyed by `(agent_id, session_id)`. All controls are opt-in — nothing fires when limits are unset.

| Control | Config key | Description |
|---|---|---|
| Step counter | `max_steps` | Hard ceiling on total tool invocations per session |
| Token burn-down | `max_tokens_per_session` | Cumulative token budget; `tool_cost_weights` multiplies cost per tool |
| Per-prompt fan-out | `max_tool_calls_per_prompt` | Resets automatically when `prompt_id` changes |
| Loop detection | `loop_detection_window` / `loop_similarity_threshold` | Jaccard similarity check over a rolling fingerprint window; `0` disables |

Configured globally in `harness.yaml` under `check_tool_call.execution_budget:`, with per-agent overrides in `agent-xx.yaml` under `limits:`. Agent values are merged on top of global defaults at `load_agent()` time.

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

Per-agent override in `agent-xx.yaml`:

```yaml
limits:
  max_steps: 10
  max_tool_calls_per_prompt: 5
```

#### Session Threat Accumulator — `boundaries/session_accumulator.py`

Detects crescendo attacks: escalation distributed across turns where each individual turn stays below per-turn scanner thresholds. Runs as a pre-check in `scan_input` — checked before scanners, updated after.

SQLite-backed (`aiosqlite`). Risk scores persist across process restarts. Keyed by `ctx.conversation_id` when set, falls back to `ctx.agent_id`.

**Signals:** blocked/warned turn rate over a sliding window of last N turns · reframe bonus when a blocked turn is followed by a semantically similar retry (bigram Jaccard ≥ threshold).

**Score formula:** `min(1.0, block_rate × 0.60 + warn_rate × 0.25 + reframe_bonus × 0.30)`

When score ≥ `escalation_threshold`: emit audit event with `extra.signals=["session_escalation"]` and return `ScanVerdict(BLOCK)` or `ScanVerdict(WARN)` per `on_escalation` config.

```yaml
session:
  enabled: true
  backend: sqlite
  path: state/sessions.db
  escalation_threshold: 0.70
  window_size: 10
  reframe_similarity: 0.72
  ttl_hours: 72
  on_escalation: block    # block | flag
```

Pass `conversation_id` on `AgentContext` to scope per-conversation:

```python
ctx = AgentContext(agent_id="my_agent", conversation_id="conv-abc123")
```

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

`AgentContext` fields:

| Field | Type | Purpose |
|---|---|---|
| `agent_id` | `str` | Identifies the agent. Required. |
| `sub_agent_id` | `str \| None` | Set by `scope_context_for_subagent`. |
| `allowed_tags` | `list[str] \| None` | Narrowed capability scope for subagents. |
| `conversation_id` | `str \| None` | Session key for the threat accumulator. When set, scopes risk scores per conversation rather than per agent. Pass a stable identifier (e.g. thread ID, user session ID). Falls back to `agent_id` when `None`. |

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