# Boundary Reference

Five security boundaries surround every agent turn. Each emits exactly one `AuditEvent` per call regardless of outcome. No raw text in any event field.

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
```

---

## Ingress Scan — `scan_input`

Inspects user text before it reaches the LLM. Detects PII, prompt injection, jailbreak attempts, and agentic identity spoofing.

| Behaviour | Detail |
|---|---|
| Disabled | Emits `AuditEvent(disabled=True, decision=allow)`. Returns `ScanVerdict(blocked=False)`. |
| Normalization | Before scanners run, text is canonicalized into views (surface form + decoded variants: base64, hex, URL, rot13, homoglyphs). Scanners match against all views. Catches encoded injection payloads. |
| Session pre-check | Checks threat accumulator score. If session ≥ `escalation_threshold`, returns immediately with `BLOCK` or `WARN` — scanners never run. Audit event carries `extra.signals=["session_escalation"]`. |
| Scanners | Run concurrently. Per-scanner exceptions logged as empty findings — pipeline never raises. |
| Block threshold | `block_at` severity (default `high`). |
| Redaction | Use `verdict.redacted_text or original`. |
| Session post-record | After verdict, threat accumulator records turn outcome for future cross-turn analysis. |

**Recommended scanner stack:**

```yaml
scan_input:
  enabled: true
  block_at: high
  on_error: fail_closed
  scanners:
    - name: injection_scan       # prompt injection, tool coercion, exfiltration — EN + FR, ES, DE, ZH
    - name: jailbreak_scan       # guardrail-integrity: persona override, refusal suppression — EN + FR, ES, DE, ZH
    - name: identity_spoof_scan  # agentic identity: claimed orchestrator/system authority — EN + FR, ES, DE, ZH
    - name: regex_pii            # PII and credentials (with optional redaction) — EN
```

**Always-on scanners (0.2.0):** `HeuristicScanner` is prepended automatically to every scan boundary. It detects structural anomalies that regex catalogs miss: high-entropy segments, instruction-dense text, register shifts, and embedded LLM markup. Not configurable — always runs.

**Ensemble severity promotion (0.2.0):** After all scanners complete, findings are cross-checked across scanners. When 2+ different scanners flag the same category and their combined weight crosses a threshold, findings are promoted to HIGH.

**Error handling (0.2.0):** The `on_error` field controls what happens when a scanner raises:
- `fail_closed` (default) — scanner failure → BLOCK. Content rejected.
- `fail_open` — scanner failure → empty findings. Pipeline continues.
- `degrade` — scanner failure → WARN. Content passes, audit event flagged.

A per-scanner circuit breaker prevents repeated calls to a broken adapter.
Every failure and circuit trip emits a `boundary=system`, `decision=degraded` audit event.

**Multilingual coverage:** `injection_scan`, `jailbreak_scan`, and `identity_spoof_scan` automatically
load multilingual variants from `l10n/*.l10n.yaml` alongside the base English catalog. No
configuration is required — French, Spanish, German, and Simplified Chinese patterns are active
by default. The multilingual rules cover the highest-threat families: instruction override,
persona/jailbreak, system prompt extraction, and tool coercion in each language.

```python
verdict = await harness.scan_input(user_text, ctx)
if verdict.blocked:
    return "Input rejected"
safe_text = verdict.redacted_text or user_text
```

---

## Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Six layers in strict order. First deny anywhere wins. Exactly one `AuditEvent` per call.

### Pre-gate — agent registered?

`AgentRegistry.get(ctx.agent_id)` raises `AgentNotRegisteredError` if the agent was never loaded. Mapped to `GateDecision(allowed=False)`.

### Pre-gate — rate limit and session budget

Rate limiter (R1) and session budget (R2) run before layer checks. See [ARCHITECTURE.md](../ARCHITECTURE.md) for full detail. Both produce structured audit events on denial.

### L1 — allowed_tool_names

Hard pre-policy gate. `tool_name` must be in `AgentConfig.allowed_tool_names`. No policy rule can override this.

### L2 — Argument rules

Deterministic parameter constraints declared on the `Tool`. Evaluated before the policy engine. First violation denies — regardless of what the LLM was told to do, regardless of any injection payload in context.

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

A payment of $1,200,000 triggered by a malicious webpage the agent read three tool calls ago is blocked here. The injection payload is irrelevant — the argument value failed a closed, deterministic check. This is the correct defense against the ForcedLeak class of attacks.

`ArgumentRule` constraint fields:

| Field | Type | Semantics |
|---|---|---|
| `arg` | `str` | Argument name to inspect |
| `max_value` | `float \| None` | Numeric upper bound (inclusive) |
| `min_value` | `float \| None` | Numeric lower bound (inclusive) |
| `allowlist` | `list[str] \| None` | Value must be one of these strings (exact match) |
| `pattern` | `str \| None` | Value must match this regex (re.search semantics) |
| `required` | `bool` | Argument must be present and non-None |

Violations produce `deny_reason` of the form: `"argument rule violation on 'approve_payment': argument 'amount' value 1200000 exceeds max 50000"`.

### L3 — Irreversibility gate

Blast-radius classification. Evaluated after argument rules, before the subagent tag gate.

| Tier | Behaviour |
|---|---|
| `REVERSIBLE` | Default. No extra check. |
| `SENSITIVE` | Denied unless `ctx.human_approved=True` |
| `IRREVERSIBLE` | Denied unless `ctx.human_approved=True` |

```python
Tool(name="delete_record", tags=["destructive"],
     irreversibility=Irreversibility.IRREVERSIBLE)

# Agent code — after human confirms:
ctx_approved = AgentContext(agent_id=ctx.agent_id, human_approved=True)
gate = await harness.check_tool_call("delete_record", args, ctx_approved)
```

`human_approved` defaults to `False`. The agent is responsible for setting it after obtaining explicit human confirmation. SHAI enforces the signal's presence — not how confirmation was obtained.

Violations produce `deny_reason` of the form: `"tool 'delete_record' is irreversible and requires human_approved=True on AgentContext"`.

### L4 — allowed_tags (subagent capability gate)

Active only when `ctx.allowed_tags is not None` (i.e. a subagent call). Every tag on the tool must be in `allowed_tags`. Prevents subagents from calling tools their parent never granted capability for.

### L5 — intersection policy

`PolicyEngine.evaluate(tool, args, ctx, rules=combined_rules)`.

`combined_rules` = subagent `policy_rules` + parent `policy_rules`. First match wins. Default allow on no match.

Policy actions: `allow`, `deny`, `redact`.

### L6 — arg scanning (optional)

Fires only for tools tagged with any tag in `scan_args_for_tags` (default: `["sensitive"]`). Any finding at `HIGH` or above denies.

```python
gate = await harness.check_tool_call(name, args, ctx)
if not gate.allowed:
    return f"Denied: {gate.deny_reason}"
effective_args = gate.redacted_args or args
result = await source.call(name, effective_args)
```

---

## Tool Stream Control — `scan_tool_result`

Scans tool return values before they re-enter the LLM context. **This is the boundary that catches indirect prompt injection** — malicious instructions embedded in documents, search results, emails, or API responses the agent reads.

The ForcedLeak attack (CVSS 9.4) worked precisely because most frameworks lack this boundary. An instruction embedded in a CRM field was processed as a tool result and executed. Input scanning never sees it.

Uses `patterns_for_doc.yaml` — a 9-rule catalog tuned for document content with lower false-positive rates for structured data.

```python
result  = await source.call(tool_name, args)
verdict = await harness.scan_tool_result(result, ctx, tool_name=tool_name)
if verdict.blocked:
    return "Tool result blocked — potential injection"
safe_result = verdict.redacted_text or result
```

Enable in `harness.yaml`:

```yaml
scan_tool_result:
  enabled: true
  block_at: high
```

---

## Egress Scan — `scan_output`

Inspects the LLM's final response before it reaches the user. Catches accidental PII egress and data leakage.

```python
verdict = await harness.scan_output(llm_response, ctx)
return verdict.redacted_text or llm_response
```

---

## Ingress Scan — `scan_file`

Inspects uploaded files. Structurally identical to `scan_input` — same pipeline, same audit invariants.

`FileScanner` handles: size gate, MIME type verification, PDF JavaScript, EXIF metadata, ZIP/Office macros, and `InjectionScanner` on extracted text.

```yaml
scan_file:
  enabled: true
  block_at: high
  max_size_mb: 50
```

---

## Audit invariants

These hold on every code path, including error and disabled paths:

- Exactly **one** `AuditEvent` per boundary call
- `disabled=True` → `decision=allow`, `finding_count=0`
- `decision=deny` → `deny_reason` is non-null, only on `tool_call_gate`
- `decision=blocked` → only on scan boundaries
- `tenant_id` stamped from `HarnessConfig`, never from the caller
- No raw user text, LLM output, tool arguments, or scanner-matched substrings in any field
- Argument rule violations and irreversibility blocks produce structured `deny_reason` values parseable by SIEM queries
