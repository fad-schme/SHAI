# Concepts

The mental model behind SHAI. Read this once and everything else in the docs will fit into place.

## The premise

Security risks in LLM-driven systems are best treated as **expected operational conditions**, not as exceptional events. The question is not "how do we make the model never misbehave?" It's "how do we build a system that survives the model misbehaving?"

That shifts enforcement downstream — into deterministic code that evaluates what the agent *proposes to do*, independently of *why* it proposed it. The model's job is to be useful. SHAI's job is to make sure that when the model fails, or is turned against you, the failure stops at a gate.

## The five boundaries

SHAI enforces security at five boundaries around every agent turn. Every boundary emits exactly one `AuditEvent` per call. Boundaries never raise — they always return a verdict.

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
                                                                                                              │
                                        scan_file (opt) ──────────────────────────────────────────────────────┘

                                                                                                              ↓
                                                                                              signed audit event stream
```

| Boundary | When it runs | What it catches |
|---|---|---|
| `scan_input` | Before user text reaches the LLM | Direct prompt injection, PII, credentials in user messages |
| `check_tool_call` | Every tool call the LLM proposes | Unauthorised tools, argument violations, irreversible-without-approval, subagent scope violations, policy denies |
| `scan_tool_result` | Every tool return value, before it re-enters the LLM context | Indirect injection in fetched documents, MCP responses, web pages |
| `scan_output` | Before the LLM's response reaches the user | PII leakage, data exfiltration patterns |
| `scan_file` | On file uploads (opt-in) | Malicious PDFs, Office macros, EXIF anomalies, embedded payloads |

There's a sixth pseudo-boundary, `SYSTEM`, that appears only in audit events — it carries structured records of scanner failures and circuit-breaker trips, so degradation is visible in the log rather than only in application errors.

## Why `scan_tool_result` matters

Most agent security frameworks scan input and output. They don't scan tool results. This is the boundary where indirect prompt injection lives: an attacker doesn't send a message to your agent — they plant a payload in a webpage, an email, an API response, or a document that the agent will read. When the agent fetches that content and hands it to the LLM, the LLM sees the payload as if it were part of the conversation. Anything the LLM has been told not to do becomes something the LLM might do, because the "instruction" now appears to come from a trusted context.

Treating tool results as untrusted content — the same way you'd treat user input — is the correct posture, and it's what SHAI does by default.

## The gate is deterministic

`check_tool_call` is not an LLM asked to judge whether the proposed tool call is safe. It's Python code that runs seven ordered layers of check. First deny anywhere wins. The layers exist so that an attacker who has already compromised the LLM's reasoning cannot argue their way past them.

| Layer | Check |
|---|---|
| Pre-gate | Rate limit + session execution budget + agent registered? |
| L1 | `tool_name ∈ allowed_tool_names`? |
| L2 | Argument rules — `max_value`, `min_value`, `allowlist`, `pattern`, `required` |
| L3 | Irreversibility gate — `SENSITIVE` / `IRREVERSIBLE` tools need `human_approved=True` |
| L4 | For subagents: `tool.tags ⊆ ctx.allowed_tags`? |
| L5 | Intersection policy: subagent → parent → global |
| L6 | Signal correlation — reads what earlier boundaries found this turn |
| L7 | Arg scanning — for `sensitive`-tagged tools or when L6 tightened |

L6 is where the boundaries stop being independent. If `scan_input` flagged injection *and* the LLM then proposes a tool tagged `destructive` / `financial` / `external`, the gate denies. If input was WARN and the tool is write-capable, L7 runs argument scanning even on tools that weren't marked `sensitive`. The attack chain becomes visible in the correlation, not in any single boundary.

For the full deny-reason string format that L2 and L3 emit, see [`.claude/skills/boundaries.md`](../.claude/skills/boundaries.md).

## The trust envelope

```
       ┌────────────────────────────────────────────────────────────┐
       │                       UNTRUSTED                            │
       │   end-user input · MCP servers · fetched web pages ·       │
       │   tool outputs · documents · API responses                 │
       └───────────┬───────────────────────────────────┬────────────┘
                   │                                   │
                   ▼                                   ▼
       ┌──────────────────────────────────────────────────────────┐
       │                     TRUSTED (SHAI)                       │
       │   scan_input · check_tool_call · scan_tool_result ·      │
       │   scan_output · audit emitter · policy engine            │
       └───────────┬──────────────────────────────────────────────┘
                   │
                   ▼
       ┌──────────────────────────────────────────────────────────┐
       │                  SEMI-TRUSTED (LLM)                      │
       │   model output cannot be trusted; SHAI evaluates what    │
       │   it proposes, not why                                   │
       └──────────────────────────────────────────────────────────┘
```

The LLM is treated as semi-trusted. Everything it produces — text, tool-call proposals, argument values — is evaluated by deterministic code before it produces an effect. That's the whole design.

## Verdicts and audit events

Every boundary call returns a verdict. Every boundary call also emits an `AuditEvent`. Both flow through your agent code — the verdict for decisions, the event for observability.

```python
verdict = await harness.scan_input(user_text, ctx)
if verdict.blocked:
    return "…"
safe_text = verdict.redacted_text or user_text
```

**Verdict shapes:**

- `ScanVerdict` — from scan boundaries. Fields: `blocked`, `status` (ALLOW / WARN / BLOCK), `redacted_text`, `findings`.
- `GateDecision` — from `check_tool_call`. Fields: `allowed`, `deny_reason`, `redacted_args`, `source_name`, `dispatch_token`.

**AuditEvent** carries only metadata:

- `boundary` — which boundary emitted this
- `decision` — allow / warn / blocked / deny / degraded
- `finding_count` and `max_severity`
- `agent_id`, `tenant_id`, `tool_name`, `timestamp_ms`
- `deny_reason` — structured string, SIEM-parseable
- `signature` — HMAC-SHA256 if signing is enabled

What's deliberately absent: raw user text, LLM responses, matched substrings. The audit trail is safe to ship to a downstream store without leaking the content it was watching.

For every field on every verdict and event, see [`.claude/skills/verdicts-events.md`](../.claude/skills/verdicts-events.md) and [`.claude/skills/audit-schema.md`](../.claude/skills/audit-schema.md).

## Agents, subagents, and capability scoping

Every boundary call carries an `AgentContext`. It identifies who is making the call and what they're allowed to do.

```python
ctx = await harness.load_agent("config/agents/my_agent.yaml")
```

Key fields on `AgentContext`:

- `agent_id` — required
- `sub_agent_id` — set when this call is on behalf of a subagent
- `allowed_tags` — narrowed capability scope for subagents
- `conversation_id` — session key for the cross-turn threat accumulator
- `human_approved` — set to `True` by the agent after explicit human confirmation, required by `SENSITIVE` / `IRREVERSIBLE` tools

Subagents can only be narrower than their parent, never wider. When you scope a context for a subagent:

```python
sub_ctx = harness.scope_context_for_subagent(ctx, "researcher")
```

You get back an `AgentContext` whose `allowed_tags` are the intersection of what the parent had and what the subagent config declared. This is validated at `load_agent()` time — a config that gives a subagent a tag its parent doesn't have is a hard configuration error, not a runtime denial.

## What flows across boundaries: `TurnSignals`

Boundaries within one turn share signals. The most useful ones:

- `scan_input` sets `input_has_injection = True` when it saw injection findings
- `check_tool_call` reads this. If input was injected and the LLM then proposes a `destructive` / `financial` / `external` tool, the gate denies at L6 with a correlation-based reason.
- `scan_tool_result` reads this too. If input was flagged and the gate allowed a specific tool, `scan_tool_result` tightens its own `block_at` by one level for this call only.

The cross-boundary correlation is why SHAI is more than a scanner catalog stitched together. Each layer strengthens the next.

## Cross-turn threat accumulation

Some attacks stay under any single turn's block threshold but form a clearly adversarial pattern across a session. The **session threat accumulator** watches for this.

- Backed by SQLite so risk scores persist across process restarts
- Keyed by `conversation_id` on `AgentContext` (falls back to `agent_id`)
- Score formula: `min(1.0, block_rate × 0.60 + warn_rate × 0.25 + reframe_bonus × 0.30)`
- When score ≥ `escalation_threshold`, `scan_input` short-circuits with a WARN or BLOCK verdict — scanners never even run for that call

Opt-in. Off by default. Set `session.enabled: true` in `harness.yaml` to turn on.

## The audit trail

`AuditEmitter` fans events out to configured sinks — file, stdout, whatever you register. Every event is optionally HMAC-SHA256 signed. Signatures are computed over the canonical field ordering, so tampering with any field invalidates the signature.

Invariants that hold on every code path:

- **Exactly one `AuditEvent` per boundary call.** Not zero, not two.
- **No raw text in any field.** Not in `deny_reason`, not in `extra`, not anywhere.
- **`decision=deny` only on `tool_call_gate`** — scan boundaries emit `blocked` or `warn`.
- **`disabled=True` implies `decision=allow`, `finding_count=0`.** A disabled boundary is not a silent boundary.
- **`tenant_id` comes from config, never from the caller.** A caller cannot spoof tenancy.

## What SHAI does not do

Being explicit:

- **Not a runtime sandbox for tools.** SHAI gates dispatch. A compromised tool implementation is still dangerous after the gate allows.
- **Not a network egress control.** The optional connectivity layer (dispatch tokens + `ShaiTransport`) enforces on outbound MCP calls, but network policy at the infrastructure layer is your problem.
- **Not a replacement for model-side safety.** Prompt-level fine-tuning, constitutional AI, RLHF safety layers are complementary.
- **Not sufficient against a well-resourced adaptive adversary on its own.** Regex catalogs are public and can be studied. This is one layer. See [../THREAT_MODEL.md](../THREAT_MODEL.md) for the honest coverage matrix.

## What next

- [configuration.md](configuration.md) — walk through `harness.yaml`, `agent.yaml`, and policy rules
- [integrations.md](integrations.md) — LangGraph, LangChain, Anthropic SDK, CrewAI, PydanticAI, OpenAI Agents
- [`.claude/skills/`](../.claude/skills/) — one file per topic, compact reference
