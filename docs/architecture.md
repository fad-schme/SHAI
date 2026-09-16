# Architecture

**Secure Harness AI** is a security control plane for AI agents. It enforces security boundaries around every agent turn, governs tool calls through a pre-gate + seven-layer stack, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
   
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely.

---

## Tool Governance — `check_tool_call`

 Pre-gate controls (revocation, rate limit, session budget, MCP manifest approval) run before the seven gate layers. First denial wins. Exactly one `AuditEvent` per call on every code path.


### Session Budget — `boundaries/session_budget.py`

`SessionBudget` is a thread-safe, per-session enforcer for DoS / Unbounded Consumption (OWASP T4). One instance per SHAI facade, keyed by `(agent_id, session_id)` where `session_id` is `ctx.conversation_id or ctx.agent_id`. All controls are opt-in via `None` defaults.

Every control counts something SHAI observes at its own boundary.

| Control | Trigger |
|---|---|
| **Step counter** | `state.steps >= max_steps` — blocks before the call is recorded |
| **Per-prompt fan-out** | `state.prompt_calls >= max_tool_calls_per_prompt` — resets when `prompt_id` changes, which the facade sources from `TurnSignals.turn_id` |
| **Loop detection** | Jaccard similarity ≥ `loop_similarity_threshold` against last `loop_detection_window` fingerprints |



---

## Scan boundaries

Every scan boundary runs the scanners its `scanners:` chain names, plus the
always-on `heuristic_scan`, over the normalised views of the text. Scanner
failures follow `on_error` (default `fail_closed`).

### Ingress Scan — `scan_input`

Runs on user text before the LLM. Typical chain: `injection_scan`,
`jailbreak_scan`, `identity_spoof_scan`, `regex_pii`; `command_injection_scan`
with the `shell` extra.

### File Scan — `scan_file`

Runs on uploads. `FileScanner` checks structure (size, MIME, extension, PDF
markers, SVG, archives, macros, metadata); `FileContentScanner` runs the
`scan_file.scanners` chain over extracted text — the document-tuned injection
catalog by default.

### Tool Stream Control — `scan_tool_result`

Runs before tool results re-enter the LLM context. The example config runs
`injection_scan`, `identity_spoof_scan`, and `jailbreak_scan` here — which is
also what an omitted block runs. When the input scan flagged injection this
turn, `block_at` steps down one level.

### Egress Scan — `scan_output`

Catches PII leakage and data exfiltration in the LLM's final response, then
computes the consolidated turn risk from `TurnSignals` and blocks the turn at
`RISK_HIGH` (0.60) even when no single scanner blocked. Clears `TurnSignals`.

### Cross-turn — threat accumulator

`ThreatAccumulator` scores escalation spread across a session's turns
(crescendo attacks). Disabled by default.

### MCP Governance — `scan_mcp_metadata`

Runs at MCP connection time before any tool is registered. Scans tool names, descriptions, and argument schemas. `block_at: medium` default — metadata injection has a near-zero false-positive rate.

---

## MCP manifest onboarding

An MCP source is **declared** under `sources:` in `harness.yaml`, the same
way a local source is — by name only:

```yaml
sources:
  - name: slack
    transport: mcp
```

`SourceConfig` accepts nothing MCP-specific beyond `name`/`transport` (plus
the fields every source already has, like `tags`/`required`) — no url,
credentials, or allow-lists on the `sources:` entry. Everything else comes
from the manifest, resolved **by convention**: `<mcp_manifests_dir>/<name>.yaml`
(see `harness.mcp.manifest`). 

**Approval gate** (`harness.mcp.gate.McpBaselineGate`): re-checked on every
`check_tool_call` for a tool from an MCP source that *was* built, not just
once at startup — a R3 pre-gate check in the facade, after the
revocation/rate-limit/session-budget checks and before the seven-layer gate
runs. 

**Onboarding** (`shai mcp onboard <manifest> --config <harness.yaml>`,
`harness.mcp.onboard`): the only way a manifest's hash gets into the
baseline store. 

---

## Audit trail

Every boundary call emits exactly one `AuditEvent` to `AuditEmitter`, which fans out to all configured sinks. Emission is structural — boundary code cannot return without emitting.
