# Configuration

SHAI is configured through two YAML files:

- **`harness.yaml`** — one per deployment. Defines what scanners run, how they're tuned, where audit events go. Loaded once at startup.
- **`agent.yaml`** — one per agent. Defines which tools the agent may call, its tag scope, and any agent-specific policy rules.

Both files are validated at load time. A malformed field is a startup error, not a runtime crash — you find configuration mistakes immediately, not in production.

For the exhaustive field-by-field schemas see [`.claude/skills/harness-yaml.md`](../.claude/skills/harness-yaml.md), [`.claude/skills/agent-yaml.md`](../.claude/skills/agent-yaml.md), and [`.claude/skills/policy.md`](../.claude/skills/policy.md). This page walks through what you actually need to configure to get running.

## `harness.yaml`

### Top of file

```yaml
version: 1
tenant_id: "my-deployment"
```

`tenant_id` is stamped on every audit event. Set it to something that identifies this deployment in your SIEM.

### Scan boundaries

All four scan boundaries share the same shape. Turn one on:

```yaml
scan_input:
  enabled: true
  block_at: high          # low | medium | high
  on_error: fail_closed   # fail_closed | fail_open | degrade
  scanners:
    - name: regex_pii
    - name: injection_scan
    - name: jailbreak_scan
    - name: identity_spoof_scan
    - name: heuristic_scan
```

**`block_at`** decides which severity level blocks the turn. Lower-severity findings still appear in audit events — they just don't block. Default: `high`.

**`on_error`** decides what happens when a scanner raises an exception:

- `fail_closed` (default) — treat as BLOCK. This is the correct security posture: if you can't scan it, don't let it through.
- `fail_open` — treat as empty findings. Useful during a rollout when scanner bugs shouldn't take production down.
- `degrade` — treat as WARN. Content passes, but the audit event carries `degraded=True` so you can see it in the log.

Per-scanner overrides let you mix actions on one boundary:

```yaml
scanners:
  - name: regex_pii
    action: redact              # redact instead of block
    redact_with: "***"
  - name: injection_scan        # inherits boundary action (block)
```

The five built-in scanners:

| Scanner | Catches |
|---|---|
| `injection_scan` | Direct and indirect prompt injection, tool coercion, context spoofing (17 EN rules + FR/ES/DE/ZH catalogs) |
| `jailbreak_scan` | Persona override, instruction override, refusal suppression, prompt extraction (6 rules + multilingual) |
| `identity_spoof_scan` | Claimed orchestrator/system authority, peer privilege escalation (4 rules + multilingual) |
| `regex_pii` | 7 PII categories with Luhn-validated credit cards and SSN structural rules — supports redaction |
| `heuristic_scan` | Structural anomalies: entropy, instruction density, coherence, structural markers. Always on (not configurable). |

For tool-result scanning (indirect injection), use the document-tuned catalog:

```yaml
scan_tool_result:
  enabled: true
  block_at: high
  scanners:
    - name: injection_scan       # uses patterns_for_doc.yaml — different tuning
    - name: identity_spoof_scan
```

### The tool-call gate

```yaml
check_tool_call:
  rate_limit:
    enabled: false               # opt in
    window_seconds: 60
    max_calls_per_window: 60
    max_calls_per_tool: 20
  arg_scanners:
    - name: regex_pii
  scan_args_for_tags:
    - sensitive                   # arg scanning runs on tools with this tag
```

You don't declare which tools are allowed here — that's per-agent. The gate config only sets rate limits and which tags trigger argument scanning.

### Policy

Two forms — inline or external file:

```yaml
policy:
  rules:
    - id: allow_local
      match:
        transport: [local]
      action: allow
```

or:

```yaml
policy:
  name: rules
  config:
    rules_path: ./policies/rules.yaml
```

Rules are evaluated in declaration order. **First match wins.** No match → implicit `allow`.

For the full match-field vocabulary (`tool_names`, `tool_tags`, `transport`, `agent_ids`, `sub_agent_ids`, `source_tags`, and the `any`/`all`/`not` combinators), see [`.claude/skills/policy.md`](../.claude/skills/policy.md).

### Audit sinks

```yaml
audit_sinks:
  - name: stdout        # default when nothing is specified
  - name: file
    config:
      path: ./logs/audit.jsonl
```

Signing is opt-in and enforced by the emitter — every event gets an HMAC-SHA256 signature over the canonical field ordering:

```yaml
audit_signing:
  enabled: true
  secret: "secret://AUDIT_HMAC_KEY"     # resolved from env var at startup
```

### Cross-turn threat accumulation (opt-in)

Catches crescendo attacks — sessions where each turn stays under threshold but the pattern is adversarial.

```yaml
session:
  enabled: true                          # off by default
  backend: sqlite
  path: state/sessions.db
  escalation_threshold: 0.70
  window_size: 10
  on_escalation: block                   # block | flag
```

Keyed by `conversation_id` on `AgentContext` — falls back to `agent_id` when unset.

### Normalization (on by default)

Runs before every scan boundary. Decodes base64, hex, URL, rot13, unicode homoglyphs; reassembles fragmented text. Without this, an attacker can trivially bypass regex scanners by base64-encoding the payload.

```yaml
normalization:
  enabled: true       # default
  decode: true
  max_depth: 2        # recursive decode limit
```

Unless you have a specific reason to turn this off, leave it on.

## `agent.yaml`

One file per agent. Loaded via `await harness.load_agent("path/to/agent.yaml")`. Returns an `AgentContext` you pass to every boundary method.

```yaml
id: orchestrator_agent
display_name: "Orchestrator"

# Tools this agent may call — hard gate L1, not overridable by policy
allowed_tool_names:
  - search_docs
  - send_email
  - list_channels

# Tag scope — for subagents, tool.tags must be a subset of this
allowed_tags:
  - read
  - internal
  - external_write

# Sources to activate (declared in harness.yaml)
sources:
  - slack_mcp
  - local

# Agent-scoped policy rules — evaluated before harness rules
policy_rules:
  - id: deny_external_writes
    match:
      tool_tags: [external_write]
    action: deny
    reason: "external writes require approval"

# Optional per-agent overrides of the global execution budget
limits:
  max_steps: 20
  max_tokens_per_session: 30000
  max_tool_calls_per_prompt: 5
```

### Subagents

Declare inline. Each subagent must be a **strict subset** of the parent's capabilities — narrower `allowed_tags`, narrower `allowed_tool_names`. Validated at `load_agent()` time; a config that gives a subagent a tag the parent doesn't have is a startup error.

```yaml
subagents:
  - id: researcher
    allowed_tool_names: [search_docs]
    allowed_tags: [read]
  - id: notifier
    allowed_tool_names: [send_email]
    allowed_tags: [external_write]
```

Scope a context for a subagent at call time:

```python
sub_ctx = harness.scope_context_for_subagent(ctx, "researcher")
```

The returned context has `allowed_tags` narrowed to the intersection of parent and subagent.

## Policy rule reference (essential subset)

Full grammar in [`.claude/skills/policy.md`](../.claude/skills/policy.md). The essentials:

**Match fields** — all listed fields must match (AND). Within a list, any element matches (OR).

```yaml
match:
  tool_names: [approve_payment]
  tool_tags: [financial, sensitive]
  transport: [mcp]                  # local | mcp | skill
  agent_ids: [orchestrator]
  sub_agent_ids: [researcher]
  source_tags: [tier_a]
```

**Combinators** — `any`, `all`, `not`:

```yaml
match:
  any:
    - tool_tags: [destructive]
    - tool_tags: [financial]
```

**Actions**:

- `allow` — accepted, gate proceeds to next layer
- `deny` — rejected, `deny_reason` required
- `redact` — accepted, but named args are replaced before dispatch
- `suppress` — accepted, but the audit event is suppressed. Rare — use sparingly.

**Intersection model** — an agent's rules run first, then the harness's. First deny anywhere wins. Both must allow for the call to proceed.

## What next

- [integrations.md](integrations.md) — drop SHAI into an existing agent framework
- [connectors.md](connectors.md) — MCP sources and dispatch-token enforcement
- [testing.md](testing.md) — writing tests against your config
- [`.claude/skills/`](../.claude/skills/) — every field on every YAML in full detail
