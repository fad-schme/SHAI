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

Enabled input, output, and tool-result boundaries must declare at least one
scanner. `heuristic_scan` is then added automatically if it is not already
listed. File scanning can run its structural checks with only that heuristic
content backstop.

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

The six built-in scanners:

| Scanner | Catches |
|---|---|
| `injection_scan` | Direct and indirect prompt injection, tool coercion, context spoofing (8 common + 16 input rules; file scanning adds 9 document rules; fr/es/de/zh overlays included) |
| `jailbreak_scan` | Persona override, instruction control, safety deactivation, refusal suppression, prompt extraction (8 rules, plus fr/es/de/zh overlays) |
| `identity_spoof_scan` | Claimed orchestrator/system authority, peer privilege escalation (4 rules, plus fr/es/de/zh overlays) |
| `regex_pii` | 7 PII categories with Luhn-validated credit cards and SSN structural rules — supports redaction |
| `heuristic_scan` | Structural anomalies: entropy, instruction density, coherence, structural markers. Always on (not configurable). |
| `command_injection_scan` | Shell command composition — a pipeline into an interpreter, a `/dev/tcp` redirect, fetch-then-execute, inline interpreter code. Requires the `shell` extra. |

#### `command_injection_scan`

A user can plant a command in input, a tool can return one in its result, and a
file can carry one in its body — so this scanner is declarable at every
boundary, including `check_tool_call`:

```yaml
scan_input:
  scanners:
    - name: command_injection_scan
```

Install it with `pip install 'shai[shell]'` — it needs `bashlex`. Declaring the
scanner without the extra fails at `SHAI.from_yaml()` rather than degrading
quietly.

It matches AST **shapes**, not command names: `curl … | sh`, `wget … && chmod
+x … && ./x`, `bash -i >& /dev/tcp/…`, `python -c` with an opaque payload. That
is why an unlisted fetcher piped into `sh` is still caught — the sink is the
signal.

**Findings are demoted, not suppressed, when the statement reads as prose**
rather than an invocation (its leading word is not a program). Text discussing
`curl … | sh` reports MEDIUM; a line that issues it reports HIGH. Padding a
payload with prose therefore lowers severity but never erases the finding, and
the evidence still reaches the audit trail and the turn-risk block.

One consequence worth planning for: at `scan_output` an agent explaining an
install command and an agent emitting one are the same text. The demotion rule
plus the default `block_at: high` is what keeps that from blocking answers.

For tool-result scanning, configure the normal injection scanner:

```yaml
scan_tool_result:
  enabled: true
  block_at: high
  scanners:
    - name: injection_scan
    - name: identity_spoof_scan
```

`injection_scan` loads `injection_common.yaml` and `injection_patterns.yaml`
for input, output, and tool-result boundaries. On `scan_file`, it additionally
loads `patterns_for_doc.yaml`, giving file content the union of common, input,
and document rules without duplicating rule ownership.

### The tool-call gate

```yaml
check_tool_call:
  rate_limit:
    enabled: false               # opt in
    window_seconds: 60
    max_calls_per_window: 60
    max_calls_per_tool: 20
  scanners:
    - name: regex_pii
  scan_args_for_tags:
    - sensitive                   # arg scanning runs on tools with this tag
```

You don't declare which tools are allowed here — that's per-agent. The gate config only sets rate limits and which tags trigger argument scanning.

#### Human approval for `SENSITIVE` / `IRREVERSIBLE` tools

Layer 3 admits a tool classified `SENSITIVE` or `IRREVERSIBLE` only against a quorum of **signed approval grants**:

```yaml
check_tool_call:
  approvals:
    secret: "secret://SHAI_APPROVAL_KEY"   # HMAC-SHA256, required
    sensitive_quorum: 1                    # one approver
    irreversible_quorum: 2                 # two-person rule
```

**With no `secret`, every `SENSITIVE` and `IRREVERSIBLE` tool is denied.** There is no weaker check to fall back to: a tool classified as needing verified approval, in a deployment that cannot verify one, is a tool that cannot run.

Your application obtains approval however it likes — a CIBA flow, Auth0, WorkOS, a Slack button, a terminal prompt — then issues a grant and attaches it to the context:

```python
from harness.core.approval import encode_grant, sign_grant

grant = sign_grant(
    agent_id=ctx.agent_id,
    tenant_id="acme",
    tool_name="pay_invoice",
    args=args,                 # the same args you will pass to check_tool_call
    approver_id="alex@acme.com",
    secret=APPROVAL_KEY,
    ttl_seconds=300,
)
ctx = ctx.model_copy(update={"approvals": (encode_grant(grant),)})
gate = await harness.check_tool_call("pay_invoice", args, ctx)
```

SHAI verifies the signature and the binding offline — it never calls out. Each grant is bound to one agent, tenant, tool, and **argument set**, so approving a $5 refund does not authorise a $50,000 one, and a grant for one tool cannot be replayed against another. Quorum counts *distinct* `approver_id`s, so two grants from one person is still one approver.

Two things to know: grants are **not** propagated to subagents (a grant authorises one call, not what that call delegates), and the approvers land on the gate's allow event as `extra.approvers`, so the audit trail can answer who authorised an irreversible action.

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

Rules are declared inline under `policy.rules` — there is no separate rules
file. Per-agent rules go in the agent's own `policy_rules:` and are evaluated
before these.

Rules are evaluated in declaration order. **First match wins.** No match → implicit `allow`.

For the full match-field vocabulary (`tool_names`, `tool_tags`, `transport`, `agent_ids`, `sub_agent_ids`, `source_tags`, and the `any`/`all`/`not` combinators), see [`.claude/skills/policy.md`](../.claude/skills/policy.md).

#### Forbidden tag combinations

Tag sets no single agent may hold at once — checked when the agent is loaded, not when it calls a tool:

```yaml
policy:
  forbidden_tag_combinations:
    - [sensitive, external_write]
```

An agent whose `allowed_tags` contains every tag in an entry is rejected with a `ConfigError` and is never registered. Each entry needs at least two distinct tags. Subagents are not checked separately — their tags are always a subset of their parent's.

The list belongs in `harness.yaml` rather than in the agent file: an agent declaring the combinations it may not hold would be declaring its own limits. `shai validate` prints each configured combination and fails on any agent that violates one.

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

### Signed pattern database (opt-in)

Loads pattern rules installed with `shai patterns apply` and merges them into the
injection-family scanner catalogs at startup. `secret` must resolve to the same
key the bundle was signed with.

```yaml
patterns_db:
  enabled: true
  path: state/patterns.db               # also backs the heuristic-candidate cache
  secret: "secret://PATTERNS_SIGNING_KEY"
```

Each row's `catalog` column routes it to a scanner: `injection` → `injection_scan`,
`jailbreak` → `jailbreak_scan`, `identity_spoof` → `identity_spoof_scan`. A scanner
only receives DB rules on boundaries where it is declared.

Rules are verified per row. A row whose HMAC does not match is skipped and logged,
never merged. A missing DB file or a wrong key loads zero rules and leaves the
bundled YAML catalog running — neither condition fails startup. Enabling
`patterns_db` without a `secret` is a config error.

Rules are read once, at `from_yaml()` time. Restart the process to pick up a
newly applied bundle.

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
