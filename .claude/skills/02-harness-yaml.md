# harness.yaml Reference

The operator config file. One per deployment. Loaded once at startup via
`await SHAI.from_yaml("path/to/harness.yaml")`.

---

## Top-level fields

```yaml
version: 1                    # always 1
tenant_id: "my-deployment"    # stamped on every audit event
```

---

## Scan boundaries

All four scan boundaries share the same shape:

```yaml
scan_input:           # or scan_output, scan_tool_result, scan_file
  enabled: true       # false → boundary is skipped, disabled=True audit event
  block_at: high      # low | medium | high — findings at this severity → blocked
  action: block       # block | alert | redact — default action for this boundary
  on_error: fail_closed  # fail_closed | fail_open | degrade — what happens on scanner failure
  scanners:
    - name: regex_pii
      action: redact        # per-scanner override (overrides boundary action)
      redact_with: "***"    # replacement string for redact action
    - name: injection_scan
      action: block
```

**Actions:**
- `block` — hard stop. `verdict.blocked = True`. LLM never sees the content.
- `alert` — content passes but `verdict.warned = True`. Audit flags it.
- `redact` — matched text is replaced with `redact_with`. `verdict.redacted_text` is set.

**`on_error` — scanner failure handling (0.2.0):**
- `fail_closed` — default. Scanner failure → BLOCK. Safe posture.
- `fail_open` — scanner failure → empty findings, pipeline continues. Use during rollout.
- `degrade` — scanner failure → WARN. Content passes, audit event flagged `degraded=True`.

A per-scanner circuit breaker prevents repeated calls to a broken adapter.
After 5 consecutive failures the scanner is skipped entirely (OPEN state).
After a recovery timeout it gets one probe call. Success resets; failure
doubles the timeout (capped at 5 minutes). Circuit breaker trips emit
`boundary=system`, `decision=degraded` audit events.

**`block_at` interacts with `action`:**
- A finding at or above `block_at` triggers the `action` for that scanner.
- A finding below `block_at` never triggers block, even if `action: block`.

### scan_file extras

```yaml
scan_file:
  enabled: false
  block_at: high
  action: block
  max_size_mb: 50     # files exceeding this are rejected before content scanning
```

---

## MCP Governance (`scan_mcp_metadata`)

Scans tool names, descriptions, and argument schemas received from MCP
servers before the tools are registered with SHAI.

```yaml
scan_mcp_metadata:
  enabled: true
  block_at: medium    # default medium — metadata injection is high signal
  action: block
  scanners:
    - name: mcp_metadata_scan
```

`block_at` defaults to `medium` here (unlike other boundaries which default
to `high`) because almost no legitimate content in tool metadata looks like
an injection. "ignore all previous instructions" in a tool description has
no benign interpretation.

When `enabled: false`, tools are registered without metadata scanning.
The `mcp_metadata_scan` scanner uses `mcp_metadata_patterns.yaml`.

## Tool Governance (`check_tool_call`)

```yaml
check_tool_call:
  rate_limit:
    enabled: true
    window_seconds: 60          # sliding window duration
    max_calls_per_window: 60    # global budget per agent per window
    max_calls_per_tool: 20      # per-tool budget per agent per window
  arg_scanners:
    - name: regex_pii           # scanners run on tool arguments
  scan_args_for_tags:
    - sensitive                 # only scan args for tools tagged with these
```

---

## Policy

Policy rules are always inline — no separate rules file.

```yaml
policy:
  rules:
    - id: allow_local
      match:
        transport: [local, skill]
      action: allow

    - id: deny_mcp_default
      match:
        transport: [mcp]
      action: deny
      reason: "MCP requires explicit agent-level allow"
```

→ See `07-policy.md` for the full rule grammar.

---

## Audit sinks

```yaml
audit_sinks:
  - name: file
    config:
      path: ./logs/audit.jsonl    # rotates at ~100 MB
  - name: stdout                  # JSONL to stdout
```

**Note:** when `stdout` is configured, raw JSONL interleaves with any
formatted output from your application. For demos and examples, omit
`stdout` and use `collect_events()` instead.

Custom sinks are registered via entry points:
```toml
[project.entry-points."harness.audit_sinks"]
my_sink = "my_package:MySink"
```

### Audit signing (HMAC-SHA256)

```yaml
audit_signing:
  enabled: true
  secret: "secret://AUDIT_SIGNING_KEY"
```

When enabled, every `AuditEvent` gains a `signature` field: HMAC-SHA256
over all non-null fields (excluding `signature`), `sort_keys=True`.

---

## Sources

Sources declare where tools come from. Activated at `load_agent()` time.

### Option A — connector manifest (recommended)

```yaml
sources:
  - name: slack
    connector: slack          # loads url, allowed_urls, tags, per-tool specs
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
    required: false           # optional — absence is skipped, not fatal
```

Available connectors: `slack`, `github`, `notion`, `jira`, `gmail`,
`postgresql`, `stripe`, `google_drive`.
→ See `09-connectors.md` for details.

### Option B — manual MCP source

```yaml
sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_BOT_TOKEN"
    tags: [external_mcp, messaging]   # applied to ALL tools from this source
    allowed_urls:                     # ShaiTransport enforces these
      - "https://mcp.slack.com/*"
      - "https://slack.com/api/*"
    allowed_methods: [GET, POST]
    required: true                    # default
```

### Option C — local source

```yaml
sources:
  - name: docs_local
    transport: local
    tool_names: [search_docs, fetch_doc]   # omit for all registered tools
    tags: [internal]
```

### `required` flag

- `required: true` (default) — missing or failed source raises `ConfigError`
  at `load_agent()`. Agent is not usable without it.
- `required: false` — logs and skips. Use for optional enrichment.

**Important:** `secret://` references are resolved at `from_yaml()` time,
including for `required: false` sources. Use `""` for credentials in
dev/demo contexts where no token is available.

---

## Connectivity

```yaml
connectivity:
  enabled: false              # default off
  token_secret: "secret://SHAI_TOKEN_SECRET"
  token_ttl_seconds: 15
  no_token_policy: permissive # permissive | strict
```

When `enabled: true`, `check_tool_call` issues a signed `DispatchToken`
on every allowed gate decision. `ShaiTransport` validates it on every
outbound MCP request.
→ See `10-connectivity.md`.

---

## Incremental pattern database (`patterns_db`)

Supplemental injection patterns stored in a signed SQLite database.
Built-in YAML patterns ship with the package and are always loaded.
The DB holds incremental patterns — new attack signatures distributed
as signed bundles via `shai patterns apply`.

```yaml
patterns_db:
  enabled: true
  path: state/patterns.db
  secret: "secret://PATTERNS_SIGNING_KEY"
```

When `enabled`, `from_yaml()` loads verified patterns from the DB and passes
them to `InjectionScanner` as `extra_rules` (appended to the built-in catalog).
Each row is HMAC-SHA256 verified against the signing secret. Tampered rows
are skipped with a warning.

**CLI commands:**

```bash
# Apply a signed bundle to the database
shai patterns apply --bundle patterns-2026-07-21.json --db state/patterns.db --secret PATTERNS_SIGNING_KEY

# List all rules in the database
shai patterns list --db state/patterns.db

# Verify all signatures
shai patterns verify --db state/patterns.db --secret PATTERNS_SIGNING_KEY
```

When `enabled: false` (default), no DB is loaded. Built-in patterns only.

---

## Secret resolution

All values that start with `secret://` are resolved from environment variables:

```yaml
token: "secret://SLACK_BOT_TOKEN"   # resolves os.environ["SLACK_BOT_TOKEN"]
```

Resolution happens in two passes at `from_yaml()` time:
1. First pass: `${ENV_VAR}` substitution
2. Second pass: `secret://` resolution via `EnvVarProvider`

**Use `""` (empty string) for optional credentials in dev.** Do not use
`secret://` for credentials that won't exist — the load will fail even if
the source is `required: false`.
