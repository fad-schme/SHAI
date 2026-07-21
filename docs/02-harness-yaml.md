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
  on_error: fail_closed  # fail_closed (default) | fail_open | degrade
  scanners:
    - name: regex_pii
      action: redact        # per-scanner override (overrides boundary action)
      redact_with: "***"    # replacement string for redact action
    - name: injection_scan
      action: block
    - name: jailbreak_scan
    - name: identity_spoof_scan
    - name: heuristic_scan
```

**Built-in scanner names:**

| Name | Catalog | Notes |
|---|---|---|
| `regex_pii` | Built-in PII + secret categories. `secret.credit_card` is Luhn-validated; `secret.ssn` is structure-validated. | Runs on any boundary. Redact-capable. |
| `injection_scan` | `injection_patterns.yaml` — direct prompt injection, tool coercion, encoded payloads. | User text surface. |
| `jailbreak_scan` | `jailbreak_patterns.yaml` — guardrail-integrity attacks (persona override, refusal suppression, mode activation, prompt extraction). | Any boundary; category prefix `jailbreak.*`. |
| `identity_spoof_scan` | `identity_spoof_patterns.yaml` — messages that claim privileged agent identity or fabricate approval. | High value at `scan_tool_result` — catches authority-completion in poisoned tool results. |
| `heuristic_scan` | Not YAML-driven. 5 sub-scores: entropy, instruction density, coherence, structural markers, typoglycemia. | Always-on backstop. Catches novel patterns the regex catalogs miss. |
| `mcp_metadata_scan` | `mcp_metadata_patterns.yaml`. | `scan_mcp_metadata` only. |

**`on_error`** — how a boundary handles a scanner failure:
- `fail_closed` (default) — treat as if the scanner blocked; boundary returns BLOCK, emits a SYSTEM/DEGRADED audit event alongside the block.
- `fail_open` — log and continue; findings from that scanner are empty for this call. Pre-0.2 behavior.
- `degrade` — content passes with `warned=True` and a SYSTEM/DEGRADED audit event with `extra.degraded=True`.

The default flip from implicit fail-open to `fail_closed` is intentional: a scanner outage without an operator opt-in should be a fail-safe, not a bypass. If you need the old behavior, add `on_error: fail_open` explicitly.

Circuit breaker (per scanner): 5 consecutive failures → OPEN for 60 s (exponential backoff to 5 min max on repeated tripping). While OPEN the scanner is skipped and its `on_error` policy applies. Restarts on next successful probe.

**Actions:**
- `block` — hard stop. `verdict.blocked = True`. LLM never sees the content.
- `alert` — content passes but `verdict.warned = True`. Audit flags it.
- `redact` — matched text is replaced with `redact_with`. `verdict.redacted_text` is set.

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

---

## Audit signing (HMAC-SHA256)

```yaml
audit_signing:
  enabled: true
  secret: "secret://AUDIT_SIGNING_KEY"
```

When enabled, every `AuditEvent` gains a `signature` field: HMAC-SHA256
over all non-null fields (excluding `signature`), `sort_keys=True`.

---

## Extended pattern database

Signed pattern rules loaded into the regex scanners at startup, on top of the
built-in YAML catalogs. Authored as catalog YAML, signed into a bundle with
`shai patterns build`, applied with `shai patterns apply`. The DB gives
operators a way to update detection without shipping a new build of SHAI.

```yaml
extended_patterns:
  enabled: false
  path:    "state/patterns.db"
  secret:  "secret://SHAI_PATTERN_SECRET"
```

**Fields:**
- `enabled` — off by default. When off, scanners use built-in catalogs only.
- `path`   — SQLite path. Created on first apply.
- `secret` — HMAC-SHA256 key; must match the value used by `shai patterns build/apply/verify`.

At startup each scanner loads verified rules by its `catalog_name`:
`injection`, `jailbreak`, `identity_spoof`, `mcp_metadata`. Rows with invalid
signatures are skipped with a `WARN` log — never silently applied.

**CLI workflow:**

```bash
# 1. Sign catalog-format YAML into a bundle (all rules for all catalogs
#    can go in a single bundle; each row carries its catalog name)
python make_bundle.py --secret SHAI_PATTERN_SECRET --out bundle.json \
    new_injection_patterns.yaml \
    injection:new_output_prompt_leakage.yaml \
    new_jailbreak_patterns.yaml \
    new_identity_spoof_patterns.yaml \
    new_mcp_metadata_patterns.yaml

# 2. Apply — re-verifies every row's HMAC, INSERT OR REPLACE by rule_id
shai patterns apply --bundle bundle.json --db state/patterns.db \
                    --secret SHAI_PATTERN_SECRET

# 3. Verify — walks every row, confirms signature
shai patterns verify --db state/patterns.db --secret SHAI_PATTERN_SECRET

# 4. List — no secret needed, no verification
shai patterns list --db state/patterns.db
```

The rule format inside a bundle is exactly the catalog format used by
`injection_patterns.yaml` and friends — `name`, `meta` (`severity`, `category`,
`threat_level`, `description`), `strings`, optional `functions`. See the
built-in catalogs under `src/harness/adapters/scanners/l10n/` for reference.

**Heuristic candidates.** The heuristic scanner records novel patterns it
sees (fingerprinted, deduplicated by LSH similarity) into `heuristic_candidates`
in the same DB. Operators review and promote them:

```bash
shai patterns candidates --db state/patterns.db --status open
shai patterns promote  --db state/patterns.db --id 42   # promoted → loaded on next scan
shai patterns dismiss  --db state/patterns.db --id 42   # false positive
shai patterns retire   --db state/patterns.db --id 42   # was promoted, no longer needed
```

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
