# CLI Reference

The `shai` command is a developer tool for validating configuration, inspecting
audit logs, and managing the signed pattern database. It ships as a `console_scripts`
entry point — installed automatically with the package.

**Not runtime.** The CLI does not scan traffic, gate tools, or attach to a
running agent. Runtime enforcement lives in the SDK. The CLI is for build-time
validation, on-call log inspection, and pattern-DB operations.

---

## Install

```bash
pip install shai-harness
which shai
# ~/.local/bin/shai   (or your venv's bin/)
shai --help
```

The entry point is `harness_cli.main:main` — declared in `pyproject.toml` under
`[project.scripts]`. Running `shai` with no arguments prints usage:

```bash
shai
# usage: shai [-h] COMMAND ...
#
# SHAI developer tools
#   validate   Validate config and agent files
#   agents     Agent management commands
#   harness    Inspect what a config wires up
#   audit      Audit log commands
#   patterns   Manage the signed pattern database
```

---

## Help

Every parser level supports `-h` and `--help`. Help prints to stdout, exits
with code `0`, and does not execute the command.

```bash
shai --help
shai validate --help
shai agents --help
shai agents list --help
shai harness --help
shai harness inspect --help
shai harness graph --help
shai audit --help
shai audit tail --help
shai audit verify --help
shai patterns --help
shai patterns apply --help
```

Running `shai` without arguments prints the top-level help. Use
`shai COMMAND --help` or `shai GROUP SUBCOMMAND --help` for scoped options.

---

## Command options

Options are scoped to the command that consumes them. For example, `--config`
belongs to `validate`:

```bash
shai validate --config prod.yaml
```

---

## `shai validate`

Validates a `harness.yaml` and its inline policy rules. When `--agents-dir` is
supplied, it also validates every agent YAML file in that directory, then
prints a concise configuration summary.

```bash
shai validate
# Validating config/harness.yaml ... OK
#   tenant_id:     acme-prod
#   policy_rules:  4
#   audit_sinks:   ['file', 'stdout']
#   normalization: enabled=True  decode=True  max_depth=3
#   session:       enabled=True  backend=sqlite  threshold=0.7  window=50  on_escalation=block
#   boundaries:
#     scan_input:       enabled=True   block_at=high   scanners=['regex_pii', 'injection_scan', 'jailbreak_scan']
#     scan_output:      enabled=True   block_at=high   scanners=['regex_pii']
#     scan_tool_result: enabled=True   block_at=high   scanners=['injection_scan', 'identity_spoof_scan', 'jailbreak_scan']
#     scan_file:        enabled=False
```

**Flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--config` / `-c PATH` | `config/harness.yaml` | Path to the harness config. |
| `--agents-dir` / `-a DIR` | — | Also validate agent YAMLs in this directory. When omitted, only the harness config is validated. |

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | Config and inline policy rules valid; all supplied agent YAMLs parsed. |
| `1` | Config invalid, or one or more agents failed to load. First error is printed on stderr. |

Use it in CI to catch configuration and agent-schema drift. It does not
instantiate adapters, connect sources, resolve `secret://` references, touch
the network, or open the pattern DB.

---

## `shai agents list`

Lists the agents in `--agents-dir` with their tool count, subagent count, and
declared sources.

```bash
shai agents list --agents-dir agents/
# ID                     VERSION   TOOLS  SUBS  SOURCES
# ---------------------------------------------------------------
# support_agent          1.2.0        14     2  slack, notion
# research_agent         0.9.1         6     0  arxiv, google_drive
# ops_agent              1.0.0         3     1  github
```

**Flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--agents-dir` / `-a DIR` | *(required)* | Directory of agent YAML files. |

Agents that fail to load emit a `Warning: could not load <file>: <error>`
line on stderr but do not cause a non-zero exit — the goal is to list what
you have and surface partial breakage, not to gate on it. Use `shai validate`
when you want a hard fail.

---

## `shai harness inspect`

Offline listing of what a config declares — boundaries and their scanners,
audit sinks, policy rule count and digest, pattern-DB state, connector
manifests, resolved sources, and (with `--agents-dir`) every agent.

```bash
shai harness inspect --config prod.yaml --agents-dir config/agents
# SHAI 0.7.0  |  tenant: acme-prod
# ...
# sources:
#   slack_primary    mcp    https://mcp.slack.com/sse    connector=slack  tags=external,messaging
```

Sources are shown **after** connector-manifest resolution, so the url, tags
and allow-lists are the ones the harness would run with. URLs are printed
without userinfo, query string, or fragment — credentials never reach the
terminal.

Nothing is built and nothing is connected to. For the identity of the adapter
code a *running* process loaded, read the `system` / `startup` audit event it
emits at construction.

## `shai harness graph`

The dependency graph behind that listing: agent -> source -> tool -> tag, plus
policy rules and subagents. `--format dot` (default) pipes into Graphviz;
`--format json` gives `{nodes, edges, warnings}`.

```bash
shai harness graph --config prod.yaml --agents-dir config/agents | dot -Tsvg -o topology.svg
shai harness graph --config prod.yaml --format json | jq '.warnings'
```

Tool nodes come from connector manifests and agent allow-lists — the only tool
names knowable without connecting to an MCP server.

**Shadow MCP detection:** two sources whose URLs match once credentials and
query strings are stripped are reported in `warnings` and on stderr. Fronting
one endpoint with two configs is legal — the second config's tags and
allow-lists simply also apply to that server — so this is a warning, never an
error.

---

## `shai audit tail`

Reads an audit JSONL file with human-readable formatting and decision-level
filtering. It can read from a file or stdin, and `--follow` follows a file like
`tail -f`.

```bash
# Tail the last 20 events (default) from a file
shai audit tail --file logs/audit.jsonl

# Follow the file live
shai audit tail --file logs/audit.jsonl --follow

# Only denials on the tool-call gate — the most common on-call filter
shai audit tail --file logs/audit.jsonl --boundary tool_call_gate --decision deny

# Show denies found within the last 50 log lines
shai audit tail --file logs/audit.jsonl --decision deny --last 50

# Stream from stdin — pipe from wherever
docker logs shai | shai audit tail --file - --decision blocked
```

**Flags:**

| Flag | Default | Meaning |
|---|---|---|
| `--file` / `-f PATH` | `-` (stdin) | Audit log path, or `-` for stdin. |
| `--follow` / `-F` | off | Follow the file — new lines print as they arrive. |
| `--last` / `-n N` | `20` | Number of lines to show before following. |
| `--boundary` / `-b NAME` | — | Filter: `input_scan`, `tool_call_gate`, `tool_result_scan`, `output_scan`, `file_scan`, `mcp_metadata_scan`, `system`. |
| `--decision` / `-d NAME` | — | Filter: `allow`, `warn`, `blocked`, `deny`, `redact`, `degraded`, `startup`. |

**Output surfaces the signals that would otherwise take a JSON pretty-printer
to find:**

- `[deobfuscated: strip_invisible,unicode_fold]` — de-obfuscation transforms fired.
- `[argument_violation] reason=...` — L2 argument-rule denial.
- `[irreversibility_blocked] reason=...` — L3 blast-radius gate.
- `findings=N max=high` — scanner findings summary.
- `+42ms` — duration.

Decisions are colorised only when stdout is an interactive terminal: red =
deny/blocked, yellow = warn/redact, and green = allow. Redirected and piped
output is plain text. Set `NO_COLOR=1` to disable color explicitly.

---

## `shai audit verify`

Recomputes the HMAC-SHA256 signature on every record in a trail written with
`audit_signing.enabled`. This is the read side of Invariant 5 — the command an
operator runs to establish that a log has not been altered since it was written.

```bash
shai audit verify --file logs/audit.jsonl --secret SHAI_AUDIT_SIGNING_KEY
cat shipped.jsonl | shai audit verify --secret SHAI_AUDIT_SIGNING_KEY
```

`--secret` names the environment variable holding the key, not the key — the
same convention as `shai patterns`, keeping it out of shell history and the
process list.

Each record lands in one of four buckets, and the summary reports all four:

| Bucket | Meaning |
|---|---|
| verified | Signature recomputed and matched |
| mismatched | Record altered after signing, or the wrong key was supplied |
| unsigned | No `signature` field — a gap in a trail that should have none |
| malformed | Not parsable as a JSON object |

**Exit 0 only when every record verified.** Unsigned and malformed records fail
the run alongside mismatched ones: a trail with a hole in it does not answer the
question signing was enabled to answer. An empty file is also a failure — zero
records verified is not a verified trail. Failing line numbers are printed, up
to 20, then a count of the rest.

Verification canonicalises before hashing, so a record that a log shipper
reserialized with different key order still verifies.

---

## `shai patterns` — signed pattern database

Manages the SQLite DB that holds signed patterns and heuristic candidates.
Every write to the `patterns` table is HMAC-SHA256 signed. `apply` verifies
before writing, `verify` checks installed rows, and `list` performs an
unverified inspection.

The DB has two tables:

| Table | Written by | Read by |
|---|---|---|
| `patterns` | `shai patterns apply` | `shai patterns list`, `shai patterns verify`, and `SHAI.from_yaml()` at startup when `patterns_db.enabled` is set |
| `heuristic_candidates` | Every scan (fire-and-forget) | `shai patterns candidates`, promoted rows read by the scan pipeline |

→ See `13-candidates.md` for the candidate lifecycle.
→ See `02-harness-yaml.md` for the pattern-DB CLI workflow.

### `apply` — install a signed bundle

```bash
shai patterns apply \
    --bundle patterns-2026-07-21.json \
    --db state/patterns.db \
    --secret PATTERNS_SIGNING_KEY
# applied 27 patterns to state/patterns.db
```

**Flags:**

| Flag | Meaning |
|---|---|
| `--bundle FILE` | Path to a signed bundle JSON file. |
| `--db PATH` | Path to the SQLite DB. Created on first use. |
| `--secret ENV_VAR` | Name of an environment variable holding the signing secret. Not the secret itself. |

**Verification is atomic.** Every row's HMAC is checked *before* any write.
A single bad signature aborts the entire apply — no partial state. Rows are
upserted by `rule_id`, so re-applying a bundle updates in place.

**Exit codes:**

| Code | Meaning |
|---|---|
| `0` | All rows verified and written. |
| `1` | Signature verification failed, secret env var unset, bundle malformed, or DB unwritable. Reason printed on stderr. |

### `list` — inspect what's installed

```bash
shai patterns list --db state/patterns.db
#   injection:affirmation_priming            catalog=injection        v1
#   injection:deferred_execution             catalog=injection        v1
#   jailbreak:dual_persona_roleplay          catalog=jailbreak        v1
#   identity_spoof:fabricated_approval       catalog=identity_spoof   v1
#   mcp_metadata:metadata_tool_shadowing     catalog=mcp_metadata     v1
#
# 5 rules total
```

No secret required — `list` does not verify. Use `verify` for that.

### `verify` — check every signature

```bash
shai patterns verify --db state/patterns.db --secret PATTERNS_SIGNING_KEY
# valid: 5  invalid: 0
```

Exit code `0` when all rows verify, `1` when any row fails. Run this in the
same CI job that deploys the DB — it catches secret rotation mismatches
and mid-flight corruption before the DB reaches production.

### `candidates`, `promote`, `dismiss`, `retire`

Heuristic candidate management — full reference in `13-candidates.md`:

```bash
shai patterns candidates --db state/patterns.db --status open
shai patterns candidates --db state/patterns.db --status open --all
shai patterns promote    --db state/patterns.db --id 12
shai patterns dismiss    --db state/patterns.db --id 8
shai patterns retire     --db state/patterns.db --id 12
```

`--status` accepts `open`, `promoted`, `dismissed`, or `retired`. With
`--status open`, low-hit-count candidates are hidden unless `--all` is set.

Status changes are persisted to SQLite but cannot invalidate the cache of a
separately running SHAI process. Restart that process or explicitly invalidate
its promoted-candidate cache when immediate pickup is required.

---

## Building a bundle from pattern YAML

`shai patterns apply` consumes an *already-signed* bundle JSON. Producing one
is a separate step: HMAC-SHA256 the canonical JSON encoding of each rule's
`{rule_id, catalog, payload}` (`json.dumps(..., sort_keys=True)`) using the
same secret the `apply` and `verify` commands read, and write out the row
shape shown in "Bundle format" below.

**One combined bundle is fine.** Each row carries its own `catalog` field —
a single bundle can carry rules for all four catalogs (`injection`, `jailbreak`,
`identity_spoof`, `mcp_metadata`).

**Same secret both sides.** Whatever signs the bundle and `shai patterns
apply` must both read the secret from the same environment variable.
Rotating the secret means re-signing every bundle before the next apply.

---

## Bundle format

For reference — the JSON schema `apply` expects:

```json
[
  {
    "rule_id":   "injection:affirmation_priming",
    "catalog":   "injection",
    "payload":   "{\"functions\":[\"intent_score\"],\"meta\":{\"category\":\"prompt_injection\",\"severity\":\"high\",\"threat_level\":4},\"name\":\"affirmation_priming\",\"strings\":{...}}",
    "signature": "3f8a...c17e",
    "version":   1
  }
]
```

- `rule_id` — `{catalog}:{name}`. The DB primary key.
- `catalog` — routes the rule to a scanner. One of `injection`, `jailbreak`,
  `identity_spoof`, `mcp_metadata`.
- `payload` — JSON *string* (not object) of the rule dict: canonical, sorted
  keys, compact separators. `apply` re-signs the verbatim string, so
  hand-editing the bundle after signing will fail verification.
- `signature` — hex `HMAC-SHA256` over
  `json.dumps({"rule_id": ..., "catalog": ..., "payload": ...}, sort_keys=True)`.
  Signing the three fields concatenated (the pre-0.4.0 format) is ambiguous —
  `catalog` selects the scanner, so an undelimited body let a signed row be
  re-split to route elsewhere. Bundles signed before 0.4.0 must be re-signed.
- `version` — informational; defaults to `1`.

Never author bundles by hand — sign them programmatically from YAML.

---

## CI: fail the build if config drifts

```yaml
# .github/workflows/validate.yml
- uses: actions/checkout@v4
- run: pip install shai-harness
- run: shai validate --config config/harness.yaml --agents-dir agents/
```

---

## Troubleshooting

**`error: environment variable 'PATTERNS_SIGNING_KEY' not set`**
The secret env var is empty in the current shell. `shai patterns apply/verify`
read the secret from the environment; export before running, or source your
secret manager first.

**`signature verification failed for rule_id=...`**
The bundle was signed with a different secret than the one `apply` is using,
or the bundle JSON was edited after signing. Re-sign against the current
secret.

**`invalid YAML in agent-xx.yaml: ...`** (from `validate`)
An agent file doesn't parse or fails Pydantic validation. The first error is
printed on stderr; fix that file first — cascading errors often disappear.

**`audit tail` has no color when piped**
Color is intentionally enabled only for an interactive stdout terminal.
Pipes and redirects receive plain text. Set `NO_COLOR=1` to disable color
explicitly in a terminal.

**`shai patterns list` shows fewer rules than the bundle contains**
Some rows verified as invalid at apply time and were skipped, OR the bundle
used `INSERT OR REPLACE` semantics and overwrote earlier rules with the same
`rule_id`. Run `shai patterns verify` to distinguish the two.

**`shai validate` passes but `from_yaml()` fails at runtime**
The validator does not resolve `secret://` URIs — those are checked at
`from_yaml()` time. A missing env-var-backed secret will pass `validate`
but fail startup. Include env-var presence checks in your deploy playbook.

---

→ See `02-harness-yaml.md` for the pattern-DB CLI workflow.
→ See `13-candidates.md` for the candidate lifecycle.
→ See `05-verdicts-events.md` for `AuditEvent` field reference (what `audit tail` renders).
