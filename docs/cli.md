# CLI

The `shai` command is a developer tool: validate config, tail and verify audit logs, and manage the signed pattern database. It does **not** enforce anything at runtime — that's the SDK's job. Think of it as your build-time and on-call companion.

Installed as a `console_scripts` entry point along with the package:

```bash
pip install shai-harness
which shai         # ~/.local/bin/shai
shai --help
```

## Help

Every command level supports `-h` and `--help`. Help exits with status `0`
and does not run the selected command.

```bash
shai --help
shai validate --help
shai agents list --help
shai harness inspect --help
shai audit tail --help
shai audit verify --help
shai patterns --help
shai patterns verify --help
```

Running `shai` without arguments prints the same top-level help. For nested
command groups such as `agents`, `harness`, `audit`, and `patterns`, run the group with
`--help` to see its available subcommands.

## Validate options

```bash
shai validate --config prod.yaml
```

`--config` (`-c`) belongs to `validate` and defaults to
`config/harness.yaml`. CLI options are scoped to the command that consumes
them.

## `shai validate`

The one command you'll run most. It validates `harness.yaml` and its inline
policy rules. When `--agents-dir` is supplied, it also validates every agent
YAML file in that directory, then prints a concise configuration summary.

```bash
shai validate
# Validating config/harness.yaml ... OK
#   tenant_id:     acme-prod
#   source_rules:  0
#   audit_sinks:   ['file', 'stdout']
#   normalization: enabled=True  decode=True  max_depth=3
#   session:       enabled=True  backend=sqlite  threshold=0.7  window=50  on_escalation=block
#   boundaries:
#     scan_input:       enabled=True   block_at=high   scanners=['regex_pii', 'injection_scan', 'jailbreak_scan']
#     scan_file:        enabled=False  block_at=high
#     scan_output:      enabled=True   block_at=high   scanners=['regex_pii']
#     scan_tool_result: enabled=True   block_at=high   scanners=['injection_scan', 'identity_spoof_scan', 'jailbreak_scan']
#     scan_mcp_metadata: enabled=True  block_at=medium  scanners=['mcp_metadata_scan']
```

Exit codes: `0` valid, `1` invalid (first error on stderr). Wire it into CI to
catch configuration and agent-schema drift. Validation does not instantiate
adapters, connect sources, resolve `secret://` references, touch the network,
or open the pattern DB.

Flags:

- `--config` / `-c PATH` selects the harness config.
- `--agents-dir` / `-a DIR` also validates agent YAMLs in that directory.
  When omitted, only the harness config is validated.

## `shai agents list`

Overview of the valid agent YAML files in a directory and their declared
capabilities.

```bash
shai agents list --agents-dir agents/
# ID                     VERSION   TOOLS  SUBS  SOURCES
# ---------------------------------------------------------------
# support_agent          1.2.0        14     2  slack, notion
# research_agent         0.9.1         6     0  arxiv, google_drive
# ops_agent              1.0.0         3     1  github
```

`--agents-dir` / `-a` is required.

Agents that fail to load emit a `Warning: could not load ...` line to stderr but don't fail the command — `agents list` surfaces partial breakage, it doesn't gate on it. Use `validate` when you want a hard fail.

## `shai harness inspect`

Offline listing of what a config declares — boundaries and their scanners,
audit sinks, policy rule count and digest, pattern-DB state, local sources,
every MCP source declared under `sources:` (id, redacted url, content
digest — whether or not it currently has a valid baseline; approval state
is a runtime concern, not shown here), and (with `--agents-dir`) every agent.

```bash
shai harness inspect --config prod.yaml --agents-dir config/agents
# SHAI 0.7.0  |  tenant: acme-prod
# ...
# mcp manifests (./mcp):
#   slack            https://mcp.slack.com/sse   digest=a1b2c3d4e5f6
```

URLs are printed without userinfo, query string, or fragment — credentials
never reach the terminal.

Nothing is built and nothing is connected to. For the identity of the adapter
code a *running* process loaded, read the `system` / `startup` audit event it
emits at construction.

## `shai harness graph`

The dependency graph behind that listing: agent -> source -> tool -> tag, plus
policy rules and subagents. `--format dot` (default) pipes into Graphviz;
`--format json` gives `{nodes, edges}`.

```bash
shai harness graph --config prod.yaml --agents-dir config/agents | dot -Tsvg -o topology.svg
shai harness graph --config prod.yaml --format json | jq '.nodes'
```

Tool nodes come from agent allow-lists — a `sources:` entry for `transport:
mcp` contributes no tool nodes of its own; MCP tool topology lives in the
manifest file it resolves to, outside this offline view.

## `shai mcp onboard`

Approve an MCP manifest — the only path that clears tool calls against it,
and the only path that lets a declared `transport: mcp` source be built into
a live source at all. Without an approved, matching baseline record, the
source is never built and any agent referencing it hits "source not
registered" instead of a gate denial.

```bash
shai mcp onboard mcp/slack.yaml --config prod.yaml
```

Parses the manifest, connects live and fetches `tools/list`, scans the
manifest's own declared tool text, reconciles it against the live response,
and emits one `AuditEvent(boundary=mcp_source_onboarding)`. A clean pass
auto-records the manifest's hash into the signed baseline store — running
the command *is* the approval. See [connectors.md](connectors.md) for the
manifest schema and the per-call approval gate this feeds.

## `shai audit tail`

Human-readable view of an audit JSONL file, with decision-level filtering. Reads from a file, from stdin, or follows a file live like `tail -f`.

```bash
# Last 20 events (default)
shai audit tail --file logs/audit.jsonl

# Follow the file live — best on-call default
shai audit tail --file logs/audit.jsonl --follow

# Only denials on the tool-call gate — the most common on-call filter
shai audit tail --file logs/audit.jsonl --boundary tool_call_gate --decision deny

# Show denies found within the last 50 log lines
shai audit tail --file logs/audit.jsonl --decision deny --last 50

# Pipe from anywhere
docker logs shai | shai audit tail --file - --decision blocked
```

The output surfaces signals that would otherwise take a JSON pretty-printer to find:

```
[deobfuscated: strip_invisible,unicode_fold]    — de-obfuscation transforms fired
[argument_violation] reason=…                    — L2 argument-rule denial
[irreversibility_blocked] reason=…               — L3 blast-radius gate
findings=N max=high                              — scanner findings summary
+42ms                                            — duration
```

Decisions are colourised when stdout is an interactive terminal: red =
deny/blocked, yellow = warn/redact, and green = allow. Redirected and piped
output is plain text. Set `NO_COLOR=1` to disable colour explicitly.

Filter flags:

| Flag | Values |
|---|---|
| `--boundary` / `-b` | `input_scan`, `tool_call_gate`, `tool_result_scan`, `output_scan`, `file_scan`, `mcp_metadata_scan`, `system` |
| `--decision` / `-d` | `allow`, `warn`, `blocked`, `deny`, `redact`, `degraded`, `startup` |
| `--last` / `-n` | N lines (default 20) |
| `--follow` / `-F` | Follow the file |
| `--file` / `-f` | Path, or `-` for stdin |

### Verify a signed trail

When `audit_signing.enabled` is set, every record carries an HMAC-SHA256
signature. `verify` recomputes each one and tells you whether the file still
says what it said when it was written:

```bash
shai audit verify --file logs/audit.jsonl --secret SHAI_AUDIT_SIGNING_KEY
```

`--secret` names the **environment variable** holding the key, never the key
itself — the same convention as `shai patterns`, so the key stays out of shell
history and the process list.

```
failures:
  line 4812: SIGNATURE MISMATCH - record altered or wrong key
  line 5210: no signature
9,043 records: 9,041 verified, 1 mismatched, 1 unsigned, 0 malformed
```

Exit status is 0 only when every record verified. Mismatched, unsigned, and
malformed records all fail the run: a trail with a hole in it does not answer
the question signing was turned on to answer. An empty file fails too — zero
records verified is not a verified trail.

Reads stdin with `-f -`, so a shipped log can be checked in a pipeline without
landing on disk.

## `shai patterns` — the signed pattern database

The SQLite pattern DB holds signed pattern rules and heuristic candidates
awaiting human review. Rows in the `patterns` table are HMAC-SHA256 signed.
`apply` verifies before writing and `verify` checks installed rows. `list` is
an inspection command and does not verify signatures.

### Apply a signed bundle

Install patterns published by a trusted operator (typically the SHAI team or your internal red team):

```bash
shai patterns apply \
    --bundle patterns-2026-07-21.json \
    --db state/patterns.db \
    --secret PATTERNS_SIGNING_KEY
# applied 27 patterns to state/patterns.db
```

Verification is atomic. Every row's HMAC is checked *before* any write. A single bad signature aborts the entire apply — no partial state.

### List installed patterns

```bash
shai patterns list --db state/patterns.db
#   injection:affirmation_priming  catalog=injection  v1
#   jailbreak:dual_persona        catalog=jailbreak  v1
#
# 2 rules total
```

### Verify installed patterns

```bash
shai patterns verify \
    --db state/patterns.db \
    --secret PATTERNS_SIGNING_KEY
# valid: 27  invalid: 0
```

`verify` exits with status `1` when any installed signature is invalid.

### Load installed patterns at runtime

Applying a bundle writes it to the database; it does not reach a running
harness. Point `harness.yaml` at the same file to have `SHAI.from_yaml()` merge
the verified rules into the scanner catalogs at startup:

```yaml
patterns_db:
  enabled: true
  path: state/patterns.db
  secret: "secret://PATTERNS_SIGNING_KEY"    # same key `apply` signed with
```

Restart the process after an `apply` — rules are read once, at startup.
→ See `docs/configuration.md` for catalog routing and failure behaviour.

### Manage heuristic candidates

The heuristic scanner writes fingerprints of near-miss detections to a `heuristic_candidates` table — patterns that scored MEDIUM or above but weren't caught by any signature. These are things worth looking at.

```bash
# List candidates, optionally filtering by status
shai patterns candidates --db state/patterns.db
shai patterns candidates --db state/patterns.db --status open

# Include low-hit-count open candidates normally filtered as noise
shai patterns candidates --db state/patterns.db --status open --all

# Update candidate lifecycle status
shai patterns promote --db state/patterns.db --id 42
shai patterns dismiss --db state/patterns.db --id 43
shai patterns retire --db state/patterns.db --id 42
```

Candidate status changes are persisted to SQLite. They do not invalidate the
cache of a separately running SHAI process; restart that process or explicitly
invalidate its promoted-candidate cache when immediate pickup is required.

The candidate lifecycle—fingerprinting, promotion, dismissal, and
retirement—is documented in
[`.claude/skills/candidates.md`](../.claude/skills/candidates.md).

## What next

- [testing.md](testing.md) — use `shai validate` in CI
- [`.claude/skills/cli.md`](../.claude/skills/cli.md) — every flag on every subcommand
- [`.claude/skills/candidates.md`](../.claude/skills/candidates.md) — heuristic-candidate lifecycle
