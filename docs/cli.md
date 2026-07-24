# CLI

The `shai` command is a developer tool: validate config, tail audit logs, and manage the signed pattern database. It does **not** enforce anything at runtime — that's the SDK's job. Think of it as your build-time and on-call companion.

Installed as a `console_scripts` entry point along with the package:

SHAI is not published on PyPI during early access. Build and install the CLI
from a local source checkout:

```bash
git clone https://github.com/fad-schme/SHAI.git
cd SHAI
pip install -e ".[dev]"
which shai         # ~/.local/bin/shai
shai               # prints usage
```

## Global option: `--config`

```bash
shai --config prod.yaml validate
```

`--config` (`-c`) sits **before** the subcommand. Consumed by `validate`; ignored by everything else. Default: `config/harness.yaml`.

## `shai validate`

The one command you'll run most. Validates `harness.yaml` and every agent file it references, then prints a summary of what would be built at `SHAI.from_yaml()` time.

```bash
shai validate
# Validating config/harness.yaml ... OK
#   tenant_id:     acme-prod
#   policy:        rule_based
#   audit_sinks:   ['file', 'stdout']
#   normalization: enabled=True  decode=True  max_depth=3
#   session:       enabled=True  threshold=0.7  on_escalation=block
#   boundaries:
#     scan_input:       enabled=True   block_at=high   scanners=['regex_pii', 'injection_scan', 'jailbreak_scan']
#     scan_output:      enabled=True   block_at=high   scanners=['regex_pii']
#     scan_tool_result: enabled=True   block_at=high   scanners=['injection_scan', 'identity_spoof_scan']
#     scan_file:        enabled=False
```

Exit codes: `0` valid, `1` invalid (first error on stderr). Wire it into CI to fail a merge that would break `SHAI.from_yaml()` at startup.

Flags: `--agents-dir` / `-a DIR` overrides where agent YAMLs are loaded from.

## `shai agents list`

Overview of the agents wired up in this deployment. Useful when a new engineer asks "what runs here?"

```bash
shai agents list --agents-dir agents/
# ID                     VERSION   TOOLS  SUBS  SOURCES
# ---------------------------------------------------------------
# support_agent          1.2.0        14     2  slack, notion
# research_agent         0.9.1         6     0  arxiv, google_drive
# ops_agent              1.0.0         3     1  github
```

Agents that fail to load emit a `Warning: could not load ...` line to stderr but don't fail the command — `agents list` surfaces partial breakage, it doesn't gate on it. Use `validate` when you want a hard fail.

## `shai audit tail`

Human-readable view of an audit JSONL file, with decision-level filtering. Reads from a file, from stdin, or follows a file live like `tail -f`.

```bash
# Last 20 events (default)
shai audit tail --file logs/audit.jsonl

# Follow the file live — best on-call default
shai audit tail --file logs/audit.jsonl --follow

# Only denials on the tool-call gate — the most common on-call filter
shai audit tail --file logs/audit.jsonl --boundary tool_call_gate --decision deny

# Last 50 denies of any kind
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

Decisions are colourised: red = deny/blocked, yellow = warn/redact, green = allow. Pipe through `less -R` for colour in a pager, or set `NO_COLOR=1` to strip ANSI.

Filter flags:

| Flag | Values |
|---|---|
| `--boundary` / `-b` | `input_scan`, `tool_call_gate`, `tool_result_scan`, `output_scan`, `file_scan`, `mcp_metadata_scan`, `system` |
| `--decision` / `-d` | `allow`, `warn`, `blocked`, `deny`, `redact`, `degraded` |
| `--last` / `-n` | N lines (default 20) |
| `--follow` / `-F` | Follow the file |
| `--file` / `-f` | Path, or `-` for stdin |

## `shai patterns` — the signed pattern database

The pattern DB is a SQLite file holding two things: extra injection-scan rules signed by an operator, and heuristic-scanner candidates awaiting human review. Every write is HMAC-SHA256 signed; every read verifies. Tampered rows are silently skipped, never applied.

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
# 27 signed patterns installed. Last applied: 2026-07-21T09:15:00Z (bundle patterns-2026-07-21).
```

### Verify without applying

```bash
shai patterns verify --bundle patterns-2026-07-21.json --secret PATTERNS_SIGNING_KEY
# 27 rows valid. Bundle is well-formed and every row is signed.
```

### Manage heuristic candidates

The heuristic scanner writes fingerprints of near-miss detections to a `heuristic_candidates` table — patterns that scored MEDIUM or above but weren't caught by any signature. These are things worth looking at.

```bash
# Show recent candidates
shai patterns candidates --db state/patterns.db --limit 20

# Promote a candidate to a real signed pattern
shai patterns candidates --db state/patterns.db --promote 42

# Retire a false positive
shai patterns candidates --db state/patterns.db --retire 43
```

The candidate lifecycle (fingerprinting, retirement policy, promotion signing) is documented in [`.claude/skills/candidates.md`](../.claude/skills/candidates.md).

## What next

- [testing.md](testing.md) — use `shai validate` in CI
- [`.claude/skills/cli.md`](../.claude/skills/cli.md) — every flag on every subcommand
- [`.claude/skills/candidates.md`](../.claude/skills/candidates.md) — heuristic-candidate lifecycle
