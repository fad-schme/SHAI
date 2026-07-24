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
shai --help
```

## Help

Every command level supports `-h` and `--help`. Help exits with status `0`
and does not run the selected command.

```bash
shai --help
shai validate --help
shai agents list --help
shai audit tail --help
shai patterns --help
shai patterns verify --help
```

Running `shai` without arguments prints the same top-level help. For nested
command groups such as `agents`, `audit`, and `patterns`, run the group with
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
#   policy_rules:  4
#   audit_sinks:   ['file', 'stdout']
#   normalization: enabled=True  decode=True  max_depth=3
#   session:       enabled=True  backend=sqlite  threshold=0.7  window=50  on_escalation=block
#   boundaries:
#     scan_input:       enabled=True   block_at=high   scanners=['regex_pii', 'injection_scan', 'jailbreak_scan']
#     scan_file:        enabled=False  block_at=high
#     scan_output:      enabled=True   block_at=high   scanners=['regex_pii']
#     scan_tool_result: enabled=True   block_at=high   scanners=['injection_scan', 'identity_spoof_scan']
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
| `--decision` / `-d` | `allow`, `warn`, `blocked`, `deny`, `redact`, `degraded` |
| `--last` / `-n` | N lines (default 20) |
| `--follow` / `-F` | Follow the file |
| `--file` / `-f` | Path, or `-` for stdin |

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
