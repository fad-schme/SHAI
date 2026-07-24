# CLI Reference

The `shai` command is a developer tool for validating configuration, inspecting
audit logs, and managing the signed pattern database. It ships as a `console_scripts`
entry point — installed automatically with the package.

**Not runtime.** The CLI does not scan traffic, gate tools, or attach to a
running agent. Runtime enforcement lives in the SDK. The CLI is for build-time
validation, on-call log inspection, and pattern-DB operations.

---

## Install

SHAI is not published on PyPI during early access. Build and install the CLI
from a local source checkout:

```bash
git clone https://github.com/fad-schme/SHAI.git
cd SHAI
pip install -e ".[dev]"
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
shai audit --help
shai audit tail --help
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
#     scan_tool_result: enabled=True   block_at=high   scanners=['injection_scan', 'identity_spoof_scan']
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
| `--decision` / `-d NAME` | — | Filter: `allow`, `warn`, `blocked`, `deny`, `redact`, `degraded`. |

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

## `shai patterns` — signed pattern database

Manages the SQLite DB that holds signed patterns and heuristic candidates.
Every write to the `patterns` table is HMAC-SHA256 signed. `apply` verifies
before writing, `verify` checks installed rows, and `list` performs an
unverified inspection.

The DB has two tables:

| Table | Written by | Read by |
|---|---|---|
| `patterns` | `shai patterns apply` | `shai patterns list`, `shai patterns verify`, and explicit `load_verified_rules()` integrations |
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
is a separate step: sign each rule's `(rule_id + catalog + payload)` with
HMAC-SHA256 using the same secret the `apply` and `verify` commands read.

`make_bundle.py` (shipped with the extended-patterns delivery) does this
end-to-end from catalog-format YAML:

```bash
export PATTERNS_SIGNING_KEY='...'    # same value shai patterns apply will use

python make_bundle.py \
    --secret PATTERNS_SIGNING_KEY \
    --out patterns-2026-07-21.json \
    new_injection_patterns.yaml \
    new_jailbreak_patterns.yaml \
    injection:new_output_prompt_leakage.yaml
#   signed  4 rule(s) from new_injection_patterns.yaml  -> catalog=injection
#   signed  2 rule(s) from new_jailbreak_patterns.yaml  -> catalog=jailbreak
#   signed  4 rule(s) from new_output_prompt_leakage.yaml -> catalog=injection
#
# wrote 10 signed rows to patterns-2026-07-21.json
```

**Positional arguments** are `CATALOG:PATH` or just `PATH`. When only a path is
given, the catalog is inferred from a filename shaped like
`new_<catalog>_patterns.yaml`. Prefix `CATALOG:` explicitly when the filename
doesn't follow that convention (e.g. `injection:new_output_prompt_leakage.yaml`).

**One combined bundle is fine.** Each row carries its own `catalog` field —
a single bundle can carry rules for all four catalogs (`injection`, `jailbreak`,
`identity_spoof`, `mcp_metadata`).

**Same secret both sides.** `make_bundle.py` and `shai patterns apply` both
read the secret from `os.environ[ENV_VAR]`. Rotating the secret means
re-signing every bundle before the next apply.

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
- `signature` — `HMAC-SHA256(secret, rule_id + catalog + payload)` in hex.
- `version` — informational; defaults to `1`.

Never author bundles by hand — use `make_bundle.py` from YAML.

---

## Common workflows

**Deploy a new pattern release:**
```bash
# 1. Author or receive catalog YAML
# 2. Sign
python make_bundle.py --secret PATTERNS_SIGNING_KEY --out release.json *.yaml
# 3. Apply
shai patterns apply --bundle release.json --db state/patterns.db --secret PATTERNS_SIGNING_KEY
# 4. Verify
shai patterns verify --db state/patterns.db --secret PATTERNS_SIGNING_KEY
# 5. Restart / redeploy so from_yaml() reloads
```

**On-call: something is being denied — figure out what:**
```bash
# Denies on the tool-call gate, live
shai audit tail --file logs/audit.jsonl --follow --boundary tool_call_gate --decision deny
```

**On-call: session escalations firing — check the accumulator:**
```bash
shai audit tail --file logs/audit.jsonl --decision blocked --last 100 | grep session_escalation
```

**CI: fail the build if config drifts:**
```yaml
# .github/workflows/validate.yml
- uses: actions/checkout@v4
- run: pip install -e ".[dev]"
- run: shai validate --config config/harness.yaml --agents-dir agents/
```

**Weekly: promote heuristic candidates the on-call team reviewed:**
```bash
shai patterns candidates --db state/patterns.db --status open
# review, then:
shai patterns promote --db state/patterns.db --id 42
shai patterns dismiss --db state/patterns.db --id 43
```

---

## Troubleshooting

**`error: environment variable 'PATTERNS_SIGNING_KEY' not set`**
The secret env var is empty in the current shell. `shai patterns apply/verify`
and `make_bundle.py` all read the secret from the environment; export before
running, or source your secret manager first.

**`signature verification failed for rule_id=...`**
The bundle was signed with a different secret than the one `apply` is using,
or the bundle JSON was edited after signing. Re-sign with `make_bundle.py`
against the current secret.

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
