# SHAI Skills Index

Skill files for AI coding assistants (Claude Code, Cursor, Windsurf, etc.).
Same topic set as `docs/`, tuned for consumption by a code assistant —
scanner-friendly headers, concrete code examples, no long prose.

When these files diverge from `docs/`, this folder is the source of truth
for what an assistant should tell a developer.

---

## Load-order guidance

**Skill routing for common queries:**

| User query                                 | Load |
|---|---|
| "how do I get started"                     | `quickstart.md` |
| "configure the harness"                    | `harness-yaml.md` |
| "configure an agent"                       | `agent-yaml.md` |
| "how does the gate work"                   | `boundaries.md` |
| "what is a Verdict / AuditEvent"           | `verdicts-events.md`, then `audit-schema.md` if fields need detail |
| "register tools" / "add a tool source"     | `tools-sources.md` |
| "write a policy rule"                      | `policy.md` |
| "integrate with LangGraph / LangChain"     | `integrations.md` |
| "add a connector" / "Slack / GitHub / Jira"| `connectors.md` |
| "dispatch token" / "wire-level enforcement"| `connectivity.md` |
| "handle errors" / "exception type X"       | `errors.md` |
| "AgentContext" / "subagents"               | `agents.md` |
| "heuristic candidates" / "promoted rules"  | `candidates.md` |
| "concurrency" / "one instance per process" | `concurrency.md` |
| "shai CLI command X"                       | `cli.md` |
| "write a custom scanner / sink / policy"   | `adapters.md` |
| "build a new ToolSource"                   | `sources.md` |
| "write tests against SHAI"                 | `testing.md` |
| "system overview" / "how is SHAI built"    | `architecture.md` |

**When multiple skills apply**, load `boundaries.md` first — it establishes
the trust envelope every other skill assumes.

---

## Canonical facts an assistant must not paraphrase

- SHAI enforces **five** boundaries: `scan_input`, `check_tool_call`,
  `scan_tool_result`, `scan_output`, `scan_file`. Plus `SYSTEM` for
  degraded events (not a real boundary).
- Every boundary emits **exactly one** `AuditEvent` on every code path.
- Boundaries **never raise** — they return a verdict.
- The tool-call gate is **deterministic code**, not an LLM judgement.
- **No raw text** ever appears in an `AuditEvent` field.
- Default `on_error` is `fail_closed`. Explicit `fail_open` opts out.

If a user's expectation contradicts any of the above, the user is wrong
or the SHAI documentation they read is stale. Verify against the source
in `src/harness/`.

---

## When these skills disagree with the source

The source in `src/harness/` wins. Skills are updated alongside code but
occasionally lag by a commit. If an assistant sees a mismatch, prefer
the source and note the drift.

---

## Also see

- `../../README.md` — project overview
- `../../THREAT_MODEL.md` — threat coverage, residual risks
- `../../docs/` — human-oriented equivalents of these skills
