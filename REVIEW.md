# REVIEW.md — reviewer instructions for shai-harness

SHAI is a deterministic security control plane for AI agents: it scans, gates,
and audits at five enforcement boundaries (scan_input, check_tool_call,
scan_tool_result, scan_output, scan_file). Review accordingly: this codebase's
job is to say "no" correctly.

## What failure looks like here

- **A boundary passes something it should block** — a scan or the tool-call
  gate returns an allow verdict for input that matches a pattern, exceeds a
  capability, or violates policy. This is the defect class that matters most.
- **Audit integrity breaks** — an audit event leaks raw scanned text (audit
  must never contain raw text), is dropped, or can be forged/reordered.
- **Silent fallback** — an error path that degrades to allow, skips a
  boundary, or falls back to legacy behavior. SHAI has a no-legacy-fallback
  policy: fail closed, loudly.

Prioritize findings that could cause the failures above. Everything else is
secondary.

## Scope

Skip these paths entirely:

- `dist/`, `logs/`, `state/`, `signatures/`, `**/__pycache__/`, `*.zip`

Sensitive paths — hold findings here to the highest bar and flag any change
for human review:

- `src/harness/boundaries/`, `src/harness/policy/`, `src/harness/audit/`,
  `src/harness/patterns/`, `src/harness/core/`
- `.github/workflows/`
- `eval/` — see the eval rules below

## Rules for findings

1. **Evidence required.** Every finding cites a file and line and explains the
   concrete failure scenario (inputs/state → wrong outcome). No guesses from
   file or function names alone.
2. **Tag every finding** as one of:
   - **Important** — a real defect this PR introduces; must be fixed or
     explicitly resolved with a reason before merge.
   - **Nit** — style or polish; author may ignore.
   - **Pre-existing** — a real defect that predates this PR; file it, don't
     blame the author or block the merge on it.
3. **Cap nits at 3 per review.**
4. **No style, diagnostic, or cleanup-only findings** presented as Important.
5. **No repeat findings** — if a finding was already raised and resolved with
   a reason in this PR, don't raise it again.
6. **Root cause on bug fixes.** If the PR claims to fix a bug, check that it
   fixes the cause, not the symptom.
7. **Summary format.** Start with a count ("3 findings: 2 Important, 1 Nit").
   If nothing needs fixing, say plainly: "0 findings — nothing needs fixing."
8. **Value > effort + complexity.** Every recommendation carries a worth-it
   judgment: value (impact × real-world likelihood) must clearly exceed the
   fix's effort plus the complexity it adds. A real-but-negligible finding is
   reported as "not worth fixing" with a one-line reason, not silently
   inflated to Important. Recommended fixes are the smallest change that
   removes the failure — a fix that is over-engineering (speculative
   generality, guards for unreachable states, abstraction for one caller) is
   itself a defect of the recommendation. Check this before recommending and
   again before fixing.
   SHAI-specific exception: fail-closed behavior at an enforcement boundary is
   never "over-engineering" — the no-legacy-fallback policy outranks fix-size
   minimalism there.

## Repo-specific checks

- **Verdict direction:** on any changed decision path, trace the error/except
  branches — an exception or unknown state must never produce an allow.
- **Audit events:** any new or changed audit emission must carry no raw
  scanned text (hashes, lengths, pattern ids, and categories only).
- **Eval changes (`eval/`):** per AGENTS.md, assertions must not be weakened,
  thresholds relaxed, failing cases removed, or success redefined to make
  current SHAI behavior pass. A test correction needs an explicit written
  reason why the test misstated the intended contract, and changed test or
  scoring semantics must be versioned. Flag any eval diff lacking this as
  Important.
- **Structural invariants:** changes to boundary dispatch, verdict types, or
  the pattern DB schema must preserve SHAI's seven structural invariants
  (see the shai-dev skill / THREAT_MODEL.md); flag anything that bypasses a
  boundary or adds a second dispatch path.
- **Dependencies:** new runtime dependencies are Important findings by
  default — SHAI's runtime dependency set is deliberately small.
