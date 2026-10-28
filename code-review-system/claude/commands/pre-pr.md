---
description: Pre-PR gate - run the project's checks with shown output, a fresh-context review, and a security pass. Passes only when checks are green and every Important finding is addressed. Run before opening any PR.
---

Run the full pre-PR gate on the current change. The principle: **show output,
never claim success** — every step's result is pasted evidence, not an
assertion.

1. **Verification commands.** Read `CLAUDE.md` for the project's test / lint /
   typecheck / build commands and run them all. Show the output of each. Any
   failure stops the gate: report it and fix (or ask) before continuing.

2. **Fresh-context review.** Launch one `bug-hunter` subagent on the diff
   against the merge-base with the default branch. (If this change is high
   risk per `docs/RISK_TIERS.md` — or touches a sensitive path in `REVIEW.md` —
   run the full `/review-deep` flow instead.)

3. **Security pass.** Launch one `security-reviewer` subagent on the same diff,
   in parallel with step 2.

4. **Value-check, then resolve findings.** Before fixing anything, evaluate
   each finding: value (impact × likelihood in real use) must clearly exceed
   cost (fix effort + complexity added). Findings that fail this test are
   recorded as `Not worth fixing — <one-line reason>` instead of fixed; a fix
   that would be over-engineering (speculative generality, guards for
   unreachable states, abstraction for one caller) is itself a reason not to
   fix. For each finding that passes: apply the **smallest fix that removes
   the failure**, or record a one-line reason why it is a false positive or
   intentional. Re-run the relevant checks after fixes. Security `BLOCK`
   means the PR does not open until resolved.

5. **Draft the PR description** using the repo's PR template: What & why,
   **Testing** (the actual commands and results from step 1), **Risk** (tier
   per `docs/RISK_TIERS.md`, blast radius, sensitive paths touched), and
   **How to revert** (one step if possible). Present it for the user to sign
   off — the person who requested the change owns these sections.

6. **Verdict.** End with one of:
   - `PRE-PR: PASS` — checks green, 0 open Important findings, security PASS
   - `PRE-PR: FAIL — <what remains>`

Do not open or push the PR yourself unless the user asks.
