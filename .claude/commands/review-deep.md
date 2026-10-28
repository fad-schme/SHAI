---
description: Deep review of the current diff - parallel bug hunters, then an independent verifier vote. Only agreed findings are reported. Use for high-stakes changes; use the built-in /code-review for everyday depth.
---

Run a deep, multi-agent review of the current change.

**Target:** `$ARGUMENTS` if given (a ref range like `main...HEAD`, a PR number,
or a path); otherwise the working tree diff against the merge-base with the
default branch (include staged, unstaged, and untracked files that belong to
the change).

**Steps:**

1. Collect the diff and a one-paragraph statement of the change's intent (from
   the PR description, recent commit messages, or conversation context). Note
   the total changed lines.

2. Launch **three `bug-hunter` subagents in parallel** (a single message with
   three Agent calls). Give each the same diff and intent, but a different
   emphasis:
   - Hunter A: logic and edge cases within the changed code
   - Hunter B: the change against the rest of the repo — callers, contracts,
     API/behavior compatibility
   - Hunter C: state, concurrency, error handling, and resource lifecycle
   For a small diff (< ~100 lines), two hunters are enough.

3. Merge their findings, de-duplicate (same file/line/claim = one finding),
   and drop anything that is style, diagnostic, or cleanup-only.

4. Launch **one `review-verifier` subagent** with the merged candidate list
   and the diff. (For a high-risk change, launch two verifiers in parallel and
   require agreement.)

5. Report only findings the verifier(s) CONFIRMED, plus PLAUSIBLE ones marked
   as uncertain. REJECTED findings are dropped silently — do not make the
   author disprove them.

6. **Value gate — before anything is recommended.** For each surviving finding,
   weigh it yourself (do not delegate this):
   - **Value**: how bad is the failure (impact) × how likely is it to be hit
     in real use (likelihood)?
   - **Cost**: effort to fix + complexity the fix adds to the codebase.
   Only recommend where **value clearly exceeds cost**. A finding whose fix is
   over-engineering — speculative generality, defenses for unreachable states,
   abstraction for a single caller, config for something that never varies —
   is reported as `[Not worth fixing]` with one line of reasoning, or dropped
   if trivial. When a fix is warranted, recommend the **smallest fix that
   removes the failure**, not the most thorough one; if a 2-line guard and a
   refactor both work, recommend the guard.

**Report format** (per REVIEW.md if present):
- First line: the count — "N findings: X Important, Y Nit, Z Pre-existing",
  or "0 findings — nothing needs fixing."
- Then each finding: `[tag] file:line — claim. Failure: scenario.
  (CONFIRMED|PLAUSIBLE) Fix: smallest change that removes it. Worth it: yes —
  value vs cost in one clause / no — why.`
- Do not fix anything unless the user then asks. Before applying any asked-for
  fix, restate its value-vs-cost call in one line; if the fix grew beyond what
  was recommended, stop and say so instead of fixing. Every Important finding
  must end up fixed or resolved with a written reason before the PR merges.
