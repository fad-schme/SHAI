# Risk tiers — human approval policy

The **change** sets the tier, not the author. Classify every PR by what it
touches and what could go wrong, then apply the matching approval requirement.
Start strict; loosen only with evidence (stable revert/incident rates).

| Tier | What it covers (EDIT per project) | Human approvals required |
|---|---|---|
| **Low** | Docs, copy, comments; internal-only tooling; additive changes behind a feature flag that is off | **0** — merges when automated review, security review, and CI are all green |
| **Medium** | Ordinary product/code changes; anything not Low or High | **1** person |
| **High** | Auth, billing/payments, data migrations, CI/release workflows, installers/updaters, crypto, anything in REVIEW.md's sensitive paths | **2** people |

## Hard rules (not tier-dependent)

- Any change to a CI workflow file (`.github/workflows/**`) needs at least one
  human, always.
- **An agent's approval never counts as a human's.** Bot/AI review comments are
  findings, not approvals.
- **The person who prompted the agent counts as a required reviewer** — the
  same as if they had typed the code. A solo developer prompting Claude is the
  one human in the loop for Medium changes; High changes need a second person.
- **Approvals cover one specific commit.** Any new commit after approval (an
  agent push, a hand-resolved merge) dismisses the approval — re-approve.
  (GitHub: enable "Dismiss stale pull request approvals".)
- Lighter paths (Low tier, single approval) are for **trusted authors** only —
  normally the owning team. External or new contributors get one tier stricter.
- No PR merges with an open Important finding from the bug or security review.
  Resolve by fixing, or by closing the thread with a short written reason.

## Enforcement mapping (GitHub)

- Branch protection: require CI + review workflow green; require conversation
  resolution; dismiss stale approvals; require approvals per tier.
- `CODEOWNERS`: put High-tier paths under owners so those PRs always request
  the right humans. Example:

  ```
  /src/auth/              @your-handle
  /src/billing/           @your-handle
  /.github/workflows/     @your-handle
  /migrations/            @your-handle
  ```

## Review depth per tier

- Low → built-in `/code-review` (quick) in CI is enough.
- Medium → standard review on every PR.
- High → `/review-deep` (parallel hunters + verifier vote) and two humans.
  Deep review is worth it wherever one missed bug is expensive.
