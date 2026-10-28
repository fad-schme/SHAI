# Risk tiers — human approval policy (shai-harness)

The **change** sets the tier, not the author. Classify every PR by what it
touches and what could go wrong, then apply the matching approval requirement.
Start strict; loosen only with evidence (stable revert/incident rates).

| Tier | What it covers in this repo | Human approvals required |
|---|---|---|
| **Low** | Docs (`docs/`, README, CHANGELOG), comments, examples; CLI output text in `src/harness_cli/` that touches no decision logic | **0** — merges when automated review, security review, and CI are all green |
| **Medium** | Everything not Low or High: adapters, connectors, integrations, CLI commands, tests, config plumbing | **1** person |
| **High** | `src/harness/boundaries/`, `src/harness/policy/`, `src/harness/audit/`, `src/harness/patterns/`, `src/harness/core/`, `eval/` scoring or assertion semantics, `.github/workflows/`, `publish.yml`, release/signing (`signatures/` tooling), dependency changes in `pyproject.toml` | **2** people (or 1 + explicit sign-off while the team is one person — see note) |

**Solo-maintainer note:** with one maintainer, the High tier can't get two
humans. The compensating controls: High changes always run `/review-deep` with
two verifiers, merge only from a PR (never direct to main), and sit at least
one day between open and merge so they are reviewed twice with fresh eyes.

## Hard rules (not tier-dependent)

- Any change to `.github/workflows/**` needs a human, always.
- **An agent's approval never counts as a human's.** AI review comments are
  findings, not approvals.
- **The person who prompted the agent counts as a required reviewer** — the
  same as if they had typed the code.
- **Approvals cover one specific commit.** Any new commit after approval
  dismisses it (GitHub: "Dismiss stale pull request approvals").
- No PR merges with an open Important finding from the bug or security
  review. Resolve by fixing, or by closing the thread with a short written
  reason.
- Eval semantics changes (`eval/`) additionally need the written contract
  justification required by AGENTS.md and REVIEW.md.

## Review depth per tier

- Low → built-in `/code-review` is enough.
- Medium → `/pre-pr` before opening; standard AI review on the PR.
- High → `/review-deep` with two verifiers, plus `/security-review`.
