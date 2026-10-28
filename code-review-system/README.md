# Code Review System for Claude Code

A drop-in review system based on how the Claude Code team reviews code at Anthropic
(claude.dev blog, "How the Claude Code Team Does Code Review", Oct 2026).

## The core idea

Stop optimizing for "a human read every line." Optimize for **the minimum human review
time that doesn't increase reverts or incidents**. The question for every change is not
"did a human read it?" but **"what could go wrong with this change, and which check —
automated or human — should catch it?"**

Review runs as layers, continuously (like spellcheck), not as a single gate at the end:

1. **Verify before the PR exists** — the agent runs tests/build/lint and shows output;
   a fresh-context subagent reviews the diff before you open the PR.
2. **Repo instruction files** — `CLAUDE.md` (conventions) and `REVIEW.md` (what failure
   looks like here) feed every review. Repeated review comments get moved into them.
3. **AI review on every PR** — parallel bug hunters, a verifier vote, findings tagged
   Important / Nit / Pre-existing. Every finding is fixed or resolved with a reason.
4. **Security review that can block** — no merge while an open security finding remains.
5. **Required CI** — lint, types, tests, build. Red blocks merge.
6. **Risk-based human approval** — the *change* sets the tier, not the author.
7. **Merge queue, flags, staged release** — make mistakes fast to undo.
8. **Feedback loop** — incidents become evals; noisy findings tune `REVIEW.md`.

## What's in this folder

```
code-review-system/
├── README.md                     ← you are here
├── docs/
│   └── RISK_TIERS.md             ← risk-tier policy (edit per project)
├── templates/
│   ├── REVIEW.md                 ← reviewer instructions template (edit per repo)
│   ├── CLAUDE.md.snippet         ← review section to add to each project's CLAUDE.md
│   └── pull_request_template.md  ← Testing / Risk / How to revert
├── claude/                       ← copy contents into each project's .claude/
│   ├── commands/
│   │   ├── pre-pr.md             ← /pre-pr : full pre-PR gate
│   │   └── review-deep.md        ← /review-deep : parallel bug hunt + verifier vote
│   └── agents/
│       ├── bug-hunter.md
│       ├── review-verifier.md
│       └── security-reviewer.md
└── github/
    └── workflows/
        └── claude-review.yml     ← AI review on every PR (GitHub Action)
```

## Install into a project

1. Copy `claude/commands/*` and `claude/agents/*` into the project's `.claude/commands/`
   and `.claude/agents/`.
2. Copy `templates/REVIEW.md` to the repo root and **edit it** — describe what failure
   looks like in *this* repo, list paths to skip, cap nits.
3. Append `templates/CLAUDE.md.snippet` to the project's `CLAUDE.md` (keep CLAUDE.md
   short; link out rather than inline).
4. Copy `templates/pull_request_template.md` to `.github/pull_request_template.md`.
5. Copy `github/workflows/claude-review.yml` to `.github/workflows/` and add the
   `ANTHROPIC_API_KEY` secret (or use the Claude GitHub App). Start with **one repo**,
   tune `REVIEW.md` for a few weeks, then expand.
6. Define your risk tiers in `docs/RISK_TIERS.md`, then enforce the human-approval part
   with `CODEOWNERS` + branch protection (auth, billing, CI workflows, release/installer
   paths always need a person).

## Daily workflow

- While coding: Claude Code's built-in `/code-review` and `/security-review` run locally
  at any time; `/review-deep` for high-stakes diffs.
- Before opening a PR: run `/pre-pr`. It only passes when checks are green and the
  review comes back clean or every finding is addressed.
- On the PR: the GitHub workflow posts findings as inline comments. Fix each one or
  resolve it with a short reason. Never merge with an open security finding.
- Approval: look up the change's tier in `docs/RISK_TIERS.md`. An agent's approval never
  counts as a human's; the person who prompted the agent counts as a required reviewer.
- After merge: if something reverts or breaks, add the failing case to your eval set and
  ask which layer should have caught it — then fix the layer (REVIEW.md, a lint rule, a
  test), not just the bug.

## Keeping the reviewer sharp (the feedback loop)

- **Repeated findings → fix at the source.** If the reviewer keeps flagging the same
  thing, add it to `REVIEW.md`, a lint rule, or a hook — don't keep paying for it.
- **Incidents → evals.** Keep a folder of past bad PRs/diffs; re-run your review command
  against them when you change prompts or models. If the score drops, drop the change.
- **Cap rounds.** After three review rounds, reconsider the approach instead of patching.
  Re-review only the new diff after the first full pass. No repeat findings.
- **Measure noise by behavior.** For each finding note: fixed / wrong / intentional /
  didn't matter. Prune whatever generates "wrong" and "didn't matter."

## Metrics to watch

- Human approvals per PR (median, p95) and time a PR waits on a person — push down.
- Revert and incident rates — the guardrail. If they rise, you moved human time,
  you didn't save it.
- Target: most PRs merge with at most one human in the loop.
