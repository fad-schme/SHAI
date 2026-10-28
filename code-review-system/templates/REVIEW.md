# REVIEW.md — reviewer instructions for this repo

<!--
Written by code owners; loaded by every AI review of this repo.
Edit every section marked EDIT. Keep it short and concrete — this file is the
main lever for review quality. When the reviewer repeatedly flags the same
thing, or repeatedly flags something wrong, encode the correction here (or in
a lint rule) instead of re-litigating it on every PR.
-->

## What failure looks like here

<!-- EDIT: the one or two ways this codebase actually hurts users when it breaks.
Examples from the article: for docs, "it lies"; for config, "it misroutes".
For an API service it might be: "it returns wrong data with a 200", or
"it leaks one tenant's data to another". Name yours: -->

- [EDIT: primary failure mode, e.g. "silently returns stale/wrong results"]
- [EDIT: secondary failure mode, e.g. "breaks backward compatibility of the public API"]

Prioritize findings that could cause the failures above. Everything else is secondary.

## Scope

Skip these paths entirely (generated, vendored, or not worth review time):

- [EDIT: e.g. `dist/`, `*.lock`, `vendor/`, `**/__snapshots__/`, `docs/generated/`]

Sensitive paths — hold findings here to the highest bar and flag any change for
human review:

- [EDIT: e.g. `src/auth/`, `src/billing/`, `.github/workflows/`, `migrations/`]

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
3. **Cap nits at 3 per review.** If you have more, pick the 3 that matter.
4. **No style, diagnostic, or cleanup-only findings** presented as Important.
5. **No repeat findings** — if a finding was already raised and resolved with a
   reason in this PR, don't raise it again.
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

## Repo-specific checks

<!-- EDIT: the checks generic reviewers miss in this codebase. Examples: -->

- [EDIT: e.g. "every new config key needs a default in `config/defaults.ts` and
  a line in `docs/config.md`"]
- [EDIT: e.g. "DB access outside `src/db/` is a defect"]
- [EDIT: e.g. "user-facing strings must go through the i18n helper"]
