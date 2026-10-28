# shai-harness

Deterministic security control plane for AI agents (scan, gate, audit at five
enforcement boundaries). Python 3.11+, src layout: `src/harness` (SDK) and
`src/harness_cli` (CLI). Project rules live in `../AGENTS.md` and the shai-dev
skill — both apply in full; this file only adds verification and review wiring.

## Verification (run these, show output)

Never claim success without showing command output. Before considering any
change done, run:

- Tests: `pytest -q`
- Lint: `ruff check src tests`
- Security lint (when touching src): `bandit -q -r src/harness`

## Review

- Reviewer instructions live in [REVIEW.md](REVIEW.md) — follow them for every
  review.
- Before opening a PR, run `/pre-pr` (checks + fresh-context review + security
  pass). High-tier changes use `/review-deep`.
- Project-specific reviewer: any diff touching `src/harness/boundaries/`,
  `policy/`, `audit/`, `patterns/`, `core/`, signing, or agent loading also
  gets the shai-dev skill's `security-reviewer` (audits the seven structural
  invariants). `/pre-pr` runs it alongside the generic `security-diff-reviewer`.
- Every review finding is fixed or resolved with a written reason; never merge
  with an open security finding.
- Risk tiers and required human approvals: [docs/RISK_TIERS.md](docs/RISK_TIERS.md).
