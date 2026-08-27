## Contributing

**External contributions are by invitation only.**

SHAI is a security library. Every merged line has to be understood well
enough to reason about its threat model — not just its behaviour. Reviewing
external code contributions at that bar costs more maintainer time than
implementing the fix directly. This will change as the project matures.

The team may invite an external contributor to submit a pull request when the
problem is well understood, the proposed approach aligns with the intended
solution, and the issue is high-impact and high-priority. Uninvited PRs are
closed without review.

Highest-leverage ways to help: open a bug report, propose a feature, or share
analysis in an existing issue thread. See `CONTRIBUTING.md` for the
bug-report and feature-proposal checklists.

### Development workflow (once invited)

- `git clone https://github.com/fad-schme/SHAI.git` and `pip install -e ".[dev]"` — Python 3.11+
- Branch from `main`, keep changes focused, all checks green before push
- Start with the issue; add tests; document behaviour; keep commits atomic
- PR template: What? Why? How? — link the issue, keep the branch current,
  mark Ready for review only when merge-able
- One maintainer reviews; undiscussed scope may get the PR closed; accepted
  PRs are squash-merged

### CLA

Paste on the PR (or reply `recheck` if already signed):

```text
I have read the CLA Document and I hereby sign the CLA
```

The CLA-Assistant bot records the signature and marks the status check.

### Security

Vulnerabilities go to **security@shai.aibestlabs.com**, not a public issue —
see `SECURITY.md`.
