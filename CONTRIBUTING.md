# Contributing to SHAI

**Feature proposals and bug reports are welcome and genuinely appreciated.**
**Code PRs are not being accepted at this stage.**

---

## Why

SHAI is a security library. Every merged line has to be understood well enough
to reason about its threat model — not just its behaviour. Reviewing external
code contributions at that bar takes time I do not currently have, and merging
code I cannot review carefully would be a disservice to everyone building on
SHAI. This will change as the project matures.

For now, the highest-leverage things you can do are:

- **Open a bug report.** A crisp reproduction is more valuable than a patch,
  because identifying the right fix is the hard part.
- **Propose a feature.** Open an issue describing what you need and why.
  Roadmap decisions are made based on these.
- **Share analysis in an existing thread.** Root-cause hypotheses, adjacent
  design considerations, and prior-art references genuinely help.
- **Test SHAI in your own agent stack** and tell me what broke.

Unsolicited pull requests will be closed without review. This is not a
statement about the quality of the contribution — it is a statement about
review capacity.

---

## Bug reports

Before filing, check that:

- You're on the latest release
- An existing issue does not already cover it
- If security-related, do **not** open a public issue — see
  [SECURITY.md](SECURITY.md)

Include:

- SHAI version (`pip show shai`)
- Python version and OS
- Minimal reproduction (a `harness.yaml` snippet + a short Python script beats
  a description every time)
- What you expected vs. what happened
- Any relevant audit-event output (redacted if needed)

---

## Feature proposals

Include:

- The problem the feature solves (not the solution first)
- Which boundary or subsystem it affects
- Whether it changes existing behaviour or adds new
- Any threat-model implications

---

## Community values

- **Be kind.** Written communication is hard — err on the side of generosity.
- **Assume good intent.** In both directions.
- **Say when something is unclear.** If you had to guess at how something
  works, that is a documentation bug worth filing.

We follow the [Contributor Covenant](https://www.contributor-covenant.org/).

---

## Invited contributions (rare, by explicit invitation only)

Occasionally I may invite a contributor to submit a PR — typically when we've
converged on an approach in an issue thread and the change is clearly scoped.
If that happens, here is how the workflow looks.

### Development workflow

SHAI is not published on PyPI during early access. Set up an invited
development checkout from source:

```bash
git clone https://github.com/fad-schme/SHAI.git
cd SHAI
pip install -e ".[dev]"
```

The editable install builds SHAI from the local checkout and installs the
development dependencies needed by the checks below. Requires Python 3.11+.

- Branch from `main` on a descriptive topic branch (`feat/xxx`, `fix/xxx`)
- Keep changes focused — unrelated fixes go in separate PRs
- All lint and test checks must pass locally before you push
- Each commit should compile and pass its tests

### Change contents

1. **Start with the issue.** Do not open a PR without a linked issue where
   the approach was agreed.
2. **Add or update tests.** A bug fix should include a test that fails before
   your change and passes after.
3. **Document behaviour.** If the change affects users, update the relevant
   file under `docs/` (and its counterpart in `.claude/skills/`), plus the
   `CHANGELOG.md`.
4. **Keep commits atomic.**

### Pull request

- Use the PR template: **What? Why? How?**
- Link to the issue where the approach was agreed
- Make sure the branch is up-to-date with `main`
- Mark **Ready for review** only when merge-able

### Review

1. A maintainer will be assigned as primary reviewer.
2. If the PR introduces scope not previously discussed, it may be closed.
3. Change requests are not personal — long-term maintainability wins over
   short-term completeness.
4. Once accepted, the PR is squash-merged.

---

## Contributor License Agreement

Invited contributors must sign the CLA:

1. Open your PR.
2. Paste this comment (or reply `recheck` if you've signed before):

   ```
   I have read the CLA Document and I hereby sign the CLA
   ```

3. The CLA-Assistant bot records your signature and marks the status check
   as passed.

---

## Security

Vulnerabilities: see [SECURITY.md](SECURITY.md). Do **not** open a public
issue. Report privately to **security@shai.aibestlabs.com**.

---

Thank you for reading this and for taking the time to make SHAI better.
