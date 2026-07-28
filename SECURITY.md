# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous minor | ✅ security fixes only |
| Older versions | ❌ |

---

## Reporting a Vulnerability

SHAI is a security project. Responsible disclosure of vulnerabilities is an
act of service to every team running agents in production, and we take it
seriously.

**Do not open a public GitHub issue to report a security vulnerability.**
Public disclosure before a fix is available puts every deployment at risk.

Report vulnerabilities by emailing **security@shai.aibestlabs.com**.

Please include:

- A clear description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (can be sent as an attachment)
- The component affected (`check_tool_call`, `scan_input`, `audit`, connectivity, etc.)
- The version(s) affected
- Whether you have a proposed fix or mitigation

---

## What to Expect

| Step | Timeline |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial triage and severity assessment | Within 5 business days |
| Fix or mitigation plan communicated to you | Within 14 days |
| Patch release | Coordinated with you, target 90 days |

We follow a **90-day coordinated disclosure** timeline by default. If a fix
requires more time due to complexity, we will communicate openly and agree on
an extension with you. If we fail to respond within the timelines above, you
are free to publish.

---

## Scope

We are particularly interested in vulnerabilities that affect the security
boundaries SHAI is designed to enforce:

- **Tool call gate bypass** — any path that allows a tool call to execute
  without passing through `check_tool_call`
- **Argument rule bypass** — a crafted argument that passes `ArgumentRule`
  evaluation when it should be denied
- **Irreversibility gate bypass** — a way to execute an `IRREVERSIBLE` or
  `SENSITIVE` tool without `human_approved=True`
- **Audit event suppression** — any boundary path that returns without
  emitting an `AuditEvent`
- **Audit event tampering** — forging or mutating signed audit events
- **Dispatch token forgery** — producing a valid `DispatchToken` without
  access to the signing secret
- **Scanner bypass** — crafted input that evades all scanners despite containing
  a detectable injection or PII pattern (including encoding bypasses)
- **Session budget bypass** — a method to exceed configured `max_steps`
  or `max_tool_calls_per_prompt` limits
- **Cross-tenant data exposure** — audit events, tool results, or session state
  leaking across agent or tenant boundaries

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream)
- Issues that require physical access to the host
- Social engineering attacks against maintainers
- Findings from automated scanners without a demonstrated impact

---

## Credit

We will credit you by name (or handle) in the release notes and CHANGELOG
unless you prefer to remain anonymous. If you discover a vulnerability that
affects a large number of deployments, we will coordinate with you on the
disclosure announcement.

---

## Safe Harbor

We will not pursue legal action against researchers who:

- Report vulnerabilities in good faith following this policy
- Avoid accessing, modifying, or deleting data beyond what is needed to
  demonstrate the vulnerability
- Do not disrupt service for other users
- Give us a reasonable opportunity to respond before publishing

Attempting to exploit a reported vulnerability against live deployments, or
using a disclosure threat to extract compensation, falls outside this safe
harbor.
