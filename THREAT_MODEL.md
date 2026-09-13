# SHAI Threat Model

This document is SHAI's coverage claim. It maps threats to the controls that
mitigate them, the tests that demonstrate those controls, and the limits of
each control.

---

## What SHAI is

A **deterministic, auditable enforcement layer** placed between an agent and
its inputs, tools, and outputs. It runs in the same process as the agent.


## Trust boundaries

```
     ┌─────────────────────────────────────────────────────────────┐
     │                  UNTRUSTED                                  │
     │  end-user input · MCP servers · fetched web pages · tool    │
     │  outputs · documents · API responses                        │
     └───────────┬─────────────────────────────────────┬───────────┘
                 │                                     │
                 ▼                                     ▼
     ┌───────────────────────────────────────────────────────────┐
     │                       TRUSTED (SHAI)                      │
     │  scan_input · check_tool_call · scan_tool_result ·        │
     │  scan_output · audit emitter · policy engine              │
     └───────────┬───────────────────────────────────────────────┘
                 │
                 ▼
     ┌───────────────────────────────────────────────────────────┐
     │                    SEMI-TRUSTED (LLM)                     │
     │  SHAI evaluates every proposal from the model before      │
     │  it takes effect                                          │
     └───────────────────────────────────────────────────────────┘
```

The LLM is treated as semi-trusted. Any output from the model — text,
tool-call proposals, arguments — is evaluated by deterministic code before
it produces an effect.

---

## Threat coverage — OWASP Top 10 for Agentic Applications (2026)

Each entry follows the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
numbering and gives (a) the threat as OWASP scopes it, (b) the coverage
rating, (c) the SHAI controls that answer it, (d) the tests that demonstrate
them, and (e) the limits of each control.

| Threat | Coverage |
|---|---|
| ASI01 Agent Goal Hijack | Partial |
| ASI02 Tool Misuse and Exploitation | Full |
| ASI03 Identity & Privilege Abuse | Partial |
| ASI04 Agentic Supply Chain Vulnerabilities | Partial |
| ASI05 Unexpected Code Execution | Limited |
| ASI06 Memory & Context Poisoning | Partial |
| ASI07 Insecure Inter-Agent Communication | Out of scope |
| ASI08 Cascading Failures | Partial |
| ASI09 Human-Agent Trust Exploitation | Out of scope |
| ASI10 Rogue Agents | Full |

### ASI01 — Agent Goal Hijack

**Threat:** attackers redirect an agent's goals or decisions through injected
instructions — in the user's message, an uploaded document, a tool output, or
external data.

**Coverage:** Partial.

**SHAI control:** every entry point is scanned before content reaches the LLM.
`scan_input`, `scan_file`, and `scan_tool_result` run the injection catalog
(`injection_common.yaml` + `injection_patterns.yaml`),
`jailbreak_patterns.yaml`, and `identity_spoof_patterns.yaml`, each merged with
its fr/es/de/zh variants, plus the heuristic scanner. `scan_file` also adds the
document-tuned catalog (`patterns_for_doc.yaml`). The normalisation pipeline
produces de-obfuscated views for the scanners to match against: substring
decoding (base64, base32, hex, ascii85, binary, unicode-escape,
percent-encoding, morse) and whole-string transforms (rot13, reversal),
recursing to `max_depth`; surface folding (NFKC, homoglyph mapping, removal of
invisible characters); and reassembly of fragmented text. Ensemble scoring
promotes a finding when independent methods agree. The cross-turn threat
accumulator detects escalation spread across several turns.

**Tests:** `tests/unit/test_jailbreak_scan.py`, `tests/unit/test_identity_spoof_scan.py`,
`tests/unit/test_heuristic_candidates.py`, `tests/integration/test_normalization_pipeline.py`,
`tests/unit/test_scan_tool_result.py`, `tests/integration/test_file_scan_content_chain.py`,
`tests/unit/test_session_accumulator.py`.

**Limits:** detection covers the catalog patterns and the heuristic signals;
the signed pattern DB extends the catalogs over time.

---

### ASI02 — Tool Misuse and Exploitation

**Threat:** an agent applies legitimate tools in unsafe ways — deleting data,
exfiltrating information, chaining calls into unintended actions.

**Coverage:** Full.

**SHAI control:** an agent does exactly what the operator's config allows, and
`check_tool_call` enforces it on every call — a 7-layer deterministic gate,
first deny wins: `allowed_tool_names` (L1), argument rules (L2),
irreversibility approvals (L3), capability tags (L4), policy intersection (L5),
cross-boundary signal correlation (L6), argument scanning (L7 — sensitive-tagged
tools, or any tool once L6 has tightened). Revocation, rate limits, and the
session budget run before the gate. Destination-typed arguments (webhook URLs,
fetch targets) can carry a `scope_policy` that canonicalises the value to the
host the network stack would dial — case, IDNA, trailing dot, userinfo, and
loose IPv4 forms (short, octal, decimal) — before matching it against the
allowlist. IP literals are admitted only through `allowed_cidrs`. The operator
decides what each agent may do; SHAI enforces that decision on every call.

Every allowed call carries a signed, single-use dispatch token bound to the
tool, agent and source. `ShaiTransport` checks it on every MCP request; a local
tool checks it with `verify_tool_dispatch` inside `dispatch_scope`, which
raises `DispatchRefused` on refusal. The gate, token check and
`scan_tool_result` events join on one `token_id`.

**Tests:** `tests/unit/test_boundaries_check_tool_call.py`, `tests/unit/test_argument_policy.py`,
`tests/contracts/test_policy_contract.py`, `tests/unit/test_turn_signals.py`,
`tests/unit/test_rate_limiter.py`, `tests/unit/test_session_budget.py`,
`tests/unit/test_dispatch_token.py`, `tests/unit/test_local_dispatch_check.py`.

**Limits:** the operator's config defines what each agent may do.
`scope_policy` matches the canonical hostname string and encodes hostnames with
IDNA2003.

---

### ASI03 — Identity & Privilege Abuse

**Threat:** access escalated through delegation chains, inherited roles, or the
credentials an agent carries.

**Coverage:** Partial.

**SHAI control:** a subagent's `allowed_tool_names` and `allowed_tags` must be
subsets of its parent's, enforced at `load_agent()`. Subagent contexts carry
the narrowed `allowed_tags` set at `scope_context_for_subagent()`; layer 4
intersects `tool.tags` with them on every call, and layer 5 intersects parent
and subagent policy rules. `check_tool_call` admits calls only from agents
loaded via `SHAI.load_agent()` and denies every other call with an audit event.
Credentials are referenced as `secret://` URIs and resolved at load from the
secrets provider.

**Tests:** `tests/unit/test_agent_registry.py`,
`tests/unit/test_boundaries_check_tool_call.py::test_subagent_*`.

---

### ASI04 — Agentic Supply Chain Vulnerabilities

**Threat:** third-party tools, MCP servers, tool descriptors, or update
channels that are malicious or tampered with.

**Coverage:** Partial.

**SHAI control:**
- An MCP source must be declared by name under `sources:` (`transport: mcp`);
  its manifest is resolved by convention from `mcp_manifests_dir`. A source is
  built only when the manifest's hash matches a signed, operator-approved
  baseline. The baseline is re-checked when the source connects — its connect
  tokens are minted from that approval — and on every `check_tool_call` for
  that source, so an edited manifest is refused at connect and at every call.
- Every MCP request passes through `ShaiTransport`. It checks the URL against
  the manifest's required `allowed_urls` and the token's, the method, and the
  token's signature, source, purpose (`connect` or `tool_call`) and nonce, and
  emits a `NetworkAuditEvent` per decision. `connectivity.token_policy: strict`
  (the default) refuses an untokened request.
- Tool names, descriptions, and tags come from the approved manifest, and
  `scan_mcp_metadata` scans them for injected instructions.
- Pattern-DB rows are HMAC-SHA256 signed; `shai patterns apply` verifies every
  row before writing it, and rows with an invalid signature are skipped at
  load.
- `from_yaml()` emits a `system`/`startup` attestation event recording the
  component set the process wired: each scanner, sink, and policy adapter with
  the SHA256 of its defining source file, MCP manifest digests, the pattern-DB
  rule count and digest, the policy digest, and every declared source. It is a
  record for SIEM correlation: a SIEM holding these events can answer "what was
  this process running when it made that decision", and can diff one startup
  against the next. `shai harness inspect` shows the same component set
  offline.

**Tests:** `tests/unit/test_mcp_baseline.py`, `tests/unit/test_mcp_metadata_scanner.py`,
`tests/unit/test_shai_transport.py`, `tests/integration/test_startup_attestation.py`.

**Limits:** the operator's baseline approval is the trust anchor for each MCP
source.

---

### ASI05 — Unexpected Code Execution

**Threat:** agent-generated or injected code and shell commands that execute on
the host.

**Coverage:** Limited.

**SHAI control:** `command_injection_scan` (`shell` extra) parses shell syntax
and flags dangerous compositions — a pipeline whose sink is an interpreter, a
redirect to `/dev/tcp`, a fetch composed with an exec — at any boundary,
including tool arguments at `check_tool_call`.

**Tests:** `tests/unit/test_command_injection_scan.py`.

---

### ASI06 — Memory & Context Poisoning

**Threat:** malicious or misleading data seeded into memory, RAG stores, or
shared context, corrupting later reasoning.

**Coverage:** Partial.

**SHAI control:** everything that reaches memory has crossed a SHAI boundary.
Everything the agent receives — user input, uploads, tool and retrieval
results — is scanned before the LLM ingests it, with the controls in ASI01.
Anything the agent then writes to memory is a tool call through
`check_tool_call`.

**Tests:** `tests/unit/test_scan_tool_result.py`, `tests/integration/test_end_to_end_turn.py`,
`tests/integration/test_file_scan_content_chain.py`.

**Limits:** detection covers injection patterns and heuristic signals in that
content.

---

### ASI07 — Insecure Inter-Agent Communication

**Threat:** messages between agents that are spoofed, tampered with, or
replayed.

**Coverage:** Out of scope.

---

### ASI08 — Cascading Failures

**Threat:** a single fault propagating across agents and workflows — rapid
fan-out, feedback loops, repeated identical actions.

**Coverage:** Partial.

**SHAI control:** scanner errors follow `on_error` (default `fail_closed`).
`SessionBudget` enforces `max_steps` and `max_tool_calls_per_prompt`, and loop
detection denies a call whose fingerprint is within
`loop_similarity_threshold` of the last `loop_detection_window` calls.
`RateLimiter` provides per-tool and per-window call caps. Revocation denies one
agent at the pre-gate — in process or via `shai agent revoke` — while the
others keep running, persists across restarts, and takes effect within
`cache_ttl_seconds`. Every decision emits an audit event, so a cascade can be
traced.

**Tests:** `tests/unit/test_session_budget.py`,
`tests/integration/test_session_budget_wiring.py`, `tests/unit/test_rate_limiter.py`,
`tests/unit/test_revocation.py`, `tests/integration/test_agent_revocation.py`.

**Limits:** budgets and rate limits are held per SHAI instance.

---

### ASI09 — Human-Agent Trust Exploitation

**Threat:** agents exploiting human trust to steer decisions or win approval
for harmful actions.

**Coverage:** Out of scope.

---

### ASI10 — Rogue Agents

**Threat:** compromised or drifting agents acting outside their intended
function or authorized scope.

**Coverage:** Full.

**SHAI control:** a rogue agent is still bound by its config. `check_tool_call`
admits calls only from registered agents and gates every call against the
operator's config (see ASI02). Revocation stops a registered agent's actions
(see ASI08). The consolidated turn-risk in `scan_output` blocks turns whose
combined cross-boundary signals reach `RISK_HIGH`. The operator decides the
scope; SHAI enforces it.

**Tests:** `tests/unit/test_agent_registry.py`, `tests/unit/test_revocation.py`,
`tests/integration/test_agent_revocation.py`, `tests/unit/test_turn_signals.py`.

**Limits:** the operator's config defines each agent's scope.

---

### Cross-cutting — Data and audit leakage

**Threat:** sensitive content ends up in logs, audit events, or error messages.

**SHAI control:** an audit event carries only `finding_count`, `max_severity`,
`boundary`, `decision`, `adapters`, and structured metadata. Every event is
HMAC-SHA256 signed with a single operator-supplied secret. Redaction is applied
to text before it leaves the scan boundary.

`audit_signing.secret` is one key per trail: events carry no key identifier and
`shai audit verify` takes one secret, so a key rotation starts a new audit file
and each retired key stays with the segment it signed. The file sink rotates at
`max_bytes` (default 100 MB) and keeps `backup_count` (default 10) rotated
files; archive rotated files to keep older records.

**Tests:** `tests/unit/test_core_events.py`, `tests/unit/test_audit_signing.py`,
`tests/unit/test_scan_tool_result.py`.

---

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md) and report privately.

---

*This document reflects the state of SHAI as of the current release. Threat
coverage evolves; this file is versioned in-tree and updated with every
release that changes coverage.*
