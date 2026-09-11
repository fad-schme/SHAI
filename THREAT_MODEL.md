# SHAI Threat Model

This document is the honest coverage claim for SHAI. It maps threats to the
controls that mitigate them, the tests that demonstrate those controls, and —
critically — the residual risks each control does not close.

Read this **before** you deploy SHAI as the sole security layer for anything
that matters.

---

## What SHAI is

A **deterministic, auditable enforcement layer** placed between an agent and
its inputs, tools, and outputs. It runs in the same process as the agent
(no separate daemon, no network hop).


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
     │  model output cannot be trusted; SHAI evaluates what it   │
     │  proposes, not why                                        │
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
them, and (e) the residual risk the controls do **not** close.

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
invisible characters); and reassembly of fragmented text. The cross-turn threat
accumulator detects escalation spread across several turns.

**Tests:** `tests/unit/test_jailbreak_scan.py`, `tests/unit/test_identity_spoof_scan.py`,
`tests/unit/test_heuristic_candidates.py`, `tests/integration/test_normalization_pipeline.py`,
`tests/unit/test_scan_tool_result.py`, `tests/integration/test_file_scan_content_chain.py`,
`tests/unit/test_session_accumulator.py`.

**Residual risk:** catalogs and heuristics are readable and can be studied;
novel or purely semantic phrasings may pass.

---

### ASI02 — Tool Misuse and Exploitation

**Threat:** an agent applies legitimate tools in unsafe ways — deleting data,
exfiltrating information, chaining calls into unintended actions.

**Coverage:** Full.

**SHAI control:** an agent can do only what the operator's config allows, and
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
decides what each agent may do; SHAI enforces that decision with no path
around it.

**Tests:** `tests/unit/test_boundaries_check_tool_call.py`, `tests/unit/test_argument_policy.py`,
`tests/contracts/test_policy_contract.py`, `tests/unit/test_turn_signals.py`,
`tests/unit/test_rate_limiter.py`, `tests/unit/test_session_budget.py`.

**Residual risk:** what the config allows is the operator's policy decision.
`scope_policy` compares canonical host strings and never resolves DNS, so an
in-scope hostname that resolves to a private address is not caught; and
hostnames are IDNA2003-encoded, which maps some compatibility characters
(e.g. `ß`) differently from the UTS46 processing real resolvers use.

---

### ASI03 — Identity & Privilege Abuse

**Threat:** access escalated through delegation chains, inherited roles, or the
credentials an agent carries.

**Coverage:** Partial.

**SHAI control:** a subagent's `allowed_tool_names` and `allowed_tags` must be
subsets of its parent's, enforced at `load_agent()`. Subagent contexts carry
the narrowed `allowed_tags` set at `scope_context_for_subagent()`; layer 4
intersects `tool.tags` with them on every call, and layer 5 intersects parent
and subagent policy rules. `check_tool_call` denies, with an audit event, any
call from an agent not loaded via `SHAI.load_agent()`. Credentials are
referenced as `secret://` URIs and resolved at load, never stored in config.

**Tests:** `tests/unit/test_agent_registry.py`,
`tests/unit/test_boundaries_check_tool_call.py::test_subagent_*`.

**Residual risk:** SHAI does not manage the downstream identities and
credentials a tool uses once it runs.

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
  that source, so an edited manifest can neither connect nor be served.
- Tool names, descriptions, and tags come from the manifest, never the live
  `tools/list`, and `scan_mcp_metadata` scans them for injected instructions.
- Pattern-DB rows are HMAC-SHA256 signed; `shai patterns apply` verifies every
  row before writing it, and rows with an invalid signature are skipped at
  load.
- `from_yaml()` emits a `system`/`startup` attestation event recording the
  component set the process wired: each scanner, sink, and policy adapter with
  the SHA256 of its defining source file, MCP manifest digests, the pattern-DB
  rule count and digest, the policy digest, and every declared source. This is
  a **record**, not a check — SHAI compares it against nothing. Its value is
  that a SIEM holding these events can answer "what was this process running
  when it made that decision", and can diff one startup against the next.
  `shai harness inspect` shows the same component set offline.

**Tests:** `tests/unit/test_mcp_baseline.py`, `tests/unit/test_mcp_metadata_scanner.py`,
`tests/unit/test_shai_transport.py`, `tests/integration/test_startup_attestation.py`.

**Residual risk:** approving a manifest is the operator's trust decision; an
approved manifest for a malicious server is trusted as approved.

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

**Residual risk:** SHAI is not a sandbox; code an allowed tool executes is
outside its reach.

---

### ASI06 — Memory & Context Poisoning

**Threat:** malicious or misleading data seeded into memory, RAG stores, or
shared context, corrupting later reasoning.

**Coverage:** Partial.

**SHAI control:** nothing reaches memory without crossing a SHAI boundary.
Everything the agent receives — user input, uploads, tool and retrieval
results — is scanned before the LLM ingests it, with the controls in ASI01.
Anything the agent then writes to memory is a tool call through
`check_tool_call`.

**Tests:** `tests/unit/test_scan_tool_result.py`, `tests/integration/test_end_to_end_turn.py`,
`tests/integration/test_file_scan_content_chain.py`.

**Residual risk:** poisoned content that carries no injection pattern — plain
false facts — is not detected.

---

### ASI07 — Insecure Inter-Agent Communication

**Threat:** messages between agents that are spoofed, tampered with, or
replayed.

**Coverage:** Out of scope. SHAI governs each agent's boundaries; securing the
channel between agents belongs to the transport.

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
agent at the pre-gate — in process or via `shai agent revoke` — without
stopping the others, persists across restarts, and takes effect within
`cache_ttl_seconds`. Every decision emits an audit event, so a cascade can be
traced.

**Tests:** `tests/unit/test_session_budget.py`,
`tests/integration/test_session_budget_wiring.py`, `tests/unit/test_rate_limiter.py`,
`tests/unit/test_revocation.py`, `tests/integration/test_agent_revocation.py`.

**Residual risk:** budgets and rate limits are held per SHAI instance, not
shared across instances.

---

### ASI09 — Human-Agent Trust Exploitation

**Threat:** agents exploiting human trust to steer decisions or win approval
for harmful actions.

**Coverage:** Out of scope. SHAI governs what the agent does, not the
judgement of the human it talks to.

---

### ASI10 — Rogue Agents

**Threat:** compromised or drifting agents acting outside their intended
function or authorized scope.

**Coverage:** Full.

**SHAI control:** a rogue agent is still bound by its config. `check_tool_call`
denies any call from an unregistered agent and gates every other call against
the operator's config (see ASI02). Revocation stops a registered agent's
actions (see ASI08). The consolidated turn-risk in `scan_output` blocks turns
where cross-boundary signals aggregate above `RISK_HIGH` even if no single
scanner blocked. The operator decides the scope; SHAI enforces it.

**Tests:** `tests/unit/test_agent_registry.py`, `tests/unit/test_revocation.py`,
`tests/integration/test_agent_revocation.py`, `tests/unit/test_turn_signals.py`.

**Residual risk:** what the config allows is the operator's policy decision.

---

### Cross-cutting — Data and audit leakage

**Threat:** sensitive content ends up in logs, audit events, or error messages.

**SHAI control:** the audit event schema **never** includes raw user text,
LLM output, matched substrings, or scanner input. Only `finding_count`,
`max_severity`, `boundary`, `decision`, `adapters`, and structured metadata.
Every event is HMAC-SHA256 signed with a single operator-supplied secret.
Redaction is applied to text before it leaves the scan boundary.

**Tests:** `tests/unit/test_core_events.py`, `tests/unit/test_audit_signing.py`,
`tests/unit/test_scan_tool_result.py`.

---

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not open a public issue.

---

*This document reflects the state of SHAI as of the current release. Threat
coverage evolves; this file is versioned in-tree and updated with every
release that changes coverage.*
