# Architecture

**Secure Harness AI** is a security control plane for AI agents. It enforces security boundaries around every agent turn, governs tool calls through a pre-gate and a seven-layer gate, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely.

---

## Tool Governance — `check_tool_call`

Pre-gate controls run first, in this order: agent revocation, rate limit, session budget, agent registration, MCP manifest approval. Then the seven gate layers: allowed tool names, argument rules and filesystem paths, irreversibility and approval, subagent tags, policy, signal correlation, argument scanning. First denial wins. Exactly one `AuditEvent` per call on every code path.

An allowed call is minted a signed dispatch token (see *Connectivity*). A failure to sign the token or build the allow event denies the call.

### Filesystem paths — gate layer 2

The operator grants each agent the files and directories it may read and write
(`allowed_paths` in `agent.yaml`); no grant means no filesystem access, and a
subagent's grant sits inside its parent's. A tool names its path arguments and
the access each needs (`path_args`, declared in code for a local tool and in the
manifest for an MCP tool), and a tool tagged `fs` must declare them. For each
declared argument, layer 2 resolves the value to its real location and denies it
inside the protected set or outside the agent's grant. The protected set is
SHAI's own files, derived from the harness config: audit sinks, pattern DB, MCP
baseline and manifests, revocation file, state stores, the config file and agent
definitions. No grant may overlap it. A local tool opens files with
`harness.fs.open`, which repeats the check at the moment of use. A denial
records `extra.fs_rule` and no path.

### Approval grants — gate layer 3

A `SENSITIVE` or `IRREVERSIBLE` tool runs only with signed `ApprovalGrant`s from
the required number of distinct approvers (`approvals.sensitive_quorum`,
`irreversible_quorum`). A grant is bound to one call and authorises it once: the
allow records the grant in `approvals.store`, shared by every process on that
backend, and a second call presenting it is denied. `approvals.secret` signs the
grants; without it every such tool is denied.

### Session Budget — `boundaries/session_budget.py`

`SessionBudget` enforces DoS / Unbounded Consumption (OWASP T4) per session, keyed by `(agent_id, session_id)` where `session_id` is `ctx.conversation_id or ctx.agent_id`. Its state lives in a `StateStore` (`session_budget.store`, default `memory`). A store failure follows `on_error` (default `fail_closed`) and denies the call. Controls are opt-in per agent.

| Control | Trigger |
|---|---|
| **Step counter** | `state.steps >= max_steps` — blocks before the call is recorded |
| **Per-prompt fan-out** | `state.prompt_calls >= max_tool_calls_per_prompt` — resets when `prompt_id` changes, which the facade sources from `TurnSignals.turn_id` |
| **Loop detection** | Jaccard similarity ≥ `loop_similarity_threshold` against last `loop_detection_window` fingerprints |

A call the gate then denies hands its step, fan-out slot and loop-window entry back.

---

## Connectivity — dispatch tokens and `ShaiTransport`

Every allowed call carries a short-lived HMAC-signed dispatch token
(`connectivity.token_secret`, `token_ttl_seconds`) bound to the tool, agent and
source, with a signed `purpose` of `connect` or `tool_call`.

- **MCP tools** run through `ShaiTransport`, which forwards a request only when
  its URL and method match both the source's manifest and the token
  (`allowed_urls`, `allowed_methods`), and the token's signature, binding and
  single use verify. Connect-phase requests carry a connect token minted from the
  source's onboarding approval, so a manifest edited since approval cannot
  connect. Each request emits a `NetworkAuditEvent` that joins the gate event on
  `token_id`.
- **Local tools** call `SHAI.verify_tool_dispatch(tool_name)` inside
  `dispatch_scope`; each check emits one `tool_dispatch_check` event.
- `connectivity.token_policy` decides a request with no token: `strict` (default)
  refuses it with a denied event, `audit` forwards it with an event carrying no
  `token_id`.

---

## Scan boundaries

Every scan boundary is always on. It runs the scanners its `scanners:` chain
names, plus the always-on `heuristic_scan`, over the normalised views of the
text. An omitted block runs SHAI's recommended chain for that boundary;
`scanners: []` runs the built-in backstop alone. Scanner failures follow
`on_error` (default `fail_closed`).

### Ingress Scan — `scan_input`

Runs on user text before the LLM. Default chain: `regex_pii`, `injection_scan`,
`jailbreak_scan`, `identity_spoof_scan`, `exec_config_scan`;
`command_injection_scan` with the `shell` extra.

### File Scan — `scan_file`

Runs on uploads. `FileScanner` checks structure (size, MIME, extension, PDF
markers, SVG, archives, macros, metadata); `FileContentScanner` runs the
`scan_file.scanners` chain over extracted text. Default chain: `injection_scan`,
`jailbreak_scan`, `regex_pii`, `exec_config_scan`.

### Tool Stream Control — `scan_tool_result`

Runs before tool results re-enter the LLM context. Default chain:
`injection_scan`, `identity_spoof_scan`, `jailbreak_scan`, `exec_config_scan`.
When the input scan flagged injection this turn, `block_at` steps down one level.
The call's `token_id` lands on the event, joining the result to its gate decision.

### Egress Scan — `scan_output`

Default chain: `regex_pii`. Catches PII leakage and data exfiltration in the
LLM's final response, then computes the consolidated turn risk from `TurnSignals`
and blocks the turn at `RISK_HIGH` (0.60) even when no single scanner blocked.
Clears `TurnSignals`.

### Argument scanning — gate layer 7

Tools tagged in `scan_args_for_tags` have their arguments scanned by
`check_tool_call.scanners` (default `exec_config_scan`).

### Cross-turn — threat accumulator

`ThreatAccumulator` scores escalation spread across a session's turns
(crescendo attacks). Disabled by default; `session.store` is required when
enabled, and `session.on_error` decides whether an unreachable store blocks the
turn (`fail_closed`, default) or continues to the scanners (`fail_open`).

### MCP Governance — `scan_mcp_metadata`

Runs at MCP connection time before any tool is registered. Scans tool names, descriptions, and argument schemas. `block_at: medium` is the default, stricter than other boundaries, because tool metadata describes a tool and instruction-like text in it is a strong injection signal.

---

## MCP manifest onboarding

An MCP source is **declared** under `sources:` in `harness.yaml`, the same
way a local source is — by name only:

```yaml
sources:
  - name: slack
    transport: mcp
```

`SourceConfig` accepts nothing MCP-specific beyond `name`/`transport` (plus
the fields every source already has, like `tags`/`required`). Everything else comes
from the manifest, resolved **by convention**: `<mcp_manifests_dir>/<name>.yaml`
(see `harness.mcp.manifest`). A manifest declares its tools, each tool's
`path_args`, and a required, non-empty `allowed_urls` list whose entries must
canonicalize; the manifest hash covers all of it.

**Onboarding** (`shai mcp onboard <manifest> --config <harness.yaml>`,
`harness.mcp.onboard`): the only way a manifest's hash gets into the baseline
store. It scans the manifest, runs `PromptDefenseScanner` over tool descriptions,
and reconciles the declared tools against the server's live `tools/list` — a
diverging description fails onboarding. One `mcp_source_onboarding` event is
emitted per run.

**Approval gate** (`harness.mcp.gate.McpBaselineGate`): a pre-gate check on every
`check_tool_call` for a tool from an MCP source. A source whose manifest is
unapproved or edited since approval denies every call, without a restart.

---

## Agents

An agent's `allowed_tool_names` and `allowed_tags` are subsets of its parent's,
and `allowed_paths` sit inside the parent's grant, all enforced at `load_agent()`.
Policy rules in an agent definition must not name `source_tags`; `load_agent()`
rejects them with the rule id. Optional non-human-identity fields (`owners`,
`sponsors`, `environment`, `review_due`, `delegation_mode`, `credential_refs`)
are stored with the definition and returned by `maintenance.registered_agents()`;
gating ignores them. `maintenance` can revoke an agent, which denies it at the
pre-gate.

---

## State stores

A `StateStore` adapter (`KVStore` + `LogStore`, with atomic `put_if_absent`)
holds shared, durable state. `sqlite` and `memory` adapters ship. It backs the
threat accumulator (`session.store`), the session budget (`session_budget.store`),
the signed pattern rule table (`patterns_db.store`) and approval-grant use
(`approvals.store`).

---

## Audit trail

Every boundary call emits exactly one `AuditEvent` to `AuditEmitter`, which fans out to all configured sinks. Emission is structural — boundary code cannot return without emitting. With `audit_signing.enabled`, each event carries an HMAC-SHA256 signature.

`SHAI.from_yaml()` emits one `system`/`startup` attestation event recording what the process wired: adapter identities and digests, MCP manifest digests, pattern-DB and policy digests, and the count and digest of the protected-path set. `shai harness inspect` and `shai harness graph` show the same topology offline.
