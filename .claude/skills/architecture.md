# Architecture

**Secure Harness AI** is a security control plane for production AI agents. It enforces security boundaries around every agent turn, governs tool calls through a pre-gate + seven-layer stack, and emits a tamper-evident audit trail on every decision.

---

## System overview

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
                                            ▲
                              MCP Governance runs at connection time (tools/list)

shai mcp onboard <manifest> ──► signed baseline store ──► checked on every check_tool_call
        (operator-run, offline)      (harness.mcp.baseline)      for that MCP source (harness.mcp.gate)
```

One `SHAI` instance per deployment. Multiple agents and concurrent turns share the same instance safely.

---

## Repository layout

```
src/harness/
├── __init__.py                        public exports: SHAI, Tool, AgentContext, verdicts
├── core/
│   ├── harness.py                     SHAI facade — the only public entry point
│   ├── context.py                     AgentContext (identity envelope)
│   ├── verdicts.py                    GateDecision, ScanVerdict
│   ├── events.py                      AuditEvent, NetworkAuditEvent
│   ├── types.py                       enums: BoundaryName, Decision, Severity, Transport
│   ├── normalize.py                   NFKC + obfuscation-resistant text views
│   ├── turn_signals.py                TurnSignals — cross-boundary signal bus, one per turn
│   ├── attestation.py                 startup attestation payload (SYSTEM/STARTUP event)
│   ├── approval.py                    ApprovalGrant — signed human authorisation (L3)
│   ├── signing.py                     signed-envelope format shared by grants and tokens
│   └── errors.py                      HarnessError hierarchy
├── boundaries/
│   ├── check_tool_call.py             seven-layer tool gate (L1–L7)
│   ├── argument_policy.py             deterministic argument-level checks (L2)
│   ├── session_budget.py              DoS budget enforcer (R2): step, fan-out, loop
│   ├── session_accumulator.py         cross-turn threat accumulator — crescendo attacks
│   ├── ensemble.py                    cross-method severity promotion, always on
│   └── _scan.py                       scan_input, scan_output, scan_tool_result, scan_file
├── adapters/
│   ├── scanners/
│   │   ├── injection_scan.py          InjectionScanner — YAML catalog, direct + doc-tuned
│   │   ├── jailbreak_scan.py          JailbreakScanner — guardrail-integrity classifier
│   │   ├── identity_spoof_scan.py     IdentitySpoofScanner — claimed privileged identity
│   │   ├── heuristic_scan.py          HeuristicScanner — structural anomaly, always on
│   │   ├── regex_pii.py               RegexPIIScanner — PII + secret categories
│   │   ├── file_scanner.py            FileScanner + FileContentScanner — structural, then content chain
│   │   ├── mcp_metadata_scanner.py    MCPMetadataScanner — tool description injection
│   │   ├── prompt_defense_scanner.py  PromptDefenseScanner — absence-of-defense (onboarding only)
│   │   ├── rate_limiter.py            RateLimiter — sliding-window (R1)
│   │   ├── rule_functions.py          shared rule helpers for the YAML catalogs
│   │   └── base.py                    Scanner Protocol
│   ├── audit_sinks/                   stdout, rotating file
│   ├── secrets/                       EnvVarProvider
├── agents/
│   ├── agent_config.py                AgentConfig, SubAgentConfig, RuleConfig
│   └── registry.py                    AgentRegistry
├── audit/
│   └── emitter.py                     AuditEmitter + HMAC signing
├── config/
│   ├── schema.py                      HarnessConfig, all sub-configs including ExecutionBudgetConfig
│   └── loader.py                      YAML loader + secret resolution
├── patterns/
│   ├── store.py                       signed pattern DB — SQLite + HMAC-SHA256 per row
│   └── fingerprint.py                 structural fingerprint / skeleton for candidates
├── policy/
│   ├── engine.py                      PolicyEngine Protocol + RuleBasedPolicy
│   └── rules.py                       rule evaluation
├── tools/
│   ├── registry.py                    ToolRegistry
│   ├── source.py                      LocalSource, MCPSource, SourceRegistry
│   └── tool.py                        Tool dataclass
├── connectivity/
│   ├── config.py                      ConnectivityConfig
│   ├── token.py                       DispatchToken (HMAC-signed)
│   └── transport.py                   ShaiTransport (httpx)
├── mcp/                                MCP manifest onboarding — see below
│   ├── manifest.py                    MCPManifest schema, loader, SHA-256 hashing
│   ├── baseline.py                    signed local store of approved manifest hashes
│   ├── discovery.py                   resolves `sources:` MCP entries to manifests, builds a live MCPSource per approved one
│   ├── gate.py                        per-tool-call approval check (McpBaselineGate)
│   ├── onboard.py                     `shai mcp onboard` orchestration
│   ├── reconciliation.py              manifest-vs-live tool comparison
│   ├── readiness.py                   operational-readiness heuristic (informational)
│   └── posture.py                     protocol posture facts (informational)
└── integrations/                      LangGraph, LangChain, Anthropic SDK, CrewAI, PydanticAI, OpenAI Agents
```

`config/mcp/` (outside the package, alongside `harness.yaml`) holds operator-authored
manifest files — data only, not code. There is no bundled/package manifest set;
`config/mcp/` ships only example/starter files.

---

## Tool Governance — `check_tool_call`

The mandatory gate. Cannot be disabled. Pre-gate controls (revocation, rate limit, session budget, MCP manifest approval) run before the seven gate layers. First denial wins. Exactly one `AuditEvent` per call on every code path.

### Execution order

```
R0: Revocation        — kill switch, before any state is consumed
R1: Rate limiter      — sliding-window token bucket (RateLimiter)
R2: Session budget    — step counter, fan-out, loop detection (SessionBudget)
    Pre-gate          — agent registered?
R3: MCP manifest approval — McpBaselineGate, MCP-sourced tools only
L1: allowed_tool_names hard gate
L2: argument rules — max_value / min_value / allowlist / pattern / required
L3: irreversibility gate — SENSITIVE / IRREVERSIBLE need a quorum of distinct
    approvers from signed, bound ApprovalGrants on ctx.approvals
L4: allowed_tags capability gate (the agent's own, narrowed by subagent)
L5: policy rules (manifest denials → subagent → parent)
L6: signal correlation — reads TurnSignals from earlier boundaries
L7: arg scanning (sensitive-tagged tools, or unconditionally when L6 tightened)
```

### Session Budget — `boundaries/session_budget.py`

`SessionBudget` is a thread-safe, per-session enforcer for DoS / Unbounded Consumption (OWASP T4). One instance per SHAI facade, keyed by `(agent_id, session_id)` where `session_id` is `ctx.conversation_id or ctx.agent_id`. All controls are opt-in via `None` defaults.

Every control counts something SHAI observes at its own boundary.

| Control | Trigger |
|---|---|
| **Step counter** | `state.steps >= max_steps` — blocks before the call is recorded |
| **Per-prompt fan-out** | `state.prompt_calls >= max_tool_calls_per_prompt` — resets when `prompt_id` changes, which the facade sources from `TurnSignals.turn_id` |
| **Loop detection** | Jaccard similarity ≥ `loop_similarity_threshold` against last `loop_detection_window` fingerprints |

Fingerprints are `frozenset` of `"key=value"` strings (values truncated at 128 chars). `loop_detection_window=0` (default) disables loop detection.

Config lives in `harness.yaml` under `check_tool_call.execution_budget:`. Per-agent overrides in `agent-xx.yaml` under `limits:` are merged on top of global defaults at `load_agent()` time. An invalid `limits:` block is rejected while parsing `agent-xx.yaml`, so `load_agent()` raises `ConfigError` before anything is registered and `reload_agent()` leaves the previous definition intact. Loading is therefore atomic: the harness never holds an agent whose budget could not be built, which would otherwise be gated with no budget at all. Falling back to global defaults is deliberately not an option — it would discard the agent's valid limits along with the bad key.

Budget state is cleaned up in `deregister_agent()` via `session_budget.reset(agent_id)`.

---

## Scan boundaries

### Ingress Scan — `scan_input`, `scan_file`

Runs before the LLM. Scanners run concurrently via `asyncio.gather`. Per-scanner exceptions produce empty findings — pipeline never raises. Disable-able; emits `disabled=True` event when off.

**Scanners:** `InjectionScanner` (common + input rules; files also add the
document overlay) · `RegexPIIScanner` (7 categories) · `FileScanner` (size
gate, MIME, macros, extracted text scan)

### Tool Stream Control — `scan_tool_result`

Runs before tool results re-enter the LLM context. Configured injection
scanners use the common and input catalogs; the example config also runs
`identity_spoof_scan` and `jailbreak_scan` here, since a retrieved document
telling the model to discard its instructions is an indirect injection rather
than a user jailbreak. Disabled by default. Closes the ClawJacked-style
indirect injection vector.

### Egress Scan — `scan_output`

Mirrors ingress. Catches PII leakage and data exfiltration in the LLM's final response.

### MCP Governance — `scan_mcp_metadata`

Runs at MCP connection time before any tool is registered. Scans tool names, descriptions, and argument schemas. `block_at: medium` default — metadata injection has a near-zero false-positive rate.

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
the fields every source already has, like `tags`/`required`) — no url,
credentials, or allow-lists on the `sources:` entry. Everything else comes
from the manifest, resolved **by convention**: `<mcp_manifests_dir>/<name>.yaml`
(see `harness.mcp.manifest`). `mcp_manifests_dir` is no longer scanned; it is
only the base directory a declared name resolves against. A manifest file
sitting in that directory with no matching `sources:` entry is invisible to
the harness. A `transport: mcp` entry with no manifest at the conventional
path is a load error, honouring that entry's `required` flag — not a silent
skip.

**Resolution** (`harness.mcp.discovery`, run once per `SHAI.from_yaml()`):
for each `sources:` entry with `transport: mcp`, resolve its manifest path,
parse it, hash it, and look up the hash in the signed baseline store
(`harness.mcp.baseline`, HMAC-SHA256, its own secret — `mcp_baseline.secret`,
not `patterns_db.secret` or `audit_signing.secret`). A live `MCPSource` is
built **only** for a name whose current hash matches an approved baseline
record. An unapproved or hash-mismatched name is not built as a source at
all — no stub, no "pending approval" object of any kind. An agent that
declares a source name the harness didn't build gets the same "source not
registered" handling any other missing source gets, honouring that source's
`required` flag. Tool registration content — name, description, tags — comes
from the manifest, never the live `tools/list` response
(`MCPSource._fetch_tools`).

**Approval gate** (`harness.mcp.gate.McpBaselineGate`): re-checked on every
`check_tool_call` for a tool from an MCP source that *was* built, not just
once at startup — a R3 pre-gate check in the facade, after the
revocation/rate-limit/session-budget checks and before the seven-layer gate
runs. Each check re-hashes the manifest's raw bytes and re-looks it up in the
baseline store, behind a bounded per-source cache
(`mcp_baseline.cache_ttl_seconds`, default 5s — the same latency model
`RevocationConfig.cache_ttl_seconds` uses for the agent kill switch). A hash
that no longer matches denies every subsequent call against that source —
the same `tool_call_gate`/`deny` shape any other gate denial produces. This
is what catches a manifest edited after the harness already started: the
source was built with a valid hash at startup, the file changes underneath
it, and the next call denies without needing a restart. A manifest that was
never onboarded never reaches this check at all — no source was built for it
in the first place, so the "source not registered" path (or L1) denies it
first.

**Onboarding** (`shai mcp onboard <manifest> --config <harness.yaml>`,
`harness.mcp.onboard`): the only way a manifest's hash gets into the
baseline store. One run: parse/validate → connect live and fetch
`tools/list` (reachability + reconciliation input, never registration
content) → scan the manifest's own declared tool text with
`MCPMetadataScanner` and `PromptDefenseScanner` → reconcile against the live
response (`harness.mcp.reconciliation` — declared-but-absent is a soft
warning, present-but-undeclared is informational, a description mismatch
fails onboarding: the actual rug-pull signal, since a compromised server
can't swap in a different description without the comparison catching it)
→ aggregate into exactly one `AuditEvent(boundary=MCP_SOURCE_ONBOARDING)`,
decision against `scan_mcp_metadata.block_at` → on a clean pass, the
manifest's hash is auto-recorded into the baseline store — running the
command *is* the approval, no separate flag. `extra["readiness"]`
(`harness.mcp.readiness`) and `extra["protocol_posture"]`
(`harness.mcp.posture`) ride along as pure governance signal and never
participate in the pass/fail decision.

---

## Audit trail

Every boundary call emits exactly one `AuditEvent` to `AuditEmitter`, which fans out to all configured sinks. Emission is structural — boundary code cannot return without emitting.

**Invariants:**
- Exactly one event per boundary call, on every code path
- No raw text in any field (no user input, LLM output, args, or matched substrings)
- `disabled=True` → `decision=allow`, `finding_count=0`
- `tenant_id` stamped from config, never from the caller
- Events are optionally HMAC-SHA256 signed and tamper-evident
