# CLAUDE.md

This file is the canonical guide for AI assistants (Claude Code and others)
working in the `harness` repository. Read it before making any change.

---

## 1. What this project is

`harness` is a Python SDK that owns the **control plane** around an agent's
LLM loop. The agent — written by the customer, in whatever framework they
prefer — owns the loop itself: when to call the LLM, when to dispatch tools,
when to stop. The harness governs the boundaries around that loop.

Three security boundaries, plus always-on structured audit:

| Boundary | Purpose | When called | Optional? |
|---|---|---|---|
| `scan_input` | Catch malicious or sensitive input before it reaches the LLM or memory | Once per turn, at the top | Disable-able |
| `check_tool_call` | Apply policy: is this tool allowed with these args in this context? | Per tool call, inside the agent's loop | No — mandatory |
| `scan_output` | Catch sensitive data leaking out | Once per turn, before response | Disable-able |
| Audit emission | Structured events from every boundary | Built into the three above | No — always on |

Plus two pre/post-turn operations that are not boundaries but are part of
the facade:

| Operation | Purpose | When called |
|---|---|---|
| `load_sources` | Activate policy-scoped tool sources for this agent/subagent turn | Once per turn, before the LLM call |
| `unload_sources` | Discard the turn's ScopedRegistryView | Once per turn, after the turn ends |

### What the harness is NOT

- **No LLM client.** The harness never imports an LLM SDK.
- **No agent loop.** Turn budgets belong to the customer's agent code.
- **No memory primitives.** Memory is UMA's job.
- **No response composition.** The agent assembles its own output.
- **No tool execution.** The harness gates; the agent dispatches.
- **No network-level enforcement.** The harness cannot see raw HTTP calls,
  subprocess output, or code execution that bypasses tool dispatch. That is
  the connectivity layer's job. See §3.9.
- **No bulk data ingestion.** Not a control-plane concern.

---

## 2. Open-core packaging

Three sibling distributions (a fourth, `harness-loop`, planned after core
is stable):

| Package | License | Contents |
|---|---|---|
| `harness` | Apache-2.0 (or BSL) | Core control plane: three boundaries, tool sources, agent registry, audit, all Protocols, reference adapters, framework integrations |
| `harness-enterprise` | Commercial | Production adapters: DLP, SIEM, enterprise policy, secrets, MCP gateways, central registries |
| `harness-cli` | Apache-2.0 | Developer tools: validate, policy test, audit replay, agent management |

Hard rules:

- `harness` may not import from `harness-enterprise`.
- `harness-enterprise` may not add public API visible to agent code.
- A customer using only `harness` must be able to run a realistic production
  agent. Reference adapters are not placeholders.
- Every adapter passes the same contract suite from `harness/tests/contracts/`.

---

## 3. Architecture

### 3.1 Public API surface

The facade is small and stable. Everything else is internal.

```python
from harness import Harness, Tool, ToolSource, RuntimeContext, AgentConfig

harness = Harness.from_yaml("harness.yaml")

# Agent management — explicit, manual, operator-driven
await harness.load_agent("agents/email_agent.yaml")    # AgentConfig
await harness.reload_agent("agents/email_agent.yaml")  # AgentConfig
await harness.deregister_agent("email_agent")          # None
await harness.list_agents()                            # list[AgentConfig]

# Startup: register local tools
await harness.register_tools([
    Tool("search_docs", schema=SearchDocsSchema, tags=["read", "internal"]),
    Tool("send_email",  schema=SendEmailSchema,  tags=["external_write", "sensitive"]),
])

# Per-turn — in order
tools   = await harness.load_sources(ctx)                  # list[Tool]
verdict = await harness.scan_input(text, ctx)              # ScanVerdict
gate    = await harness.check_tool_call(name, args, ctx)   # GateDecision
verdict = await harness.scan_output(text, ctx)             # ScanVerdict
await harness.unload_sources(ctx)                          # None

# Subagent — called by framework integrations, not manually by agent code
child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
```

Wire types:

- `ScanVerdict`: `blocked: bool`, `findings: list[Finding]`,
  `redacted_text: str | None`
- `GateDecision`: `allowed: bool`, `deny_reason: str | None`,
  `redacted_args: dict | None`
- `Finding`: `scanner: str`, `category: str`, `severity: Severity`,
  `span: tuple[int,int] | None`, `detail: str | None`
- `RuntimeContext`: `tenant_id: str`, `agent_id: str`,
  `sub_agent_id: str | None`, `user_id: str | None`,
  `session_id: str | None`
  — `user_id` and `session_id` are audit/logging fields only; the harness
  never uses them as keys or in policy evaluation.
- `Tool`: `name: str`, `schema: Any`, `tags: list[str]`,
  `transport: Literal["local","mcp","skill"]`, `description: str | None`

All boundary calls emit audit events as a side effect. All facade methods
are `async def`. `scope_context_for_subagent` is the only synchronous
method — it is a pure function with no I/O.

### 3.2 Boundary semantics

**`load_sources(ctx) -> list[Tool]`**
Not a security boundary — no audit event. Called once per turn before
the LLM call. Activates sources declared for the calling agent or
subagent, loads their tools into a `ScopedRegistryView`, stores the
view internally keyed on `(agent_id, sub_agent_id or "")`, and returns
the active tool list. MCP credentials are resolved at construction time
— this call is network-bound but credential-free from the agent's
perspective.

**`unload_sources(ctx) -> None`**
Drops the `ScopedRegistryView` for `(agent_id, sub_agent_id or "")`.
Must be called at turn end. No audit event. The internal
`WeakValueDictionary` provides a GC safety net if the agent forgets,
but explicit call is required.

**`scan_input(text, ctx) -> ScanVerdict`**
Runs configured input scanners, aggregates findings, emits one
`input_scan` audit event, returns a `ScanVerdict`. Disable-able — when
disabled, returns allow verdict and emits audit event marked
`disabled=true`.

**`check_tool_call(name, args, ctx) -> GateDecision`**
The mandatory core gate. Per call — four layers, strict order:

```
Layer 1a — agent/subagent registered?
    no → deny "agent not registered"

Layer 1b — tool.name in agent's allowed_tool_names?
    no → deny "tool not in agent tool list"

Layer 1c — tool.tags ⊆ ctx.allowed_tags?
    no → deny "tool not in agent capability set"

Layer 2 — subagent policy rules (if sub_agent_id set)
    ∩ parent agent policy rules
    ∩ global policy rules
    first deny in any layer wins → deny
    all allow → allow / redact

Layer 3 — optional arg scanning (tools tagged "sensitive")
    finding.severity >= high → deny

→ GateDecision + audit event
```

The agent dispatches with `gate.redacted_args or args` when allowed.
The harness never dispatches.

**`scan_output(text, ctx) -> ScanVerdict`**
Mirrors `scan_input` for LLM output. Disable-able. Emits one
`output_scan` audit event.

**`scope_context_for_subagent(ctx, sub_agent_id) -> RuntimeContext`**
Pure synchronous function — no audit event, no I/O. Looks up the
`SubAgentConfig` declared under `ctx.agent_id` in the `AgentRegistry`.
Returns a new `RuntimeContext` with:
- `agent_id` = parent's `agent_id` (unchanged — identifies the parent)
- `sub_agent_id` = the requested subagent id
- `allowed_tags` = subagent's declared `allowed_tags`
- `tenant_id`, `user_id`, `session_id` inherited from parent ctx

Raises `SubAgentNotDeclaredError` if `sub_agent_id` is not declared
under the parent agent. Called by framework integrations at the subagent
handoff point — not by agent code directly.

### 3.3 Agent and subagent model

#### Identity

```python
agent_id:     str        # mandatory — top-level agent
sub_agent_id: str | None # optional — if set, this is a subagent;
                          # its parent is agent_id
```

If `sub_agent_id` is None → top-level agent call.
If `sub_agent_id` is set → subagent call; parent is `agent_id`.
No third field. `user_id` and `session_id` are for audit only.

The effective identity for internal keying (view storage, source
activation) is always the pair `(agent_id, sub_agent_id or "")`.

#### One parent → many subagents. One subagent → one parent.

Subagents are declared inside the parent's `agent-xx.yaml`. A subagent
is only valid in the context of its declaring parent. Two different
parents may each declare a subagent called `"research_sub"` — no
conflict because the effective identity is always the pair.

#### `agent-xx.yaml` shape

```yaml
id: orchestrator_agent
display_name: "Orchestrator"
version: "1.0.0"

# Layer 1b — explicit tool allowlist (hard gate, principle of least privilege)
allowed_tool_names: ["search_docs", "send_email", "list_inbox"]

# Layer 1c — capability tags
allowed_tags: ["read", "internal", "external_write"]

# Sources this agent uses
sources: [docs_skill, outlook_mcp]

# Layer 2 — agent-scoped policy rules
policy_rules:
  - id: deny_external_write_untrusted
    match:
      tool_tags: ["external_write"]
      user_ids: []   # not a policy key — user_id is audit only
    action: deny
    reason: "external_write requires explicit approval"

# Per-agent observability
log_level: INFO
audit_tags:
  team: "platform"

# Subagents — declared here, valid only under this parent
sub_agents:
  - id: research_sub
    allowed_tool_names: ["search_docs"]   # strict subset — need-to-know
    allowed_tags: ["read", "internal"]    # strict subset of parent tags
    sources: [docs_skill]                 # independent — not required to
                                          # be subset of parent sources
    policy_rules:
      - id: read_only_enforce
        match:
          tool_tags: ["external_write"]
        action: deny
        reason: "research_sub is read-only"

  - id: email_sub
    allowed_tool_names: ["send_email", "list_inbox"]
    allowed_tags: ["read", "internal", "external_write"]
    sources: [outlook_mcp]
    policy_rules: []
```

#### Policy evaluation — intersection model

Effective permission = global rules ∩ parent agent rules ∩ subagent rules.

A first deny anywhere in the chain wins immediately. Restriction flows
downward only — a subagent can never broaden beyond what its parent and
global rules allow. Rules do not need to be re-declared at a higher
level; the intersection enforces the ceiling automatically.

For top-level agents (no `sub_agent_id`): global rules ∩ agent rules.
For subagents: global rules ∩ parent agent rules ∩ subagent rules.

#### Principle of least privilege

Every agent and subagent declares only the tools it needs:
- `allowed_tool_names` — the exact set of tools, hard gate before policy
- `allowed_tags` — the capability envelope, hard gate before policy
- `sources` — only the sources this agent/subagent needs, independent
  per agent; not required to mirror parent

A subagent's `allowed_tool_names` must be a subset of the parent's
`allowed_tool_names`. Validated at `load_agent()` time.
A subagent's `allowed_tags` must be a subset of the parent's
`allowed_tags`. Validated at `load_agent()` time.

### 3.4 Tool sources and ScopedRegistryView

Sources are declared per agent and per subagent independently. A
subagent's sources are not required to be a subset of the parent's
sources — each declares only what it needs. The `allowed_tags`
capability gate is the enforcement mechanism.

**`load_sources` keying:**
The `ScopedRegistryView` is stored internally in a `WeakValueDictionary`
keyed on `(agent_id, sub_agent_id or "")`. This key is agent identity —
it has nothing to do with `user_id`, `session_id`, or `request_id`.
Those fields exist on `RuntimeContext` for audit purposes only and play
no role in source activation or view management.

**Transport kinds:**

| Transport | What it is | Credentials |
|---|---|---|
| `local` | Python functions registered at startup | none |
| `mcp` | Remote MCP server (Slack, Outlook, browser, etc.) | `secret://` ref, resolved at construction |
| `skill` | Named group of local tools, activated on demand | none |

**harness.yaml `tool_sources`:**

```yaml
tool_sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_MCP_TOKEN"
    tags: ["external_mcp", "messaging", "external_write"]

  - name: docs_skill
    transport: skill
    tools: ["search_docs", "fetch_doc"]
    tags: ["skill", "read", "internal"]
```

**Two policy evaluation points:**

1. `PolicyEngine.evaluate_source(source, ctx)` — which sources are
   active for this agent/subagent this turn. Runs inside `load_sources`.
   Uses `(agent_id, sub_agent_id)` to determine active agent profile.
2. `PolicyEngine.evaluate(tool, args, ctx)` — individual tool call gate.

Credentials resolved once at `Harness.from_yaml()`. `load()` is
async and network-bound but credential-free.

### 3.5 Adapter Protocols — all async

Six extension points, all `async def`, all discovered via entry points:

| Protocol | Responsibility | Reference impl | Enterprise impl |
|---|---|---|---|
| `Scanner` | Inspect text, return findings | regex_pii, basic_injection | Purview, Nightfall, Lakera |
| `PolicyEngine` | Gate calls + activate sources | YAML rule evaluator | OPA, Cedar |
| `AuditSink` | Accept `AuditEvent` | stdout JSONL, rotating file | Splunk, Sentinel, OTel |
| `ToolRegistry` | Store/lookup tools + scoped views | in-memory | Redis, central service |
| `ToolSource` | Load tools from a source | local, skill | MCP gateway adapters |
| `SecretsProvider` | Resolve `secret://` references | env vars | Vault, AWS KMS, GCP SM |

Entry-point groups:

```
harness.scanners
harness.policy
harness.audit_sinks
harness.tool_registry
harness.tool_sources
harness.secrets
```

All Protocol methods are `async def`. This is a one-pass decision —
do not add sync variants. Reference adapters that have no I/O
(regex_pii, rules evaluator, env secrets) implement `async def` methods
that return immediately. The async overhead is negligible; the
consistency is mandatory.

### 3.6 Audit pipeline

Every boundary call emits exactly one `AuditEvent`. `load_sources`,
`unload_sources`, and `scope_context_for_subagent` do not emit.

`AuditEvent` fields:

```
timestamp       boundary        decision        disabled
tenant_id       agent_id        sub_agent_id    user_id
session_id      adapters        tool_name       transport
finding_count   max_severity    deny_reason     duration_ms
extra           audit_tags      (from AgentConfig)
```

`user_id` and `session_id` on `AuditEvent` are populated from
`RuntimeContext` for audit trail correlation. They are never used by
the harness for any internal decision.

No raw text in any field. Redaction happens before emission.

### 3.7 Repository layout

```
src/harness/
├── __init__.py              public exports
├── core/                    facade, context, verdicts, events, errors, types
├── boundaries/              scan_input, check_tool_call, scan_output
├── agents/                  AgentConfig, SubAgentConfig, AgentRegistry
├── tools/                   Tool model, ToolRegistry Protocol + ScopedRegistryView
├── policy/                  PolicyEngine Protocol, PolicyDecision, rules evaluator
├── audit/                   AuditEmitter, AuditSink Protocol, redaction
├── adapters/                Protocols + reference impls + entry-point discovery
│   ├── scanners/            base.py, regex_pii.py, basic_injection.py
│   ├── audit_sinks/         stdout.py, file.py
│   ├── tool_registry/       memory.py (+ InMemoryRegistryView)
│   ├── tool_sources/        base.py (ToolSource + SourceRegistry), local.py, skill.py
│   └── secrets/             env.py
├── integrations/            framework wiring — calls scope_context_for_subagent
│   ├── anthropic_sdk.py     canonical hand-rolled reference
│   ├── langgraph.py
│   ├── langchain.py
│   ├── crewai.py
│   ├── pydantic_ai.py
│   └── openai_agents.py
└── config/                  harness.yaml loader, pydantic schema, resolution
```

### 3.8 Concurrency and agent isolation

One `Harness` instance serves multiple concurrent agents. Isolation is
structural:

- **Own `RuntimeContext`** — `(agent_id, sub_agent_id)` uniquely
  identifies each call stream. `user_id` and `session_id` are audit
  fields, not isolation keys.
- **Own `ScopedRegistryView`** — keyed on `(agent_id, sub_agent_id or
  "")`. Tools loaded for one agent are invisible to all others.
  Stored in `WeakValueDictionary` — GC safety net if `unload_sources`
  is not called.
- **Own audit trail** — every `AuditEvent` carries `agent_id` and
  `sub_agent_id`. Per-agent and per-subagent filtering is a query on
  the audit stream.
- **Own agent profile** — `AgentConfig` with `allowed_tool_names`,
  `allowed_tags`, `sources`, `policy_rules`, `log_level`, `audit_tags`.
- **Own source set** — `load_sources` activates only the sources
  declared for the calling agent or subagent.

`AgentRegistry.get()` is on the hot path. Internal dict reads are
GIL-safe in CPython. Writes (load, reload, deregister) hold a
`threading.Lock`.

All facade methods are `async def`. The async runtime is `asyncio`.
No `trio` or `anyio`.

See `docs/concurrency.md` for the full specification.

---

### 3.9 Connectivity layer and egress gateway

The connectivity layer sits below the harness and enforces at the network
and process boundary — the layer the harness cannot reach. It is a future
package; the interface is defined here so the harness is designed to
accommodate it from the start.

#### The bypass problem

The harness gates tool calls before dispatch. Once a call is allowed and
dispatched, the actual network traffic is outside the harness's visibility.
A tool — or code generated by the LLM and executed by a code-execution
tool — can make arbitrary outbound calls: raw HTTP, subprocess exec, direct
socket. The harness never sees these. The connectivity layer catches them.

#### Dispatch token — the interface

When `check_tool_call` returns `GateDecision(allowed=True)`, the harness
issues a signed **dispatch token**. This is the only interface between the
harness and the connectivity layer.

```
DispatchToken:
  agent_id:             str
  sub_agent_id:         str | None
  tool_name:            str
  allowed_destinations: list[str]   (URLs / hostnames this call may reach)
  issued_at:            datetime
  ttl_seconds:          int         (short — typically 5–30 seconds)
  signature:            str         (HMAC-SHA256, shared secret)
```

The token travels with the dispatched call. Every outbound connection —
from a registered tool, from generated code, from a subprocess — must
present a valid token at the egress gateway. No valid token means no
egress, regardless of how the call was constructed. This is what closes
the bypass gaps.

#### Connectivity layer components

Four enforcement domains, all operating on the same container that
the agent process runs in:

**Egress gateway** (dynamic, hot-reloadable)
The network-level enforcement point. Validates the dispatch token on every
outbound connection: HMAC signature, TTL, and destination against
`allowed_destinations`. Any call without a valid token is denied and logged.
Also enforces per-agent rate limits — the primary defense against
"delete all emails in a loop" patterns where each individual tool call is
allowed but the aggregate is not.

**L7 network policy** (dynamic, hot-reloadable)
HTTP method and path enforcement on actual wire traffic. Operates
independently of the dispatch token — an allowed token for Slack MCP does
not override an L7 rule denying POST to a specific path. Policies are
declarative YAML, hot-reloadable without container restart.

**Process isolation** (static, locked at container creation)
One container per agent. Separate filesystem namespace, seccomp syscall
filtering, no privilege escalation paths. The harness runs inside this
container; the container boundary is the outermost enforcement layer.

**Inference router** (dynamic, hot-reloadable)
Intercepts all LLM API calls. Strips the agent's credentials, injects
controlled backend credentials. Enforces which models an agent is allowed
to call. The agent never holds production LLM API keys directly. This is
where per-agent model routing is enforced — not in the harness, which has
no LLM client.

#### Audit correlation

The connectivity layer emits network-level audit events correlated by
`agent_id` and dispatch token. These feed the same SIEM as the harness
audit stream. The complete chain is:

```
harness AuditEvent  →  decision at control plane (what was allowed)
connectivity event  →  decision at network layer (what actually happened)
```

Cross-referencing both streams gives: policy permitted it, network executed
it, at this destination, at this time. Neither stream alone is sufficient
for a complete audit trail.

#### Policy domains

| Domain | Scope | Reloadable? |
|---|---|---|
| Filesystem | read/write paths | No — locked at creation |
| Process / seccomp | syscalls, privilege | No — locked at creation |
| Network egress | destinations, methods, paths | Yes — hot-reload |
| Inference routing | LLM backends, model allowlist | Yes — hot-reload |

Static domains require a container restart to change; dynamic domains
accept a policy update on a running container without interrupting the
agent.

#### What the harness provides to the connectivity layer

- Dispatch token (issued on every `GateDecision(allowed=True)`)
- `agent_id` and `sub_agent_id` for per-agent network policy scope
- `allowed_destinations` list derived from the tool's source config
  (MCP tool URLs are known at registration time)
- Shared HMAC secret (configured in `harness.yaml`, resolved via
  `SecretsProvider`, never in the dispatch token itself)

The connectivity layer has no dependency on the harness codebase. It
only needs the shared secret and the token format. This is intentional —
the connectivity layer can be implemented in any language (Rust, Go) while
the harness remains a Python SDK.


---

## 4. How to build this

### Phase 1 — Core types and facade

1. `core/types.py` — `BoundaryName`, `Decision`, `Severity`, `Transport`.
2. `core/context.py` — `RuntimeContext`: `tenant_id`, `agent_id`,
   `sub_agent_id`, `user_id`, `session_id`. Note: `user_id` and
   `session_id` are audit fields only — never used as keys.
3. `core/verdicts.py` — `ScanVerdict`, `GateDecision`, `Finding`.
4. `core/events.py` — `AuditEvent` with `agent_id`, `sub_agent_id`,
   `user_id`, `session_id` (audit fields).
5. `core/errors.py` — full error hierarchy including
   `SubAgentNotDeclaredError`.
6. `core/harness.py` — async facade shell. All methods `async def`
   except `scope_context_for_subagent`.
7. `config/schema.py`, `config/loader.py`, `config/resolution.py`.
8. `harness.yaml.example`.

### Phase 2 — Agent registry

9. `agents/agent_config.py` — `AgentConfig` and `SubAgentConfig`
   pydantic schemas. Validate at load time:
   - subagent `allowed_tool_names` ⊆ parent `allowed_tool_names`
   - subagent `allowed_tags` ⊆ parent `allowed_tags`
10. `agents/registry.py` — `AgentRegistry`: async load, reload,
    deregister, get, list. Threading lock on writes.
11. Wire agent management methods on facade.

### Phase 3 — Adapter discovery and reference implementations

12. `adapters/discovery.py`.
13. Reference adapters — all `async def`: `secrets/env.py` →
    `tool_registry/memory.py` (+ `InMemoryRegistryView`) →
    `audit_sinks/stdout.py` + `file.py` →
    `scanners/regex_pii.py` + `basic_injection.py` →
    `policy/rules.py` (intersection model, `evaluate_source`) →
    `tool_sources/local.py` + `skill.py`.
14. Register all in `pyproject.toml` entry points.

### Phase 4 — Tools and sources

15. `tools/tool.py` — `Tool` with `transport` field.
16. `tools/registry.py` — `ToolRegistry` Protocol + `ScopedRegistryView`.
17. `adapters/tool_sources/base.py` — `ToolSource` Protocol +
    `SourceRegistry`. Internal `WeakValueDictionary` keyed on
    `(agent_id, sub_agent_id or "")`.

### Phase 5 — Boundaries

18. `audit/` pipeline — async emitter, sink, redaction.
19. `boundaries/scan_input.py`, `boundaries/scan_output.py` — async.
20. `boundaries/check_tool_call.py` — four-layer async evaluation:
    - L1a: agent registered?
    - L1b: tool.name in allowed_tool_names?
    - L1c: tool.tags ⊆ allowed_tags?
    - L2: intersection of subagent rules ∩ parent rules ∩ global rules
    - L3: optional arg scanning
21. Wire all boundary methods on facade. Implement
    `scope_context_for_subagent` (sync, pure).
22. Implement `load_sources` / `unload_sources` with
    `WeakValueDictionary`.

### Phase 6 — Framework integrations

23. `integrations/anthropic_sdk.py` — canonical reference.
24. Remaining five integrations — each wires `check_tool_call` and
    calls `scope_context_for_subagent` at the framework's subagent
    handoff point.

### Phase 7 — Test surface

25. Unit tests alongside each module.
26. `tests/contracts/` — all async. Include concurrent-emit test.
27. `tests/integration/test_concurrent_agents.py`.

### Phase 8 — Sibling packages

`harness-enterprise`, `harness-cli` after core stable. `harness-loop`
after that.

---

## 5. Absolute design constraints for this repo

### Backward compatibility

New implementation, in dev. No older versions. Remove obsolete paths
rather than preserving them.

### Before making any change

- Inspect existing code, architecture, conventions, related files.
- Infer real intent from the codebase context.
- Search for existing helpers, utilities, abstractions that already
  solve part or all of the problem.
- Determine whether the requested behavior already exists.

### Mandatory execution stance

- Do not over-engineer.
- Simplify before extending.
- Prefer direct code over indirection.
- Converge duplicate concepts into one canonical path.
- Keep public surfaces small and sharp.
- Avoid parallel paths for the same behavior.
- Prefer extending canonical paths over creating alternate ones.

### Code style

- One responsibility per module.
- Explicit, direct code over cleverness.
- Lean, traceable end-to-end.
- No thin wrappers, pass-through helpers, or duplicated utility layers.
- No abstractions unless they remove real duplication or clarify a
  core contract.
- Logs only where they pay for themselves.

### When implementing

- Minimum new code needed.
- Prefer reuse over new duplicate logic.
- Never duplicate existing functionality.
- Preserve existing abstractions unless there is a clear reason to
  improve them.
- No speculative abstraction.

### Error handling

- Never swallow exceptions silently in core flows.
- Always log with context: `tenant_id`, `agent_id`, `sub_agent_id`,
  counts, operation name.
- Keep error handling close to where recovery is meaningful.
- No defensive catch-all logic that hides broken invariants.

### Comments and logging

- High-signal, durable comments. Explain invariants and contracts.
- No redundant comments that restate the code.
- Log state transitions, scope decisions, counts, failures.
- No large payloads or full prompts in logs.
- Consistent field naming across modules.

---

## 6. Repo-specific rules

### One canonical path per boundary

`scan_input`, `check_tool_call`, `scan_output` — one file each under
`boundaries/`. No parallel variants.

### The facade is the only public surface

`Harness`, `Tool`, `ToolSource`, `AgentConfig`, `RuntimeContext`,
`ScanVerdict`, `GateDecision`, `Finding` — the entire public API.
Nothing else exported from `harness/__init__.py`.

### All facade methods are async

Every method on `Harness` is `async def` except `scope_context_for_subagent`
which is a pure synchronous function. No sync variants. No mixed-mode.

### All Protocol methods are async

Every method on every adapter Protocol is `async def`. Reference
adapters with no I/O implement async methods that return immediately.
Consistency is mandatory.

### Agent identity is (agent_id, sub_agent_id)

`user_id` and `session_id` on `RuntimeContext` are audit fields only.
The harness never uses them as keys, in policy evaluation, in source
activation, or in view management. Any code that keys on `user_id` or
`session_id` internally is a bug.

### ScopedRegistryView is keyed on agent identity

`WeakValueDictionary` key is `(agent_id, sub_agent_id or "")`. Nothing
else. `load_sources` creates the view, `unload_sources` drops it.
No other code path creates or drops views.

### Subagents are declared inside their parent's agent-xx.yaml

A `sub_agent_id` that is not declared under the calling `agent_id` →
`SubAgentNotDeclaredError`. No dynamic subagent registration. The
operator declares all subagent types at agent load time.

### Subagent constraints are validated at load_agent() time

- subagent `allowed_tool_names` ⊆ parent `allowed_tool_names`
- subagent `allowed_tags` ⊆ parent `allowed_tags`
Never at runtime. A misconfigured agent file is a `ConfigError` at
load time, not a runtime deny.

### Subagent sources are independent

A subagent's `sources` list is not required to be a subset of the
parent's `sources`. Each declares only what it needs. `allowed_tags`
is the enforcement mechanism — a source whose tags exceed the
subagent's `allowed_tags` will be suppressed by policy at
`load_sources` time.

### Policy evaluation is intersection, not stacking

Global rules ∩ parent agent rules ∩ subagent rules. First deny wins.
Restriction flows downward only. No rule needs to be re-declared at a
higher level.

### allowed_tool_names is a hard pre-policy gate

Even if tags and policy allow a tool, if it is not in the agent's or
subagent's `allowed_tool_names`, deny at Layer 1b. This is the
principle of least privilege and need-to-know enforcement.

### No re-export base.py files

Protocols are defined in their canonical domain module. No one-line
re-export files in adapter subdirectories.

### Agent isolation is structural

Every agent and subagent: own `RuntimeContext`, own `ScopedRegistryView`,
own audit trail, own profile, own source set. Not configurable.

### Agent registry changes are explicit and operator-driven

No file watching. No automatic reload. All changes via facade or CLI.

### Configuration over code

All behavioral choices in `harness.yaml` (adapters, sinks, sources) or
`agent-xx.yaml` (tools, tags, rules, subagents). No constructor
arguments for things that belong in config.

### No silent disable

Disabled boundaries emit an audit event marked `disabled=true`.

### Audit emission is structural

Every boundary call emits exactly one `AuditEvent`. `load_sources`,
`unload_sources`, `scope_context_for_subagent` do not emit.

### Logging fields are consistent

- `tenant_id`, `agent_id`, `sub_agent_id` — from `RuntimeContext`
- `user_id`, `session_id` — from `RuntimeContext`, audit/log only
- `boundary` — `input_scan`, `tool_call_gate`, `output_scan`
- `decision` — `allow`, `deny`, `redact`, `blocked`
- `adapter` — adapter name from entry points
- `source_name` — tool source activation
- `finding_count`, `severity` — scan results
- `transport` — tool call gate
- `op` — non-boundary code paths

Do not invent variants. Grep must work.

---

## 7. Where to look first

- `docs/architecture.md` — full folder tree, per-file responsibilities.
- `docs/connectivity.md` — connectivity layer architecture, dispatch token,
  egress gateway, L7 policy, process isolation, inference router.
- `docs/concurrency.md` — isolation, scoped view, async model.
- `docs/boundaries.md` — per-boundary contracts.
- `docs/agents.md` — agent-xx.yaml schema, subagent model,
  three-layer evaluation, registry lifecycle.
- `docs/sources.md` — ToolSource lifecycle, MCP gateway, skills,
  policy activation, credential resolution.
- `docs/policy.md` — rule grammar, intersection model, evaluate_source.
- `docs/adapters.md` — writing a new adapter.
- `docs/audit-schema.md` — AuditEvent schema, field by field.
- `examples/hand_rolled_loop.py` — canonical reference.
- `harness.yaml.example` — canonical reference configuration.
