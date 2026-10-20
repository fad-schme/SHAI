# Capabilities — Agents and Subagents

An agent is a named identity with a declared capability set, defined in one
`agent-xx.yaml` file per agent and loaded via
`await harness.load_agent("path/to/agent.yaml")`. Every boundary call
carries the returned `AgentContext`, which identifies which agent (and
optionally which subagent) is making the call.

---

## agent-xx.yaml schema

```yaml
id: orchestrator_agent          # snake_case: ^[a-z][a-z0-9_]*$, unique within harness
display_name: "Orchestrator"    # optional, human-readable
version: "1.0.0"                # optional

# Optional NHI profile: stored and returned by maintenance.registered_agents(),
# never enforced. Omit any or all.
description: "Triages inbound mail"
owners: [alice@example.com]
sponsors: [bob@example.com]
environment: production
review_due: 2026-12-01
delegation_mode: autonomous     # or on_behalf_of_user
credential_refs:                # names only, never secret values
  - name: outlook_token
    expires_at: 2027-01-15
    rotated_at: 2026-07-01

# Tools this agent may call — hard gate L1, cannot be overridden by policy
allowed_tool_names:
  - search_docs
  - send_email
  - list_inbox

# Capability gate L4 — every tool's tags must be a subset of this list.
# Applies to this agent, not only its subagents.
allowed_tags:
  - read
  - internal
  - external_write

# Filesystem paths this agent may read and write (absolute files or directories).
# A write entry also grants read. No block means no filesystem access.
allowed_paths:
  read:  [/srv/workspace, /srv/reference]
  write: [/srv/workspace/out]

# Tool source activation — names must match sources declared in harness.yaml
sources:
  - docs_local
  - outlook_mcp

# Agent-scoped policy rules (evaluated before global rules, first match wins)
policy_rules:
  - id: deny_external_write_default
    match:
      tool_tags: [external_write]
    action: deny
    reason: "external_write requires explicit permission"
  - id: allow_email_tools
    match:
      tool_names: [send_email, list_inbox]
    action: allow

log_level: INFO    # DEBUG | INFO | WARNING | ERROR

# Attached to every AuditEvent emitted during this agent's turns
audit_tags:
  team: platform
  env: prod

# Subagents — capabilities always ⊆ parent
sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]      # ⊆ parent allowed_tool_names
    allowed_tags: [read, internal]         # ⊆ parent allowed_tags
    allowed_paths:
      read: [/srv/reference]               # inside a parent entry of the same mode
    sources: [docs_local]
    policy_rules:
      - id: research_deny_write
        match:
          tool_tags: [external_write]
        action: deny
        reason: "research_sub is read-only"
```

---

## Cross-field invariants enforced at load_agent() time

These are validated when the YAML is parsed — not at gate time.

- `id` must match `^[a-z][a-z0-9_]*$`
- `allowed_tool_names` and `allowed_tags` must be non-empty
- Subagent `allowed_tool_names` ⊆ parent `allowed_tool_names`
- Subagent `allowed_tags` ⊆ parent `allowed_tags`
- `allowed_paths` entries must be absolute; a subagent's entries sit inside a
  parent entry of the same mode (a parent `write` entry also covers a subagent
  `read` entry)
- An `allowed_paths` entry that equals, contains or sits inside a protected SHAI
  path raises `ConfigError` at `load_agent()` / `reload_agent()`
- Subagent `id` values must be unique within the parent
- `deny` rules require a non-empty `reason`
- `redact` rules require a `redact` mapping
- `log_level` must be one of `DEBUG`, `INFO`, `WARNING`, `ERROR`

Violations raise `ConfigError` with the field path.

---

## `allowed_tool_names` — the hard gate (L1)

The most important field. Any tool not listed here is permanently denied —
policy rules cannot override this.

```python
# This always denies, regardless of policy:
gate = await harness.check_tool_call("delete_database", {}, ctx)
# gate.allowed = False — "delete_database" not in allowed_tool_names
```

A tool must be both in `allowed_tool_names` AND pass the policy rules to be
allowed. L1 runs before policy.

---

## `allowed_tags` — the capability gate (L4)

Every tool's tags must be a **subset** of `allowed_tags`, or the call is
denied at gate layer 4, before policy runs.

This applies to the agent itself, not only to its subagents. An agent
declaring `allowed_tags: [read]` cannot call a tool tagged `[read, internal]`
— list every tag the tools it may call actually carry. Tools from MCP
sources carry an `mcp` tag plus any tags the source declares.

A subagent context narrows further: the effective set is the intersection of
the agent's declared tags and the subagent's.

```yaml
# parent
allowed_tags: [read, internal, external_write]

# subagent — can't call tools tagged external_write
sub_agents:
  - id: reader_sub
    allowed_tags: [read, internal]   # ⊆ parent
```

---

## `allowed_paths` — the filesystem grant

`allowed_paths` lists the absolute files and directories an agent may read
(`read`) and write (`write`). A directory covers everything beneath it, and a
`write` entry also grants read. No block means no filesystem access.

For each argument a tool declares in `path_args`, gate layer 2 resolves the
value to its real location (`..` and symlinks resolved, on every call) and
denies the call unless it sits outside the protected set and inside the agent's
grant for the access the tool needs. A subagent context is checked against the
subagent's own grant.

The protected set is SHAI's own files, derived from `harness.yaml`: audit sink
files, the pattern DB, the MCP baseline and manifests directory, the revocation
file, the session and budget stores, the config file and every loaded agent
definition. A grant overlapping it fails at load, so `/srv` cannot cover
`/srv/state`.

```yaml
allowed_paths:
  read:  [/srv/workspace, /srv/reference]
  write: [/srv/workspace/out]
sub_agents:
  - id: researcher
    allowed_tool_names: [read_file]
    allowed_tags: [fs]
    allowed_paths:
      read: [/srv/reference]
```

---

## `policy_rules`

Evaluated before global rules from `harness.yaml`. Same grammar as global
rules — see `policy.md` for the full match field reference.

**Rule ordering:** first match wins. Put deny rules before allow rules if you
want explicit allow-listing:

```yaml
policy_rules:
  - id: deny_write      # checked first
    match:
      tool_tags: [external_write]
    action: deny
  - id: allow_everything_else
    match:
      tool_tags: [read]
    action: allow
```

---

## Subagent model

Subagents are declared inside the parent YAML. They are not separate agents
— they are scoped views of the parent's capability set.

```python
ctx       = await harness.load_agent("agents/orchestrator.yaml")
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")

# child_ctx.agent_id     == "orchestrator_agent"  (parent identity preserved)
# child_ctx.sub_agent_id == "research_sub"
# child_ctx.allowed_tags == ["read", "internal"]  (scoped down from parent)
```

`scope_context_for_subagent` looks up `SubAgentConfig` from the
already-loaded parent config and returns a new frozen `AgentContext`. It
raises `SubAgentNotDeclaredError` if the sub_agent_id is not declared under
the parent.

`harness.tools_for(ctx)` returns the tools a context reaches the gate's
per-call layers with: L1 `allowed_tool_names` and L4 `allowed_tags` applied
to the context's effective profile, so a subagent context gets its narrowed
set. It is a superset of what `check_tool_call` allows — use it to build the
tool list you give the LLM, and gate every call with `check_tool_call`.

In `check_tool_call`, the subagent's `allowed_tool_names` and `policy_rules`
are used directly. The parent's `policy_rules` are added after the
subagent's (intersection model — both must pass for an allow).

**Invariants enforced at load time:**
- `sub_agent.allowed_tool_names ⊆ parent.allowed_tool_names`
- `sub_agent.allowed_tags ⊆ parent.allowed_tags`

Violations raise `ConfigError` at `load_agent()`.

---

## `sources`

List of source names to activate for this agent. Must match names declared
in `harness.yaml`'s `sources:` block.

Sources not found in the `SourceRegistry` are logged and skipped — not
fatal. Sources that fail to connect are fatal only if `required: true` in
`harness.yaml`.

---

## `audit_tags`

Free-form key-value pairs stamped onto every `AuditEvent` emitted for that
agent. Use them for SIEM filtering, cost attribution, or environment
tagging — e.g. `team`, `env`, `cost_center`, `case_id`. They are never set by
agent code; they come from the static config.

```yaml
audit_tags:
  team: security
  env: production
  cost_center: "eng-platform"
```

---

## AgentRegistry lifecycle

```python
# Load (parse + validate + register)
ctx = await harness.load_agent("agents/my_agent.yaml")

# Reload (atomic replace — old definition kept on validation failure)
ctx = await harness.maintenance.reload_agent("agents/my_agent.yaml")

# Deregister
harness.maintenance.deregister_agent(ctx.agent_id)
```

`load_agent()` is idempotent on identical content — loading the same file
twice returns the same `AgentConfig` without error. Loading the same `id`
with different content raises `AgentConflictError` — use `reload_agent`
instead.

`deregister_agent()` clears the agent's entry from `_agent_tools` and resets
the rate limiter for that `agent_id`.

---

## AgentContext

`load_agent()` returns `AgentContext`. Pass it to every boundary call.

```python
ctx = await harness.load_agent("config/agents/my_agent.yaml")
# ctx.agent_id = "my_agent"
# ctx.sub_agent_id = None
# ctx.allowed_tags = None (no subagent narrowing; the agent's own
#                          allowed_tags still gates its calls at L4)

# Load the same agent again — returns a fresh context, same config
ctx2 = await harness.load_agent("config/agents/my_agent.yaml")
```

**`AgentContext` is lightweight.** Multiple contexts for the same agent can
coexist for concurrent turns. The harness is stateless per-turn.

---

## Tool resolution at load_agent() time

Tools are resolved once, not per turn:

1. `SourceRegistry.activate(ctx, cfg.sources)` — activate declared sources, collect their tools
2. Register source tools into the shared `ToolRegistry`
3. `_resolve_tools(cfg)` — filter to `allowed_tool_names`
4. Store in `_agent_tools[cfg.id]`

Every subsequent turn reads from `_agent_tools[cfg.id]` directly — no
registry lookup, no source activation.

If `register_tools()` is called after `load_agent()`, all loaded agents are
re-resolved automatically so new tools become immediately available.
