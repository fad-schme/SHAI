# agent-xx.yaml Reference

One file per agent. Loaded via `await harness.load_agent("path/to/agent.yaml")`.
Returns `AgentContext` — pass it to every boundary method.

---

## Full schema

```yaml
id: orchestrator_agent          # unique — used as agent_id in audit events
display_name: "Orchestrator"    # human-readable, optional
version: "1.0.0"                # optional

# Tools this agent may call — hard gate L1, cannot be overridden by policy
allowed_tool_names:
  - search_docs
  - send_email
  - list_channels

# Tag gate L2 — tool.tags must be a subset of this list
# For subagent contexts, enforced before policy runs
allowed_tags:
  - read
  - internal
  - external_write

# Sources to activate for this agent (declared in harness.yaml)
sources:
  - slack_mcp
  - docs_local

# Per-agent policy rules — evaluated before global rules
# First match wins
policy_rules:
  - id: deny_external_write
    match:
      tool_tags: [external_write]
    action: deny
    reason: "external writes require approval"
  - id: allow_read
    match:
      tool_tags: [read]
    action: allow
  - id: allow_slack_tools
    match:
      tool_names: [list_channels, search_messages]
    action: allow

# Attached to every AuditEvent emitted during this agent's turns
audit_tags:
  team: platform
  env: prod

# Subagents — capabilities must be ⊆ parent
sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]     # ⊆ parent allowed_tool_names
    allowed_tags: [read, internal]         # ⊆ parent allowed_tags
    policy_rules:
      - id: read_only
        match:
          tool_tags: [external_write]
        action: deny
        reason: "research_sub is read-only"
```

---

## `allowed_tool_names` — the hard gate (L1)

This is the most important field. Any tool not listed here is permanently
denied — policy rules cannot override this.

```python
# This always denies, regardless of policy:
gate = await harness.check_tool_call("delete_database", {}, ctx)
# gate.allowed = False — "delete_database" not in allowed_tool_names
```

A tool must be both in `allowed_tool_names` AND pass the policy rules
to be allowed. L1 runs before policy.

---

## `allowed_tags` — the tag gate (L2)

For subagent contexts (`scope_context_for_subagent()`), every tool's tags
must be a subset of `allowed_tags`. Tools with tags outside this set are
denied at L2 before policy runs.

For top-level agents, `allowed_tags` is used as a filter when activating
sources — tools from a `LocalSource` with tags outside this set are excluded.

```yaml
# parent
allowed_tags: [read, internal, external_write]

# subagent — can't call tools tagged external_write
sub_agents:
  - id: reader_sub
    allowed_tags: [read, internal]   # ⊆ parent
```

---

## `policy_rules`

Evaluated before global rules from `harness.yaml`. Same grammar as global rules.
→ See `07-policy.md` for the full match field reference.

**Rule ordering:** first match wins. Put deny rules before allow rules if
you want explicit allow-listing:

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

## Subagents

Declare subagents in the parent YAML. Access via:

```python
# In the parent's turn
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")

# child_ctx carries:
# - agent_id = "orchestrator_agent" (parent)
# - sub_agent_id = "research_sub"
# - allowed_tags = ["read", "internal"]  (narrowed from parent)
```

**Invariants enforced at load time:**
- `sub_agent.allowed_tool_names ⊆ parent.allowed_tool_names`
- `sub_agent.allowed_tags ⊆ parent.allowed_tags`

Violations raise `ConfigError` at `load_agent()`.

---

## `sources`

List of source names to activate for this agent. Must match names declared
in `harness.yaml sources:`.

Sources not found in the `SourceRegistry` are logged and skipped — not fatal.
Sources that fail to connect are fatal if `required: true` in harness.yaml.

---

## `audit_tags`

Free-form key-value pairs stamped on every `AuditEvent` for this agent.
Use for SIEM filtering, cost attribution, environment tagging.

```yaml
audit_tags:
  team: security
  env: production
  cost_center: "eng-platform"
```

---

## AgentContext

`load_agent()` returns `AgentContext`. Pass it to every boundary call.

```python
ctx = await harness.load_agent("config/agents/my_agent.yaml")
# ctx.agent_id = "my_agent"
# ctx.sub_agent_id = None
# ctx.allowed_tags = None (top-level agents don't narrow tags)

# Load the same agent again — returns a fresh context, same config
ctx2 = await harness.load_agent("config/agents/my_agent.yaml")
```

**`AgentContext` is lightweight.** Multiple contexts for the same agent
can coexist for concurrent turns. The harness is stateless per-turn.
