# Capabilities — Agents and Subagents

An agent is a named identity with a declared capability set. Every boundary call carries an `AgentContext` that identifies which agent (and optionally which subagent) is making the call.

---

## agent-xx.yaml schema

```yaml
id: orchestrator_agent          # snake_case: ^[a-z][a-z0-9_]*$, unique within harness
display_name: "Orchestrator"    # optional, human-readable
version: "1.0.0"                # optional

# Capability declarations — mandatory, must be non-empty
allowed_tool_names:
  - search_docs
  - send_email
  - list_inbox

allowed_tags:
  - read
  - internal
  - external_write

# Tool source activation — names must match sources declared in harness.yaml
sources:
  - docs_local
  - outlook_mcp

# Agent-scoped policy rules (evaluated before global rules)
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

log_level: DEBUG    # DEBUG | INFO | WARNING | ERROR
audit_tags:
  team: platform
  env: prod

# Subagents — capabilities always ⊆ parent
sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]      # ⊆ parent allowed_tool_names
    allowed_tags: [read, internal]         # ⊆ parent allowed_tags
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
- Subagent `id` values must be unique within the parent
- `deny` rules require a non-empty `reason`
- `redact` rules require a `redact` mapping
- `log_level` must be one of `DEBUG`, `INFO`, `WARNING`, `ERROR`

Violations raise `ConfigError` with the field path.

---

## Subagent model

Subagents are declared inside the parent YAML. They are not separate agents — they are scoped views of the parent's capability set.

```python
ctx       = await harness.load_agent("agents/orchestrator.yaml")
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")

# child_ctx.agent_id     == "orchestrator_agent"  (parent identity preserved)
# child_ctx.sub_agent_id == "research_sub"
# child_ctx.allowed_tags == ["read", "internal"]  (scoped down from parent)
```

`scope_context_for_subagent` looks up `SubAgentConfig` from the already-loaded parent config and returns a new frozen `AgentContext`. It raises `SubAgentNotDeclaredError` if the sub_agent_id is not declared under the parent.

In `check_tool_call`, the subagent's `allowed_tool_names` and `policy_rules` are used directly. The parent's `policy_rules` are added after the subagent's (intersection model — both must pass for an allow).

---

## AgentRegistry lifecycle

```python
# Load (parse + validate + register)
ctx = await harness.load_agent("agents/my_agent.yaml")

# Reload (atomic replace — old definition kept on validation failure)
ctx = await harness.reload_agent("agents/my_agent.yaml")

# Deregister
await harness.deregister_agent(ctx.agent_id)
```

`load_agent()` is idempotent on identical content — loading the same file twice returns the same `AgentConfig` without error. Loading the same `id` with different content raises `AgentConflictError` — use `reload_agent` instead.

`deregister_agent()` clears the agent's entry from `_agent_tools` and resets the rate limiter for that `agent_id`.

---

## audit_tags

`audit_tags` in `agent-xx.yaml` are stamped onto every `AuditEvent` emitted for that agent. Use them for SIEM filtering — e.g. `team`, `env`, `cost_center`, `case_id`. They are never set by agent code; they come from the static config.

```json
{
  "audit_tags": {"team": "platform", "env": "prod"}
}
```

---

## Tool resolution at load_agent() time

Tools are resolved once, not per turn:

1. `SourceRegistry.activate(ctx, cfg.sources)` — activate declared sources, collect their tools
2. Register source tools into the shared `ToolRegistry`
3. `_resolve_tools(cfg)` — filter to `allowed_tool_names`
4. Store in `_agent_tools[cfg.id]`

Every subsequent turn reads from `_agent_tools[cfg.id]` directly — no registry lookup, no source activation.

If `register_tools()` is called after `load_agent()`, all loaded agents are re-resolved automatically so new tools become immediately available.
