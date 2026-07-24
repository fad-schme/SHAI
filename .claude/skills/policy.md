# Policy Reference

Policy rules govern which tool calls are allowed, denied, or redacted.

---

## Rule structure

```yaml
policy:
  rules:
    - id: my_rule           # unique identifier
      match:                # conditions — all listed fields must match (AND)
        tool_tags: [read]
        transport: [local]
      action: allow         # allow | deny | redact | suppress
      reason: "optional"    # included in deny_reason and audit event
```

**First match wins.** Rules are evaluated in declaration order.
No match → implicit `allow`.

---

## Match fields

All match fields are OR within the list, AND between fields:

```yaml
match:
  tool_tags: [read, internal]     # tool has ANY of these tags
  transport: [local, skill]       # tool transport is ANY of these
  tool_names: [search_docs, fetch_doc]  # tool name is ANY of these
  agent_ids: [orchestrator]       # agent_id is ANY of these
  sub_agent_ids: [research_sub]   # sub_agent_id is ANY of these
  source_tags: [external_mcp]     # source has ANY of these tags
```

**Multiple fields = AND:**
```yaml
match:
  tool_tags: [external_write]
  agent_ids: [untrusted_agent]
# Matches tools tagged external_write AND agent is untrusted_agent
```

**`tool_tags` vs `tool_names`:**
- `tool_tags` — matches any tool carrying any of the listed tags
- `tool_names` — matches specific named tools (exact match, not prefix)

---

## Actions

### `allow`
Allows the tool call. Stops rule evaluation.

```yaml
- id: allow_read_tools
  match:
    tool_tags: [read]
  action: allow
```

### `deny`
Blocks the tool call. `gate.allowed = False`, `gate.deny_reason` is set.

```yaml
- id: deny_external_writes
  match:
    tool_tags: [external_write]
  action: deny
  reason: "external writes require human approval"
```

### `redact`
Redacts specified args before dispatch. `gate.allowed = True`,
`gate.redacted_args` is set with redacted values.

```yaml
- id: redact_sensitive_args
  match:
    tool_tags: [sensitive]
  action: redact
  redact:
    ssn: "[REDACTED]"
    credit_card: "[REDACTED]"
```

### `suppress`
Deactivates a source for an agent. Used in `evaluate_source()` — does not
appear in the `check_tool_call` flow directly.

```yaml
- id: suppress_mcp_for_untrusted
  match:
    source_tags: [external_mcp]
    agent_ids: [untrusted_agent]
  action: suppress
  reason: "MCP not permitted for untrusted agents"
```

---

## Rule ordering — practical patterns

### Allow-list pattern (recommended for MCP)

```yaml
policy:
  rules:
    # Global deny for all MCP tools by default
    - id: deny_mcp
      match:
        transport: [mcp]
      action: deny
      reason: "MCP tools require explicit agent-level allow"

    # Allow specific tools in agent YAML, not here
```

Then in `agent-xx.yaml`:
```yaml
policy_rules:
  - id: allow_slack_read
    match:
      tool_names: [list_channels, read_messages, search_messages]
    action: allow
```

### Deny-list pattern (for trusted environments)

```yaml
policy:
  rules:
    - id: allow_all_local
      match:
        transport: [local, skill]
      action: allow
    - id: deny_write_ops
      match:
        tool_tags: [external_write]
      action: deny
```

---

## Intersection model

Rules are evaluated in layers:
1. Agent's `policy_rules` (most specific)
2. Global `policy.rules` from `harness.yaml`

First match anywhere wins. This means agent rules can override global rules.

**Subagent rule evaluation:**
```
subagent policy_rules → parent policy_rules → global rules
```

A subagent can be more restrictive than its parent (deny something the parent
allows). It cannot be more permissive (allow something the parent denies at L1/L2).

---

## What policy cannot do

- **Override L1** — a tool not in `allowed_tool_names` is never reached by policy.
- **Override L2** — a tool whose tags aren't in `allowed_tags` is denied before policy.
- **Override rate limits** — rate limiting fires before L1 and policy.

These are hard boundaries by design.

---

## Combinators (advanced)

```yaml
match:
  any:          # OR — any sub-condition matches
    - tool_tags: [external_write]
    - transport: [mcp]
  all:          # AND — all sub-conditions match
    - tool_tags: [sensitive]
    - agent_ids: [orchestrator]
  not:          # NOT — condition must not match
    tool_tags: [read]
```

---

## Custom PolicyEngine

Implement the protocol and register via entry points:

```python
class MyPolicy:
    async def evaluate(
        self, tool: Tool, ctx: AgentContext, args: dict
    ) -> PolicyDecision:
        if "unsafe" in tool.tags:
            return PolicyDecision(action="deny", reason="unsafe tool")
        return PolicyDecision(action="allow")

    async def evaluate_source(
        self, source: ToolSource, ctx: AgentContext
    ) -> SourceDecision:
        return SourceDecision(active=True)
```

```toml
[project.entry-points."harness.policy"]
my_policy = "my_package.policy:MyPolicy"
```
