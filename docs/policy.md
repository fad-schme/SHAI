# Policy

SHAI uses an intersection model: agent-scoped rules are evaluated first, then global rules. First match wins. Default allow on no match.

---

## Rule schema

```yaml
- id: my_rule            # snake_case, unique within the rule set
  match:                 # all declared conditions must be satisfied (AND semantics)
    tool_names:    []    # tool.name must be in this list
    tool_tags:     []    # tool.tags must intersect this list (any tag matches)
    transport:     []    # tool.transport: local | mcp | skill
    agent_ids:     []    # ctx.agent_id must be in this list
    sub_agent_ids: []    # ctx.sub_agent_id must be in this list
    source_tags:   []    # source.tags must intersect (evaluate_source only)
    any:           []    # OR: any sub-match satisfies
    all:           []    # AND: all sub-matches must satisfy
    not:           {}    # NOT: sub-match must not satisfy
  action: deny           # allow | deny | redact | suppress
  reason: "why"          # required for deny
  redact:                # required for redact
    field_name: "[REDACTED]"
```

All `match` conditions are optional. An empty `match: {}` matches every call.

---

## Intersection model

```
Turn: agent_id=orchestrator_agent, sub_agent_id=research_sub, tool=search_docs

Pass 1: research_sub.policy_rules + orchestrator_agent.policy_rules  (in that order)
Pass 2: global rules from rules_path

First deny in pass 1 or pass 2 → GateDecision(allowed=False)
First allow in pass 1           → GateDecision(allowed=True)  ← does not skip pass 2 global denies
No match in either pass         → default allow
```

**Important:** an `allow` in pass 1 (agent rules) does not skip pass 2 global denies. If you have a global deny that must fire regardless of agent rules, it will fire in pass 2 after agent rules complete without a match.

To enforce a global deny that agent rules cannot override:

```yaml
# Global rules — evaluated after agent rules
- id: deny_pii_tools_globally
  match:
    tool_tags: [pii_access]
    agent_ids: [untrusted_agent]   # scope to agent so only applies where needed
  action: deny
  reason: "PII access not permitted for untrusted_agent"
```

---

## Rule evaluation order

Rules are evaluated in declaration order within each pass. Put more-specific rules before less-specific ones.

```yaml
policy_rules:
  # More specific first — allow this one tool
  - id: allow_search
    match:
      tool_names: [search_docs]
    action: allow

  # Less specific catch-all
  - id: deny_all_reads
    match:
      tool_tags: [read]
    action: deny
    reason: "read tools denied except search_docs"
```

---

## Actions

| Action | Behaviour |
|---|---|
| `allow` | Returns `GateDecision(allowed=True)` immediately. Pass 2 still runs for global denies. |
| `deny` | Returns `GateDecision(allowed=False, deny_reason=rule.reason)`. |
| `redact` | Returns `GateDecision(allowed=True, redacted_args=rule.redact)`. Agent dispatches with `redacted_args`. |
| `suppress` | Used in `evaluate_source()` only. Deactivates the source for this agent/turn. |

---

## Combinators

```yaml
# OR: allow if tool is search_docs OR fetch_doc
- id: allow_read_tools
  match:
    any:
      - tool_names: [search_docs]
      - tool_names: [fetch_doc]
  action: allow

# AND: deny only when both conditions are true
- id: deny_external_mcp_for_sub
  match:
    all:
      - transport: [mcp]
      - tool_tags: [external]
  action: deny
  reason: "external MCP denied for subagents"

# NOT: deny everything except local tools
- id: deny_non_local
  match:
    not:
      transport: [local]
  action: deny
  reason: "only local tools permitted"
```

---

## Transport-based rules

The `transport` field distinguishes tools by origin:

```yaml
# Allow local and skill tools; require explicit approval for MCP
- id: allow_local_skill
  match:
    transport: [local, skill]
  action: allow

- id: deny_mcp_by_default
  match:
    transport: [mcp]
  action: deny
  reason: "MCP requires explicit agent-level allow rule"
```

Agent-level rules can then allow specific MCP tools:

```yaml
# In agent YAML — allows slack MCP tools for this agent
policy_rules:
  - id: allow_slack_mcp
    match:
      transport: [mcp]
      tool_tags: [messaging]
    action: allow
```

---

## Source suppression

`evaluate_source()` runs before `source.load()` at `load_agent()` time. A `suppress` rule deactivates the source entirely for that agent:

```yaml
- id: suppress_external_mcp_for_untrusted
  match:
    source_tags: [external_mcp]
    agent_ids: [untrusted_agent]
  action: suppress
  reason: "external MCP not permitted for untrusted_agent"
```

---

## Global rules file

```yaml
# config/policies/rules.yaml
# Loaded by RuleBasedPolicy at startup. Not reloaded at runtime.

- id: allow_local_default
  match:
    transport: [local, skill]
  action: allow

- id: deny_mcp_default
  match:
    transport: [mcp]
  action: deny
  reason: "MCP requires explicit agent-level permission"

- id: deny_external_write_globally
  match:
    tool_tags: [external_write]
  action: deny
  reason: "external_write requires explicit agent-level allow"
```

---

## RuleBasedPolicy

Reference `PolicyEngine` backed by YAML-declared rules. Constructed at `from_yaml()` time.

```python
# In harness.yaml
policy:
  name: rules
  config:
    rules_path: ./config/policies/rules.yaml
```

Rules are validated at construction. Changes to `rules_path` require process restart — the file is not watched or reloaded at runtime.

Enterprise engines (OPA, Cedar) implement the `PolicyEngine` protocol and are registered under `harness.policy`.
