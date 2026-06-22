# SHAI — Secure Harness AI

**Production-grade security control plane for AI agents.**

Your agent calls tools. Some of those tools send emails, write files, query databases, and talk to external APIs. The LLM decides which ones to call and what arguments to pass. You don't get to review that decision before it executes.

SHAI sits between your agent and its tools. Every tool call passes through a policy gate. Every piece of text the LLM touches is scanned. Every decision is logged. You stay in control.

---

## What it does

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► LLM ──► scan_output ──► response
```

Three boundaries, always on:

**`scan_input`** — Inspect the user's text before it reaches the LLM. Detect PII, prompt injection, and custom patterns. Block or redact before the LLM ever sees the content.

**`check_tool_call`** — Gate every tool call through a four-layer policy engine before dispatch. The harness decides; the agent dispatches. No exceptions, no bypasses.

**`scan_output`** — Inspect the LLM's response before it reaches the user. Catch accidental data egress, PII leakage, or content that shouldn't leave the system.

One structured audit event per boundary call, every time, regardless of outcome. Ship them to stdout, a rotating file, Splunk, Sentinel, or any custom sink.

---

## Why do you need SHAI?

**Your LLM will try to call tools it shouldn't.** Prompt injection, confused deputy attacks, and simple hallucinations all produce tool calls your agent was never meant to make. Without a gate, the only thing stopping them is the model's judgment — and that's not a security boundary.

**Compliance requires an audit trail you can defend.** "The model decided" is not an acceptable answer in a SOC 2 audit or a GDPR investigation. You need a structured, tamper-evident record of every tool call, every scan result, and every denial — before the call happens, not reconstructed from logs afterward.

**Subagent delegation is harder than it looks.** When an orchestrator spins up a research subagent, that subagent should only be able to call read tools, not send emails. Enforcing that in application code means every agent, every framework integration, and every new tool has to remember the rule. One harness enforces it structurally — the subagent physically cannot call tools outside its declared capability set.

**Every framework integration is a different hook.** LangGraph has `ToolNode`. LangChain has `BaseTool`. CrewAI has `@tool`. OpenAI Agents has `before_tool_call`. Writing a gate that works consistently across all of them — and stays consistent as frameworks evolve — is ongoing maintenance work, not a one-time task.

**Production scanners need a clean protocol to plug into.** Today you have regex PII detection. Next quarter you need Microsoft Purview or Lakera Guard. If your scanning logic is wired directly into your agent code, every change is a refactor. SHAI's adapter protocol means swapping a scanner is one line in `harness.yaml`.

**Concurrent agents share state in subtle ways.** Ten turns running concurrently for the same agent all write to the same tool registry key — unless you key views by object identity, not agent ID. Getting this wrong means tools loaded for one turn silently appear in another. These bugs don't show up in sequential tests.

SHAI solves these problems once, with a tested and documented design, so you can focus on what your agent actually does.

---

## Install

```bash
pip install harness
```

Requires Python 3.11+.

---

## Quick start

**1. Create your config** (`config/harness.yaml`):

```yaml
version: 1
tenant_id: "my-deployment"

scan_input:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii
    - name: basic_injection

scan_output:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii

policy:
  name: rules
  config:
    rules_path: ./config/policies/rules.yaml

audit_sinks:
  - name: stdout
```

**2. Declare your agent** (`config/agents/my_agent.yaml`):

```yaml
id: my_agent
allowed_tool_names:
  - search_docs
  - send_email
allowed_tags:
  - read
  - internal
  - external_write
policy_rules:
  - id: deny_external_write_default
    match:
      tool_tags: [external_write]
    action: deny
    reason: "external_write requires explicit permission"
  - id: allow_email
    match:
      tool_names: [send_email]
    action: allow
```

**3. Run your agent through the harness**:

```python
import asyncio
from harness import Harness, Tool
from harness.core.types import Transport

async def main():
    harness = Harness.from_yaml("config/harness.yaml")

    # Register tools once at startup
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],        transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write"],          transport=Transport.LOCAL),
    ])

    # load_agent returns AgentContext — hold it for all subsequent calls
    agent = await harness.load_agent("config/agents/my_agent.yaml")

    # Per-turn flow
    tools    = await harness.load_sources(agent)
    verdict  = await harness.scan_input(user_text, agent)
    if verdict.blocked:
        return "Input rejected"

    # ... call your LLM with tools ...

    gate = await harness.check_tool_call("search_docs", {"query": "report"}, ctx)
    if gate.allowed:
        result = await dispatch("search_docs", gate.redacted_args or {"query": "report"})

    out_verdict = await harness.scan_output(llm_response, ctx)
    response = out_verdict.redacted_text or llm_response

    await harness.unload_sources(ctx)
    return response

asyncio.run(main())
```

> `load_agent()` returns the `AgentContext` — the object you pass to every subsequent call. No separate context construction step.

---

## The four-layer gate

`check_tool_call` runs four layers in order. First deny anywhere wins.

| Layer | Check | Bypassable? |
|---|---|---|
| **L1a** | Agent registered in the harness? | No |
| **L1b** | Tool name in `allowed_tool_names`? | No — hard pre-policy gate |
| **L1c** | Tool tags ⊆ subagent's `allowed_tags`? | No — capability gate |
| **L2** | Intersection policy (subagent ∩ parent ∩ global rules) | By design |
| **L3** | Arg scanning for `sensitive`-tagged tools | Configurable |

L1b is the critical one. Policy rules can allow or deny — but a tool not in `allowed_tool_names` is denied before policy ever runs. An agent cannot call a tool it was never declared to use, regardless of what the LLM decides.

---

## Subagents

Declare subagents inside the parent's YAML. Subagent capabilities are always a subset of the parent's.

```yaml
# config/agents/orchestrator.yaml
id: orchestrator
allowed_tool_names: [search_docs, send_email, list_inbox]
allowed_tags: [read, internal, external_write]

sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]   # ⊆ parent
    allowed_tags: [read, internal]      # ⊆ parent — no external_write
    sources: [docs_skill]
    policy_rules:
      - id: deny_write
        match:
          tool_tags: [external_write]
        action: deny
        reason: "research_sub is read-only"
```

```python
agent       = await harness.load_agent("config/agents/orchestrator.yaml")
child_agent = harness.scope_context_for_subagent(agent, "research_sub")
# child_agent.allowed_tags == ["read", "internal"]
# send_email is denied at L1b — not in research_sub's allowed_tool_names
```

Parent and subagent can run concurrently on the same `Harness` instance. Each gets its own `ScopedRegistryView`. Tool additions to one view are invisible to the other.

---

## Policy rules

Rules are YAML. They compose with `any`, `all`, and `not`. First match wins.

```yaml
# config/policies/rules.yaml

# Allow local and skill tools by default
- id: allow_local
  match:
    transport: [local, skill]
  action: allow

# Block all MCP tools unless the agent explicitly allows them
- id: deny_mcp_default
  match:
    transport: [mcp]
  action: deny
  reason: "MCP requires explicit agent-level allow rule"

# Redact sensitive args before they reach the tool
- id: redact_pii_args
  match:
    tool_tags: [sensitive]
  action: redact
  redact:
    phone_number: "[REDACTED]"
    ssn: "[REDACTED]"
```

The intersection model: agent-scoped rules run first, then global rules. A global `deny` still fires even if the agent has no matching rule — it cannot be silently bypassed by omission.

---

## Framework integrations

SHAI ships with six framework integrations. All framework SDKs are imported lazily — the integration modules are importable even if the framework is not installed.

| Framework | Integration | How it works |
|---|---|---|
| Anthropic SDK | `gated_dispatch`, `run_turn` | Wraps the tool dispatch call; full-turn helper |
| LangGraph | `HarnessToolNode` | Drop-in replacement for `ToolNode` |
| LangChain | `wrap_tool`, `wrap_tools` | Wraps `BaseTool`; denied calls raise `ToolException` |
| CrewAI | `wrap_tool`, `wrap_tools` | Wraps `@tool` functions and `BaseTool` subclasses |
| PydanticAI | `harness_tool` decorator, `add_harness_middleware` | Per-tool or whole-agent |
| OpenAI Agents SDK | `make_before_tool_hook`, `wrap_tool` | `AgentHooks` integration |

```python
# LangGraph
from harness.integrations.langgraph import HarnessToolNode

tool_node = HarnessToolNode(tools=[search, send_email], harness=harness, ctx=ctx)
graph.add_node("tools", tool_node)

# LangChain
from harness.integrations.langchain import wrap_tools

gated_tools = wrap_tools([search, send_email], harness=harness, ctx=ctx)
agent = create_react_agent(llm, gated_tools)

# Anthropic SDK
from harness.integrations.anthropic_sdk import gated_dispatch, make_tool_result_from_denial

result = await gated_dispatch(tool_name, tool_args, ctx, harness=harness, dispatch=dispatcher)
if isinstance(result, GateDecision):
    messages.append({"role": "user", "content": [make_tool_result_from_denial(result, tool_use_id)]})
```

---

## Adapters

Everything is pluggable via Python entry points.

| Group | Reference adapters | Enterprise adapters |
|---|---|---|
| `harness.scanners` | `regex_pii`, `basic_injection` | Purview, Nightfall, Lakera |
| `harness.policy` | `rules` (YAML) | OPA, Cedar |
| `harness.audit_sinks` | `stdout`, `file` | Splunk, Sentinel, Elasticsearch, OTEL |
| `harness.tool_registry` | `memory` | Redis |
| `harness.tool_sources` | `local`, `skill` | MCP gateway |
| `harness.secrets` | `env` | Vault, AWS KMS, GCP Secret Manager |

To add an adapter, implement the Protocol and register it:

```toml
# your_package/pyproject.toml
[project.entry-points."harness.scanners"]
my_scanner = "my_package.scanners:MyScanner"
```

```yaml
# config/harness.yaml
scan_input:
  enabled: true
  scanners:
    - name: my_scanner
```

See [docs/adapters.md](docs/adapters.md) for the full implementation guide and contract tests.

---

## Audit events

Every boundary call emits exactly one structured event. Nothing in the event ever contains raw user text, LLM output, tool arguments, or scanner-matched substrings.

```json
{
  "timestamp": "2025-01-15T10:23:45.123456+00:00",
  "boundary": "tool_call_gate",
  "decision": "deny",
  "duration_ms": 2,
  "tenant_id": "platform-prod",
  "agent_id": "orchestrator",
  "sub_agent_id": "research_sub",
  "tool_name": "send_email",
  "transport": "local",
  "adapters": ["rules"],
  "deny_reason": "research_sub is read-only",
  "audit_tags": {"team": "platform", "env": "prod"}
}
```

`tenant_id` is set once in `harness.yaml` — not by the agent. When you run multiple deployments, give each a distinct `tenant_id` and your SIEM can filter by deployment without any coordination.

See [docs/audit-schema.md](docs/audit-schema.md) for the full field reference.

---

## CLI

```bash
# Validate your config and all agent files
harness validate

# List all declared agents with their tool counts and subagents
harness agents list

# Tail the audit log with colour-coded decisions
harness audit tail --file logs/audit.jsonl --follow

# Filter to denied tool calls only
harness audit tail --file logs/audit.jsonl --decision deny
```

---

## Project layout

```
harness/
├── config/                  ← your deployment config (edit these)
│   ├── harness.yaml
│   ├── agents/
│   └── policies/
├── src/
│   ├── harness/             ← core SDK (Apache-2.0)
│   │   ├── core/            ← types, context, events, facade
│   │   ├── boundaries/      ← scan_input, check_tool_call, scan_output
│   │   ├── agents/          ← AgentConfig, AgentRegistry
│   │   ├── adapters/        ← reference adapters (scanners, sinks, etc.)
│   │   ├── integrations/    ← framework integrations
│   │   ├── policy/          ← RuleBasedPolicy
│   │   ├── audit/           ← AuditEmitter, redaction
│   │   └── tools/           ← Tool, ToolRegistry protocol
│   └── harness_cli/         ← harness validate / agents list / audit tail
├── examples/
│   ├── hand_rolled_loop.py  ← canonical reference — start here
│   ├── langgraph_agent.py
│   └── with_uma.py
├── tests/
│   ├── unit/                ← 135 tests
│   ├── contracts/           ← 119 adapter contract tests
│   ├── integration/         ← 16 end-to-end tests
│   ├── security/            ← 19 security tests
│   └── perf/                ← 6 performance baseline tests
├── docs/
│   ├── boundaries.md
│   ├── agents.md
│   ├── sources.md
│   ├── policy.md
│   ├── audit-schema.md
│   ├── adapters.md
│   ├── concurrency.md
│   └── connectivity.md
└── harness.yaml.example     ← annotated reference config
```

---

## Running the examples

```bash
pip install -e ".[dev]"

# Canonical hand-rolled loop — runs end-to-end, no API key needed
python examples/hand_rolled_loop.py

# SHAI + UMA (memory) coexistence pattern
python examples/with_uma.py

# LangGraph integration (mocks the framework, no install needed)
python examples/langgraph_agent.py
```

---

## Running tests

```bash
pip install -e ".[dev]"

# Full suite
pytest

# Specific suites
pytest tests/unit/
pytest tests/contracts/
pytest tests/integration/
pytest tests/security/

# Performance baselines (prints timings)
pytest tests/perf/ -v -s
```

---

## Concurrency model

One `Harness` instance serves many concurrent agent turns. Each turn gets its own `ScopedRegistryView` keyed by `id(ctx)` — Python object identity. Two concurrent turns for the same agent never share a view.

The shared `InMemoryRegistry` is lock-free on reads. Writes (`register_tools`) hold a `threading.Lock` and are startup-only.

See [docs/concurrency.md](docs/concurrency.md) for hazards to avoid and the parent+subagent concurrent pattern.

---

## Connectivity layer (planned)

The harness gates at the API level. A determined tool — or LLM-generated code running in a code-execution tool — can still make raw outbound calls the harness never sees.

`harness-connectivity` (planned) will enforce at the network boundary via a dispatch token issued by `check_tool_call` and validated by an egress proxy. The token scopes exactly which destinations a tool call may reach, with a short TTL and HMAC-SHA256 signature.

The interface is defined in [docs/connectivity.md](docs/connectivity.md) and tested in `tests/security/test_dispatch_token.py`.

---

## Packages

| Package | License | Description |
|---|---|---|
| `harness` | Apache-2.0 | Core SDK + reference adapters |
| `harness-enterprise` | Commercial | Production adapters (OPA, Splunk, Vault, Lakera, …) |
| `harness-cli` | Apache-2.0 | Developer tools (bundled with `harness`) |
| `harness-connectivity` | Planned | Network-layer enforcement, egress gateway |

---

## Documentation

| Doc | What it covers |
|---|---|
| [docs/boundaries.md](docs/boundaries.md) | Per-boundary contracts, gate layers, audit invariants |
| [docs/agents.md](docs/agents.md) | agent-xx.yaml schema, subagent model, registry lifecycle |
| [docs/sources.md](docs/sources.md) | Tool source lifecycle, skill groups, MCP sources |
| [docs/policy.md](docs/policy.md) | Rule grammar, intersection model, combinators |
| [docs/audit-schema.md](docs/audit-schema.md) | AuditEvent field reference, SIEM query examples |
| [docs/adapters.md](docs/adapters.md) | Writing and registering adapters |
| [docs/concurrency.md](docs/concurrency.md) | View isolation, threading model, hazards |
| [docs/connectivity.md](docs/connectivity.md) | Dispatch token, egress gateway, process isolation |

---

## License

`harness` core is Apache-2.0. See [LICENSE](LICENSE) for details.
