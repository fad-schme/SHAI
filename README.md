# SHAI — Secure Harness AI

**Production-grade security control plane for AI agents.**

Your agent calls tools. Some send emails, write files, query databases, and talk to external APIs. The LLM decides which to call and what arguments to pass. You do not get to review that decision before it executes.

SHAI sits between your agent and its tools. Every tool call passes through a policy gate. Every piece of text the LLM touches is scanned. Every decision is logged. You stay in control.

---

## What it does

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
```

**`scan_input`** — Inspect user text before it reaches the LLM. Detect PII and prompt injection. Block or redact.

**`check_tool_call`** — Gate every tool call through a four-layer policy engine. Hard pre-policy gate, subagent capability gate, policy intersection, optional arg scanning. Cannot be disabled.

**`scan_tool_result`** — Scan tool return values before they re-enter the LLM context. Detects indirect prompt injection embedded in documents, search results, or API responses.

**`scan_output`** — Inspect the LLM response before it reaches the user. Catch data egress or PII leakage.

One structured audit event per boundary call, every time, regardless of outcome.

---

## Install

```bash
pip install shai
```

For MCP server connectivity:
```bash
pip install shai[mcp]
```

Requires Python 3.11+.

---

## Quick start

**`config/harness.yaml`:**

```yaml
version: 1
tenant_id: "my-deployment"

scan_input:
  enabled: true
  block_at: high
  scanners:
    - name: regex_pii
    - name: injection_scan

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

**`config/agents/my_agent.yaml`:**

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

**Agent loop:**

```python
import asyncio
from harness import SHAI, Tool
from harness.core.types import Transport

async def main():
    harness = await SHAI.from_yaml("config/harness.yaml")

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],   transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write"],     transport=Transport.LOCAL),
    ])

    ctx = await harness.load_agent("config/agents/my_agent.yaml")

    # Per-turn
    verdict = await harness.scan_input(user_text, ctx)
    if verdict.blocked:
        return "Input rejected"

    # ... LLM call ...

    gate = await harness.check_tool_call("search_docs", {"query": "report"}, ctx)
    if gate.allowed:
        result = await dispatch("search_docs", gate.redacted_args or {"query": "report"})
        tverdict = await harness.scan_tool_result(result, ctx)
        safe_result = tverdict.redacted_text or result

    out_verdict = await harness.scan_output(llm_response, ctx)
    return out_verdict.redacted_text or llm_response

asyncio.run(main())
```

---

## The four-layer gate

`check_tool_call` runs four layers in order. First deny anywhere wins.

| Layer | Check | Bypassable? |
|---|---|---|
| Pre-gate | Agent registered? | No |
| L1 | `tool_name` in `allowed_tool_names`? | No — hard pre-policy gate |
| L2 | `tool.tags ⊆ ctx.allowed_tags`? | No — subagent capability gate |
| L3 | Intersection policy (subagent → parent → global rules) | By design |
| L4 | Arg scanning for `sensitive`-tagged tools | Configurable |

L1 fires before policy. A tool not in `allowed_tool_names` cannot be called regardless of what the LLM requests or what policy rules say.

---

## Security coverage — OWASP Agentic AI Threats

SHAI addresses the [OWASP Agentic AI Threats and Mitigations](https://genai.owasp.org) threat model. The table below maps each implemented control to the threats it mitigates.

| Control | Where | OWASP Threats mitigated |
|---|---|---|
| `check_tool_call` L1 — `allowed_tool_names` hard gate | `boundaries/check_tool_call.py` | **T1** Agent Goal/Instruction Hijacking, **T2** Tool Misuse |
| `check_tool_call` L2 — subagent `allowed_tags` gate | `boundaries/check_tool_call.py` | **T2** Tool Misuse, **T3** Uncontrolled Agent Actions |
| `check_tool_call` L3 — intersection policy | `policy/rules.py` | **T2** Tool Misuse, **T3** Uncontrolled Agent Actions, **T9** Privilege Escalation |
| `scan_input` — InjectionScanner | `adapters/scanners/injection_scan.py` | **T5** Prompt Injection, **T1** Goal Hijacking |
| `scan_input` — RegexPIIScanner | `adapters/scanners/regex_pii.py` | **T11** Sensitive Data Exposure |
| `scan_tool_result` — patterns_for_doc | `boundaries/_scan.py` | **T6** Indirect Prompt Injection |
| `scan_output` — RegexPIIScanner | `adapters/scanners/regex_pii.py` | **T11** Sensitive Data Exposure, **T16** Data Exfiltration |
| Rate limiter (R1) | `adapters/scanners/rate_limiter.py` | **T4** Resource Overload, **T2** Tool Misuse (flooding) |
| Arg scanning (L4) | `boundaries/check_tool_call.py` | **T11** Sensitive Data Exposure, **T2** Tool Misuse |
| `FileScanner` — structural checks | `adapters/scanners/file_scanner.py` | **T3** Uncontrolled Agent Actions, **T17** Supply Chain |
| Audit event signing (R3) | `audit/emitter.py` | **T8** Repudiation and Untraceability |
| Tamper-evident audit trail | `audit/emitter.py`, `core/events.py` | **T8** Repudiation and Untraceability |
| Subagent capability scoping | `agents/agent_config.py`, `core/context.py` | **T9** Privilege Escalation, **T3** Uncontrolled Actions |
| `SourceRegistry` policy suppression | `tools/source.py` | **T3** Uncontrolled Agent Actions, **T17** Supply Chain |
| Secret resolution via `EnvVarProvider` | `adapters/secrets/env.py` | **T17** Supply Chain (credential exposure) |

### Threat coverage summary

| OWASP Threat | Coverage | Controls |
|---|---|---|
| **T1** Agent Goal/Instruction Hijacking | Partial | InjectionScanner on input, `allowed_tool_names` hard gate |
| **T2** Tool Misuse | Full | L1 hard gate, L2 tag gate, L3 policy, rate limiter, arg scanning |
| **T3** Uncontrolled Agent Actions | Full | L1–L3 gates, subagent scoping, source suppression |
| **T4** Resource Overload | Full | Rate limiter (global + per-tool sliding window) |
| **T5** Prompt Injection (direct) | Full | InjectionScanner — 17-rule YAML catalog |
| **T6** Indirect Prompt Injection | Full | `scan_tool_result` with `patterns_for_doc.yaml` |
| **T8** Repudiation & Untraceability | Full | HMAC-signed audit events, one event per boundary call |
| **T9** Privilege Escalation | Full | Subagent capability gate, policy intersection model |
| **T11** Sensitive Data Exposure | Full | RegexPII on input + output, arg scanning for `sensitive` tools |
| **T16** Data Exfiltration | Partial | RegexPII on output; network-layer enforcement is planned |
| **T17** Supply Chain | Partial | FileScanner structural checks, source suppression, secret resolution |

*Partial coverage indicates the control addresses the threat at the application layer. Network-layer enforcement (planned as `shai-connectivity`) would provide deeper coverage for T16 and T17.*

---

## Scanners

### `regex_pii` — RegexPIIScanner

Detects personally identifiable information using compiled regex patterns. All patterns run concurrently. Matched text is redacted in-place — `Finding.detail` contains only the category name, never the matched value.

| Category | Severity | Pattern |
|---|---|---|
| `pii.email` | medium | RFC 5321 local-part + domain |
| `pii.phone` | medium | US/international formats, separators normalised |
| `pii.ssn` | high | `NNN-NN-NNNN` with separator variants |
| `pii.credit_card` | high | 13–16 digit sequences passing Luhn check |

**Configuration:**

```yaml
scanners:
  - name: regex_pii
    # optionally scope to specific categories:
    # config:
    #   categories: ["pii.email", "pii.ssn"]
```

**Performance:** < 0.5 ms per call on typical inputs (500 characters).

---

### `injection_scan` — InjectionScanner

YAML-rule scanner for prompt injection and jailbreak patterns. Loads a compiled pattern catalog at construction time. Each rule has a severity and category. Findings never contain the matched text.

Default catalog (`injection_patterns.yaml`) — 17 rules:

| Rule | Category | Severity |
|---|---|---|
| `jailbreak_prompt` | prompt_injection | high |
| `code_injection` | code_injection | high |
| `context_switching` | prompt_injection | high |
| `data_exfiltration` | data_exfiltration | high |
| `encoded_payloads` | prompt_injection | high |
| `homoglyph_obfuscation` | prompt_injection | medium |
| `prompt_reset` | prompt_injection | high |
| `role_impersonation` | prompt_injection | high |
| `config_leakage` | configuration_exposure | high |
| `rule_override` | prompt_injection | high |
| `alignment_breaking` | alignment_evasion | high |
| `policy_evasion` | prompt_injection | medium |
| `debug_mode_spoofing` | system_spoofing | high |
| `escalation_phrases` | privilege_escalation | medium |
| `hidden_instruction_probe` | configuration_exposure | high |
| `tool_coercion` | tool_injection | high |
| `delimiter_smuggling` | obfuscation | high |

Document catalog (`patterns_for_doc.yaml`) — used by `scan_tool_result`. 9 rules tuned for content embedded in documents and search results, where false positives must be lower.

**Custom patterns:**

```yaml
scanners:
  - name: injection_scan
    config:
      patterns_file: "./config/custom_patterns.yaml"
```

**Performance:** < 2 ms per call on typical inputs. Pattern compilation is at startup, not per call.

---

### `file_scanner` — FileScanner

Structural scanner for uploaded files. Always included in the `scan_file` boundary — no explicit configuration needed.

| Check | What it detects |
|---|---|
| Size gate | Rejects files exceeding `max_size_mb` before any parsing |
| MIME type | Detects mismatch between declared extension and actual magic bytes |
| PDF JavaScript | Embedded JS execution triggers in PDFs |
| EXIF metadata | Sensitive fields in image metadata |
| ZIP/Office macros | Macro-enabled Office documents, nested ZIPs |
| Content text | Runs InjectionScanner on extracted text content |

**Performance:** < 5 ms for typical documents (< 1 MB). Large files are gated by the size check before any content parsing.

---

### Rate limiter

Sliding-window token bucket in `check_tool_call`. Two independent counters per `agent_id`:

- **Global budget:** max calls across all tools per window
- **Per-tool budget:** max calls to one tool per window

Both must pass. Counters use `collections.deque` with O(1) amortised pruning. Thread-safe.

```yaml
check_tool_call:
  rate_limit:
    enabled: true
    window_seconds: 60
    max_calls_per_window: 60
    max_calls_per_tool: 20
```

**Performance:** < 0.1 ms per call.

---

## Performance budget

All figures are soft targets on a single core with no network I/O (boundaries disabled, policy in-memory, stdout sink).

| Operation | Target | Measured |
|---|---|---|
| `scan_input` (disabled) | < 1 ms | ~0.1 ms |
| `scan_output` (disabled) | < 1 ms | ~0.1 ms |
| `check_tool_call` (allow) | < 2 ms | ~0.5 ms |
| Full turn (all disabled) | < 5 ms | ~1 ms |
| `regex_pii` on 500-char input | < 5 ms | ~0.3 ms |
| 50 concurrent turns | < 2 s total | ~100 ms |

When enabled, scanner overhead depends on input length. The regex PII scanner adds ~0.3 ms per 500 characters. The injection scanner adds ~1–2 ms per call (pattern matching is CPU-bound, not I/O-bound).

Run `pytest tests/perf/ -v -s` to measure on your hardware.

---

## Subagents

Declare subagents inside the parent YAML. Subagent capabilities are always a strict subset of the parent.

```yaml
# config/agents/orchestrator.yaml
id: orchestrator
allowed_tool_names: [search_docs, send_email, list_inbox]
allowed_tags: [read, internal, external_write]

sub_agents:
  - id: research_sub
    allowed_tool_names: [search_docs]    # ⊆ parent
    allowed_tags: [read, internal]       # ⊆ parent — no external_write
    policy_rules:
      - id: deny_write
        match:
          tool_tags: [external_write]
        action: deny
        reason: "research_sub is read-only"
```

```python
ctx       = await harness.load_agent("config/agents/orchestrator.yaml")
child_ctx = harness.scope_context_for_subagent(ctx, "research_sub")
# child_ctx.allowed_tags == ["read", "internal"]
# send_email → denied at L1 (not in research_sub.allowed_tool_names)
```

---

## Tool sources

Sources declare where tools come from. They are activated at `load_agent()` time — not per turn.

```yaml
# harness.yaml
sources:
  - name: docs_local
    transport: local
    tool_names: [search_docs, fetch_doc]   # subset; omit for all registered tools
    tags: [internal]

  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    credentials:
      token: "secret://SLACK_MCP_TOKEN"
    tags: [external_mcp, messaging]
```

```yaml
# agent YAML — declares which sources to activate
sources:
  - docs_local
  - slack_mcp
```

For MCP tool invocation after gating:

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    source = await harness.get_source("slack_mcp")
    result = await source.call(tool_name, gate.redacted_args or args)
```

---

## Policy rules

Rules evaluate in declaration order. First match wins.

```yaml
# config/policies/rules.yaml

# Allow all local and skill tools by default
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

# Redact sensitive args before dispatch
- id: redact_pii_in_args
  match:
    tool_tags: [sensitive]
  action: redact
  redact:
    phone_number: "[REDACTED]"
    ssn: "[REDACTED]"

# Suppress external MCP sources for untrusted agents
- id: suppress_external_mcp
  match:
    source_tags: [external_mcp]
    agent_ids: [untrusted_agent]
  action: suppress
  reason: "MCP not permitted for untrusted agents"
```

**Combinators:** `any` (OR), `all` (AND), `not` (NOT) for composite conditions.

---

## Audit events

Every boundary call emits exactly one structured event. No raw user text, LLM output, tool arguments, or scanner-matched substrings in any field.

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

Optional HMAC-SHA256 signing:

```yaml
audit_signing:
  enabled: true
  secret: "secret://AUDIT_SIGNING_KEY"
```

See [docs/audit-schema.md](docs/audit-schema.md) for the full field reference.

---

## Framework integrations

All framework SDKs are imported lazily — integration modules are importable without the framework installed.

| Framework | Module | Integration |
|---|---|---|
| Anthropic SDK | `harness.integrations.anthropic_sdk` | `gated_dispatch`, `run_turn`, `make_tool_result_from_denial` |
| LangGraph | `harness.integrations.langgraph` | `HarnessToolNode` — drop-in for `ToolNode` |
| LangChain | `harness.integrations.langchain` | `wrap_tool`, `wrap_tools` |
| CrewAI | `harness.integrations.crewai` | `wrap_tool`, `wrap_tools` |
| PydanticAI | `harness.integrations.pydantic_ai` | `harness_tool` decorator, `add_harness_middleware` |
| OpenAI Agents | `harness.integrations.openai_agents` | `make_before_tool_hook`, `wrap_tool` |

```python
# LangGraph — drop-in ToolNode replacement
from harness.integrations.langgraph import HarnessToolNode
tool_node = HarnessToolNode(tools=[search, send_email], harness=harness, ctx=ctx)

# LangChain — wrap existing BaseTool
from harness.integrations.langchain import wrap_tools
gated = wrap_tools([search, send_email], harness=harness, ctx=ctx)

# Anthropic SDK — gate then dispatch
from harness.integrations.anthropic_sdk import gated_dispatch, make_tool_result_from_denial
result = await gated_dispatch(name, args, ctx, harness=harness, dispatch=dispatcher)
if isinstance(result, GateDecision):
    messages.append({"role": "user", "content": [make_tool_result_from_denial(result, use_id)]})
```

---

## Adapters

Everything is pluggable via Python entry points. Implement the protocol and register under the appropriate group.

| Group | Reference adapters | Protocol |
|---|---|---|
| `harness.scanners` | `regex_pii`, `injection_scan` | `Scanner` |
| `harness.policy` | `rules` | `PolicyEngine` |
| `harness.audit_sinks` | `stdout`, `file` | `AuditSink` |
| `harness.sources` | `local`, `skill`, `mcp` | `ToolSource` |
| `harness.secrets` | `env` | `SecretsProvider` |

```toml
# your_package/pyproject.toml
[project.entry-points."harness.scanners"]
my_scanner = "my_package:MyScanner"
```

```yaml
# harness.yaml
scan_input:
  scanners:
    - name: my_scanner
```

See [docs/adapters.md](docs/adapters.md) for the full implementation guide and contract tests.

---

## CLI

```bash
# Validate harness.yaml and all agent files
shai validate --config config/harness.yaml --agents-dir config/agents/

# List all declared agents
shai agents list --agents-dir config/agents/

# Tail the audit log (colour-coded by decision)
shai audit tail --file logs/audit.jsonl --follow

# Filter to denied tool calls
shai audit tail --file logs/audit.jsonl --decision deny --boundary tool_call_gate
```

---

## Running tests

```bash
pip install -e ".[dev]"

pytest                     # full suite
pytest tests/unit/
pytest tests/contracts/
pytest tests/integration/
pytest tests/security/
pytest tests/perf/ -v -s   # prints timings
```

---

## Packages

| Package | License | Description |
|---|---|---|
| `shai` | Apache-2.0 | Core SDK + reference adapters + CLI |
| `shai[mcp]` | Apache-2.0 | + httpx for MCP server connectivity |

---

## Documentation

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component map, construction sequence, hot path, concurrency model |
| [docs/boundaries.md](docs/boundaries.md) | Per-boundary contracts, gate layers, audit invariants |
| [docs/agents.md](docs/agents.md) | agent-xx.yaml schema, subagent model, registry lifecycle |
| [docs/sources.md](docs/sources.md) | Source lifecycle, LocalSource, SkillSource, MCPSource |
| [docs/policy.md](docs/policy.md) | Rule grammar, intersection model, combinators |
| [docs/audit-schema.md](docs/audit-schema.md) | AuditEvent field reference, SIEM query examples |
| [docs/adapters.md](docs/adapters.md) | Writing and registering adapters, contract tests |
| [docs/concurrency.md](docs/concurrency.md) | Threading model, concurrent turn isolation |

---

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
