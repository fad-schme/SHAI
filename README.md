# SHAI

> **Live documentation**
>
> To help you get up to speed quickly, SHAI ships interactive documentation as a set of skills that can answer your questions directly in your workflow.
>
> 🌐 Website: [shai.aibestlabs.com](https://shai.aibestlabs.com)  
> 📄 Full docs: [shai.aibestlabs.com/docs.html](https://shai.aibestlabs.com/docs.html)

**Secure Harness AI — the security control plane for production AI agents.**

SHAI sits between your agent and everything it can touch: tools, external APIs, files, and users. It enforces security at the boundaries — not by hoping the model behaves, but by intercepting every action before it executes.

---

## The problem with "safe" AI

Most teams securing AI agents today are doing the same thing: writing better system prompts, fine-tuning for instruction following, adding guardrails that ask the model if a request seems dangerous.

This is safety theater. It secures the model's *internal state* — a black box that defies traditional testing and will eventually produce an anomaly regardless of how much safety training it has received.

A model that has been told to ignore bad instructions is not a secure system. It is a system with a single unpredictable point of failure.

**The correct approach treats security risks as expected operational conditions, not exceptional events.** The goal is not to prevent the model from ever misbehaving. The goal is to build a system that survives the model misbehaving. That requires enforcement at the system boundary — deterministic code that evaluates what the agent *proposes to do*, independently of why it proposed it.

The ForcedLeak attack (CVSS 9.4, Salesforce Agentforce, September 2025) demonstrated this concretely: an attacker embedded instructions in a routine CRM form field. When an employee later asked the AI to process that lead, the agent executed both the legitimate query and the attacker's hidden payload. Every security control saw legitimate traffic. The injection was in the *tool result*, not the user message. Input scanning would not have caught it.

SHAI is built on this model.

---

## What SHAI protects

Every agent turn follows the same pattern. SHAI intercepts at every boundary:

```
User input → [scan] → LLM → [gate] → tool → [scan result] → LLM → [scan] → response
```

| Boundary | Method | What it catches |
|---|---|---|
| Ingress scan | `scan_input` | Prompt injection, jailbreaks, identity spoofing, PII |
| Tool call gate | `check_tool_call` | Unauthorized tools, argument violations, irreversible actions, policy violations |
| Tool result scan | `scan_tool_result` | Indirect injection in documents, API responses, search results |
| File scan | `scan_file` | Malicious uploads, macro-enabled documents, embedded injection |
| Egress scan | `scan_output` | PII leakage, data exfiltration in responses |

Five boundaries. None optional on the hot path. Every boundary emits a structured, tamper-evident audit event.

---

## Why the action layer is where security lives

Most AI security products defend the input layer. They scan what the user sends. This is necessary but not sufficient.

Prompt injection attacks do not need to come from the user. They come from tool results — a web page the agent browsed, an email it read, a document it retrieved. The agent reads the content, the content contains instructions, and the model follows them. Input scanning never sees it.

**SHAI's tool call gate defends the action layer.** When the LLM proposes an action, SHAI evaluates that action against a deterministic policy before anything executes. The evaluation does not care why the action was proposed. It does not ask the model whether the instruction was legitimate. It applies a closed set of rules in code.

This inverts the burden. Detecting a cleverly disguised injection is open-ended — the attacker has infinite creative freedom. Checking whether a wire transfer exceeds a configured limit is a closed problem with a definite answer.

---

## Tool call gate — six layers in strict order

`check_tool_call` is the core of SHAI. It cannot be disabled. Every tool call goes through six checks before anything executes. First failure wins.

```
Pre-gate:  Is the agent registered?
Pre-gate:  Rate limit check (sliding window)
Pre-gate:  Session budget (step counter, token burn-down, fan-out, loop detection)
Layer 1:   tool_name in agent's allowed_tool_names?
Layer 2:   Argument rules — deterministic parameter constraints
Layer 3:   Irreversibility gate — requires human approval for high-blast-radius actions
Layer 4:   tool.tags ⊆ ctx.allowed_tags? (subagent capability gate)
Layer 5:   Policy engine (YAML rules: allow / deny / redact)
Layer 6:   Arg scanning for tools tagged "sensitive"
```

### Argument rules — the ForcedLeak fix

Argument rules encode typed, deterministic constraints on tool call parameters. They run before the policy engine and deny on the first violation — regardless of what the LLM was told to do, regardless of any injection payload in context.

```python
from shai import Tool, ArgumentRule

harness.register_tools([
    Tool(
        name="approve_payment",
        tags=["financial"],
        argument_rules=[
            ArgumentRule(arg="amount",      max_value=50_000),
            ArgumentRule(arg="vendor",      allowlist=["acme_corp", "globex"]),
            ArgumentRule(arg="destination", pattern=r"^https://pay\.internal/"),
        ],
    )
])
```

A payment of $1,200,000 to an unexpected vendor at 2am — triggered by a malicious webpage the agent browsed three tool calls ago — is denied here. The injection payload that produced the call is irrelevant. The argument value failed a closed, deterministic check.

Available constraints:

| Field | Type | Semantics |
|---|---|---|
| `max_value` | `float` | Numeric upper bound (inclusive) |
| `min_value` | `float` | Numeric lower bound (inclusive) |
| `allowlist` | `list[str]` | Value must be one of these strings |
| `pattern` | `str` | Value must match this regex (re.search) |
| `required` | `bool` | Argument must be present and non-None |

### Irreversibility gate — blast-radius control

Every tool carries a blast-radius classification. The gate enforces it before the policy engine runs.

```python
from shai import Tool, Irreversibility

harness.register_tools([
    Tool("search_docs"),   # REVERSIBLE by default — no extra gate

    Tool(
        name="send_bulk_email",
        irreversibility=Irreversibility.SENSITIVE,
    ),

    Tool(
        name="delete_customer_record",
        irreversibility=Irreversibility.IRREVERSIBLE,
    ),
])
```

| Tier | Behaviour |
|---|---|
| `REVERSIBLE` | Default. No extra gate. |
| `SENSITIVE` | Denied unless `ctx.human_approved=True` |
| `IRREVERSIBLE` | Denied unless `ctx.human_approved=True` |

The agent sets `human_approved=True` on `AgentContext` after obtaining explicit human confirmation. SHAI does not define how confirmation is obtained — that is the agent's responsibility. SHAI only enforces that the signal is present before an irreversible action executes.

```python
# After the user confirms: "Yes, delete this record"
ctx_approved = AgentContext(
    agent_id=ctx.agent_id,
    human_approved=True,
)
gate = await harness.check_tool_call("delete_customer_record", args, ctx_approved)
```

---

## Session budget — DoS and unbounded consumption

Agents can be induced into resource exhaustion: unbounded loops, logic bombs that spawn hundreds of tool calls, prompts designed to consume the entire token budget of a session. These attacks pass through input scanning because no single turn looks dangerous.

SHAI's session budget enforces four controls at the gate:

```yaml
# harness.yaml
check_tool_call:
  execution_budget:
    max_steps: 30                      # total tool calls per session
    max_tokens_per_session: 50000      # cumulative token budget
    max_tool_calls_per_prompt: 10      # fan-out per user turn
    loop_detection_window: 5           # rolling fingerprint window
    loop_similarity_threshold: 0.95   # Jaccard similarity threshold
    tool_cost_weights:
      web_search: 3
      database_query: 2
```

**Fan-out vs rate limit:** Rate limiting controls *frequency over time* (requests per minute). Fan-out limiting controls *amplification within a single request* (tool calls per prompt). A single carefully-crafted prompt that spawns 200 tool calls bypasses rate limiting entirely — it is one request. Fan-out catches it.

---

## Prompt injection scanning

SHAI ships five production scanners. All are async and run concurrently.

| Scanner | What it detects | Languages |
|---|---|---|
| `injection_scan` | Direct and indirect prompt injection, tool coercion, exfiltration, encoded payloads (17 rules) | EN + FR, ES, DE, ZH |
| `jailbreak_scan` | Guardrail bypass: persona override, refusal suppression, mode activation, prompt extraction (6 rules) | EN + FR, ES, DE, ZH |
| `identity_spoof_scan` | Agentic identity attacks: claimed orchestrator/system authority, peer privilege escalation, tool-result authority injection (4 rules) | EN + FR, ES, DE, ZH |
| `regex_pii` | PII and credentials: email, SSN, credit cards, API keys — with optional redaction | EN (Unicode-aware) |
| `mcp_metadata_scan` | MCP tool name/description injection at connection time (8 rules) | EN |

**Multilingual coverage:** The three core threat scanners ship multilingual pattern catalogs
(`l10n/*.l10n.yaml`) covering French, Spanish, German, and Simplified Chinese. Each language
covers the highest-threat rule families: instruction override, jailbreak/persona, system prompt
extraction, and tool coercion. Multilingual patterns load automatically alongside the base
English catalog — no configuration required.

**Input normalization:** Before any scanner runs, the input is canonicalized into multiple views — the surface form plus decoded variants (base64, hex, URL encoding, rot13, unicode homoglyphs, fragment reassembly). A payload that bypasses the surface scanner by encoding `ignore all previous instructions` in base64 is caught after decoding. The raw text the agent sees is never mutated.

---

## Cross-turn threat detection

Individual turns can be clean while the session as a whole is an attack. Crescendo attacks distribute a jailbreak across many turns — each turn looks below threshold, but the cumulative pattern is clearly adversarial.

SHAI's threat accumulator tracks risk scores across turns (SQLite-backed, persists across restarts). When a session crosses the configured escalation threshold, `scan_input` blocks it before scanners even run.

```yaml
session:
  enabled: true
  escalation_threshold: 0.70
  window_size: 10
  on_escalation: block
```

---

## Tool result scanning — indirect injection

The most common attack vector in production agentic systems is indirect prompt injection via tool results: a malicious webpage the agent browsed, an email it read, a document it retrieved. The content re-enters the LLM's context and contains instructions.

```python
result  = await source.call(tool_name, args)
verdict = await harness.scan_tool_result(result, ctx)
if verdict.blocked:
    return "Tool result blocked — potential injection"
```

`scan_tool_result` uses a doc-tuned injection scanner with lower false-positive rates for structured content. Connector manifests can declare `scan_tool_result_on` to limit scanning to high-risk tools.

---

## Subagent scoping — least privilege

```python
# Orchestrator context — full capability set
ctx = await harness.load_agent("agents/orchestrator.yaml")

# Subagent context — capability automatically narrowed
child = harness.scope_context_for_subagent(ctx, "research_sub")
# child.allowed_tags = ["read", "internal"]  (no write capability)
```

Subagent `allowed_tool_names` and `allowed_tags` are validated at load time to be subsets of the parent. A read-only research subagent cannot acquire write capability regardless of what the LLM requests.

---

## Framework integrations

SHAI wraps existing agents without requiring a rebuild.

| Framework | Integration |
|---|---|
| LangGraph | `HarnessToolNode` — drop-in replacement for `ToolNode` |
| LangChain | `ShaiMiddleware`, `wrap_tools()` |
| Anthropic SDK | `gated_dispatch` |
| CrewAI | `wrap_tools()` |
| PydanticAI | `@harness_tool`, `add_harness_middleware()` |
| OpenAI Agents | `make_before_tool_hook()`, `wrap_tool()` |

---

## Multi language support

The pattern scanners support English (EN), French (FR), Spanish (ES), German (DE), and Simplified Chinese (ZH). Localized patterns are loaded automatically alongside the base English catalog, with no additional configuration required.

---

## Quick start

```python
from shai import SHAI, Tool, AgentContext, ArgumentRule, Irreversibility

harness = await SHAI.from_yaml("config/harness.yaml")

await harness.register_tools([
    Tool("search_docs", tags=["read"]),
    Tool(
        "approve_payment",
        tags=["financial"],
        argument_rules=[
            ArgumentRule(arg="amount", max_value=50_000),
            ArgumentRule(arg="vendor", allowlist=["acme_corp", "globex"]),
        ],
    ),
    Tool(
        "delete_record",
        tags=["destructive"],
        irreversibility=Irreversibility.IRREVERSIBLE,
    ),
])

ctx = await harness.load_agent("config/agents/my_agent.yaml")

# Per-turn loop
verdict = await harness.scan_input(user_text, ctx)
if verdict.blocked:
    return "Input rejected"

# ... call LLM, get tool call ...

gate = await harness.check_tool_call(tool_name, args, ctx)
if not gate.allowed:
    return f"Action denied: {gate.deny_reason}"

result  = await source.call(tool_name, gate.redacted_args or args)
verdict = await harness.scan_tool_result(result, ctx, tool_name=tool_name)
if verdict.blocked:
    return "Tool result blocked"

verdict = await harness.scan_output(response_text, ctx)
return verdict.redacted_text or response_text
```

---

## Audit trail

Every boundary call emits exactly one structured, signed audit event. No raw text. No argument payloads. No scanner-matched substrings. When something goes wrong, you know exactly what happened.

```bash
# Tail the live audit log
shai audit tail --file logs/audit.jsonl --follow

# Filter to gate denials only
shai audit tail --file logs/audit.jsonl --boundary tool_call_gate --decision deny
```

Argument rule violations and irreversibility blocks appear as structured `deny_reason` fields — not unstructured log lines — so SIEM queries work.

---

## Install

```bash
pip install shai
```

Requires Python 3.11+.

---

## OWASP Agentic AI coverage

| OWASP threat | Coverage | SHAI control |
|---|---|---|
| `T1` Goal and instruction hijacking | **Full** | Normalization + injection scan + jailbreak scan + identity spoof scan + MCP metadata scan + tool governance |
| `T2` Tool misuse | **Full** | Allowlists, tag scoping, argument rules, irreversibility gate, policy rules, rate limits |
| `T3` Uncontrolled agent actions | **Full** | Layered tool governance, argument rules, irreversibility gate, subagent scoping |
| `T4` Resource overload | **Full** | Rate limits, session budget (step counter, token burn-down, fan-out ceiling, loop detection) |
| `T5` Direct prompt injection | **Full** | Normalization + injection scan + jailbreak scan + identity spoof scan |
| `T6` Indirect prompt injection | **Full** | Tool result scanning, MCP governance, argument rules |
| `T7` Escalation via multi-turn | **Full** | Cross-turn threat accumulator (crescendo detection) |
| `T8` Repudiation and untraceability | **Full** | Signed audit events at every boundary |
| `T9` Privilege escalation | **Full** | Subagent scoping, irreversibility gate, layered tool governance, identity spoof scan |
| `T11` Sensitive data exposure | **Full** | PII scanning on input, tool args, and output |
| `T16` Data exfiltration | Partial | Output scanning and governed connectivity paths |
| `T17` Supply chain compromise | Partial | MCP metadata scanning, source governance, file scanning |

---

## Learn more

- Product site: [shai.aibestlabs.com](https://shai.aibestlabs.com)
- Full documentation: [shai.aibestlabs.com/docs.html](https://shai.aibestlabs.com/docs.html)
- Architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md)

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
