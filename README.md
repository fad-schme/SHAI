# SHAI

**Secure Harness for AI agents — deterministic control plane between your agent and everything it can touch.**

SHAI sits between your agent and its inputs, tools, and outputs. It scans inputs, gates every tool call through a deterministic policy, scans tool results for indirect injection, and emits a signed audit event at every boundary — before anything executes.

One Python package. Works with LangGraph, LangChain, CrewAI, PydanticAI, Anthropic SDK, OpenAI Agents, or a custom loop.

> **Status:** pre-1.0. The public API is stable enough to build against; breaking
> changes ship in minor bumps and are always announced in [CHANGELOG.md](CHANGELOG.md).
> Not yet recommended as a sole security control for high-stakes production
> agents. See [THREAT_MODEL.md](THREAT_MODEL.md) for what SHAI catches, what it
> doesn't, and how to compose it with other defences.

---

## The premise

Agents can write code, manage inboxes, deploy infrastructure, and make hundreds
of autonomous decisions between morning coffees. The productivity is real. The
attack surface — every input, every tool, every returned document — is new.

The correct posture is to **treat model misbehaviour as an expected operational
condition**, not an exceptional one. That means enforcement at the *system
boundary*: deterministic code that evaluates what the agent proposes to do,
independently of why it proposed it.

SHAI is one implementation of that idea. It does not replace prompt-side
guardrails, model-level fine-tuning, or runtime sandboxing. It is a
**deterministic, auditable enforcement layer** you compose with them.

---

## What it enforces

```
user input → [scan] → LLM → [gate] → tool → [scan result] → LLM → [scan] → response
                                                                         ↓
                                                          signed audit event stream
```

| Boundary | What runs | Catches (see THREAT_MODEL.md for the honest coverage matrix) |
|---|---|---|
| `scan_input` | PII regex, injection catalogs, heuristic scanner | Direct prompt injection, PII, credentials in user text |
| `check_tool_call` | 7-layer gate | Unauthorised tools, argument violations, irreversibility without approval, subagent scope violations, policy denies, cross-boundary signal correlation |
| `scan_tool_result` | Injection catalog (document-tuned) | Indirect injection in fetched documents, MCP responses, web pages |
| `scan_output` | PII regex, consolidated-risk block | PII leakage, data exfiltration, turn-level risk accumulation |
| `scan_file` | Structural + content scan | Malicious PDFs, Office macros, EXIF anomalies, embedded payloads |

Every boundary emits **exactly one** signed `AuditEvent` — allow, warn, block, or degraded. No raw user text, LLM response, or matched substring ever appears in the log.

---

## Quick start

```bash
git clone https://github.com/fad-schme/SHAI.git
cd SHAI
pip install -e ".[dev]"
pytest tests/unit -q
python examples/quickstart.py
```

Requires Python 3.11+.

The quickstart exercises every boundary with real scanners and real policy — no API keys, no LLM. You'll see input blocked, PII redacted, tool calls denied, and the audit trail.

Wire it into your agent:

```python
from shai import SHAI, Tool

harness = await SHAI.from_yaml("config/harness.yaml")
await harness.register_tools([Tool("search_docs", tags=["read"])])
ctx = await harness.load_agent("config/agents/my_agent.yaml")

# Per turn
verdict = await harness.scan_input(user_text, ctx)
gate    = await harness.check_tool_call(tool_name, args, ctx)
verdict = await harness.scan_tool_result(result, ctx)
verdict = await harness.scan_output(response, ctx)
```

Framework-specific templates live in [`docs/08-integrations.md`](docs/08-integrations.md).

---

## Documentation

Full docs are in [`docs/`](docs/):

- **[quickstart.md](docs/quickstart.md)** — five-minute walkthrough
- **[concepts.md](docs/concepts.md)** — boundaries, trust envelope, verdicts, cross-turn accumulator
- **[architecture.md](docs/architecture.md)** — how SHAI is put together
- **[configuration.md](docs/configuration.md)** — `harness.yaml`, `agent.yaml`, policy rules
- **[integrations.md](docs/integrations.md)** — LangGraph, LangChain, Anthropic SDK, CrewAI, PydanticAI, OpenAI Agents
- **[connectors.md](docs/connectors.md)** — Tier A connectors and dispatch-token enforcement
- **[testing.md](docs/testing.md)** — writing tests against SHAI
- **[errors.md](docs/errors.md)** — exception hierarchy and common failures
- **[cli.md](docs/cli.md)** — `shai` command reference
- **[THREAT_MODEL.md](THREAT_MODEL.md)** — threat → control → residual risks

AI coding assistants (Claude Code, Cursor, Windsurf, etc.) look at
[`.claude/skills/`](.claude/skills/) — a compact per-topic reference tuned
for retrieval by a code assistant. For any single schema or field-level
detail, that folder is more thorough than `docs/`.

---

## Where SHAI fits

SHAI is a **harness** — the enforcement layer that wraps an agent. That's a different category from most of the "AI safety" projects you'll find.

The security surface of a production agent has several distinct problems: is the user input hostile, is the LLM about to call a tool it shouldn't, is the tool result carrying instructions the LLM will treat as authoritative, is the response leaking data, is the whole session drifting adversarially over multiple turns. Different projects solve different subsets. SHAI covers the full lifecycle in one place.

**LLM guardrails — text classifiers**
([Guardrails AI](https://github.com/guardrails-ai/guardrails), [NVIDIA NeMo Guardrails](https://github.com/NVIDIA/NeMo-Guardrails), [Meta LlamaFirewall / PromptGuard](https://github.com/meta-llama/PurpleLlama), [Protect AI Rebuff](https://github.com/protectai/rebuff), [Lakera Guard](https://www.lakera.ai/))

These validate LLM inputs and outputs — typically with a fine-tuned classifier or a rules DSL. They answer "is this text malicious?" Useful, and complementary to SHAI. They do not gate tool calls, scan tool results, enforce per-agent capability scoping, or emit a signed audit trail. You can plug any of them into SHAI as a scanner adapter and get the best of both.

**Agent-trace analysis**
([Invariant Labs](https://github.com/invariantlabs-ai/invariant))

Analyses traces of agent behaviour post-hoc, defines contracts, flags deviations. Complementary to SHAI, and closer conceptually. Trace-based rather than boundary-based — you learn what happened, versus SHAI where the boundary decides what's allowed before it happens.

### Where SHAI is different

SHAI treats the **whole agent lifecycle** as the unit of enforcement, not just input/output filtering:

1. **Deterministic policy-based tool-call gate.** Seven layers of check between the LLM proposing a tool call and the tool running — allowed-tool set, argument rules, irreversibility, subagent capability scope, policy intersection, cross-boundary signal correlation, optional argument scanning. Code, not LLM judgement.
2. **Tool-result scanning as a first-class boundary.** When a tool returns a document, web page, or API response, its content is scanned before it re-enters the LLM's context. This is where indirect prompt injection lives, and most other tools miss it entirely.
3. **Cross-boundary signal correlation within a turn.** `scan_input` sets `TurnSignals`; `check_tool_call` reads them (input flagged for injection + a proposed write-capable tool → deny); `scan_output` computes a consolidated turn-risk that can block a turn even when no single scanner blocked.
4. **Cross-turn threat accumulation.** Adversarial patterns that stay below any single turn's threshold are caught at the session level.
5. **Signed, tamper-evident audit trail.** HMAC-SHA256 over every event, one event per boundary call, no raw content ever recorded. Structured for SIEM ingestion.
6. **Framework-agnostic drop-in.** Same package integrates with LangGraph, LangChain, CrewAI, PydanticAI, Anthropic SDK, and OpenAI Agents. You don't rewrite your agent to add SHAI.

Prompt injection defence is one of the things a harness has to do. It is not the whole job, and it is not what makes SHAI different.

### Where SHAI is not

- Not a replacement for prompt-level safety fine-tuning
- Not a runtime sandbox for tool execution — it gates dispatch; a compromised tool implementation is still dangerous
- Not sufficient on its own against a well-resourced adaptive adversary — no single layer is
- Not a substitute for network egress controls at the infrastructure layer

---

## Honest coverage claim

We implement deterministic controls that map to the OWASP Top 10 for LLM
Agentic Applications. Coverage is **layered and imperfect by design** — no
single scanner catches every attack, and a bundled regex catalog can be
studied and bypassed by anyone who reads the source (yours can too, and
you should assume they will).

The [THREAT_MODEL.md](THREAT_MODEL.md) file has the honest mapping:
which threat maps to which boundary, which tests demonstrate the control,
and — critically — the residual risks each control does not close.

Please read it before you deploy SHAI as the sole security layer for anything
that matters.

---

## Contributing

**Feature proposals and bug reports are very welcome — open an issue.**

Code PRs are not being accepted at this stage. I do not have capacity to
review external contributions properly, and merging code I cannot review
carefully would be a disservice to everyone building on SHAI. This will
change; for now, see [CONTRIBUTING.md](CONTRIBUTING.md) for the full policy.

CI runs unit tests, contract tests, security-invariant tests, `pip-audit`
(CVE scan), `bandit` (static analysis), and `gitleaks` (secret scan) on
every PR. Nothing merges without a green pipeline.

Security issues: see [SECURITY.md](SECURITY.md). Do not open a public issue.

---

## License

Apache-2.0. See [LICENSE](LICENSE).
