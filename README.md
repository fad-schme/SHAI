# SHAI

> **Live documentation**
>
> To help you get up to speed quickly, SHAI ships interactive documentation as a set of skills that can answer your questions directly in your workflow.
>
> Website: [shai.aibestlabs.com](https://shai.aibestlabs.com)  
> Full docs: [shai.aibestlabs.com/docs.html](https://shai.aibestlabs.com/docs.html)

**Secure Harness AI for production agents.**

SHAI is the security control plane that sits between your agent, its tools, and the outside world.

It helps you:

- scan inputs before they reach the model
- govern every tool call before it executes
- inspect tool results before they go back into context
- scan final responses before they leave the system
- log every decision for traceability and compliance

If your agent can send emails, read files, query databases, or call external APIs, SHAI gives you a clean enforcement layer without forcing you to redesign your stack.

## Why teams use SHAI

SHAI is built for teams that want agent velocity without giving up control.

- **Safer by default**: prompt injection, PII, risky tool calls, and unsafe outputs are checked at the right boundaries
- **Simple to adopt**: drop it into existing agent flows instead of rebuilding the whole application
- **Policy driven**: define what tools and actions are allowed, denied, or redacted
- **Audit ready**: every boundary produces structured events for observability and review

## What SHAI protects

SHAI wraps the full agent turn:

```text
User Input -> Ingress Scan -> LLM -> Tool Governance -> Tool -> Tool Result Scan -> LLM -> Output Scan -> Response
```

Core protection areas:

- **Ingress Scan**: checks user messages and files before they reach the model
- **Tool Governance**: enforces allowlists, tags, rate limits, session budgets, and policy rules on every tool call
- **Tool Result Scan**: inspects tool output before it returns to model context
- **Output Scan**: checks final responses for leakage or unsafe content
- **MCP Governance**: validates MCP metadata before tools are even registered

## Install

```bash
pip install shai
```

Requires Python 3.11+.

## Quick start

**Works with agents you're already running**

You don't need to rebuild anything. SHAI ships with native integrations for every major framework:

`LangGraph` `LangChain` `CrewAI` `Anthropic SDK` `PydanticAI` `OpenAI Agents`

If you already have an agent running in production, SHAI can protect it today, without changing your agent logic.
SHAI doesn't replace your agent framework. It completes it.

Start with the live quickstart in the docs:

- [Quickstart guide](https://shai.aibestlabs.com/docs.html#quickstart)
- [Full documentation](https://shai.aibestlabs.com/docs.html)

## Included out of the box

- input normalization and de-obfuscation (base64, rot13, homoglyphs, fragmentation)
- input scanning for prompt injection, jailbreak attempts, agentic identity spoofing, and PII
- tool-call governance with layered policy enforcement
- session execution budgets (step counter, token burn-down, fan-out limiter, loop detection)
- cross-turn threat accumulator (crescendo attack detection, SQLite-backed, persistent across restarts)
- tool-result scanning for indirect injection risk
- output scanning for leakage control
- MCP metadata scanning
- audit events for every boundary
- connector-ready architecture for governed external tools

## OWASP coverage

| OWASP threat | Coverage | SHAI control |
|---|---|---|
| `T1` Goal and instruction hijacking | **Full** | normalization, injection scan, jailbreak scan, identity spoof scan, MCP metadata scanning, tool governance |
| `T2` Tool misuse | Full | allowlists, tag scoping, policy rules, rate limits |
| `T3` Uncontrolled agent actions | Full | layered tool governance, scoped permissions, policy enforcement |
| `T4` Resource overload | Full | rate limits, session budgets (step counter, token burn-down, fan-out ceiling, loop detection) |
| `T5` Direct prompt injection | **Full** | normalization + injection scan + jailbreak scan + identity spoof scan |
| `T6` Indirect prompt injection | Full | tool-result scanning, MCP governance |
| `T7` Escalation via multi-turn | **Full** | cross-turn threat accumulator (crescendo detection) |
| `T8` Repudiation and untraceability | Full | audit events at every boundary |
| `T9` Privilege escalation | Full | subagent scoping, layered tool governance, identity spoof scan |
| `T11` Sensitive data exposure | Full | PII scanning on input, tool args, and output |
| `T16` Data exfiltration | Partial | output scanning and governed connectivity paths |
| `T17` Supply chain compromise | Partial | MCP metadata scanning, source governance, and file scanning |

## Learn more

- Product site: [shai.aibestlabs.com](https://shai.aibestlabs.com)
- Full documentation: [shai.aibestlabs.com/docs.html](https://shai.aibestlabs.com/docs.html)
- Architecture overview: [ARCHITECTURE.md](ARCHITECTURE.md)

The website and live docs describe the full model, connectors, policies, and integration patterns in detail.

## License

Apache-2.0. See [LICENSE](LICENSE) for details.
