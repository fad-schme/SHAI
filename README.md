# SHAI

**Secure Harness AI — the security control plane for production AI agents.**

SHAI sits between your agent and everything it can touch. It scans inputs, gates every tool call through a deterministic policy, scans tool results for indirect injection, and audits every decision — before anything executes.

One Python package. Works with LangGraph, LangChain, CrewAI, PydanticAI, Anthropic SDK, OpenAI Agents, or your own loop.

> **Live documentation**
>
> SHAI includes a set of Claude Skills in the repo — structured knowledge files your coding agent (Claude Code, Cursor, Windsurf) picks up automatically. Instead of reading docs, ask your agent directly: "How do I add tool result scanning?" — it already knows the codebase.
>
> 🌐 Website: [shai.aibestlabs.com](https://shai.aibestlabs.com)  
> 📄 Full docs: [shai.aibestlabs.com/docs.html](https://shai.aibestlabs.com/docs.html)

---

## Why SHAI exists

Everyone's racing to make AI agents smarter. Nobody's making them safe.

Agents can write your code, manage your inbox, deploy your infrastructure, and make hundreds of autonomous decisions before you've had your morning coffee. The productivity is real. But so is the risk.

AI agents are a fundamentally new kind of security problem.

OWASP recognized this and published the first-ever security framework for AI agents — ten threat categories specific to autonomous systems: prompt injection, tool misuse, privilege escalation, memory poisoning, supply chain compromise, rogue agents, and more. A clear map of what can go wrong.

**The correct approach treats security risks as expected operational conditions, not exceptional events.** The goal is not to prevent the model from ever misbehaving. The goal is to build a system that survives the model misbehaving. That requires enforcement at the system boundary — deterministic code that evaluates what the agent *proposes to do*, independently of why it proposed it.

Nobody had built the open source layer to actually prevent it. **Until SHAI.**

SHAI is a Python package — not an agent itself, but the security harness that wraps around one. You keep building with whatever framework you love: LangChain, LangGraph, CrewAI, PydanticAI, or your own custom loop. SHAI sits around it and protects it, covering every threat on the OWASP Agentic AI list. It works on new agents you're building today, and on existing ones already running in production.

---

## What it protects

```
user input → [scan] → LLM → [gate] → tool → [scan result] → LLM → [scan] → response
```

| Boundary | What it catches |
|---|---|
| `scan_input` | Prompt injection, jailbreaks, PII |
| `check_tool_call` | Unauthorized tools, argument violations, policy violations |
| `scan_tool_result` | Indirect injection in documents, API responses |
| `scan_output` | PII leakage, data exfiltration |

---

## Quick start

```bash
git clone https://github.com/fad-schme/SHAI.git
cd SHAI
pip install -e .
python examples/quickstart.py
```
Requires Python 3.11+.

No API keys. No LLM. The script exercises every boundary with real scanners and real policy. You'll see input blocked, PII redacted, tool calls denied, and the full audit trail.

Then wire it into your agent:

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

See the [full docs](https://shai.aibestlabs.com/docs.html) for framework-specific templates (LangGraph, LangChain, CrewAI, Anthropic SDK, PydanticAI, OpenAI Agents).

---

## License

Apache-2.0. See [LICENSE](LICENSE).
