"""langgraph_agent.py — SHAI + LangGraph + Ollama

A minimal but fully working ReAct agent using:
  - Ollama (local LLM, qwen2.5:3b)
  - LangGraph (agent loop and state management)
  - SHAI (security harness — scan, gate, audit)

Configuration:
  Edit config/harness.yaml  to change scanner actions, rate limits,
                             policy rules, and audit settings.
  Edit config/agents/orchestrator_agent.yaml  to change tool permissions
                             and subagent declarations.

Install:
    pip install -e ".[dev]"
    pip install langgraph langchain-ollama langchain-core

Run:
    python examples/langgraph_agent.py
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"

# ── Silence noisy third-party loggers ────────────────────────────────────
logging.basicConfig(level=logging.WARNING)
for logger in ("httpx", "harness", "langchain", "langgraph"):
    logging.getLogger(logger).setLevel(logging.WARNING)

# ── ANSI colours ──────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"
USE_COLOUR = sys.stdout.isatty()

def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}" if USE_COLOUR else text


# ── Audit capture sink ─────────────────────────────────────────────────────

class CaptureSink:
    name = "capture"
    def __init__(self): self.events: list[dict] = []
    async def emit(self, event) -> None:
        self.events.append(json.loads(event.model_dump_json()))
    async def close(self) -> None: pass


# ── Tool implementations ───────────────────────────────────────────────────

def search_docs(query: str) -> str:
    docs = {
        "onboarding": "Onboarding takes 3 days. Complete the IT setup checklist first.",
        "vacation":   "Vacation policy: 20 days/year, accrued monthly. Submit via HR portal.",
        "expenses":   "Expense reports must be submitted within 30 days of the purchase.",
    }
    for key, content in docs.items():
        if key in query.lower():
            return content
    return f"No documentation found for: {query}"

def get_weather(city: str) -> str:
    weather = {
        "london":   "Overcast, 12°C, 80% chance of rain",
        "new york": "Sunny, 22°C, clear skies",
        "berlin":   "Partly cloudy, 15°C",
        "munich":   "Sunny, 18°C, clear",
    }
    return weather.get(city.lower(), f"Weather data unavailable for {city}")

def write_file(path: str, content: str) -> str:
    # Blocked by agent policy (write tag) — demonstrates deny in action
    return f"Wrote {len(content)} bytes to {path}"


# ── Display helpers ────────────────────────────────────────────────────────

def print_header(title: str) -> None:
    w = 62
    print()
    print(c(BOLD, "╔" + "═" * w + "╗"))
    print(c(BOLD, "║") + c(BOLD + CYAN, f"  {title:<{w-2}}") + c(BOLD, "  ║"))
    print(c(BOLD, "╚" + "═" * w + "╝"))

def print_section(title: str) -> None:
    print()
    print(c(BOLD, f"  ┌─ {title}"))

def print_audit_summary(events: list[dict]) -> None:
    print_section("SHAI Audit Trail")
    if not events:
        print(f"  │  {c(DIM, '(no events)')}")
        print(f"  └{'─'*50}")
        return

    labels = {
        "input_scan":       "Input scan      ",
        "tool_call_gate":   "Tool gate       ",
        "tool_result_scan": "Tool result scan",
        "output_scan":      "Output scan     ",
    }
    cols  = {"allow": GREEN, "deny": RED, "blocked": RED, "warn": YELLOW, "redact": YELLOW}
    icons = {"allow": "✓", "deny": "✗", "blocked": "✗", "warn": "⚠", "redact": "~"}

    for i, ev in enumerate(events):
        tree  = "└" if i == len(events) - 1 else "├"
        bnd   = ev.get("boundary", "?")
        dec   = ev.get("decision", "?")
        label = labels.get(bnd, f"{bnd:<16}")
        col   = cols.get(dec, DIM)
        icon  = icons.get(dec, "?")

        status = c(DIM, f"{icon} {dec.upper()} (disabled)") \
                 if ev.get("disabled") else c(col, f"{icon} {dec.upper()}")

        detail = ""
        if ev.get("tool_name"):
            detail += f"  tool={c(CYAN, ev['tool_name'])}"
        if ev.get("finding_count", 0):
            detail += f"  findings={c(YELLOW, str(ev['finding_count']))}"
            if ev.get("max_severity"):
                detail += f" max={c(YELLOW, ev['max_severity'])}"
        if ev.get("duration_ms"):
            detail += f"  {c(DIM, str(ev['duration_ms']) + 'ms')}"

        print(f"  │  {tree}─ {label}  {status}{detail}")
        if ev.get("deny_reason"):
            pad = "      " if i == len(events) - 1 else "  │   "
            print(f"  │  {pad}   {c(RED, '↳')} {c(DIM, ev['deny_reason'])}")

    print(f"  └{'─'*50}")
    allows = sum(1 for e in events if e["decision"] == "allow")
    denies = sum(1 for e in events if e["decision"] in ("deny", "blocked"))
    warns  = sum(1 for e in events if e["decision"] == "warn")
    parts  = [c(GREEN, f"{allows} allowed")]
    if warns:  parts.append(c(YELLOW, f"{warns} warned"))
    if denies: parts.append(c(RED,    f"{denies} denied/blocked"))
    print(f"     {len(events)} event(s):  {'  '.join(parts)}")


async def main() -> None:
    try:
        from langchain_ollama import ChatOllama
        from langchain_core.tools import tool as lc_tool
        from langchain_core.messages import HumanMessage, AIMessage
        from langgraph.graph import StateGraph, MessagesState, END
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print("Install with:  pip install langgraph langchain-ollama langchain-core")
        sys.exit(1)

    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport
    from harness.integrations.langgraph import HarnessToolNode

    print_header("SHAI  +  LangGraph  +  Ollama (qwen2.5:3b)")
    print(c(DIM, "  Config: config/harness.yaml  ·  config/agents/orchestrator_agent.yaml"))

    # ── SHAI ──────────────────────────────────────────────────────────────
    print_section("Starting up")

    harness = await SHAI.from_yaml(HARNESS_YAML)
    sink = CaptureSink()
    # Keep file sink (silent, writes to logs/audit.jsonl) but drop stdout sink
    # so raw JSONL doesn't interleave with the formatted output.
    file_sinks = [s for s in harness._emitter._sinks
                  if s.name != "stdout"]
    harness._emitter._sinks = file_sinks + [sink]

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],       transport=Transport.LOCAL),
        Tool(name="get_weather", tags=["read", "external_read"],  transport=Transport.LOCAL),
        Tool(name="write_file",  tags=["write"],                  transport=Transport.LOCAL),
    ])
    await harness.load_agent(AGENT_YAML)
    agent_ctx = AgentContext(agent_id="orchestrator_agent")

    cfg = harness._config
    inp_action  = cfg.scan_input.action
    out_action  = cfg.scan_output.action
    trs_action  = cfg.scan_tool_result.action
    rate_on     = cfg.check_tool_call.rate_limit.enabled

    print(f"  │  {c(GREEN, '✓')} SHAI loaded  (tenant={c(CYAN, harness._tenant_id)})")
    print(f"  │  {c(GREEN, '✓')} scan_input={c(CYAN, inp_action)}  "
          f"scan_output={c(CYAN, out_action)}  "
          f"scan_tool_result={c(CYAN, trs_action)}")
    print(f"  │  {c(GREEN, '✓')} rate_limit={c(CYAN, str(rate_on))}  "
          f"tools: search_docs, get_weather, {c(YELLOW, 'write_file (blocked by policy)')}")
    print(f"  └{'─'*50}")

    # ── LangChain tool wrappers ────────────────────────────────────────────
    @lc_tool("search_docs")
    def search_docs_tool(query: str) -> str:
        """Search internal documentation for HR policies, IT guides, and procedures."""
        return search_docs(query)

    @lc_tool("get_weather")
    def get_weather_tool(city: str) -> str:
        """Get the current weather conditions for a city."""
        return get_weather(city)

    @lc_tool("write_file")
    def write_file_tool(path: str, content: str) -> str:
        """Write text content to a file at the given path."""
        return write_file(path, content)

    lc_tools = [search_docs_tool, get_weather_tool, write_file_tool]

    # ── LLM ──────────────────────────────────────────────────────────────
    llm = ChatOllama(model="qwen2.5:3b", temperature=0).bind_tools(lc_tools)

    # ── Graph ─────────────────────────────────────────────────────────────
    # HarnessToolNode runs the full SHAI pipeline per tool call:
    #   check_tool_call → invoke → scan_tool_result
    # All config comes from HARNESS_YAML — no hardcoded settings here.
    async def agent_node(state):
        return {"messages": [await llm.ainvoke(state["messages"])]}

    tool_node = HarnessToolNode(tools=lc_tools, harness=harness, ctx=agent_ctx)

    def should_continue(state):
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue)
    graph.add_edge("tools", "agent")
    app = graph.compile()

    # ── Run ───────────────────────────────────────────────────────────────
    question = (
        "What is the vacation policy? "
        "Also, what is the weather in Munich today?"
    )

    print_section("Conversation")
    print(f"  │  {c(BOLD, 'User:')}  {question}")
    print(f"  │")
    print(f"  │  {c(DIM, 'Thinking...')}", end="\r", flush=True)

    # scan_input — config/harness.yaml determines action (block/alert/redact)
    input_verdict = await harness.scan_input(question, agent_ctx)
    if input_verdict.blocked:
        print(f"  │  {c(RED, '✗ Input blocked')}  "
              f"(findings: {input_verdict.findings})")
        print(f"  └{'─'*50}")
        await harness.close()
        return

    # Agent graph — HarnessToolNode handles gate + dispatch + scan_tool_result
    result = await app.ainvoke({"messages": [HumanMessage(content=question)]})

    # scan_output — config/harness.yaml determines action
    final         = result["messages"][-1]
    response_text = final.content if hasattr(final, "content") else str(final)
    out_verdict   = await harness.scan_output(response_text, agent_ctx)

    if out_verdict.blocked:
        response_text = "[Response blocked by SHAI — output scan]"
    else:
        response_text = out_verdict.redacted_text or response_text

    print(f"  │  {' ' * 50}", end="\r")
    print(f"  │  {c(BOLD, 'Agent:')}  {response_text}")
    if out_verdict.redacted_text:
        print(f"  │  {c(YELLOW, '  ↳ output redacted by scan_output')}")
    print(f"  └{'─'*50}")

    # ── Audit summary ─────────────────────────────────────────────────────
    print_audit_summary(sink.events)

    # ── Gate decisions ────────────────────────────────────────────────────
    gates = [e for e in sink.events if e["boundary"] == "tool_call_gate"]
    if gates:
        print_section("Tool gate decisions")
        for ev in gates:
            tool = ev.get("tool_name", "?")
            dec  = ev["decision"]
            if dec == "allow":
                print(f"  │  {c(GREEN, '✓')} {c(CYAN, tool)} — allowed")
            else:
                print(f"  │  {c(RED, '✗')} {c(CYAN, tool)} — {c(RED, dec.upper())}  "
                      f"{c(DIM, ev.get('deny_reason', ''))}")
        print(f"  └{'─'*50}")

    await harness.close()
    print()


if __name__ == "__main__":
    asyncio.run(main())
