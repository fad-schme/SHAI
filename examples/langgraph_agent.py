"""langgraph_agent.py — SHAI + LangGraph + Ollama

A minimal but fully working ReAct agent using:
  - Ollama (local LLM, qwen2.5:3b)
  - LangGraph (agent loop and state management)
  - SHAI (security harness — scan, gate, audit)

Install:
    pip install -e ".[dev]"
    pip install langgraph langchain-ollama langchain-core

Run:
    python examples/langgraph_agent.py
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"

# ── Silence noisy loggers — we print our own formatted output ─────────────
logging.basicConfig(level=logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("harness").setLevel(logging.WARNING)
logging.getLogger("langchain").setLevel(logging.WARNING)
logging.getLogger("langgraph").setLevel(logging.WARNING)

# ── ANSI colours ──────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BLUE   = "\033[34m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

USE_COLOUR = sys.stdout.isatty()

def c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}" if USE_COLOUR else text


# ── Audit capture sink ────────────────────────────────────────────────────
# Replaces stdout JSONL with a capture buffer so we can pretty-print later.

class CaptureSink:
    """In-process audit sink — collects events for end-of-run summary."""
    name = "capture"
    def __init__(self):
        self.events: list[dict] = []

    async def emit(self, event) -> None:
        self.events.append(json.loads(event.model_dump_json()))

    async def close(self) -> None:
        pass


# ── Tool implementations ──────────────────────────────────────────────────

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
    # Intentionally blocked by agent policy — demonstrates deny in action
    return f"Wrote {len(content)} bytes to {path}"


# ── Pretty-print helpers ──────────────────────────────────────────────────

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

    boundary_labels = {
        "input_scan":       "Input scan      ",
        "tool_call_gate":   "Tool gate       ",
        "tool_result_scan": "Tool result scan",
        "output_scan":      "Output scan     ",
        "file_scan":        "File scan       ",
    }
    decision_colours = {
        "allow":   GREEN,
        "deny":    RED,
        "blocked": RED,
        "redact":  YELLOW,
    }
    decision_icons = {
        "allow":   "✓",
        "deny":    "✗",
        "blocked": "✗",
        "redact":  "~",
    }

    for i, ev in enumerate(events):
        is_last   = i == len(events) - 1
        tree_char = "└" if is_last else "├"

        boundary = ev.get("boundary", "?")
        decision = ev.get("decision", "?")
        dur      = ev.get("duration_ms", 0)
        tool     = ev.get("tool_name")
        reason   = ev.get("deny_reason")
        findings = ev.get("finding_count", 0)
        max_sev  = ev.get("max_severity")
        disabled = ev.get("disabled", False)

        label = boundary_labels.get(boundary, f"{boundary:<16}")
        col   = decision_colours.get(decision, DIM)
        icon  = decision_icons.get(decision, "?")

        # Main line
        if disabled:
            status = c(DIM, f"{icon} {decision.upper()} (disabled)")
        else:
            status = c(col, f"{icon} {decision.upper()}")

        detail = ""
        if tool:
            detail += f"  tool={c(CYAN, tool)}"
        if findings:
            detail += f"  findings={c(YELLOW, str(findings))}"
            if max_sev:
                detail += f" max={c(YELLOW, max_sev)}"
        if dur:
            detail += f"  {c(DIM, f'{dur}ms')}"

        print(f"  │  {tree_char}─ {label}  {status}{detail}")

        # Denial reason on its own line
        if reason:
            pad = "      " if is_last else "  │   "
            print(f"  │  {pad}   {c(RED, '↳')} {c(DIM, reason)}")

    print(f"  └{'─'*50}")
    total  = len(events)
    allows = sum(1 for e in events if e["decision"] == "allow")
    denies = sum(1 for e in events if e["decision"] in ("deny", "blocked"))
    print(f"     {total} event(s):  "
          f"{c(GREEN, str(allows) + ' allowed')}  "
          f"{c(RED,   str(denies) + ' denied/blocked') if denies else c(DIM, '0 denied')}")


async def main() -> None:
    try:
        from langchain_ollama import ChatOllama
        from langchain_core.tools import tool as lc_tool
        from langchain_core.messages import HumanMessage, AIMessage
        from langgraph.graph import StateGraph, MessagesState, END
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print("Install with:")
        print("  pip install langgraph langchain-ollama langchain-core")
        sys.exit(1)

    from harness import SHAI, Tool
    from harness.core.context import AgentContext
    from harness.core.types import Transport
    from harness.integrations.langgraph import HarnessToolNode

    print_header("SHAI  +  LangGraph  +  Ollama (qwen2.5:3b)")
    print(c(DIM, "  Security control plane demonstration"))

    # ── SHAI setup ────────────────────────────────────────────────────────
    print_section("Starting up")

    sink    = CaptureSink()
    harness = await SHAI.from_yaml(HARNESS_YAML)
    # Replace the default stdout sink with our capture sink
    harness._emitter._sinks = [sink]

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],       transport=Transport.LOCAL),
        Tool(name="get_weather", tags=["read", "external_read"],  transport=Transport.LOCAL),
        Tool(name="write_file",  tags=["write"],                  transport=Transport.LOCAL),
    ])
    await harness.load_agent(AGENT_YAML)
    agent_ctx = AgentContext(agent_id="orchestrator_agent")

    print(f"  │  {c(GREEN, '✓')} SHAI loaded  "
          f"(tenant={c(CYAN, harness._tenant_id)}, "
          f"agent={c(CYAN, 'orchestrator_agent')})")
    print(f"  │  {c(GREEN, '✓')} 3 tools registered: "
          f"{c(CYAN, 'search_docs')}, {c(CYAN, 'get_weather')}, "
          f"{c(CYAN, 'write_file')} (blocked by policy)")
    print(f"  └{'─'*50}")

    # ── LangChain tools ───────────────────────────────────────────────────
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
    async def agent_node(state):
        response = await llm.ainvoke(state["messages"])
        return {"messages": [response]}

    tool_node = HarnessToolNode(tools=lc_tools, harness=harness, ctx=agent_ctx)

    def should_continue(state):
        last = state["messages"][-1]
        if isinstance(last, AIMessage) and last.tool_calls:
            return "tools"
        return END

    graph = StateGraph(MessagesState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.set_entry_point("agent")
    graph.add_conditional_edges("agent", should_continue)
    graph.add_edge("tools", "agent")
    app = graph.compile()

    # ── Run ───────────────────────────────────────────────────────────────
    question = (
        "What is the vacation policy? my credit card number is 1234-5678-9012-3456. "
        "Also, what is the weather in Munich today?"
    )

    print_section("Conversation")
    print(f"  │  {c(BOLD, 'User:')}  {question}")
    print(f"  │")
    print(f"  │  {c(DIM, 'Thinking...')}", end="\r", flush=True)

    # Scan input
    input_verdict = await harness.scan_input(question, agent_ctx)
    if input_verdict.blocked:
        print(f"  │  {c(RED, '✗ Input blocked by SHAI')}  "
              f"(findings: {input_verdict.findings})")
        print(f"  └{'─'*50}")
        await harness.close()
        return

    # Run the agent graph
    result = await app.ainvoke({"messages": [HumanMessage(content=question)]})

    # Scan output
    final        = result["messages"][-1]
    response_text = final.content if hasattr(final, "content") else str(final)
    out_verdict  = await harness.scan_output(response_text, agent_ctx)
    safe_response = out_verdict.redacted_text or response_text

    # Clear the "Thinking..." line
    print(f"  │  {' ' * 40}", end="\r")
    print(f"  │  {c(BOLD, 'Agent:')}  {safe_response}")
    if out_verdict.redacted_text:
        print(f"  │  {c(YELLOW, '  ↳ (output was redacted by scan_output)')}")
    print(f"  └{'─'*50}")

    # ── Audit summary ──────────────────────────────────────────────────────
    print_audit_summary(sink.events)

    # ── What SHAI did ──────────────────────────────────────────────────────
    tool_gates = [e for e in sink.events if e["boundary"] == "tool_call_gate"]
    if tool_gates:
        print_section("What SHAI enforced")
        for ev in tool_gates:
            tool    = ev.get("tool_name", "?")
            decision = ev["decision"]
            reason  = ev.get("deny_reason", "")
            if decision == "allow":
                print(f"  │  {c(GREEN, '✓')} {c(CYAN, tool)} — allowed through gate")
            else:
                print(f"  │  {c(RED, '✗')} {c(CYAN, tool)} — {c(RED, 'DENIED')}  {c(DIM, reason)}")
        print(f"  └{'─'*50}")

    await harness.close()
    print()


if __name__ == "__main__":
    asyncio.run(main())