"""langgraph_agent.py — SHAI + LangGraph + Ollama

Configuration:
  config/harness.yaml                   — scanner actions, rate limits, policy
  config/agents/orchestrator_agent.yaml — tool permissions, subagents

Install:
    pip install shai-harness
    pip install langgraph langchain-ollama langchain-core

Run:
    python examples/langgraph_agent.py
"""
from __future__ import annotations

# Windows consoles default to a legacy codepage (cp1252), and every example
# below prints box-drawing characters. Without this the first print() raises
# UnicodeEncodeError before any SHAI output appears. Safe on POSIX, where the
# stream is already UTF-8.
import sys

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))      # for display.py

from display import (
    print_agent,
    print_audit_summary,
    print_blocked,
    print_gate_summary,
    print_header,
    print_startup,
    print_thinking,
    print_user,
)

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"

logging.basicConfig(level=logging.WARNING)
for name in ("httpx", "harness", "langchain", "langgraph"):
    logging.getLogger(name).setLevel(logging.WARNING)


# ── Tools — defined once, used everywhere ─────────────────────────────────

from harness.integrations.langgraph import HarnessToolNode, shai_tool


@shai_tool(tags=["read", "internal"])
def search_docs(query: str) -> str:
    """Search internal documentation for HR policies and procedures."""
    docs = {
        "onboarding": "Onboarding takes 3 days. Complete the IT setup checklist first.",
        "vacation":   "Vacation policy: 20 days/year, accrued monthly. Submit via HR portal.",
        "expenses":   "Expense reports must be submitted within 30 days of the purchase.",
    }
    for key, content in docs.items():
        if key in query.lower():
            return content
    return f"No documentation found for: {query}"

@shai_tool(tags=["read", "external_read"])
def get_weather(city: str) -> str:
    """Get the current weather conditions for a city."""
    weather = {"london": "Overcast, 12°C, 80% chance of rain",
               "munich": "Sunny, 18°C, clear"}
    return weather.get(city.lower(), f"Weather data unavailable for {city}")

@shai_tool(tags=["write"])
def write_file(path: str, content: str) -> str:
    """Write text content to a file at the given path."""
    return f"Wrote {len(content)} bytes to {path}"  # blocked by agent policy

tools = [search_docs, get_weather, write_file]


# ── Agent ──────────────────────────────────────────────────────────────────

async def main() -> None:
    try:
        from langchain_core.messages import AIMessage, HumanMessage
        from langchain_ollama import ChatOllama
        from langgraph.graph import END, MessagesState, StateGraph
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print("Install:  pip install langgraph langchain-ollama langchain-core")
        sys.exit(1)

    from harness import SHAI

    print_header("SHAI  +  LangGraph  +  Ollama (qwen2.5:3b)",
                 "config/harness.yaml · config/agents/orchestrator_agent.yaml")

    harness   = await SHAI.from_yaml(HARNESS_YAML)
    agent_ctx = await harness.load_agent(AGENT_YAML)

    # HarnessToolNode.create() registers tools with the harness.
    # Pass the same list to bind_tools() — one list, no duplication.
    llm       = ChatOllama(model="qwen2.5:3b", temperature=0).bind_tools(tools)
    tool_node = await HarnessToolNode.create(tools, harness, agent_ctx)

    print_startup(harness, [("search_docs", ""), ("get_weather", ""),
                             ("write_file", "blocked by policy")])

    async def agent_node(state):
        return {"messages": [await llm.ainvoke(state["messages"])]}

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

    question = ("What is the vacation policy? "
                "Also, what is the weather in Munich today?")

    print_user(question)
    print_thinking()

    with harness.collect_events() as events:
        verdict = await harness.scan_input(question, agent_ctx)
        if verdict.blocked:
            print_blocked("Input", str(verdict.findings))
            await harness.close()
            return

        result        = await app.ainvoke({"messages": [HumanMessage(content=question)]})
        final         = result["messages"][-1]
        response_text = final.content if hasattr(final, "content") else str(final)
        out_verdict   = await harness.scan_output(response_text, agent_ctx)

    if out_verdict.blocked:
        response_text = "[Response blocked by SHAI — output scan]"
    else:
        response_text = out_verdict.redacted_text or response_text

    print_agent(response_text, redacted=bool(out_verdict.redacted_text))
    print_audit_summary(events)
    print_gate_summary(events)

    await harness.close()


if __name__ == "__main__":
    asyncio.run(main())
