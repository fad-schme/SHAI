"""langchain_agent_loop.py — SHAI + LangChain Agent Loop (create_agent)

Uses the LangChain Agent Loop (langchain>=0.3) with ShaiMiddleware.
SHAI wires into the official middleware API — no manual loop needed.

  ShaiMiddleware hooks:
    before_agent   → scan_input   (PII + injection scan on user message)
    wrap_tool_call → check_tool_call + scan_tool_result (gate + T6 protection)
    after_agent    → scan_output  (PII scan on final response)

Configuration:
  config/harness.yaml                   — scanner actions, rate limits, policy
  config/agents/orchestrator_agent.yaml — tool permissions, subagents

Install:
    pip install -e ".[dev]"
    pip install "langchain>=0.3" langgraph langchain-ollama langchain-core

Run:
    python examples/langchain_agent_loop.py
"""
from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent))

from display import (print_header, print_startup, print_user,
                     print_thinking, print_agent, print_blocked,
                     print_audit_summary, print_gate_summary)

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"

logging.basicConfig(level=logging.WARNING)
for name in ("httpx", "harness", "langchain", "langgraph"):
    logging.getLogger(name).setLevel(logging.WARNING)


# ── Tools — defined once, used everywhere ─────────────────────────────────

from harness.integrations.langchain import shai_tool, ShaiMiddleware

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
        from langchain.agents import create_agent
        from langchain_ollama import ChatOllama
        from langchain_core.messages import HumanMessage
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print('Install:  pip install "langchain>=0.3" langgraph langchain-ollama langchain-core')
        sys.exit(1)

    from harness import SHAI

    print_header("SHAI  +  LangChain Agent Loop  +  Ollama (qwen2.5:3b)",
                 "ShaiMiddleware · before_agent · wrap_tool_call · after_agent")

    harness   = await SHAI.from_yaml(HARNESS_YAML)
    agent_ctx = await harness.load_agent(AGENT_YAML)

    # ShaiMiddleware.create() registers tools and builds the middleware.
    # Pass the same tools list to create_agent — one list, no duplication.
    middleware = await ShaiMiddleware.create(tools, harness=harness, ctx=agent_ctx)

    llm = ChatOllama(model="qwen2.5:3b", temperature=0)

    agent = create_agent(
        llm,
        tools=tools,
        middleware=[middleware],
    )

    print_startup(harness, [("search_docs", ""), ("get_weather", ""),
                             ("write_file", "blocked by policy")])

    question = ("What is the vacation policy? "
                "Also, what is the weather in Munich today?")

    print_user(question)
    print_thinking()

    # collect_events() captures all audit events from all four boundaries.
    # The middleware handles scan_input, check_tool_call, scan_tool_result,
    # and scan_output — all internally, without any manual calls here.
    with harness.collect_events() as events:
        result = await agent.ainvoke({"messages": [HumanMessage(question)]})

    # Extract final response — last AIMessage with no tool_calls
    messages      = result.get("messages", [])
    response_text = ""
    for msg in reversed(messages):
        if hasattr(msg, "content") and not getattr(msg, "tool_calls", None):
            response_text = str(msg.content)
            break

    if not response_text:
        response_text = "[No response generated]"

    print_agent(response_text)
    print_audit_summary(events)
    print_gate_summary(events)

    await harness.close()


if __name__ == "__main__":
    asyncio.run(main())
