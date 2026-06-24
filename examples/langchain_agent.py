"""langchain_agent.py — SHAI + LangChain + Ollama

Uses LangChain's tool-calling interface with a manual agent loop.
Simpler than LangGraph for single-agent use cases — no graph needed.

Configuration:
  config/harness.yaml                   — scanner actions, rate limits, policy
  config/agents/orchestrator_agent.yaml — tool permissions, subagents

Install:
    pip install -e ".[dev]"
    pip install langchain-ollama langchain-core langchain

Run:
    python examples/langchain_agent.py
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
for name in ("httpx", "harness", "langchain"):
    logging.getLogger(name).setLevel(logging.WARNING)


# ── Tools — defined once, used everywhere ─────────────────────────────────

from harness.integrations.langchain import shai_tool, wrap_tools

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


# ── Manual tool-calling loop ───────────────────────────────────────────────
# LangChain's create_react_agent / create_tool_calling_agent both require
# AgentExecutor to run the loop, which hides the intermediate tool calls
# from SHAI's scan_tool_result. A manual loop gives us full control:
#   1. LLM responds with tool_calls
#   2. SHAI gates and dispatches each call
#   3. SHAI scans the tool result before it re-enters the LLM context
#   4. Repeat until the LLM produces a final text response

async def run_agent_loop(llm, gated_tools, messages, harness, agent_ctx):
    """Run the tool-calling loop until the LLM produces a final response."""
    from langchain_core.messages import ToolMessage

    tool_map = {t.name: t for t in gated_tools}
    max_iterations = 10

    for _ in range(max_iterations):
        response = await llm.ainvoke(messages)
        messages.append(response)

        # No tool calls → LLM is done
        if not getattr(response, "tool_calls", None):
            return response.content

        # Execute each tool call through the harness
        for tc in response.tool_calls:
            name    = tc["name"]
            args    = tc["args"]
            call_id = tc["id"]

            tool_fn = tool_map.get(name)
            if tool_fn is None:
                result = f"Tool '{name}' not found"
            else:
                try:
                    raw = await tool_fn._async_call(**args)
                except Exception as e:
                    raw = f"Tool error: {e}"

                # Scan tool result before it re-enters LLM context (T6)
                tverdict = await harness.scan_tool_result(str(raw), agent_ctx)
                if tverdict.blocked:
                    result = f"Tool result blocked by SHAI (indirect injection detected)"
                else:
                    result = tverdict.redacted_text or str(raw)

            messages.append(ToolMessage(content=result, tool_call_id=call_id))

    return "Maximum iterations reached without a final answer."


# ── Agent ──────────────────────────────────────────────────────────────────

async def main() -> None:
    try:
        from langchain_ollama import ChatOllama
        from langchain_core.messages import SystemMessage, HumanMessage
    except ImportError as e:
        print(f"\nMissing dependency: {e}")
        print("Install:  pip install langchain-ollama langchain-core")
        sys.exit(1)

    from harness import SHAI

    print_header("SHAI  +  LangChain  +  Ollama (qwen2.5:3b)",
                 "config/harness.yaml · config/agents/orchestrator_agent.yaml")

    harness   = await SHAI.from_yaml(HARNESS_YAML)
    agent_ctx = await harness.load_agent(AGENT_YAML)

    # wrap_tools() registers tools with the harness and returns
    # gated LangChain-compatible wrappers — one call, no duplication.
    gated_tools = await wrap_tools(tools, harness=harness, ctx=agent_ctx)

    print_startup(harness, [("search_docs", ""), ("get_weather", ""),
                             ("write_file", "blocked by policy")])

    # Bind gated_tools so the LLM sees the tool schemas
    # and the harness gate fires on every invocation
    llm = ChatOllama(model="qwen2.5:3b", temperature=0).bind_tools(gated_tools)

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

        messages = [
            SystemMessage(content="You are a helpful assistant. Use tools to answer questions."),
            HumanMessage(content=question),
        ]

        response_text = await run_agent_loop(
            llm, gated_tools, messages, harness, agent_ctx
        )

        out_verdict = await harness.scan_output(response_text, agent_ctx)

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