"""langgraph_agent.py — SHAI + LangGraph integration example.

Demonstrates HarnessToolNode as a drop-in replacement for LangGraph's ToolNode.

This example runs WITHOUT requiring LangGraph or an Anthropic API key by using
a MockLLM that simulates a model requesting tool calls.

Run from repo root:
    python examples/langgraph_agent.py

For a real LangGraph graph, see the inline commented section at the bottom.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harness import Harness, RuntimeContext, Tool
from harness.core.types import Transport
from harness.integrations.langgraph import HarnessToolNode

CONFIG = Path(__file__).parent.parent / "config"
AGENT_YAML = CONFIG / "agents" / "orchestrator_agent.yaml"


# ── Minimal tool implementations ──────────────────────────────────────────

async def search_docs_fn(query: str) -> str:
    return f"Found 3 results for: {query}"


async def send_email_fn(to: str, subject: str, body: str) -> str:
    return f"Email sent to {to}"


class _FakeTool:
    """Minimal tool shim — real code would use @tool from langchain-core."""
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    async def ainvoke(self, args: dict) -> str:
        return await self._fn(**args)


# ── Simulate a LangGraph state with tool_calls ────────────────────────────

class _FakeAIMessage:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class _MockLangChainToolMessage:
    def __init__(self, content, tool_call_id, status="ok"):
        self.content = content
        self.tool_call_id = tool_call_id
        self.status = status

    def __repr__(self):
        return f"ToolMessage(id={self.tool_call_id!r}, status={self.status!r}, content={self.content!r})"


async def main() -> None:
    print("=" * 60)
    print("SHAI + LangGraph — HarnessToolNode example")
    print("=" * 60)

    harness = Harness.from_yaml(CONFIG / "harness.yaml")
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
    ])
    await harness.load_agent(AGENT_YAML)

    ctx = RuntimeContext(agent_id="orchestrator_agent")

    tools = [
        _FakeTool("search_docs", search_docs_fn),
        _FakeTool("send_email",  send_email_fn),
    ]

    node = HarnessToolNode(tools=tools, harness=harness, ctx=ctx)

    # Simulate LangGraph state with two tool calls
    state = {
        "messages": [
            _FakeAIMessage(tool_calls=[
                {"name": "search_docs", "args": {"query": "onboarding guide"}, "id": "tc1"},
                {"name": "send_email",  "args": {"to": "bob@x.com", "subject": "hi", "body": "hello"}, "id": "tc2"},
            ])
        ]
    }

    # Monkey-patch LangChain types since we don't have them installed
    import harness.integrations.langgraph as lg_mod
    import unittest.mock as mock

    FakeAIMessage = _FakeAIMessage
    FakeToolMessage = _MockLangChainToolMessage

    with mock.patch.dict("sys.modules", {
        "langchain_core": mock.MagicMock(),
        "langchain_core.messages": mock.MagicMock(
            AIMessage=FakeAIMessage,
            ToolMessage=FakeToolMessage,
        ),
    }):
        # Re-import to pick up mock
        import importlib
        importlib.reload(lg_mod)
        node2 = lg_mod.HarnessToolNode(tools=tools, harness=harness, ctx=ctx)
        result = await node2(state)

    print("\n── Tool results ─────────────────────────────────────────────")
    for msg in result.get("messages", []):
        print(f"  {msg}")

    await harness.close()
    print("\nDone.")
    print()
    print("Real LangGraph usage:")
    print("  from harness.integrations.langgraph import HarnessToolNode")
    print("  tool_node = HarnessToolNode(tools=[search, email], harness=h, ctx=ctx)")
    print("  graph.add_node('tools', tool_node)")


if __name__ == "__main__":
    asyncio.run(main())
