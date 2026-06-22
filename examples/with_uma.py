"""with_uma.py — SHAI + UMA (Unified Memory API) coexistence example.

Shows the correct boundary between SHAI (security control plane) and UMA
(memory / retrieval). SHAI never touches memory. UMA never touches tool gates.

The agent loop:
  1. UMA retrieves relevant context for the user message
  2. SHAI gates the input scan
  3. The LLM uses context + user message
  4. SHAI gates each tool call
  5. SHAI gates the output scan
  6. UMA stores the turn in memory

This example runs without requiring a real UMA implementation — it uses
a minimal stub that demonstrates the integration points.

Run from repo root:
    python examples/with_uma.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harness import Harness, RuntimeContext, Tool
from harness.core.types import Transport
from harness.integrations.anthropic_sdk import gated_dispatch

CONFIG = Path(__file__).parent.parent / "config"
AGENT_YAML = CONFIG / "agents" / "orchestrator_agent.yaml"


# ── Minimal UMA stub ──────────────────────────────────────────────────────

class StubUMA:
    """Placeholder for a real UMA implementation.

    In production this would be replaced with an actual Unified Memory API
    client that provides semantic retrieval and persistent storage.
    """

    def __init__(self):
        self._memory: list[dict[str, str]] = []

    async def retrieve(self, query: str, agent_id: str) -> list[dict]:
        """Retrieve relevant context for a query."""
        relevant = [m for m in self._memory if query[:10].lower() in m["content"].lower()]
        return relevant[-3:]  # return last 3 relevant items

    async def store(self, agent_id: str, role: str, content: str) -> None:
        """Store a turn in memory."""
        self._memory.append({"agent_id": agent_id, "role": role, "content": content})


# ── Tool implementations ──────────────────────────────────────────────────

async def search_docs(query: str) -> str:
    return f"[search_docs] Found docs for: {query}"


# ── The integrated agent loop ─────────────────────────────────────────────

async def agent_turn(
    user_text: str,
    *,
    harness: Harness,
    uma: StubUMA,
    ctx: RuntimeContext,
) -> str:
    """One full turn: UMA retrieve → SHAI scan → LLM → SHAI gate → SHAI scan → UMA store."""

    # 1. UMA: retrieve relevant memory (before SHAI — pure retrieval, no security concern)
    memory_context = await uma.retrieve(user_text, ctx.agent_id)
    print(f"[UMA retrieve]  {len(memory_context)} relevant memories")

    # 2. UMA: store user turn
    await uma.store(ctx.agent_id, "user", user_text)

    # 3. SHAI: load sources for this turn
    tools = await harness.load_sources(ctx)

    # 4. SHAI: scan input
    input_verdict = await harness.scan_input(user_text, ctx)
    if input_verdict.blocked:
        await harness.unload_sources(ctx)
        return "[blocked: input scan]"

    print(f"[SHAI scan_in]  blocked={input_verdict.blocked}")

    # 5. Simulate LLM deciding to call a tool
    # In production: call the LLM with user_text + memory_context + tools
    simulated_tool_call = ("search_docs", {"query": user_text[:30]})
    print(f"[LLM]           requesting tool: {simulated_tool_call[0]}")

    # 6. SHAI: gate tool call
    async def dispatcher(name: str, args: dict) -> Any:
        if name == "search_docs":
            return await search_docs(**args)
        raise ValueError(f"unknown tool: {name}")

    tool_result = await gated_dispatch(
        simulated_tool_call[0],
        simulated_tool_call[1],
        ctx,
        harness=harness,
        dispatch=dispatcher,
    )
    print(f"[SHAI gate]     allowed={not hasattr(tool_result, 'allowed') or tool_result.allowed}")
    print(f"[tool result]   {tool_result!r}")

    # 7. Simulate LLM producing a final response
    llm_response = f"Based on the docs: {tool_result}"

    # 8. SHAI: scan output
    output_verdict = await harness.scan_output(llm_response, ctx)
    print(f"[SHAI scan_out] blocked={output_verdict.blocked}")

    final = output_verdict.redacted_text or llm_response

    # 9. SHAI: unload sources
    await harness.unload_sources(ctx)

    # 10. UMA: store assistant turn (after SHAI — store the safe, possibly-redacted response)
    await uma.store(ctx.agent_id, "assistant", final)

    return final


async def main() -> None:
    print("=" * 60)
    print("SHAI + UMA — coexistence example")
    print("=" * 60)
    print()
    print("Architecture:")
    print("  UMA  owns: memory retrieval, conversation storage")
    print("  SHAI owns: input scan, tool gates, output scan")
    print("  Neither owns the other. Clean separation.")
    print()

    harness = Harness.from_yaml(CONFIG / "harness.yaml")
    uma     = StubUMA()

    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"], transport=Transport.LOCAL),
    ])
    await harness.load_agent(AGENT_YAML)

    ctx = RuntimeContext(agent_id="orchestrator_agent")

    # Pre-populate some memory
    await uma.store("orchestrator_agent", "user", "Tell me about onboarding")
    await uma.store("orchestrator_agent", "assistant", "Onboarding involves setup.md")

    print("\n── Turn 1 ───────────────────────────────────────────────────")
    response = await agent_turn(
        "What is the onboarding process?",
        harness=harness, uma=uma, ctx=ctx,
    )
    print(f"\n[Response] {response!r}")

    print("\n── Turn 2 (subagent) ────────────────────────────────────────")
    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    print(f"[scope_subagent] sub_agent_id={child_ctx.sub_agent_id}")
    print(f"                 allowed_tags={child_ctx.allowed_tags}")

    response2 = await agent_turn(
        "Find policy documents",
        harness=harness, uma=uma, ctx=child_ctx,
    )
    print(f"\n[Response] {response2!r}")

    await harness.close()
    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())
