"""hand_rolled_loop.py — canonical SHAI integration reference.

Demonstrates the full per-turn flow with a hand-rolled agent loop:
  load_sources → scan_input → [tool call gates] → scan_output → unload_sources

Run from the repo root:
    python examples/hand_rolled_loop.py

Expected output: JSONL audit events on stdout, plus a printed summary.

Requires: pip install -e ".[dev]"

User-managed config files live in config/ at the repo root.
Developers edit config/harness.yaml, config/agents/, and config/policies/
to configure SHAI for their deployment. These files are never inside the
package.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow running from repo root without install
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harness import Harness, RuntimeContext, Tool
from harness.core.types import Transport

# User-managed config — lives outside the package
CONFIG      = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"


async def main() -> None:
    print("=" * 60)
    print("SHAI — hand-rolled loop example")
    print("=" * 60)

    # ── 1. Build harness from user config ─────────────────────────────────
    harness = Harness.from_yaml(HARNESS_YAML)

    # ── 2. Register local tools at startup ───────────────────────────────
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])

    # ── 3. Load agent from user config ───────────────────────────────────
    await harness.load_agent(AGENT_YAML)

    # ── 4. Construct a per-turn RuntimeContext ────────────────────────────
    ctx = RuntimeContext(
        agent_id="orchestrator_agent",
    )

    print("\n── Turn start ───────────────────────────────────────────────")

    # ── 5. load_sources ───────────────────────────────────────────────────
    tools = await harness.load_sources(ctx)
    print(f"[load_sources]    {len(tools)} tools active: {[t.name for t in tools]}")

    # ── 6. scan_input ─────────────────────────────────────────────────────
    user_text = "Please search the docs for the onboarding guide."
    verdict = await harness.scan_input(user_text, ctx)
    print(f"[scan_input]      blocked={verdict.blocked}  findings={len(verdict.findings)}")
    if verdict.blocked:
        print("  Input blocked — turn aborted.")
        await harness.unload_sources(ctx)
        return

    # ── 7a. Tool call — ALLOW path ────────────────────────────────────────
    gate = await harness.check_tool_call(
        "search_docs",
        {"query": "onboarding guide", "limit": 5},
        ctx,
    )
    print(f"[check_tool_call] search_docs  allowed={gate.allowed}  reason={gate.deny_reason!r}")
    if gate.allowed:
        tool_result = "Found 3 documents: onboarding.pdf, setup.md, faq.html"
        print(f"  → tool result: {tool_result!r}")

    # ── 7b. Tool call — DENY path ─────────────────────────────────────────
    gate2 = await harness.check_tool_call(
        "send_email",
        {"to": "bob@example.com", "subject": "test", "body": "hello"},
        ctx,
    )
    print(f"[check_tool_call] send_email   allowed={gate2.allowed}  reason={gate2.deny_reason!r}")

    # ── 8. scan_output ────────────────────────────────────────────────────
    llm_response = "Here are the docs I found: onboarding.pdf, setup.md, faq.html"
    out_verdict = await harness.scan_output(llm_response, ctx)
    print(f"[scan_output]     blocked={out_verdict.blocked}  findings={len(out_verdict.findings)}")
    final_response = out_verdict.redacted_text or llm_response
    print(f"\n── Agent response ───────────────────────────────────────────")
    print(f"  {final_response!r}")

    # ── 9. unload_sources ─────────────────────────────────────────────────
    await harness.unload_sources(ctx)
    print("\n── Turn end ─────────────────────────────────────────────────")

    # ── 10. Subagent example ──────────────────────────────────────────────
    print("\n── Subagent turn ────────────────────────────────────────────")
    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    print(f"[scope_subagent]  agent_id={child_ctx.agent_id}  sub_agent_id={child_ctx.sub_agent_id}")
    print(f"                  allowed_tags={child_ctx.allowed_tags}")

    child_tools = await harness.load_sources(child_ctx)
    print(f"[load_sources]    {len(child_tools)} tools: {[t.name for t in child_tools]}")

    g1 = await harness.check_tool_call("search_docs", {"query": "policy"}, child_ctx)
    g2 = await harness.check_tool_call("send_email",  {"to": "x@y.com"},   child_ctx)
    print(f"[check_tool_call] search_docs  allowed={g1.allowed}")
    print(f"[check_tool_call] send_email   allowed={g2.allowed}  reason={g2.deny_reason!r}")

    await harness.unload_sources(child_ctx)
    await harness.close()
    print("\nDone. JSONL audit events are printed above each section.")


if __name__ == "__main__":
    asyncio.run(main())
