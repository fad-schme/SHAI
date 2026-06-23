"""hand_rolled_loop.py — canonical SHAI integration reference.

Demonstrates the full per-turn flow with a hand-rolled agent loop:
  scan_input → check_tool_call → scan_tool_result → scan_output

Configuration is loaded from config/harness.yaml and
config/agents/orchestrator_agent.yaml — edit those files to change
scanner actions, rate limits, and policy rules.

Run from the repo root:
    python examples/hand_rolled_loop.py

Requires: pip install -e ".[dev]"
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harness import SHAI, Tool
from harness.core.context import AgentContext
from harness.core.types import Transport

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"


async def main() -> None:
    print("=" * 60)
    print("SHAI — hand-rolled loop example")
    print("=" * 60)

    # ── 1. Build harness from config ──────────────────────────────────────
    harness = await SHAI.from_yaml(HARNESS_YAML)

    # ── 2. Register local tools at startup ───────────────────────────────
    await harness.register_tools([
        Tool(name="search_docs", tags=["read", "internal"],            transport=Transport.LOCAL),
        Tool(name="send_email",  tags=["external_write", "sensitive"], transport=Transport.LOCAL),
        Tool(name="list_inbox",  tags=["read", "internal"],            transport=Transport.LOCAL),
    ])

    # ── 3. Load agent ─────────────────────────────────────────────────────
    # Tools are resolved once here — no per-turn registry lookup.
    ctx = await harness.load_agent(AGENT_YAML)

    print("\n── Turn start ───────────────────────────────────────────────")

    # ── 4. scan_input ─────────────────────────────────────────────────────
    user_text = "Please search the docs for the onboarding guide."
    verdict = await harness.scan_input(user_text, ctx)
    print(f"[scan_input]      status={verdict.status}  findings={len(verdict.findings)}")
    if verdict.blocked:
        print("  Input blocked — turn aborted.")
        await harness.close()
        return
    safe_input = verdict.redacted_text or user_text

    # ── 5. check_tool_call — ALLOW path ──────────────────────────────────
    gate = await harness.check_tool_call(
        "search_docs",
        {"query": "onboarding guide", "limit": 5},
        ctx,
    )
    print(f"[check_tool_call] search_docs  allowed={gate.allowed}  reason={gate.deny_reason!r}")
    if gate.allowed:
        # Agent dispatches with effective args (redacted_args if policy redacted them)
        effective_args = gate.redacted_args or {"query": "onboarding guide", "limit": 5}
        raw_result = "Found 3 documents: onboarding.pdf, setup.md, faq.html"

        # ── 6. scan_tool_result ───────────────────────────────────────────
        tverdict = await harness.scan_tool_result(raw_result, ctx)
        print(f"[scan_tool_result] status={tverdict.status}  findings={len(tverdict.findings)}")
        if tverdict.blocked:
            raw_result = "[tool result blocked — indirect injection detected]"
        else:
            raw_result = tverdict.redacted_text or raw_result
        print(f"  → safe result: {raw_result!r}")

    # ── 7. check_tool_call — DENY path ────────────────────────────────────
    gate2 = await harness.check_tool_call(
        "send_email",
        {"to": "bob@example.com", "subject": "test", "body": "hello"},
        ctx,
    )
    print(f"[check_tool_call] send_email   allowed={gate2.allowed}  reason={gate2.deny_reason!r}")

    # ── 8. scan_output ────────────────────────────────────────────────────
    llm_response = "Here are the docs I found: onboarding.pdf, setup.md, faq.html"
    out_verdict = await harness.scan_output(llm_response, ctx)
    print(f"[scan_output]     status={out_verdict.status}  findings={len(out_verdict.findings)}")
    final_response = out_verdict.redacted_text or llm_response

    print("\n── Agent response ───────────────────────────────────────────")
    print(f"  {final_response!r}")

    # ── 9. Subagent example ───────────────────────────────────────────────
    print("\n── Subagent turn ────────────────────────────────────────────")
    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    print(f"[scope_subagent]  agent_id={child_ctx.agent_id}  sub_agent_id={child_ctx.sub_agent_id}")
    print(f"                  allowed_tags={child_ctx.allowed_tags}")

    g1 = await harness.check_tool_call("search_docs", {"query": "policy"}, child_ctx)
    g2 = await harness.check_tool_call("send_email",  {"to": "x@y.com"},   child_ctx)
    print(f"[check_tool_call] search_docs  allowed={g1.allowed}")
    print(f"[check_tool_call] send_email   allowed={g2.allowed}  reason={g2.deny_reason!r}")

    await harness.close()
    print("\nDone. Audit events written to logs/audit.jsonl")


if __name__ == "__main__":
    asyncio.run(main())
