"""hand_rolled_loop.py — canonical SHAI integration reference.

Demonstrates the full per-turn flow with a hand-rolled agent loop:
  scan_input → check_tool_call → scan_tool_result → scan_output

Section 8 shows the approval cycle for an IRREVERSIBLE tool: the gate denies
for want of a quorum, the application collects approval and signs a grant per
approver, and the same call is made again.

Configuration is loaded from config/harness.yaml and
config/agents/orchestrator_agent.yaml — edit those files to change
scanner actions, rate limits, and policy rules.

Run from the repo root:
    python examples/hand_rolled_loop.py

Requires: pip install shai-harness
Environment: SHAI_TOKEN_SECRET, SHAI_APPROVAL_KEY
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
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from harness import SHAI, Tool
from harness.core.approval import encode_grant, sign_grant
from harness.core.types import Irreversibility, Transport

CONFIG       = Path(__file__).parent.parent / "config"
HARNESS_YAML = CONFIG / "harness.yaml"
AGENT_YAML   = CONFIG / "agents" / "orchestrator_agent.yaml"

# Grants are bound to the tenant the harness runs as — this is `tenant_id` in
# harness.yaml. The signing key is the one `approvals.secret` resolves to
# there: the application issuing grants and the gate verifying them share it.
TENANT_ID    = "shai-demo"


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
        # Classified IRREVERSIBLE, so gate layer 3 holds it until a quorum of
        # signed approval grants is present — see section 8.
        Tool(name="send_alert",  tags=["external_write"],              transport=Transport.LOCAL,
             irreversibility=Irreversibility.IRREVERSIBLE),
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

    # ── 8. The approval cycle — IRREVERSIBLE tool ─────────────────────────
    # SHAI verifies approvals inline; it cannot pause a run to wait for one.
    # So the cycle belongs to this loop: call, read the denial, collect the
    # humans, sign, call again.
    alert_args = {"channel": "#ops", "message": "deploy complete"}

    # First call carries no grants. Layer 3 denies — irreversible_quorum is 2.
    gate3 = await harness.check_tool_call("send_alert", alert_args, ctx)
    print(f"[check_tool_call] send_alert   allowed={gate3.allowed}  reason={gate3.deny_reason!r}")

    # The application now prompts its approvers however it likes — a Slack
    # button, a CIBA flow, a terminal prompt — and signs one grant per
    # decision. Quorum counts distinct approver_ids, so two grants from one
    # person would still be one approver.
    approval_key = os.environ["SHAI_APPROVAL_KEY"].encode()
    grants = tuple(
        encode_grant(sign_grant(
            agent_id=ctx.agent_id,
            tenant_id=TENANT_ID,
            tool_name="send_alert",
            args=alert_args,      # the same args the retry passes — the grant
                                  # binds their digest, so a value changed in
                                  # between is a different call, and denied
            approver_id=who,
            secret=approval_key,
            ttl_seconds=300,      # come back inside the TTL or sign again
        ))
        for who in ("alex@example.com", "sam@example.com")
    )

    # Same call, now with the grants attached. SHAI re-issues nothing: this
    # loop does. The approver ids land on the allow event as extra.approvers.
    approved_ctx = ctx.model_copy(update={"approvals": grants})
    gate4 = await harness.check_tool_call("send_alert", alert_args, approved_ctx)
    print(f"[check_tool_call] send_alert   allowed={gate4.allowed}  (2 approvers)")

    # ── 9. scan_output ────────────────────────────────────────────────────
    llm_response = "Here are the docs I found: onboarding.pdf, setup.md, faq.html"
    out_verdict = await harness.scan_output(llm_response, ctx)
    print(f"[scan_output]     status={out_verdict.status}  findings={len(out_verdict.findings)}")
    final_response = out_verdict.redacted_text or llm_response

    print("\n── Agent response ───────────────────────────────────────────")
    print(f"  {final_response!r}")

    # ── 10. Subagent example ───────────────────────────────────────────────
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
