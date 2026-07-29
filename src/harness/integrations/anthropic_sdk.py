"""SHAI integration for the Anthropic Python SDK.

Canonical reference — read this before implementing other integrations.

Two public helpers:

  gated_dispatch(tool_name, tool_args, ctx, *, harness, dispatch)
      Gate one tool call, dispatch if allowed, then scan the result for
      indirect injection before it re-enters the model's context.
      Use this inside a hand-rolled agent loop.

  run_turn(user_text, ctx, *, harness, llm_fn)
      Full turn wrapper: scan_input → llm_fn loop → scan_output.
      llm_fn receives (user_text, tools, ctx) and returns the LLM response
      string. It is responsible for calling gated_dispatch for each tool
      call the model requests — that is where tool results get scanned.

The Anthropic SDK is imported lazily — this module is importable without
the SDK installed. Import errors surface only when you call these helpers.

Subagent handoff example (called by the integration, not agent code):
    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    # then run child agent with child_ctx
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from harness.core.verdicts import GateDecision
from harness.integrations.base import (  # shai_tool re-exported
    BLOCKED_RESULT_MESSAGE,
    execute_gated_tool_call,
    shai_tool,
)

if TYPE_CHECKING:
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI
    from harness.core.verdicts import ScanVerdict
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)

__all__ = ["shai_tool", "gated_dispatch", "run_turn", "make_tool_result_from_denial"]


async def gated_dispatch(
    tool_name: str,
    tool_args: dict[str, Any],
    ctx: AgentContext,
    *,
    harness: SHAI,
    dispatch: Callable[[str, dict[str, Any]], Awaitable[Any]] | None = None,
) -> Any:
    """Gate one tool call, dispatch it, then scan the result.

    Args:
        tool_name:  the tool name from the model's tool_use block
        tool_args:  the tool input dict from the model's tool_use block
        ctx:        the AgentContext for this turn
        harness:    the SHAI instance
        dispatch:   async callable(tool_name, args) → tool result. Omit for
                    MCP tools: the call is then routed to the source that owns
                    the tool, carrying the gate's dispatch token — which is
                    what ShaiTransport validates on the outbound request.

    Returns one of three things:
        GateDecision    — the gate denied the call; it was never dispatched.
        ScanVerdict     — the call ran but its result was blocked by
                          scan_tool_result as indirect injection.
        the tool result — allowed and clean, carrying scan_tool_result's
                          redacted text when it replaced content.

    Both denial cases are verdict objects, not results. Pass either to
    make_tool_result_from_denial() to surface the reason to the model —
    never hand them to the model as tool output.
    """
    call = await execute_gated_tool_call(
        harness=harness,
        ctx=ctx,
        tool_name=tool_name,
        tool_args=tool_args,
        invoke=(lambda a: dispatch(tool_name, a)) if dispatch is not None else None,
    )
    if call.status == "denied":
        return call.gate
    if call.status == "blocked":
        return call.verdict
    # Allowed: the redacted text when the scan replaced content, else the raw
    # result — an SDK caller may need the object, not its str().
    return call.text if (call.verdict and call.verdict.redacted_text) else call.result


async def run_turn(
    user_text: str,
    ctx: AgentContext,
    *,
    harness: SHAI,
    llm_fn: Callable[
        [str, list[Tool], AgentContext],
        Awaitable[str],
    ],
) -> ScanVerdict | str:
    """Full turn: scan_input → llm_fn → scan_output.

    llm_fn(user_text, tools, ctx) → str
        The agent's LLM loop. It receives the active tool list and is
        responsible for calling gated_dispatch for each tool call.
        Must return the final response string.

    Returns:
        ScanVerdict if input is blocked (caller should abort and surface reason).
        str (the final response) if the turn completed normally.
        The response may have been redacted by scan_output.
    """

    input_verdict = await harness.scan_input(user_text, ctx)
    if input_verdict.blocked:
        return input_verdict

    # Tools are resolved at load_agent() time — read from the harness directly.
    # Values are (source_name, Tool); llm_fn receives the Tools. source_name is
    # the gate's business, not the caller's.
    agent_tools = [
        tool for _, tool in harness._agent_tools.get(ctx.agent_id, {}).values()
    ]
    response = await llm_fn(user_text, agent_tools, ctx)
    output_verdict = await harness.scan_output(response, ctx)
    return output_verdict.redacted_text or response


def make_tool_result_from_denial(
    denial: GateDecision | ScanVerdict,
    tool_use_id: str,
) -> dict:
    """Build an Anthropic tool_result content block for a blocked tool call.

    Accepts either denial gated_dispatch can return:
        GateDecision — the gate refused the call; deny_reason is surfaced.
        ScanVerdict  — the result was blocked as indirect injection. The
                       message is fixed: findings describe matched content,
                       which must never be echoed back to the model.

    Usage in a hand-rolled loop::

        result = await gated_dispatch(name, args, ctx, harness=h, dispatch=dispatcher)
        if isinstance(result, (GateDecision, ScanVerdict)):
            # denied or blocked — tell the model
            tool_result = make_tool_result_from_denial(result, tool_use_id)
            messages.append({"role": "user", "content": [tool_result]})
    """
    if isinstance(denial, GateDecision):
        content = f"Tool call denied: {denial.deny_reason}"
    else:
        content = BLOCKED_RESULT_MESSAGE
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "is_error": True,
        "content": content,
    }
