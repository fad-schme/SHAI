"""SHAI integration for the Anthropic Python SDK.

Canonical reference — read this before implementing other integrations.

Two public helpers:

  gated_dispatch(tool_name, tool_args, ctx, *, harness, dispatch)
      Gate one tool call then dispatch if allowed.
      Use this inside a hand-rolled agent loop.

  run_turn(user_text, ctx, *, harness, llm_fn, tools)
      Full turn wrapper: load_sources → scan_input → llm_fn loop →
      scan_output → unload_sources.
      llm_fn receives (user_text, tools, ctx) and returns the LLM response
      string. It is responsible for calling gated_dispatch for each tool
      call the model requests.

The Anthropic SDK is imported lazily — this module is importable without
the SDK installed. Import errors surface only when you call these helpers.

Subagent handoff example (called by the integration, not agent code):
    child_ctx = harness.scope_context_for_subagent(ctx, sub_agent_id="research_sub")
    # then run child agent with child_ctx
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Awaitable, Callable

if TYPE_CHECKING:
    from harness.core.context import RuntimeContext
    from harness.core.harness import Harness
    from harness.core.verdicts import GateDecision, ScanVerdict
    from harness.tools.tool import Tool

log = logging.getLogger(__name__)


async def gated_dispatch(
    tool_name: str,
    tool_args: dict[str, Any],
    ctx: "RuntimeContext",
    *,
    harness: "Harness",
    dispatch: Callable[[str, dict[str, Any]], Awaitable[Any]],
) -> Any:
    """Gate one tool call then dispatch if allowed.

    Args:
        tool_name:  the tool name from the model's tool_use block
        tool_args:  the tool input dict from the model's tool_use block
        ctx:        the RuntimeContext for this turn
        harness:    the Harness instance
        dispatch:   async callable(tool_name, args) → tool result

    Returns the tool result on allow, or the GateDecision on deny so the
    caller can surface the reason to the model as a tool_result.
    """
    gate = await harness.check_tool_call(tool_name, tool_args, ctx)
    if not gate.allowed:
        log.info(
            "tool call denied",
            extra={"tool": tool_name, "reason": gate.deny_reason,
                   **ctx.to_log_fields()},
        )
        return gate

    effective_args = gate.redacted_args if gate.redacted_args is not None else tool_args
    return await dispatch(tool_name, effective_args)


async def run_turn(
    user_text: str,
    ctx: "RuntimeContext",
    *,
    harness: "Harness",
    llm_fn: Callable[
        [str, list["Tool"], "RuntimeContext"],
        Awaitable[str],
    ],
) -> "ScanVerdict | str":
    """Full turn: load_sources → scan_input → llm_fn → scan_output → unload.

    llm_fn(user_text, tools, ctx) → str
        The agent's LLM loop. It receives the active tool list and is
        responsible for calling gated_dispatch for each tool call.
        Must return the final response string.

    Returns:
        ScanVerdict if input is blocked (caller should abort and surface reason).
        str (the final response) if the turn completed normally.
        The response may have been redacted by scan_output.
    """
    tools = await harness.load_sources(ctx)

    input_verdict = await harness.scan_input(user_text, ctx)
    if input_verdict.blocked:
        await harness.unload_sources(ctx)
        return input_verdict

    try:
        response = await llm_fn(user_text, tools, ctx)
        output_verdict = await harness.scan_output(response, ctx)
        return output_verdict.redacted_text or response
    finally:
        await harness.unload_sources(ctx)


def make_tool_result_from_denial(gate: "GateDecision", tool_use_id: str) -> dict:
    """Build an Anthropic tool_result content block for a denied tool call.

    Surfaces the deny reason to the model so it can respond appropriately.

    Usage in a hand-rolled loop::

        result = await gated_dispatch(name, args, ctx, harness=h, dispatch=dispatcher)
        if isinstance(result, GateDecision):
            # denied — tell the model
            tool_result = make_tool_result_from_denial(result, tool_use_id)
            messages.append({"role": "user", "content": [tool_result]})
    """
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "is_error": True,
        "content": f"Tool call denied: {gate.deny_reason}",
    }
