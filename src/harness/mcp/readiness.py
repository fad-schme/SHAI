"""mcp/readiness.py — zero-dependency, zero-network operational-readiness
heuristic for a manifest's declared tool set.

Purely informational governance signal, attached to the onboarding
AuditEvent's extra["readiness"] — never security, and by construction never
part of the block_at pass/fail decision. harness.mcp.onboard does not read
this module's output when deciding whether onboarding passes — see the
assertion in that module's decision path.

A small, fixed heuristic set — not an attempt at parity with any larger
external tool's rule count.
"""
from __future__ import annotations

from harness.mcp.manifest import MCPManifest, MCPToolSpec

_MIN_DESCRIPTION_LEN = 10
_MAX_TOOL_ARGS = 8  # above this, a tool's argument count is flagged as high
_PENALTY_PER_FLAG = 10  # points deducted per flagged condition, out of 100


def _flags_for_tool(tool: MCPToolSpec) -> list[str]:
    flags: list[str] = []

    description = tool.description.strip()
    if not description:
        flags.append("missing_description")
    elif len(description) < _MIN_DESCRIPTION_LEN:
        flags.append("short_description")

    if len(tool.arguments) > _MAX_TOOL_ARGS:
        flags.append("argument_count_high")

    if any(not (arg.type or "").strip() for arg in tool.arguments):
        flags.append("missing_argument_types")

    if tool.timeout_seconds is None:
        flags.append("no_timeout_hint")

    return flags


def score_readiness(manifest: MCPManifest) -> dict:
    """Score a manifest's declared tool set. Returns a plain dict — this is
    what lands directly in AuditEvent.extra["readiness"].

    No tools declared scores 100 — nothing to flag is not the same as
    something wrong; an empty manifest is a discovery-time concern (caught
    elsewhere), not a readiness one.
    """
    if not manifest.tools:
        return {"score": 100, "flags": []}

    flags: list[dict] = []
    for tool in manifest.tools:
        tool_flags = _flags_for_tool(tool)
        if tool_flags:
            flags.append({"tool_name": tool.name, "flags": tool_flags})

    penalty = sum(len(f["flags"]) for f in flags) * _PENALTY_PER_FLAG
    score = max(0, 100 - penalty)
    return {"score": score, "flags": flags}
