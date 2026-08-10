"""Maintenance — the operational surface, off the per-turn path.

Reached as `harness.maintenance`. Never constructed directly.

What lives here and what does not
---------------------------------
The `SHAI` facade carries the per-turn contract: the five enforcement
boundaries, the scoping and lookup calls a turn needs, and startup. Everything
here is the other thing — agent lifecycle administration, the kill switch, and
introspection. None of it runs during a turn, none of it is on a hot path, and
an application that never administers anything never touches this class.

Splitting it out is what keeps the facade readable. Nineteen public members on
one object cannot say what the object is for; the boundaries and the admin verbs
answer to different callers on different schedules, and mixing them made the
per-turn contract harder to find than the thing it protects.

`scanners` is here rather than on the facade for a second reason. Scanners are
selected by name in `harness.yaml` and resolved through the `harness.scanners`
entry-point group — an operator enables them, nobody constructs or calls one.
Handing live scanner instances back out of the facade contradicted that, and
the only thing the property is good for is inspection, which is what this class
is.

Async surface
-------------
`async` iff the method awaits. Only `reload_agent` does — it parses YAML off the
event loop and activates sources concurrently. Everything else is a dict
operation or a small file read and says so in its signature.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from harness.core.errors import ConfigError

if TYPE_CHECKING:
    from pathlib import Path

    from harness.adapters.scanners.base import Scanner
    from harness.adapters.scanners.rate_limiter import RateLimiter
    from harness.agents.agent_config import AgentConfig
    from harness.core.context import AgentContext
    from harness.core.harness import SHAI


class Maintenance:
    """Operational surface for one SHAI instance.

        harness = await SHAI.from_yaml("config/harness.yaml")
        harness.maintenance.revoke_agent("billing_agent", reason="incident 4471")
        harness.maintenance.revoked_agents()      # {'billing_agent'}
        harness.maintenance.restore_agent("billing_agent")

    Holds the harness rather than copies of its collaborators: `reload_agent`
    and `deregister_agent` rebuild and tear down the same per-agent state
    `load_agent` builds, so they have to reach the live instance. Both go
    through one named entry point on it (`_wire_agent`, `_forget_agent`) instead
    of touching the six dictionaries that state actually lives in.
    """

    __slots__ = ("_h",)

    def __init__(self, harness: SHAI) -> None:
        self._h = harness

    # ── Agent lifecycle ───────────────────────────────────────────────────

    async def reload_agent(self, path: str | Path) -> AgentContext:
        """Re-read an agent-xx.yaml and refresh its resolved tool set.

        Atomic: the registry validates and swaps the definition first, so a
        malformed file leaves the previous one in place and raises.
        """
        cfg = await self._h._agent_registry.reload(path)
        await self._h._wire_agent(cfg, message="agent reloaded", op="reload_agent")
        from harness.core.context import AgentContext
        return AgentContext(agent_id=cfg.id)

    def deregister_agent(self, agent_id: str) -> None:
        """Remove an agent entirely — registration, tools, limits, counters.

        This stops conversation as well as actions: the agent is gone, and a
        later `check_tool_call` denies it as unregistered. To stop actions while
        keeping the agent addressable, use `revoke_agent()`.
        """
        config = self._h._agent_registry.get(agent_id)
        self._h._agent_registry.deregister(config)
        self._h._forget_agent(agent_id)

    def list_agents(self) -> list[AgentConfig]:
        """Every agent currently registered on this harness."""
        return self._h._agent_registry.list()

    # ── Kill switch ───────────────────────────────────────────────────────

    def revoke_agent(self, agent_id: str, *, reason: str | None = None) -> None:
        """Stop this agent from calling tools. Takes effect immediately here.

        Denies at the gate's pre-gate on the next call, leaving every other
        agent in the process running. The revocation is written to
        `revocation.path`, so it survives a restart and is visible to any other
        process reading the same file — including `shai agent revoke`, which is
        the same switch from the other side.

        The agent stays registered: this stops actions, not conversation, and
        `restore_agent()` reverses it without reloading anything. Use
        `deregister_agent()` to remove it entirely.

        Raises ConfigError when `revocation.path` is not configured — a kill
        switch that silently did nothing would be worse than none.
        """
        if not self._h._revocations.enabled:
            raise ConfigError(
                "revocation is not configured; set revocation.path in harness.yaml",
                op="revoke_agent",
            )
        self._h._revocations.revoke(agent_id, reason=reason)

    def restore_agent(self, agent_id: str) -> bool:
        """Lift a revocation. False if the agent was not revoked."""
        if not self._h._revocations.enabled:
            raise ConfigError(
                "revocation is not configured; set revocation.path in harness.yaml",
                op="restore_agent",
            )
        return self._h._revocations.restore(agent_id)

    def revoked_agents(self) -> frozenset[str]:
        """Currently revoked agent ids. Empty when revocation is unconfigured."""
        return self._h._revocations.revoked_agents()

    # ── Introspection ─────────────────────────────────────────────────────

    @property
    def scanners(self) -> dict[str, Scanner | RateLimiter]:
        """Active scanner instances by name — for inspection and debugging.

        Covers the boundaries the facade runs: scan_input, scan_output,
        scan_tool_result, scan_file, and the gate's argument scanners. A scanner
        configured at more than one boundary appears once, the first seen,
        scanning input first — so the instance returned may not be the one a
        given boundary uses, and its per-scanner `action` may differ there. MCP
        metadata scanners are absent: they live on the MCPSource that runs them
        at connect time.

        Read-only in intent. These are the live objects the boundaries call, and
        reconfiguring one here changes what runs without touching harness.yaml
        or the startup attestation that recorded it.
        """
        h = self._h
        result: dict[str, Scanner | RateLimiter] = {}
        configured = (
            h._input_scanners
            + h._output_scanners
            + h._tool_result_scanners
            + h._file_scanners
        )
        for scanner in [c.scanner for c in configured + h._arg_scanners]:
            name = getattr(scanner, "name", type(scanner).__name__)
            result[name] = scanner
        if h._rate_limiter is not None:
            result["rate_limiter"] = h._rate_limiter
        return result
