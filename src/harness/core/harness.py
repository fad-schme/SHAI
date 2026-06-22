"""Harness facade — the only public entry point of the SDK.

Phases 1–3: from_yaml, agent management, and scope_context_for_subagent
are fully implemented. Boundary methods raise NotImplementedError until Phase 5.
"""
from __future__ import annotations

import logging
from pathlib import Path

from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.config.loader import load_yaml
from harness.config.schema import HarnessConfig
from harness.core.context import RuntimeContext

log = logging.getLogger(__name__)


class Harness:
    """Control-plane facade for production agents."""

    def __init__(
        self,
        config: HarnessConfig,
        agent_registry: AgentRegistry,
    ) -> None:
        self._config = config
        self._agent_registry = agent_registry

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Harness":
        """Load harness.yaml and construct a Harness instance.

        Phase 5 will add adapter instantiation; for now constructs the
        agent registry and validates config.
        """
        config = load_yaml(path)
        log.info("harness config loaded", extra={"op": "from_yaml", "path": str(path)})
        return cls(config=config, agent_registry=AgentRegistry())

    # ── Agent management ──────────────────────────────────────────────────

    async def load_agent(self, path: str | Path) -> AgentConfig:
        """Validate and register an agent-xx.yaml file."""
        return await self._agent_registry.load(path)

    async def reload_agent(self, path: str | Path) -> AgentConfig:
        """Validate and atomically replace an existing agent definition."""
        return await self._agent_registry.reload(path)

    async def deregister_agent(self, agent_id: str) -> None:
        """Remove an agent from the registry."""
        await self._agent_registry.deregister(agent_id)

    async def list_agents(self) -> list[AgentConfig]:
        """Return all registered agents."""
        return await self._agent_registry.list()

    # ── Subagent scoping (sync, pure — no I/O, no audit event) ───────────

    def scope_context_for_subagent(
        self,
        ctx: RuntimeContext,
        sub_agent_id: str,
    ) -> RuntimeContext:
        """Return a RuntimeContext scoped to a declared subagent.

        Pure synchronous function:
        - agent_id preserved (identifies the parent)
        - sub_agent_id set
        - allowed_tags narrowed to the subagent's declared tags
        - user_id and session_id inherited for audit trail continuity

        Raises SubAgentNotDeclaredError if sub_agent_id not declared
        under ctx.agent_id. Raises AgentNotRegisteredError if agent
        not in registry.

        Called by framework integrations at the handoff point — not by
        agent code directly.
        """
        agent_config = self._agent_registry.get(ctx.agent_id)
        sub_config   = agent_config.get_sub_agent(sub_agent_id)

        return RuntimeContext(
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
            sub_agent_id=sub_agent_id,
            allowed_tags=sub_config.allowed_tags,
            user_id=ctx.user_id,
            session_id=ctx.session_id,
        )

    # ── Startup ───────────────────────────────────────────────────────────

    async def register_tools(self, tools: list) -> None:
        raise NotImplementedError("Phase 5")

    # ── Per-turn boundaries ───────────────────────────────────────────────

    async def load_sources(self, ctx: RuntimeContext) -> list:
        raise NotImplementedError("Phase 5")

    async def unload_sources(self, ctx: RuntimeContext) -> None:
        raise NotImplementedError("Phase 5")

    async def scan_input(self, text: str, ctx: RuntimeContext):
        raise NotImplementedError("Phase 5")

    async def check_tool_call(self, name: str, args: dict, ctx: RuntimeContext):
        raise NotImplementedError("Phase 5")

    async def scan_output(self, text: str, ctx: RuntimeContext):
        raise NotImplementedError("Phase 5")
