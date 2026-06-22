"""Harness facade — the only public entry point of the SDK.

Phase 5: all boundary methods fully wired.
_views: dict[int, InMemoryRegistryView] keyed on id(ctx).
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from typing import Any

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.adapters.scanners.basic_injection import BasicInjectionScanner
from harness.adapters.tool_registry.memory import InMemoryRegistry, InMemoryRegistryView
from harness.adapters.tool_sources.base import SourceRegistry
from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries import scan_input, scan_output, check_tool_call
from harness.config.loader import load_yaml
from harness.config.schema import HarnessConfig
from harness.core.context import RuntimeContext
from harness.core.types import Severity
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class Harness:
    """Control-plane facade for production agents.

    One instance serves N concurrent agents. Isolation is structural:
    each agent/subagent pair gets its own ScopedRegistryView keyed on
    id(ctx) stored in _views for per-turn isolation.
    """

    def __init__(
        self,
        config: HarnessConfig,
        agent_registry: AgentRegistry,
        tool_registry: InMemoryRegistry,
        source_registry: SourceRegistry,
        emitter: AuditEmitter,
        input_scanners: list,
        output_scanners: list,
        arg_scanners: list,
        policy: RuleBasedPolicy,
        scan_input_enabled: bool,
        scan_output_enabled: bool,
        block_at: Severity,
        scan_args_for_tags: frozenset[str],
    ) -> None:
        self._config              = config
        self._tenant_id           = config.tenant_id
        self._agent_registry      = agent_registry
        self._tool_registry       = tool_registry
        self._source_registry     = source_registry
        self._emitter             = emitter
        self._input_scanners      = input_scanners
        self._output_scanners     = output_scanners
        self._arg_scanners        = arg_scanners
        self._policy              = policy
        self._scan_input_enabled  = scan_input_enabled
        self._scan_output_enabled = scan_output_enabled
        self._block_at            = block_at
        self._scan_args_for_tags  = scan_args_for_tags
        # Per-turn scoped views — keyed on ctx.agent_key()
        # Per-turn view store. Key = id(ctx) — the Python object identity of the
        # RuntimeContext passed to load_sources(). This gives each turn its own
        # view even when multiple concurrent turns run under the same agent_id.
        # The agent holds ctx for the turn's duration, so id(ctx) is stable.
        # unload_sources(ctx) is the explicit cleanup signal.
        self._views: dict[int, InMemoryRegistryView] = {}

    # ── Construction ──────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Harness":
        """Load harness.yaml and construct a fully wired Harness instance.

        Instantiates adapters from entry points when the package is installed,
        falling back to reference adapters directly when running from source.
        """
        config = load_yaml(path)
        log.info("harness config loaded", extra={"op": "from_yaml", "path": str(path)})

        # Resolve adapters via discovery when installed, else use reference impls
        input_scanners  = _build_scanners(config.scan_input.scanners)
        output_scanners = _build_scanners(config.scan_output.scanners)
        arg_scanners    = _build_scanners(config.check_tool_call.arg_scanners)

        policy_cfg = config.policy.config
        policy = RuleBasedPolicy(
            rules_path=policy_cfg.get("rules_path") if policy_cfg else None,
        )

        sinks = _build_sinks(config.audit_sinks)
        emitter = AuditEmitter(sinks)

        tool_registry = InMemoryRegistry()
        source_registry = SourceRegistry(sources={}, policy=policy)

        block_at = config.scan_input.block_at  # same for both boundaries
        scan_args_tags = frozenset(config.check_tool_call.scan_args_for_tags)

        return cls(
            config=config,
            agent_registry=AgentRegistry(),
            tool_registry=tool_registry,
            source_registry=source_registry,
            emitter=emitter,
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            arg_scanners=arg_scanners,
            policy=policy,
            scan_input_enabled=config.scan_input.enabled,
            scan_output_enabled=config.scan_output.enabled,
            block_at=block_at,
            scan_args_for_tags=scan_args_tags,
        )

    # ── Agent management ──────────────────────────────────────────────────

    async def load_agent(self, path: str | Path) -> AgentConfig:
        return await self._agent_registry.load(path)

    async def reload_agent(self, path: str | Path) -> AgentConfig:
        return await self._agent_registry.reload(path)

    async def deregister_agent(self, agent_id: str) -> None:
        await self._agent_registry.deregister(agent_id)

    async def list_agents(self) -> list[AgentConfig]:
        return await self._agent_registry.list()

    # ── Startup ───────────────────────────────────────────────────────────

    async def register_tools(self, tools: list[Tool]) -> None:
        """Register local tools at startup. Call before load_sources()."""
        await self._tool_registry.register_many(tools)

    # ── Subagent scoping (sync, pure) ─────────────────────────────────────

    def scope_context_for_subagent(
        self,
        ctx: RuntimeContext,
        sub_agent_id: str,
    ) -> RuntimeContext:
        """Return a RuntimeContext scoped to a declared subagent.

        Pure synchronous function — no I/O, no audit event.
        Called by framework integrations at the handoff point.
        """
        agent_config = self._agent_registry.get(ctx.agent_id)
        sub_config   = agent_config.get_sub_agent(sub_agent_id)
        return RuntimeContext(
            agent_id=ctx.agent_id,
            sub_agent_id=sub_agent_id,
            allowed_tags=sub_config.allowed_tags,
        )

    # ── Per-turn boundaries ───────────────────────────────────────────────

    async def load_sources(self, ctx: RuntimeContext) -> list[Tool]:
        """Activate declared sources for this agent/subagent turn.

        Creates a ScopedRegistryView keyed on ctx.agent_key(), populates it
        from active sources, returns the tool list for the LLM.
        """
        agent_config = self._agent_registry.get(ctx.agent_id)

        if ctx.sub_agent_id is not None:
            effective = agent_config.get_sub_agent(ctx.sub_agent_id)
            source_names = effective.sources
        else:
            source_names = agent_config.sources

        view = self._tool_registry.scoped_view(ctx)
        self._views[id(ctx)] = view

        tools = await self._source_registry.activate(ctx, source_names, view)
        log.debug(
            "sources loaded",
            extra={
                "tool_count": len(tools),
                "source_count": len(source_names),
                **ctx.to_log_fields(),
            },
        )
        return tools

    async def unload_sources(self, ctx: RuntimeContext) -> None:
        """Discard this turn's ScopedRegistryView. Call at turn end."""
        self._views.pop(id(ctx), None)
        log.debug("sources unloaded", extra={**ctx.to_log_fields()})

    async def scan_input(self, text: str, ctx: RuntimeContext) -> ScanVerdict:
        audit_tags = self._audit_tags_for(ctx)
        return await scan_input.run(
            text, ctx,
            scanners=self._input_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_input_enabled,
            block_at=self._block_at,
            audit_tags=audit_tags,
        )

    async def check_tool_call(
        self, name: str, args: dict[str, Any], ctx: RuntimeContext
    ) -> GateDecision:
        view = self._views.get(id(ctx))
        if view is None:
            # Fall back to base registry if load_sources was not called
            view = self._tool_registry.scoped_view(ctx)

        audit_tags = self._audit_tags_for(ctx)
        return await check_tool_call.run(
            name, args, ctx,
            agent_registry=self._agent_registry,
            registry_view=view,
            policy=self._policy,
            arg_scanners=self._arg_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            scan_args_for_tags=self._scan_args_for_tags,
        )

    async def scan_output(self, text: str, ctx: RuntimeContext) -> ScanVerdict:
        audit_tags = self._audit_tags_for(ctx)
        return await scan_output.run(
            text, ctx,
            scanners=self._output_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_output_enabled,
            block_at=self._block_at,
            audit_tags=audit_tags,
        )

    async def close(self) -> None:
        """Flush and close all audit sinks. Call at process shutdown."""
        await self._emitter.close()

    # ── Internal helpers ──────────────────────────────────────────────────

    def _audit_tags_for(self, ctx: RuntimeContext) -> dict[str, str]:
        """Return audit_tags from the agent's profile, or empty dict."""
        try:
            return dict(self._agent_registry.get(ctx.agent_id).audit_tags)
        except Exception:
            return {}


# ── Module-level adapter builders ─────────────────────────────────────────
# Used by Harness.from_yaml(). Kept outside the class to stay testable.

def _build_scanners(adapter_refs: list) -> list:
    """Instantiate scanners from AdapterRef list.

    Falls back to reference implementations when entry points are not
    registered (running from source without pip install -e .).
    """
    _REFERENCE = {
        "regex_pii":       lambda cfg: RegexPIIScanner(**cfg),
        "basic_injection": lambda cfg: BasicInjectionScanner(**cfg),
    }
    scanners = []
    for ref in adapter_refs:
        factory = _REFERENCE.get(ref.name)
        if factory:
            scanners.append(factory(ref.config))
        else:
            try:
                from harness.adapters.discovery import resolve
                cls = resolve("harness.scanners", ref.name)
                scanners.append(cls(**ref.config))
            except Exception as e:
                log.warning(
                    "scanner adapter not found — skipped",
                    extra={"name": ref.name, "error": str(e)},
                )
    return scanners


def _build_sinks(adapter_refs: list) -> list:
    """Instantiate audit sinks from AdapterRef list."""
    _REFERENCE = {
        "stdout": lambda cfg: StdoutSink(),
        "file":   lambda cfg: __import__(
            "harness.adapters.audit_sinks.file", fromlist=["FileSink"]
        ).FileSink(**cfg),
    }
    sinks = []
    for ref in adapter_refs:
        factory = _REFERENCE.get(ref.name)
        if factory:
            sinks.append(factory(ref.config))
        else:
            try:
                from harness.adapters.discovery import resolve
                cls = resolve("harness.audit_sinks", ref.name)
                sinks.append(cls(**ref.config))
            except Exception as e:
                log.warning(
                    "audit sink not found — skipped",
                    extra={"name": ref.name, "error": str(e)},
                )
    if not sinks:
        log.warning("no audit sinks configured — falling back to stdout")
        sinks = [StdoutSink()]
    return sinks
