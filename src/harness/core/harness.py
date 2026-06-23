"""SHAI facade — the only public entry point of the SDK.

One SHAI instance serves many concurrent agent turns safely.
Agent tools are resolved once at load_agent() time — no per-turn overhead.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.adapters.scanners.rate_limiter import RateLimiter
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.adapters.scanners.injection_scan import InjectionScanner
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, MCPSource, SourceRegistry, ToolSource
from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import run_scan, run_file_scan, run_tool_result_scan
from harness.boundaries.check_tool_call import run as run_gate
from harness.core.types import BoundaryName
from harness.config.loader import load_yaml
from harness.adapters.secrets.env import EnvVarProvider
from harness.config.schema import HarnessConfig
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.policy.rules import RuleBasedPolicy
from harness.tools.tool import Tool

log = logging.getLogger(__name__)


class SHAI:
    """Control-plane facade for production agents.

    Startup sequence:
        harness = SHAI.from_yaml("config/harness.yaml")
        await harness.register_tools([...])
        agent = await harness.load_agent("config/agents/my_agent.yaml")

    Per-turn:
        verdict = await harness.scan_input(text, agent)
        gate    = await harness.check_tool_call(name, args, agent)
        verdict = await harness.scan_output(text, agent)
    """

    def __init__(
        self,
        config: HarnessConfig,
        agent_registry: AgentRegistry,
        tool_registry: ToolRegistry,
        emitter: AuditEmitter,
        input_scanners: list,
        output_scanners: list,
        arg_scanners: list,
        policy: RuleBasedPolicy,
        scan_input_enabled: bool,
        scan_output_enabled: bool,
        scan_file_enabled: bool,
        block_at: Severity,
        file_block_at: Severity,
        file_scanners: list,
        file_max_size_mb: float,
        scan_args_for_tags: frozenset[str],
        rate_limiter: RateLimiter | None,
        tool_result_scanners: list,
        scan_tool_result_enabled: bool,
        tool_result_block_at: Severity,
        source_registry: SourceRegistry,
    ) -> None:
        self._config              = config
        self._tenant_id           = config.tenant_id
        self._agent_registry      = agent_registry
        self._tool_registry       = tool_registry
        self._emitter             = emitter
        self._input_scanners      = input_scanners
        self._output_scanners     = output_scanners
        self._arg_scanners        = arg_scanners
        self._policy              = policy
        self._scan_input_enabled  = scan_input_enabled
        self._scan_output_enabled = scan_output_enabled
        self._scan_file_enabled   = scan_file_enabled
        self._block_at            = block_at
        self._file_block_at       = file_block_at
        self._file_scanners       = file_scanners
        self._file_max_size_mb    = file_max_size_mb
        self._scan_args_for_tags  = scan_args_for_tags
        self._rate_limiter              = rate_limiter
        self._tool_result_scanners      = tool_result_scanners
        self._scan_tool_result_enabled  = scan_tool_result_enabled
        self._tool_result_block_at      = tool_result_block_at
        self._source_registry           = source_registry
        # Per-agent resolved tool sets — populated at load_agent() time
        # key: agent_id, value: {tool_name: Tool} for that agent
        self._agent_tools: dict[str, dict[str, Tool]] = {}

    # ── Construction ──────────────────────────────────────────────────────

    @classmethod
    async def from_yaml(cls, path: str | Path) -> "SHAI":
        """Load harness.yaml and construct a fully wired SHAI instance.

        Secret resolution:
          Resolves ${ENV_VAR} then secret:// URIs using EnvVarProvider.
          All secret:// references must be present as environment variables.
        """
        # First pass: resolve ${ENV_VAR} only (no provider yet)
        config_pre = load_yaml(path)

        # Always use EnvVarProvider for secret:// resolution.
        # Enterprise providers can be swapped by subclassing or patching before
        # calling from_yaml() — no config field needed since there is only one
        # implementation in core.
        provider = EnvVarProvider()

        # Second pass: resolve secret:// URIs with the provider
        config = load_yaml(path, provider=provider)
        log.info("harness config loaded", extra={"op": "from_yaml", "path": str(path)})

        input_scanners  = _build_scanners(config.scan_input.scanners)
        output_scanners = _build_scanners(config.scan_output.scanners)
        arg_scanners    = _build_scanners(config.check_tool_call.arg_scanners)
        file_scanners   = _build_file_scanners(
            config.scan_file.scanners,
            max_size_mb=config.scan_file.max_size_mb,
        )

        policy_cfg = config.policy.config
        policy = RuleBasedPolicy(
            rules_path=policy_cfg.get("rules_path") if policy_cfg else None,
        )

        sinks   = _build_sinks(config.audit_sinks)

        # R3: resolve signing key if configured
        signing_secret: bytes | None = None
        if config.audit_signing.enabled:
            raw_secret = config.audit_signing.secret
            if raw_secret.startswith("secret://"):
                raw_secret = provider.resolve(
                    raw_secret[len("secret://"):]
                ).value
            signing_secret = raw_secret.encode()
            log.info("audit event signing enabled")

        emitter = AuditEmitter(sinks, signing_secret=signing_secret)

        # R2: tool result scanner — uses bundled patterns_for_doc.yaml
        from pathlib import Path as _Path
        from harness.adapters.scanners.injection_scan import InjectionScanner as _IS
        _doc_patterns = _Path(__file__).parent.parent / \
            "adapters/scanners/patterns_for_doc.yaml"
        tool_result_scanners = (
            [_IS(patterns_file=_doc_patterns, name="injection_scan_doc")]
            if config.scan_tool_result.enabled else []
        )

        # Build shared registries first — source_registry needs tool_registry
        tool_registry   = ToolRegistry()
        agent_registry  = AgentRegistry()

        # Build SourceRegistry and register all declared sources
        source_registry = SourceRegistry(policy)
        for src_cfg in config.sources:
            if src_cfg.transport == "mcp":
                # Resolve credential values (already resolved by loader pass)
                source = MCPSource(
                    name=src_cfg.name,
                    url=src_cfg.url,
                    credentials=dict(src_cfg.credentials),
                    tags=list(src_cfg.tags),
                )
            else:
                # LOCAL — backed by the shared tool registry
                source = LocalSource(
                    name=src_cfg.name,
                    registry=tool_registry,
                    tool_names=list(src_cfg.tool_names) or None,
                    tags=list(src_cfg.tags),
                )
            await source_registry.register(source)

        rl_cfg = config.check_tool_call.rate_limit
        rate_limiter = (
            RateLimiter(
                window_seconds=rl_cfg.window_seconds,
                max_calls_per_window=rl_cfg.max_calls_per_window,
                max_calls_per_tool=rl_cfg.max_calls_per_tool,
            )
            if rl_cfg.enabled else None
        )

        return cls(
            config=config,
            agent_registry=agent_registry,
            tool_registry=tool_registry,
            emitter=emitter,
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            arg_scanners=arg_scanners,
            policy=policy,
            scan_input_enabled=config.scan_input.enabled,
            scan_output_enabled=config.scan_output.enabled,
            scan_file_enabled=config.scan_file.enabled,
            block_at=config.scan_input.block_at,
            file_block_at=config.scan_file.block_at,
            file_scanners=file_scanners,
            file_max_size_mb=config.scan_file.max_size_mb,
            scan_args_for_tags=frozenset(config.check_tool_call.scan_args_for_tags),
            rate_limiter=rate_limiter,
            tool_result_scanners=tool_result_scanners,
            scan_tool_result_enabled=config.scan_tool_result.enabled,
            tool_result_block_at=config.scan_tool_result.block_at,
            source_registry=source_registry,
        )

    # ── Startup ───────────────────────────────────────────────────────────

    async def register_tools(self, tools: list[Tool]) -> None:
        """Register tools and re-resolve all already-loaded agents.

        May be called before or after load_agent() — order does not matter.
        After registering, every loaded agent's tool set is refreshed so
        newly registered tools become immediately available.
        """
        await self._tool_registry.register_many(tools)
        # Re-resolve all already-loaded agents so they see the new tools
        for cfg in await self._agent_registry.list():
            self._agent_tools[cfg.id] = self._resolve_tools(cfg)

    # ── Agent management ──────────────────────────────────────────────────

    async def load_agent(self, path: str | Path) -> AgentContext:
        """Load an agent-xx.yaml, resolve its tools, return an AgentContext.

        Tool resolution merges two sources:
          1. Tools registered directly via register_tools() (LOCAL/SKILL).
          2. Tools discovered from the agent's declared sources (MCP and local).

        The merged set is filtered to allowed_tool_names from the agent config.
        Resolution happens once at load_agent() time — no per-turn overhead.

        Returns AgentContext — pass it to scan_input, check_tool_call,
        scan_output on every turn.
        """
        cfg = await self._agent_registry.load(path)
        ctx = AgentContext(agent_id=cfg.id)

        # Activate declared sources for this agent
        source_tools = await self._source_registry.activate(ctx, list(cfg.sources))
        # Register source-discovered tools into the shared registry so they
        # are visible to check_tool_call and policy rules
        for tool in source_tools:
            try:
                await self._tool_registry.register(tool)
            except Exception as e:
                log.warning("source tool registration failed — skipped",
                            extra={"tool": tool.name, "error": str(e)})

        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        log.info("agent loaded",
                 extra={"agent_id": cfg.id,
                        "tools": len(self._agent_tools[cfg.id]),
                        "source_tools": len(source_tools)})
        return AgentContext(agent_id=cfg.id)

    async def reload_agent(self, path: str | Path) -> AgentContext:
        """Reload an agent-xx.yaml and refresh its resolved tool set."""
        cfg = await self._agent_registry.reload(path)
        ctx = AgentContext(agent_id=cfg.id)
        source_tools = await self._source_registry.activate(ctx, list(cfg.sources))
        for tool in source_tools:
            try:
                await self._tool_registry.register(tool)
            except Exception:
                pass
        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        log.info("agent reloaded",
                 extra={"agent_id": cfg.id,
                        "tools": len(self._agent_tools[cfg.id])})
        return AgentContext(agent_id=cfg.id)

    async def deregister_agent(self, agent_id: str) -> None:
        # Retrieve the config first so we can pass the object to deregister()
        config = self._agent_registry.get(agent_id)
        await self._agent_registry.deregister(config)
        self._agent_tools.pop(agent_id, None)
        if self._rate_limiter is not None:
            self._rate_limiter.reset(agent_id)

    async def list_agents(self) -> list[AgentConfig]:
        return await self._agent_registry.list()

    # ── Subagent scoping (sync, pure) ─────────────────────────────────────

    def scope_context_for_subagent(
        self,
        ctx: AgentContext,
        sub_agent_id: str,
    ) -> AgentContext:
        """Return an AgentContext scoped to a declared subagent.

        Pure synchronous function — no I/O, no audit event.
        Validates the subagent is declared under ctx.agent_id and narrows
        allowed_tags to the subagent's declared capability set.
        """
        agent_config = self._agent_registry.get(ctx.agent_id)
        sub_config   = agent_config.get_sub_agent(sub_agent_id)
        return ctx.scope_subagent(
            sub_agent_id,
            allowed_tags=sub_config.allowed_tags,
        )

    # ── Per-turn boundaries ───────────────────────────────────────────────

    async def scan_input(self, text: str, ctx: AgentContext) -> ScanVerdict:
        return await run_scan(
            text, ctx,
            boundary=BoundaryName.INPUT_SCAN,
            scanners=self._input_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_input_enabled,
            block_at=self._block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def check_tool_call(
        self, name: str, args: dict[str, Any], ctx: AgentContext
    ) -> GateDecision:
        # R1: rate limit check before the gate runs
        if self._rate_limiter is not None:
            allowed, reason = self._rate_limiter.check(ctx.agent_id, name)
            if not allowed:
                from harness.core.events import AuditEvent, now_ms
                from harness.core.types import BoundaryName, Decision
                event = AuditEvent.build(
                    boundary=BoundaryName.TOOL_CALL_GATE,
                    decision=Decision.DENY,
                    ctx=ctx,
                    tenant_id=self._tenant_id,
                    duration_ms=0,
                    tool_name=name,
                    deny_reason=reason,
                    audit_tags=self._audit_tags_for(ctx),
                )
                await self._emitter.emit(event)
                return GateDecision(allowed=False, deny_reason=reason)

        agent_config = self._agent_registry.get(ctx.agent_id)
        tools        = self._agent_tools.get(ctx.agent_id, {})
        return await run_gate(
            name, args, ctx,
            agent_config=agent_config,
            tools=tools,
            policy=self._policy,
            arg_scanners=self._arg_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            scan_args_for_tags=self._scan_args_for_tags,
        )

    async def scan_file(self, path: str | Path, ctx: AgentContext) -> ScanVerdict:
        """Scan an uploaded file through the file boundary.

        Pass 1 (structural): MIME type, extension, size, filename, PDF JS,
                             EXIF metadata, ZIP structure, Office macros.
        Pass 2 (content):    Extracted text run through configured scanners.

        Returns ScanVerdict identical in shape to scan_input/scan_output.
        """
        return await run_file_scan(
            str(path), ctx,
            scanners=self._file_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_file_enabled,
            block_at=self._file_block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def scan_tool_result(self, result: str, ctx: AgentContext) -> ScanVerdict:
        """Scan a tool's return value before it re-enters the LLM context.

        Call after every tool dispatch and before passing the result to the LLM.
        Detects indirect prompt injection embedded in tool outputs (T6).

        Example:
            result   = await dispatch(tool_name, args)
            verdict  = await harness.scan_tool_result(result, agent)
            safe_result = verdict.redacted_text or result
        """
        return await run_tool_result_scan(
            result, ctx,
            scanners=self._tool_result_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_tool_result_enabled,
            block_at=self._tool_result_block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def scan_output(self, text: str, ctx: AgentContext) -> ScanVerdict:
        return await run_scan(
            text, ctx,
            boundary=BoundaryName.OUTPUT_SCAN,
            scanners=self._output_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_output_enabled,
            block_at=self._block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def close(self) -> None:
        """Flush and close all audit sinks and sources. Call at process shutdown."""
        await self._source_registry.close()
        await self._emitter.close()

    async def get_source(self, name: str) -> "ToolSource":
        """Return a registered source by name.

        Callers use this to get a reference to an MCPSource for direct tool
        invocation after check_tool_call has gated the call.

            gate   = await harness.check_tool_call(tool_name, args, ctx)
            if gate.allowed:
                source = await harness.get_source("my_mcp_server")
                result = await source.call(tool_name, gate.redacted_args or args)
        """
        return await self._source_registry.get(name)

    # ── Internal helpers ──────────────────────────────────────────────────

    def _resolve_tools(self, cfg: AgentConfig) -> dict[str, Tool]:
        """Build the {name: Tool} dict for an agent at startup.

        Includes every registered tool whose name is in allowed_tool_names.
        Tag-based capability filtering happens at gate time (check_tool_call L2)
        via ctx.allowed_tags — not here. Tools may carry tags like 'sensitive'
        that are scanner hints, not capability gates, so excluding by tag at
        resolution time would incorrectly drop valid tools.
        """
        all_tools   = self._tool_registry.as_dict()
        agent_names = set(cfg.allowed_tool_names)
        return {name: tool for name, tool in all_tools.items()
                if name in agent_names}

    def _audit_tags_for(self, ctx: AgentContext) -> dict[str, str]:
        try:
            return dict(self._agent_registry.get(ctx.agent_id).audit_tags)
        except Exception:
            return {}


# ── Module-level adapter builders ─────────────────────────────────────────

def _build_scanners(adapter_refs: list) -> list:
    _REFERENCE = {
        "regex_pii":       lambda cfg: RegexPIIScanner(**cfg),
        "injection_scan":  lambda cfg: InjectionScanner(**cfg),
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
                log.warning("scanner adapter not found — skipped",
                            extra={"adapter_name": ref.name, "error": str(e)})
    return scanners




def _build_file_scanners(adapter_refs: list, *, max_size_mb: float) -> list:
    """Build file scanners — always includes FileScanner as the structural pass.

    FileScanner runs structural checks (MIME, size, extension, PDF JS, EXIF, ZIP,
    Office macros) then runs InjectionScanner on extracted text content.
    Additional scanners declared in config are appended after.
    """
    from harness.adapters.scanners.file_scanner import FileScanner
    from harness.adapters.scanners.injection_scan import InjectionScanner
    from pathlib import Path as _Path

    patterns_for_doc = _Path(__file__).parent.parent / \
        "adapters/scanners/patterns_for_doc.yaml"

    text_scanner = InjectionScanner(
        patterns_file=patterns_for_doc if patterns_for_doc.exists() else None,
        name="injection_scan_doc",
    )
    scanners = [FileScanner(max_size_mb=max_size_mb, text_scanner=text_scanner)]

    for ref in adapter_refs:
        if ref.name in {"file_scanner"}:
            continue  # already added above
        try:
            from harness.adapters.discovery import resolve
            cls = resolve("harness.scanners", ref.name)
            scanners.append(cls(**ref.config))
        except Exception as e:
            log.warning("file scanner adapter not found — skipped",
                        extra={"adapter_name": ref.name, "error": str(e)})
    return scanners


def _build_sinks(adapter_refs: list) -> list:
    sinks = []
    for ref in adapter_refs:
        if ref.name == "stdout":
            sinks.append(StdoutSink())
        elif ref.name == "file":
            from harness.adapters.audit_sinks.file import FileSink
            sinks.append(FileSink(**ref.config))
        else:
            try:
                from harness.adapters.discovery import resolve
                cls = resolve("harness.audit_sinks", ref.name)
                sinks.append(cls(**ref.config))
            except Exception as e:
                log.warning("audit sink not found — skipped",
                            extra={"adapter_name": ref.name, "error": str(e)})
    if not sinks:
        log.warning("no audit sinks configured — falling back to stdout")
        sinks = [StdoutSink()]
    return sinks
