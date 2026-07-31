"""SHAI facade — the only public entry point of the SDK.

One SHAI instance serves many concurrent agent turns safely.
Agent tools are resolved once at load_agent() time — no per-turn overhead.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.adapters.scanners.base import ConfiguredScanner
from harness.adapters.scanners.heuristic_scan import HeuristicScanner
from harness.adapters.scanners.injection_scan import InjectionScanner
from harness.adapters.scanners.mcp_metadata_scanner import MCPMetadataScanner
from harness.adapters.scanners.rate_limiter import RateLimiter
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.adapters.secrets.env import EnvVarProvider
from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import ScanState, run_scan, run_tool_result_scan
from harness.boundaries.check_tool_call import emit_deny as emit_gate_deny
from harness.boundaries.check_tool_call import run as run_gate
from harness.boundaries.session_accumulator import ThreatAccumulator
from harness.boundaries.session_budget import ExecutionLimits, SessionBudget
from harness.config.loader import load_yaml
from harness.config.schema import HarnessConfig
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.events import now_ms
from harness.core.turn_signals import RISK_HIGH, TurnSignals
from harness.core.types import BoundaryName, Decision, ScanStatus
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.policy.rules import RuleBasedPolicy
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, MCPSource, SourceRegistry, ToolSource
from harness.tools.tool import Tool

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from harness.core.events import AnyAuditEvent

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
        *,
        config: HarnessConfig,
        agent_registry: AgentRegistry,
        tool_registry: ToolRegistry,
        emitter: AuditEmitter,
        input_scanners: list[ConfiguredScanner],
        output_scanners: list[ConfiguredScanner],
        arg_scanners: list,
        file_scanners: list[ConfiguredScanner],
        tool_result_scanners: list[ConfiguredScanner],
        policy: RuleBasedPolicy,
        rate_limiter: RateLimiter | None,
        source_registry: SourceRegistry,
        connectivity_secret: bytes | None = None,
    ) -> None:
        # Only built objects are passed in. Everything a boundary reads from
        # harness.yaml is read off self._config at the call site — config is
        # the single source of truth for enabled / block_at / action.
        self._config              = config
        self._tenant_id           = config.tenant_id
        self._agent_registry      = agent_registry
        self._tool_registry       = tool_registry
        self._emitter             = emitter
        self._input_scanners      = input_scanners
        self._output_scanners     = output_scanners
        self._arg_scanners        = arg_scanners
        self._file_scanners       = file_scanners
        self._policy              = policy
        self._scan_args_for_tags        = frozenset(config.check_tool_call.scan_args_for_tags)
        self._correlate_tool_result     = config.check_tool_call.correlate_tool_result
        self._rate_limiter              = rate_limiter
        self._session_budget            = SessionBudget()
        self._threat_accumulator: ThreatAccumulator | None = (
            ThreatAccumulator(
                db_path=config.session.path,
                escalation_threshold=config.session.escalation_threshold,
                window_size=config.session.window_size,
                reframe_similarity=config.session.reframe_similarity,
                ttl_hours=config.session.ttl_hours,
                on_escalation=config.session.on_escalation,
                density_threshold=config.session.density_threshold,
            )
            if config.session.enabled else None
        )
        # Per-agent ExecutionLimits — populated at load_agent() time
        self._agent_limits: dict[str, ExecutionLimits] = {}
        self._tool_result_scanners      = tool_result_scanners
        self._source_registry           = source_registry
        # Per-agent resolved tool sets — populated at load_agent() time
        # key: agent_id, value: {tool_name: Tool} for that agent
        # Composite tool identity: agent_id → {tool_name: (source_name, Tool)}
        # source_name is 'local' for LOCAL/SKILL tools, MCP source name for remote.
        # Populated at load_agent() time — no per-turn lookup needed.
        self._agent_tools: dict[str, dict[str, tuple[str, Tool]]] = {}
        # Per-agent source-enriched tool overrides — keyed by agent_id then tool name.
        # When a source merges tags onto a tool, the enriched Tool is stored here
        # and takes precedence over the registry entry in _resolve_tools.
        self._source_overrides: dict[str, dict[str, Tool]] = {}
        self._connectivity        = config.connectivity
        self._connectivity_secret = connectivity_secret
        # Per-instance scan state: circuit breakers, promoted-candidate cache.
        # Shares patterns_db.path — signed rules and heuristic candidates are two
        # tables in the one DB file the CLI writes.
        self._scan_state = ScanState(config.patterns_db.path)

    # ── Construction ──────────────────────────────────────────────────────

    @classmethod
    async def from_yaml(cls, path: str | Path) -> SHAI:
        """Load harness.yaml and construct a fully wired SHAI instance.

        Secret resolution:
          Resolves ${ENV_VAR} then secret:// URIs using EnvVarProvider.
          All secret:// references must be present as environment variables.
        """
        # Always use EnvVarProvider for secret:// resolution.
        # Enterprise providers can be swapped by subclassing or patching before
        # calling from_yaml() — no config field needed since there is only one
        # implementation in core.
        provider = EnvVarProvider()

        # The loader resolves ${ENV_VAR} and every secret:// URI in one pass —
        # it recurses the whole parsed tree, so no field reaches the config
        # models still holding a URI.
        config = load_yaml(path, provider=provider)
        log.info("harness config loaded", extra={"op": "from_yaml", "path": str(path)})

        # Signed pattern DB → extra rules merged onto every catalog scanner's
        # bundled rules. The DB is incremental: operators add rules over time
        # and each is independent, so both failure modes drop one row rather
        # than the set — HMAC failure inside load_verified_rules, schema
        # failure inside compile_rules_incrementally. The bundled YAML catalog
        # stays active regardless.
        db_extra_rules: dict[str, list] = {}
        if config.patterns_db.enabled:
            from harness.adapters.scanners.injection_scan import compile_rules_incrementally
            from harness.patterns.store import load_verified_rules

            db_secret = config.patterns_db.secret.encode()

            for scanner_name, catalog in _DB_CATALOG_FOR_SCANNER.items():
                raw_rules = load_verified_rules(
                    config.patterns_db.path, db_secret, catalog=catalog
                )
                if raw_rules:
                    compiled = compile_rules_incrementally(
                        raw_rules, source=f"patterns_db[{catalog}]"
                    )
                    if compiled:
                        db_extra_rules[scanner_name] = compiled
            log.info(
                "signed pattern DB loaded",
                extra={
                    "op":       "from_yaml",
                    "path":     config.patterns_db.path,
                    "catalogs": len(db_extra_rules),
                    "rules":    sum(len(r) for r in db_extra_rules.values()),
                },
            )

        input_scanners  = _build_text_scanners(config.scan_input.scanners, extra_rules=db_extra_rules)
        output_scanners = _build_text_scanners(config.scan_output.scanners, extra_rules=db_extra_rules)
        # The gate runs arg scanners directly — no boundary action model, so it
        # takes the scanner instances rather than the configured pairs.
        arg_scanners    = [
            c.scanner for c in
            _build_text_scanners(config.check_tool_call.scanners, extra_rules=db_extra_rules)
        ]
        file_scanners   = _build_file_scanners(
            config.scan_file.scanners,
            max_size_mb=config.scan_file.max_size_mb,
        )

        # Inline policy rules from harness.yaml — no separate rules file
        global_rules = config.policy.parsed_rules()
        policy = RuleBasedPolicy(rules=global_rules)

        sinks   = _build_sinks(config.audit_sinks)

        # Connectivity: resolve token secret if configured
        connectivity_secret: bytes | None = None
        if config.connectivity.enabled:
            connectivity_secret = config.connectivity.token_secret.encode()
            log.info("connectivity layer enabled — dispatch tokens will be issued")

        # R3: resolve signing key if configured
        signing_secret: bytes | None = None
        if config.audit_signing.enabled:
            signing_secret = config.audit_signing.secret.encode()
            log.info("audit event signing enabled")

        emitter = AuditEmitter(sinks, signing_secret=signing_secret)

        tool_result_scanners = _build_text_scanners(
            config.scan_tool_result.scanners,
            extra_rules=db_extra_rules,
        )

        # MCP metadata scanners run inside MCPSource via scan_tool(), not
        # through run_scan — instances only. They take signed-DB rules like
        # every other catalog scanner.
        mcp_metadata_scanners = [
            c.scanner for c in _build_text_scanners(
                config.scan_mcp_metadata.scanners, extra_rules=db_extra_rules
            )
        ]

        # Build shared registries first — source_registry needs tool_registry
        tool_registry   = ToolRegistry()
        agent_registry  = AgentRegistry()

        # Build SourceRegistry and register all declared sources
        source_registry = SourceRegistry(policy)
        for src_cfg in config.sources:
            # Resolve connector manifest if specified
            if src_cfg.connector:
                from harness.config.schema import SourceConfig as _SC
                from harness.connectors import load_manifest, manifest_to_source_config_fields
                try:
                    manifest = load_manifest(src_cfg.connector)
                except ValueError as e:
                    from harness.core.errors import ConfigError as _CE
                    raise _CE(str(e), op="load_connector") from e
                # Merge manifest fields with operator overrides
                # Operator fields take precedence (non-None values in src_cfg)
                overrides = src_cfg.model_dump(exclude_none=True)
                overrides.pop("connector", None)
                overrides.pop("name", None)
                merged = manifest_to_source_config_fields(manifest, overrides)
                merged["name"] = src_cfg.name
                merged["credentials"] = dict(src_cfg.credentials)
                src_cfg = _SC.model_validate(merged)
                log.info("connector manifest loaded",
                         extra={"connector": manifest.id, "source": src_cfg.name})

            if src_cfg.transport == "mcp":
                # Credential values were resolved by the loader pass.
                # connectivity + emitter let _connect() wire ShaiTransport.
                source = MCPSource(
                    src_cfg,
                    connectivity=config.connectivity,
                    emitter=emitter,
                    tenant_id=config.tenant_id,
                    metadata_scanners=mcp_metadata_scanners,
                    metadata_enabled=config.scan_mcp_metadata.enabled,
                    metadata_block_at=config.scan_mcp_metadata.block_at,
                    metadata_action=config.scan_mcp_metadata.action,
                )
            else:
                # LOCAL — backed by the shared tool registry
                source = LocalSource(src_cfg, registry=tool_registry)
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
            file_scanners=file_scanners,
            tool_result_scanners=tool_result_scanners,
            policy=policy,
            rate_limiter=rate_limiter,
            source_registry=source_registry,
            connectivity_secret=connectivity_secret,
        )

    # ── Startup ───────────────────────────────────────────────────────────

    async def register_tools(self, tools: list[Tool | Any]) -> None:
        """Register tools and re-resolve all already-loaded agents.

        Accepts a list of:
          - Tool descriptors (plain harness.tools.tool.Tool)
          - ShaiTool instances from the @shai_tool decorator
            (SHAI metadata + implementation in one object)

        May be called before or after load_agent() — order does not matter.
        After registering, every loaded agent's tool set is refreshed so
        newly registered tools become immediately available.
        """
        from harness.integrations.base import extract_shai_tools
        shai_descriptors = extract_shai_tools(tools)
        await self._tool_registry.register_many(shai_descriptors)
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
        # Build required_flags from SourceConfig — required=True (default) means
        # a missing or failed source raises ConfigError rather than degrading silently.
        required_flags = {
            sc.name: sc.required
            for sc in self._config.sources
        }
        source_tools = await self._source_registry.activate(
            ctx, list(cfg.sources), required_flags=required_flags
        )

        # Source tools may carry additional tags merged from the source config.
        # We cannot blindly re-register them — the registry rejects same-name
        # tools with different tags (correct: it protects canonical definitions).
        # Instead, store source-enriched variants as per-agent overrides.
        # _resolve_tools() prefers these over the registry entry, so the gate
        # evaluates policy against the fully-enriched tag set.
        overrides: dict[str, Tool] = {}
        for tool in source_tools:
            try:
                await self._tool_registry.register(tool)
                # Registered cleanly (new tool from MCP or first registration)
            except Exception:
                # Tag mismatch with an existing registry entry — store as override
                # so this agent sees the enriched version without polluting others.
                overrides[tool.name] = tool
        self._source_overrides[cfg.id] = overrides

        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        self._agent_limits[cfg.id] = self._build_execution_limits(cfg)
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
        overrides: dict[str, Tool] = {}
        for tool in source_tools:
            try:
                await self._tool_registry.register(tool)
            except Exception:
                overrides[tool.name] = tool
        self._source_overrides[cfg.id] = overrides
        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        self._agent_limits[cfg.id] = self._build_execution_limits(cfg)
        log.info("agent reloaded",
                 extra={"agent_id": cfg.id,
                        "tools": len(self._agent_tools[cfg.id])})
        return AgentContext(agent_id=cfg.id)

    async def deregister_agent(self, agent_id: str) -> None:
        # Retrieve the config first so we can pass the object to deregister()
        config = self._agent_registry.get(agent_id)
        await self._agent_registry.deregister(config)
        self._agent_tools.pop(agent_id, None)
        self._source_overrides.pop(agent_id, None)
        self._agent_limits.pop(agent_id, None)
        if self._rate_limiter is not None:
            self._rate_limiter.reset(agent_id)
        self._session_budget.reset(agent_id)

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
        session_id = ctx.conversation_id or ctx.agent_id

        # Attach fresh TurnSignals at turn start. scan_input is always the
        # first boundary in a turn; downstream boundaries read/write this.
        ctx._attach_signals(TurnSignals())

        # Accumulator pre-check: escalated sessions blocked before scanners run.
        if self._threat_accumulator is not None:
            escalated, reason = await self._threat_accumulator.check(session_id)
            if escalated:
                from harness.core.events import AuditEvent
                cfg = self._config.session
                status = ScanStatus.BLOCK if cfg.on_escalation == "block" else ScanStatus.WARN
                decision = Decision.BLOCKED if status == ScanStatus.BLOCK else Decision.WARN
                event = AuditEvent.build(
                    boundary=BoundaryName.INPUT_SCAN,
                    decision=decision,
                    ctx=ctx,
                    tenant_id=self._tenant_id,
                    duration_ms=0,
                    deny_reason=reason,
                    audit_tags=self._audit_tags_for(ctx),
                    extra={"signals": ["session_escalation"]},
                )
                await self._emitter.emit(event)
                # Session-escalation short-circuit: clear signals, no downstream boundaries
                ctx._clear_signals()
                return ScanVerdict(status=status)

        verdict = await run_scan(
            text, ctx,
            boundary=BoundaryName.INPUT_SCAN,
            scanners=self._input_scanners,
            boundary_action=self._config.scan_input.action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._config.scan_input.enabled,
            block_at=self._config.scan_input.block_at,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            on_error=self._config.scan_input.on_error,
        )

        # Record signals from the input scan
        ctx.turn_signals.record_input(verdict)

        # Accumulator record moved to scan_output — needs full turn context
        # for consolidated turn_risk. scan_input BLOCK short-circuits still
        # need to record; do that here for BLOCK only.
        if verdict.status == ScanStatus.BLOCK:
            if self._threat_accumulator is not None:
                categories = [f.category for f in verdict.findings]
                density = _extract_density(verdict)
                turn_risk = ctx.turn_signals.compute_risk()
                await self._threat_accumulator.record(
                    session_id, text, verdict.status.value, categories,
                    density=density, turn_risk=turn_risk,
                )
            # Turn ends here — clear signals
            ctx._clear_signals()

        return verdict

    async def scan_pii(self, text: str, ctx: AgentContext) -> ScanVerdict:
        """Run the configured PII scanner on text, and nothing else.

        Same pipeline as scan_input — action, block_at, on_error, one audit
        event — narrowed to `regex_pii`. Useful for content that needs PII
        detection but not injection scanning (a structured API response, say).

        **Blocks** when `regex_pii` is not declared under `scan_input.scanners`:
        asking for a scan that cannot be performed is not an allow. See
        _narrow_scan.
        """
        return await self._narrow_scan(
            text, ctx, subset="regex_pii",
            match=lambda n: n == "regex_pii",
        )

    async def scan_injection(self, text: str, ctx: AgentContext) -> ScanVerdict:
        """Run the configured injection scanner on text, and nothing else.

        Same pipeline as scan_input, narrowed to the injection-catalog family.
        Useful for a specific input surface — a URL parameter, a tool name, a
        structured field.

        **Blocks** when no injection scanner is declared under
        `scan_input.scanners`. See _narrow_scan.
        """
        return await self._narrow_scan(
            text, ctx, subset="injection_scan",
            match=lambda n: n.startswith("injection_scan"),
        )

    async def _narrow_scan(
        self,
        text: str,
        ctx: AgentContext,
        *,
        subset: str,
        match: Callable[[str], bool],
    ) -> ScanVerdict:
        """Run the subset of `scan_input.scanners` whose name satisfies `match`.

        Config is the only source of what runs. A scanner the operator did not
        declare is never substituted in: these helpers previously fell back to
        the *entire* input stack when the named scanner was absent, so asking
        for targeted PII detection silently ran injection, jailbreak and the
        heuristic backstop under scan_input's block_at — the opposite of what
        the call says.

        With nothing to run, run_scan fails the call closed: an enabled
        boundary that inspects nothing must not answer ALLOW, because the
        caller cannot tell that from a scan that ran and found nothing. The
        operator picks which scanners run; picking none for a surface the code
        asks about is a configuration error, not a pass.

        Emits under BoundaryName.NARROW_SCAN rather than INPUT_SCAN so a
        consumer counting input scans per turn is not thrown off by a helper
        call, and `adapters` names the subset that actually ran.
        """
        scanners = [
            c for c in self._input_scanners
            if match(getattr(c.scanner, "name", ""))
        ]
        if not scanners:
            log.warning(
                "narrow scan requested but no matching scanner is configured — "
                "nothing will run",
                extra={"op": "narrow_scan", "subset": subset,
                       "configured": [getattr(c.scanner, "name", "?")
                                      for c in self._input_scanners],
                       **ctx.to_log_fields()},
            )
        return await run_scan(
            text, ctx,
            boundary=BoundaryName.NARROW_SCAN,
            scanners=scanners,
            boundary_action=self._config.scan_input.action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._config.scan_input.enabled,
            block_at=self._config.scan_input.block_at,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            on_error=self._config.scan_input.on_error,
        )

    async def check_tool_call(
        self, name: str, args: dict[str, Any], ctx: AgentContext
    ) -> GateDecision:
        # R1: rate limit check before the gate runs
        if self._rate_limiter is not None:
            allowed, reason = self._rate_limiter.check(ctx.agent_id, name)
            if not allowed:
                return await self._deny_pre_gate(reason, name, ctx)

        # R2: session execution budget check
        limits = self._agent_limits.get(ctx.agent_id)
        if limits is not None and limits.any_enabled():
            # Same session key as the threat accumulator (scan_input,
            # scan_tool_result) — one spelling of "which session is this".
            session_id = ctx.conversation_id or ctx.agent_id
            # The turn is the prompt: TurnSignals is created at scan_input and
            # cleared at scan_output, so a new turn_id means a new user turn
            # and SessionBudget resets the fan-out counter. Tool-only flows
            # that never call scan_input carry no signals — fan-out stays off.
            prompt_id = ctx.turn_signals.turn_id if ctx.turn_signals else None
            allowed, reason = self._session_budget.check(
                ctx.agent_id, session_id, name, args, limits,
                prompt_id=prompt_id,
            )
            if not allowed:
                return await self._deny_pre_gate(reason, name, ctx)

        # Pre-gate: agent must be registered — deny with audit event on miss
        try:
            agent_config = self._agent_registry.get(ctx.agent_id)
        except Exception:
            # audit_tags come off the agent config, which is exactly what is
            # missing here — the event carries none rather than guessing.
            return await self._deny_pre_gate(
                f"agent '{ctx.agent_id}' is not registered in this harness",
                name, ctx, audit_tags={},
            )

        # Composite tool identity: (source_name, Tool) tuple
        agent_tool_map = self._agent_tools.get(ctx.agent_id, {})
        tool_entry     = agent_tool_map.get(name)
        source_name    = tool_entry[0] if tool_entry else "local"
        # Pass flat {name: Tool} to run_gate — gate only needs the Tool
        tools = {k: v[1] for k, v in agent_tool_map.items()}

        gate = await run_gate(
            name, args, ctx,
            agent_config=agent_config,
            tools=tools,
            policy=self._policy,
            arg_scanners=self._arg_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            scan_args_for_tags=self._scan_args_for_tags,
            correlate_tool_result=self._correlate_tool_result,
            turn_signals=ctx.turn_signals,
            source_name=source_name,
            # The gate calls this only when it allows, and before it emits, so
            # token_id lands on the event that authorised the dispatch.
            issue_token=(
                (lambda: self._mint_dispatch_token(name, source_name, ctx))
                if self._connectivity.enabled and self._connectivity_secret
                else None
            ),
        )

        # Record gate outcome to TurnSignals for downstream boundaries
        if ctx.turn_signals is not None:
            tool_obj = tools.get(name)
            tool_tags = frozenset(tool_obj.tags) if tool_obj else frozenset()
            ctx.turn_signals.record_gate(gate.allowed, name, tool_tags)

        return gate

    async def scan_file(self, path: str | Path, ctx: AgentContext) -> ScanVerdict:
        """Scan an uploaded file through the file boundary.

        Pass 1 (structural): MIME type, extension, size, filename, PDF JS,
                             EXIF metadata, ZIP structure, Office macros.
        Pass 2 (content):    Extracted text run through configured scanners.

        Returns ScanVerdict identical in shape to scan_input/scan_output.
        """
        return await run_scan(
            str(path), ctx,
            boundary=BoundaryName.FILE_SCAN,
            # scan_file has no per-scanner overrides — FileScanConfig rejects
            # them, so the boundary action applies to the whole content chain.
            scanners=self._file_scanners,
            boundary_action=self._config.scan_file.action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._config.scan_file.enabled,
            block_at=self._config.scan_file.block_at,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            on_error=self._config.scan_file.on_error,
        )

    async def scan_tool_result(
        self,
        result: str,
        ctx: AgentContext,
    ) -> ScanVerdict:
        """Scan a tool return value before it re-enters the LLM context.

        Every tool result is scanned. There is no per-tool opt-out — a tool
        whose output the operator believes is safe is exactly the one an
        indirect-injection payload arrives through.
        """
        verdict = await run_tool_result_scan(
            result, ctx,
            scanners=self._tool_result_scanners,
            boundary_action=self._config.scan_tool_result.action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._config.scan_tool_result.enabled,
            block_at=self._config.scan_tool_result.block_at,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            on_error=self._config.scan_tool_result.on_error,
        )

        # Record signals from the tool result scan
        if ctx.turn_signals is not None:
            ctx.turn_signals.record_tool_result(verdict)

        return verdict

    async def scan_output(self, text: str, ctx: AgentContext) -> ScanVerdict:
        session_id = ctx.conversation_id or ctx.agent_id

        verdict = await run_scan(
            text, ctx,
            boundary=BoundaryName.OUTPUT_SCAN,
            scanners=self._output_scanners,
            boundary_action=self._config.scan_output.action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._config.scan_output.enabled,
            block_at=self._config.scan_output.block_at,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            on_error=self._config.scan_output.on_error,
        )

        # Option A: consolidated risk-based block. Even if no individual
        # scanner blocked, if the accumulated turn risk crosses RISK_HIGH,
        # block at scan_output — the last boundary with the full picture.
        turn_risk = 0.0
        if ctx.turn_signals is not None:
            turn_risk = ctx.turn_signals.compute_risk()
            if turn_risk >= RISK_HIGH and verdict.status != ScanStatus.BLOCK:
                verdict = await self._emit_risk_block(ctx, turn_risk)

        # Accumulator record — moved from scan_input to scan_output so the
        # session score reflects the full-turn consolidated risk, not just
        # the input scan verdict.
        if self._threat_accumulator is not None:
            categories = [f.category for f in verdict.findings]
            density = _extract_density(verdict)
            await self._threat_accumulator.record(
                session_id, text, verdict.status.value, categories,
                density=density, turn_risk=turn_risk,
            )

        # Clear the turn signal bus — the turn ends here
        ctx._clear_signals()

        return verdict

    async def _emit_risk_block(
        self, ctx: AgentContext, turn_risk: float
    ) -> ScanVerdict:
        """Emit an audit event for a consolidated-risk block. Called by
        scan_output when compute_risk() crosses RISK_HIGH.
        """
        from harness.core.events import AuditEvent

        deny_reason = (
            f"consolidated turn risk {turn_risk:.2f} exceeds high threshold "
            f"({RISK_HIGH:.2f})"
        )
        event = AuditEvent.build(
            boundary=BoundaryName.OUTPUT_SCAN,
            decision=Decision.BLOCKED,
            ctx=ctx,
            tenant_id=self._tenant_id,
            duration_ms=0,
            deny_reason=deny_reason,
            audit_tags=self._audit_tags_for(ctx),
            extra={
                "turn_risk":     round(turn_risk, 4),
                "signal_source": "consolidated",
            },
        )
        await self._emitter.emit(event)
        return ScanVerdict(status=ScanStatus.BLOCK)


    @property
    def scanners(self) -> dict[str, object]:
        """Return all active scanner instances keyed by name.

        Provides visibility into which scanners are running and their
        configuration. Useful for inspection, testing, and debugging.

        Covers the boundaries the facade runs: scan_input, scan_output,
        scan_tool_result, scan_file, and the gate's argument scanners. A
        scanner used at more than one boundary appears once (the first
        instance seen, scanning input first). MCP metadata scanners are not
        here — they live on the MCPSource that runs them at connect time.

            harness.scanners
            # {
            #   'regex_pii':          RegexPIIScanner(...),
            #   'injection_scan':     InjectionScanner(...),
            #   'heuristic_scan':     HeuristicScanner(...),   # always-on backstop
            #   'file_scanner':       FileScanner(...),
            #   'file_content_scan':  FileContentScanner(...),
            #   'rate_limiter':       RateLimiter(...),
            # }
        """
        result: dict[str, object] = {}
        configured = (
            self._input_scanners
            + self._output_scanners
            + self._tool_result_scanners
            + self._file_scanners
        )
        for scanner in [c.scanner for c in configured] + self._arg_scanners:
            name = getattr(scanner, "name", type(scanner).__name__)
            result[name] = scanner
        if self._rate_limiter is not None:
            result["rate_limiter"] = self._rate_limiter
        return result

    def collect_events(self) -> AbstractContextManager[list[AnyAuditEvent]]:
        """Context manager that collects AuditEvents emitted during the block.

        Events are appended to the returned list in-place. Complete when the
        block exits. Configured sinks (file, stdout) are unaffected.

        Usage::

            with harness.collect_events() as events:
                gate    = await harness.check_tool_call(name, args, ctx)
                verdict = await harness.scan_input(text, ctx)
            for ev in events:
                print(ev.boundary, ev.decision)

        Or around a full agent turn::

            with harness.collect_events() as events:
                result = await app.ainvoke(messages)
            display_audit_summary(events)
        """
        return self._emitter.collect_events()

    async def close(self) -> None:
        """Release every resource the harness holds. Call at process shutdown.

        Best-effort and idempotent: one component failing to close must not
        strand the others. Sources first, then the audit trail, then the
        session store — an event emitted during source teardown still has
        somewhere to land.
        """
        await self._source_registry.close()
        await self._emitter.close()
        if self._threat_accumulator is not None:
            try:
                await self._threat_accumulator.close()
            except Exception as e:
                # Broad catch is deliberate: shutdown continues regardless of
                # what the session DB does on the way out.
                log.warning("threat accumulator close failed",
                            extra={"error": str(e), "op": "close"})

    async def get_source(self, name: str) -> ToolSource:
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

    def _mint_dispatch_token(
        self, tool_name: str, source_name: str, ctx: AgentContext
    ) -> tuple[str, str]:
        """Issue a dispatch token for an allowed call. Returns (encoded, token_id).

        Called by the gate on its allow path only. The destination allow-lists
        come from the source that owns the tool, falling back to the source's
        own host when it declares none — a token is never issued unbounded.
        """
        from harness.connectivity.token import (
            default_allowed_urls,
            encode_token,
            sign_token,
        )

        source_cfg = next(
            (s for s in self._config.sources if s.name == source_name), None
        )
        allowed_urls = (
            list(source_cfg.allowed_urls)
            if source_cfg and source_cfg.allowed_urls
            else (default_allowed_urls(source_cfg.url)
                  if source_cfg and source_cfg.url else [])
        )
        allowed_methods = (
            list(source_cfg.allowed_methods)
            if source_cfg and source_cfg.allowed_methods
            else ["GET", "POST", "PUT", "DELETE", "PATCH"]
        )
        token = sign_token(
            agent_id=ctx.agent_id,
            sub_agent_id=ctx.sub_agent_id,
            tenant_id=self._tenant_id,
            tool_name=tool_name,
            source_name=source_name,
            allowed_urls=allowed_urls,
            allowed_methods=allowed_methods,
            secret=self._connectivity_secret,
            ttl_seconds=self._connectivity.token_ttl_seconds,
        )
        log.debug("dispatch token issued",
                  extra={"agent_id": ctx.agent_id, "tool": tool_name,
                         "token_id": token.token_id,
                         "expires_at": token.expires_at.isoformat()})
        return encode_token(token), token.token_id

    async def _deny_pre_gate(
        self,
        reason: str,
        tool_name: str,
        ctx: AgentContext,
        *,
        audit_tags: dict[str, str] | None = None,
    ) -> GateDecision:
        """Refuse a tool call before the gate runs — rate limit, session budget,
        unregistered agent.

        Routes through the gate's own deny path so a pre-gate refusal is
        indistinguishable in the audit trail from one the seven layers produced:
        same boundary, same decision, same fields. The turn-signal write happens
        here because these refusals never reach the layer that records it.
        """
        gate = await emit_gate_deny(
            reason, tool_name, None, ctx, self._emitter,
            now_ms(), self._tenant_id,
            audit_tags=self._audit_tags_for(ctx) if audit_tags is None else audit_tags,
        )
        if ctx.turn_signals is not None:
            ctx.turn_signals.record_gate(False, tool_name)
        return gate

    def _source_name_for_tool(self, tool_name: str, tool: Tool) -> str:
        """Return the source name for a Tool object.

        Uses the Tool's transport to determine the source type:
        - LOCAL/SKILL → 'local'
        - MCP → look up via connector_tool_specs or tool_names on source configs

        Called once per tool at _resolve_tools() time — no per-turn overhead.
        """
        from harness.core.types import Transport
        if tool.transport != Transport.MCP:
            return "local"
        # Check connector manifests first — most precise
        for src_cfg in self._config.sources:
            if src_cfg.transport != "mcp":
                continue
            if tool_name in src_cfg.connector_tool_specs:
                return src_cfg.name
            if src_cfg.tool_names and tool_name in src_cfg.tool_names:
                return src_cfg.name
        # Fall back to first unrestricted MCP source
        for src_cfg in self._config.sources:
            if src_cfg.transport == "mcp" and not src_cfg.tool_names:
                return src_cfg.name
        return "local"

    def _resolve_tools(self, cfg: AgentConfig) -> dict[str, tuple[str, Tool]]:
        """Build the {tool_name: (source_name, Tool)} dict for an agent at startup.

        Composite identity: every tool carries its source_name so the gate
        always knows which source the tool belongs to without a separate lookup.
        source_name is 'local' for LOCAL/SKILL tools, the MCP source name
        for remote tools.
        """
        all_tools   = self._tool_registry.as_dict()
        overrides   = self._source_overrides.get(cfg.id, {})
        agent_names = set(cfg.allowed_tool_names)

        resolved: dict[str, tuple[str, Tool]] = {}

        for name, tool in all_tools.items():
            if name not in agent_names:
                continue
            source_name = self._source_name_for_tool(name, tool)
            resolved[name] = (source_name, tool)

        # Apply enriched overrides — replaces registry entry for this agent only
        for name, tool in overrides.items():
            if name in agent_names:
                source_name = self._source_name_for_tool(name, tool)
                resolved[name] = (source_name, tool)

        return resolved

    def _audit_tags_for(self, ctx: AgentContext) -> dict[str, str]:
        try:
            return dict(self._agent_registry.get(ctx.agent_id).audit_tags)
        except Exception:
            return {}

    def _build_execution_limits(self, cfg: AgentConfig) -> ExecutionLimits:
        """Merge global execution_budget defaults with per-agent limits: overrides."""
        from harness.config.schema import ExecutionBudgetConfig

        # Global defaults from harness.yaml check_tool_call.execution_budget
        global_budget: ExecutionBudgetConfig = self._config.check_tool_call.execution_budget

        # Agent-level overrides from agent-xx.yaml limits: block
        agent_raw: dict = cfg.limits  # validated as dict[str, Any] by AgentConfig

        # Parse agent overrides through the same schema for validation
        if agent_raw:
            # Merge: agent values override global values
            merged = {
                "max_steps":                 global_budget.max_steps,
                "max_tool_calls_per_prompt": global_budget.max_tool_calls_per_prompt,
                "loop_detection_window":     global_budget.loop_detection_window,
                "loop_similarity_threshold": global_budget.loop_similarity_threshold,
            }
            merged.update(agent_raw)
            try:
                effective = ExecutionBudgetConfig.model_validate(merged)
            except Exception as e:
                # Backstop. AgentConfig._valid_limits rejects a bad limits: block
                # at parse time, so a file-loaded agent cannot reach here — this
                # catches a directly-constructed AgentConfig. Fail closed either
                # way: falling back to global defaults would discard the agent's
                # *valid* limits alongside the bad key, and an agent declaring
                # max_steps would silently run unbounded on a typo.
                raise ConfigError(
                    f"agent '{cfg.id}' has an invalid limits: block: {e}",
                    agent_id=cfg.id,
                    op="build_execution_limits",
                ) from e
        else:
            effective = global_budget

        return ExecutionLimits(
            max_steps=effective.max_steps,
            max_tool_calls_per_prompt=effective.max_tool_calls_per_prompt,
            loop_detection_window=effective.loop_detection_window,
            loop_similarity_threshold=effective.loop_similarity_threshold,
        )


# ── Module-level adapter builders ─────────────────────────────────────────
#
# Each scanner is a named, standalone class. _build_text_scanners resolves
# them from AdapterRef declarations in harness.yaml. The named factories
# below make the mapping explicit — no magic string dispatch.

def _extract_density(verdict) -> float:
    """Instruction-density sub-score from the heuristic scanner, or 0.0.

    Reads Finding.signals rather than parsing Finding.detail — the detail
    string is for humans and rewording it must not change what the threat
    accumulator scores.
    """
    for f in verdict.findings:
        if f.scanner == "heuristic_scan" and "density" in f.signals:
            return f.signals["density"]
    return 0.0


def _make_file_injection_scanner(cfg: dict) -> InjectionScanner:
    """Build the common + input + document catalog union for file content."""
    doc_patterns = Path(__file__).parent.parent / "adapters/scanners/l10n/patterns_for_doc.yaml"
    return InjectionScanner(
        additional_patterns_files=(doc_patterns,),
        **cfg,
    )


# Signed-DB catalog name per injection-family scanner. Explicit rather than
# derived from the scanner name: the catalog names are an operator-facing
# contract in the bundle format and must not shift if a scanner is renamed.
# Only InjectionScanner and its subclasses appear here — they share one
# __init__, so every name in this table accepts extra_rules. A subclass that
# overrides __init__ without forwarding the kwarg breaks that and is rejected
# by test_db_catalog_scanners_accept_extra_rules.
_DB_CATALOG_FOR_SCANNER: dict[str, str] = {
    "injection_scan":      "injection",
    "jailbreak_scan":      "jailbreak",
    "identity_spoof_scan": "identity_spoof",
    "mcp_metadata_scan":   "mcp_metadata",
}


# Named registry — explicit, no magic strings
_SCANNER_FACTORIES: dict[str, Any] = {
    "regex_pii":           lambda cfg: RegexPIIScanner(**cfg),
    "injection_scan":      lambda cfg: InjectionScanner(**cfg),
    "heuristic_scan":      lambda cfg: HeuristicScanner(**cfg),
    "mcp_metadata_scan":   lambda cfg: MCPMetadataScanner(**cfg),
    "jailbreak_scan":      lambda cfg: __import__(
        "harness.adapters.scanners.jailbreak_scan", fromlist=["JailbreakScanner"]
    ).JailbreakScanner(**cfg),
    "identity_spoof_scan": lambda cfg: __import__(
        "harness.adapters.scanners.identity_spoof_scan", fromlist=["IdentitySpoofScanner"]
    ).IdentitySpoofScanner(**cfg),
}


def _build_text_scanners(
    adapter_refs: list,
    *,
    extra_rules: dict[str, list] | None = None,
    include_document_patterns: bool = False,
) -> list[ConfiguredScanner]:
    """Build text scanners from AdapterRef declarations in harness.yaml.

    Built-in scanners (regex_pii, injection_scan) are resolved via the
    named factory table above. Custom scanners are resolved via entry points.

    Each scanner is paired with the action / redact_with of the ref that
    produced it, so a ref that fails to resolve drops out with its own
    overrides and cannot shift another scanner's action onto it.

    extra_rules maps scanner name → compiled rules from the signed pattern DB
    (see _DB_CATALOG_FOR_SCANNER). Only injection-family names appear in it, so
    scanners that do not accept extra_rules never receive the kwarg.

    HeuristicScanner is the always-on structural backstop: appended here with
    no override (the boundary action governs it) unless an explicit
    `heuristic_scan` ref already placed it. Declaring it in harness.yaml only
    controls its position and per-scanner action.
    """
    scanners: list[ConfiguredScanner] = []
    for ref in adapter_refs:
        factory = _SCANNER_FACTORIES.get(ref.name)
        if factory:
            cfg = ref.config
            if extra_rules and ref.name in extra_rules:
                # Copy: ref.config is shared across every boundary's build call.
                cfg = {**cfg, "extra_rules": extra_rules[ref.name]}
            scanner = (
                _make_file_injection_scanner(cfg)
                if include_document_patterns and ref.name == "injection_scan"
                else factory(cfg)
            )
        else:
            try:
                from harness.adapters.discovery import resolve
                cls = resolve("harness.scanners", ref.name)
                scanner = cls(**ref.config)
            except Exception as e:
                log.warning("scanner adapter not found — skipped",
                            extra={"adapter_name": ref.name, "error": str(e)})
                continue
        scanners.append(ConfiguredScanner(scanner, ref.action, ref.redact_with))
    if not any(getattr(c.scanner, "name", "") == HeuristicScanner.name for c in scanners):
        scanners.append(ConfiguredScanner(HeuristicScanner()))
    return scanners


def _build_file_scanners(
    adapter_refs: list, *, max_size_mb: float
) -> list[ConfiguredScanner]:
    """Build the scan_file scanner list.

    Two independent scanners, so a failing content scanner cannot discard the
    structural findings and each is governed by on_error on its own:

      FileScanner        — structural pass (MIME, size, extension, PDF JS, SVG,
                           EXIF, ZIP, Office macros)
      FileContentScanner — the configured chain over extracted text and image
                           metadata

    `scan_file.scanners` is that content chain and is authoritative, exactly as
    `scan_input.scanners` is for input — declared scanners are what run over
    extracted content.
    """
    from harness.adapters.scanners.file_scanner import (
        FileContentScanner,
        FileScanner,
    )

    refs = [r for r in adapter_refs if r.name != "file_scanner"]
    # The content chain runs inside FileContentScanner, which calls the
    # scanners directly — FileScanConfig rejects per-scanner overrides, so
    # only the instances travel down.
    text_scanners = [
        c.scanner
        for c in _build_text_scanners(refs, include_document_patterns=True)
    ]
    return [
        ConfiguredScanner(FileScanner(max_size_mb=max_size_mb)),
        ConfiguredScanner(
            FileContentScanner(text_scanners=text_scanners, max_size_mb=max_size_mb)
        ),
    ]


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
