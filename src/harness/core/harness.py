"""SHAI facade — the only public entry point of the SDK.

One SHAI instance serves many concurrent agent turns safely.
Agent tools are resolved once at load_agent() time — no per-turn overhead.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness.adapters.scanners.base import ConfiguredScanner
from harness.adapters.scanners.rate_limiter import RateLimiter
from harness.agents.agent_config import AgentConfig, RuleConfig
from harness.agents.registry import AgentRegistry
from harness.agents.revocation import RevocationStore
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import ScanState, run_scan, run_tool_result_scan
from harness.boundaries.check_tool_call import emit_deny as emit_gate_deny
from harness.boundaries.check_tool_call import run as run_gate
from harness.boundaries.session_accumulator import ThreatAccumulator
from harness.boundaries.session_budget import ExecutionLimits, SessionBudget
from harness.config.loader import build_secrets_provider, load_dict, read_yaml
from harness.config.schema import HarnessConfig, SourceConfig
from harness.core import wiring
from harness.core.approval import ApprovalPolicy
from harness.core.attestation import STARTUP_AGENT_ID, build_attestation
from harness.core.context import AgentContext
from harness.core.errors import ConfigError
from harness.core.events import AuditEvent, now_ms
from harness.core.turn_signals import RISK_HIGH, TurnSignals
from harness.core.types import BoundaryName, Decision, ScanStatus, Transport
from harness.core.verdicts import GateDecision, ScanVerdict
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, SourceRegistry, ToolSource
from harness.tools.tool import Tool

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from harness.agents.agent_config import SubAgentConfig
    from harness.core.events import AnyAuditEvent
    from harness.maintenance import Maintenance
    from harness.mcp.gate import McpBaselineGate
    from harness.policy.engine import PolicyEngine

log = logging.getLogger(__name__)


class SHAI:
    """Control-plane facade for production agents.

    Startup sequence:
        harness = SHAI.from_yaml("config/harness.yaml")
        await harness.register_tools([...])
        agent = await harness.load_agent("config/agents/my_agent.yaml")

    Per-turn:
        ctx     = agent.for_conversation(conversation_id)
        verdict = await harness.scan_input(text, ctx)
        gate    = await harness.check_tool_call(name, args, ctx)
        verdict = await harness.scan_output(text, ctx)

    One instance serves many concurrent turns. Instance state — resolved tools,
    rate limiter, session budget, audit emitter — is keyed and safe to share.
    The *context* is not: it carries the turn's signal bus, so concurrent turns
    need one context each. `for_conversation()` derives them, and doing so also
    separates the execution budget and the cross-turn threat score, which key
    on `conversation_id or agent_id`. Reusing one context across concurrent
    turns merges all three.

    Async surface
    -------------
    Two layers, two rules, and they differ on purpose.

    *This facade* is uniformly async for boundaries and lifecycle. It is the
    stability boundary the SDK publishes, and `await harness.get_source(...)`
    appears in the docs and in every integration; a method here does not lose
    its `await` because today's implementation happens to be a dict read.

    *The registries behind it* (`ToolRegistry`, `AgentRegistry`,
    `SourceRegistry`) are `async` iff they actually await —
    `AgentRegistry.load` parses YAML off the event loop, `SourceRegistry.activate`
    loads sources concurrently, and everything else is synchronous. They are
    internal, so nothing outside this package has to change when that rule is
    applied.
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
        policy: PolicyEngine,
        rate_limiter: RateLimiter | None,
        source_registry: SourceRegistry,
        connectivity_secret: bytes | None = None,
        mcp_required_flags: dict[str, bool] | None = None,
        mcp_baseline_gate: McpBaselineGate | None = None,
        mcp_policy_rules: dict[str, list[RuleConfig]] | None = None,
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
        self._revocations = RevocationStore(
            config.revocation.path or None,
            cache_ttl_seconds=config.revocation.cache_ttl_seconds,
        )
        # Layer 3 approval policy. An empty secret leaves it None, which denies
        # every SENSITIVE/IRREVERSIBLE tool rather than admitting one unverified.
        _approvals_cfg = config.check_tool_call.approvals
        self._approvals = ApprovalPolicy(
            secret=_approvals_cfg.secret.encode() if _approvals_cfg.secret else None,
            sensitive_quorum=_approvals_cfg.sensitive_quorum,
            irreversible_quorum=_approvals_cfg.irreversible_quorum,
        )
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
        # required flags for MCP sources built from manifests — keyed by
        # manifest id, merged with local sources' required flags in
        # _wire_agent (local sources carry their own on SourceConfig).
        self._mcp_required_flags: dict[str, bool] = dict(mcp_required_flags or {})
        # Gate-level MCP manifest approval check — see harness.mcp.gate. None
        # when mcp_manifests_dir is unset, matching McpBaselineGate's own
        # always-approve posture for an unknown source_name.
        self._mcp_baseline_gate: McpBaselineGate | None = mcp_baseline_gate
        # Per-source deny rules compiled from each manifest's per-tool
        # `action: block` — keyed by source name, handed to layer 5 ahead of
        # the agent's own rules. See harness.mcp.discovery.compile_manifest_rules.
        self._mcp_policy_rules: dict[str, list[RuleConfig]] = dict(mcp_policy_rules or {})
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
        # Operational surface — agent admin, kill switch, scanner inspection.
        # Off the per-turn path and reached as `harness.maintenance`, so the
        # facade below carries only what a turn actually calls.
        from harness.maintenance import Maintenance
        self._maintenance = Maintenance(self)
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

        Startup attestation:
          Emits one SYSTEM/STARTUP AuditEvent recording the wired components
          (see core/attestation.py) before returning. Unlike the SYSTEM/DEGRADED
          event, this emission is not best-effort: if every sink fails,
          AuditEmissionError propagates and construction fails. A harness that
          cannot write its first audit record cannot write the rest either.
        """
        # The provider is named by the raw `secrets:` block and built before
        # validation, because it is what resolves the secret:// URIs the rest
        # of the config holds. Absent block → EnvVarProvider.
        raw = read_yaml(path)
        provider = build_secrets_provider(raw.get("secrets"))

        # The loader resolves ${ENV_VAR} and every secret:// URI in one pass —
        # it recurses the whole parsed tree, so no field reaches the config
        # models still holding a URI.
        config = load_dict(raw, provider=provider, source=str(path))
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

            for scanner_name, catalog in wiring._DB_CATALOG_FOR_SCANNER.items():
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

        input_scanners  = wiring._build_text_scanners(config.scan_input.scanners, extra_rules=db_extra_rules)
        output_scanners = wiring._build_text_scanners(config.scan_output.scanners, extra_rules=db_extra_rules)
        # Configured pairs, not bare instances: layer 7 honours each scanner's
        # declared action exactly as every other boundary does. Stripping the
        # pairing here made `action: redact` on a check_tool_call scanner load
        # without complaint and do nothing.
        arg_scanners    = wiring._build_text_scanners(
            config.check_tool_call.scanners, extra_rules=db_extra_rules
        )
        file_scanners   = wiring._build_file_scanners(
            config.scan_file.scanners,
            max_size_mb=config.scan_file.max_size_mb,
            normalization=config.normalization,
        )

        policy = wiring._build_policy(config.policy)

        sinks   = wiring._build_sinks(config.audit_sinks)

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

        tool_result_scanners = wiring._build_text_scanners(
            config.scan_tool_result.scanners,
            extra_rules=db_extra_rules,
        )

        # MCP metadata scanners run inside MCPSource via scan_tool(), not
        # through run_scan — instances only. They take signed-DB rules like
        # every other catalog scanner.
        mcp_metadata_scanners = [
            c.scanner for c in wiring._build_text_scanners(
                config.scan_mcp_metadata.scanners, extra_rules=db_extra_rules
            )
        ]

        # Build shared registries first — source_registry needs tool_registry
        tool_registry   = ToolRegistry()
        agent_registry  = AgentRegistry(
            forbidden_tag_combinations=config.policy.forbidden_tag_sets(),
        )

        # Build SourceRegistry: local sources straight from config.sources
        # (transport: local | skill), MCP sources resolved from the
        # `transport: mcp` entries in config.sources — see
        # harness.mcp.discovery. Sources always build and connect regardless
        # of onboarding approval — approval is checked per tool call instead
        # (see harness.mcp.gate.McpBaselineGate, built below).
        # resolved_sources holds every declared SourceConfig — the startup
        # attestation records what the harness declares, MCP included, even
        # for a name whose manifest has no approved baseline.
        source_registry = SourceRegistry(policy)
        resolved_sources: list[SourceConfig] = list(config.sources)
        for src_cfg in config.sources:
            if src_cfg.transport == Transport.MCP:
                continue
            source = LocalSource(src_cfg, registry=tool_registry)
            source_registry.register(source)

        mcp_required_flags: dict[str, bool] = {}
        mcp_manifest_paths: dict[str, Path] = {}
        mcp_policy_rules: dict[str, list[RuleConfig]] = {}
        if any(s.transport == Transport.MCP for s in config.sources):
            from harness.mcp.discovery import (
                build_mcp_source,
                compile_manifest_rules,
                resolve_mcp_sources,
            )

            for resolved in resolve_mcp_sources(
                config.sources,
                mcp_manifests_dir=config.mcp_manifests_dir,
                baseline_path=config.mcp_baseline.path,
                baseline_secret=config.mcp_baseline.secret.encode(),
            ):
                mcp_required_flags[resolved.manifest.id] = resolved.manifest.required
                mcp_manifest_paths[resolved.manifest.id] = resolved.path
                rules = compile_manifest_rules(resolved.manifest)
                if rules:
                    mcp_policy_rules[resolved.manifest.id] = rules
                source = build_mcp_source(
                    resolved,
                    secrets_provider=provider,
                    connectivity=config.connectivity,
                    emitter=emitter,
                    tenant_id=config.tenant_id,
                    metadata_scanners=mcp_metadata_scanners,
                    metadata_enabled=config.scan_mcp_metadata.enabled,
                    metadata_block_at=config.scan_mcp_metadata.block_at,
                    metadata_action=config.scan_mcp_metadata.action,
                )
                source_registry.register(source)

        mcp_baseline_gate = None
        if mcp_manifest_paths:
            from harness.mcp.gate import McpBaselineGate
            mcp_baseline_gate = McpBaselineGate(
                mcp_manifest_paths,
                baseline_path=config.mcp_baseline.path,
                secret=config.mcp_baseline.secret.encode(),
                cache_ttl_seconds=config.mcp_baseline.cache_ttl_seconds,
            )

        rl_cfg = config.check_tool_call.rate_limit
        rate_limiter = (
            RateLimiter(
                window_seconds=rl_cfg.window_seconds,
                max_calls_per_window=rl_cfg.max_calls_per_window,
                max_calls_per_tool=rl_cfg.max_calls_per_tool,
            )
            if rl_cfg.enabled else None
        )

        instance = cls(
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
            mcp_required_flags=mcp_required_flags,
            mcp_baseline_gate=mcp_baseline_gate,
            mcp_policy_rules=mcp_policy_rules,
        )

        await emitter.emit(AuditEvent.build(
            boundary=BoundaryName.SYSTEM,
            decision=Decision.STARTUP,
            # No agent exists yet — this event describes the process, not a call.
            ctx=AgentContext(agent_id=STARTUP_AGENT_ID),
            tenant_id=config.tenant_id,
            duration_ms=0,
            extra=build_attestation(
                config=config,
                # Scanner instances actually wired, across every boundary.
                scanners=[
                    *[c.scanner for c in input_scanners],
                    *[c.scanner for c in output_scanners],
                    *[c.scanner for c in arg_scanners],
                    *[c.scanner for c in file_scanners],
                    *[c.scanner for c in tool_result_scanners],
                    *mcp_metadata_scanners,
                ],
                sinks=sinks,
                policy=policy,
                sources=resolved_sources,
            ),
        ))
        log.info("harness startup attested",
                 extra={"op": "from_yaml", "tenant_id": config.tenant_id,
                        "sources": len(resolved_sources)})
        return instance

    # ── Operational surface ───────────────────────────────────────────────

    @property
    def maintenance(self) -> Maintenance:
        """Agent administration, the kill switch, and scanner inspection.

            harness.maintenance.revoke_agent("billing_agent")
            harness.maintenance.registered_agents()

        Separate because none of it runs during a turn. What stays on this
        facade is the per-turn contract: the five boundaries plus the calls a
        turn needs to reach them.
        """
        return self._maintenance

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
        self._tool_registry.register_many(shai_descriptors)
        # Re-resolve all already-loaded agents so they see the new tools
        for cfg in self._agent_registry.list():
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
        await self._wire_agent(cfg, message="agent loaded", op="load_agent")
        return AgentContext(agent_id=cfg.id)

    async def _wire_agent(self, cfg: AgentConfig, *, message: str, op: str) -> None:
        """Activate an agent's sources and build its resolved tools and limits.

        The one place an agent's per-turn state is constructed. load_agent and
        reload_agent differ only in which registry call produced `cfg`; keeping
        two copies of this body is how reload_agent came to omit
        required_flags, which promoted every `required: false` source back to
        mandatory and turned a reload into ConfigError whenever an optional
        source was down.
        """
        ctx = AgentContext(agent_id=cfg.id)

        # Activate declared sources for this agent
        # Build required_flags starting from every SourceConfig's own
        # `required` (covers a `transport: mcp` entry whose manifest has no
        # approved baseline and so was never built), then override with each
        # built MCP source's own manifest `required` field. required=True
        # (default either way) means a missing or failed source raises
        # ConfigError rather than degrading silently.
        required_flags = {
            sc.name: sc.required
            for sc in self._config.sources
        }
        required_flags.update(self._mcp_required_flags)
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
                self._tool_registry.register(tool)
                # Registered cleanly (new tool from MCP or first registration)
            except Exception:
                # Tag mismatch with an existing registry entry — store as override
                # so this agent sees the enriched version without polluting others.
                overrides[tool.name] = tool
        self._source_overrides[cfg.id] = overrides

        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        self._agent_limits[cfg.id] = self._build_execution_limits(cfg)
        log.info(message,
                 extra={"op": op,
                        "agent_id": cfg.id,
                        "tools": len(self._agent_tools[cfg.id]),
                        "source_tools": len(source_tools)})

    def _forget_agent(self, agent_id: str) -> None:
        """Drop every piece of per-agent state `_wire_agent` built, plus the
        counters keyed on the agent.

        The teardown half of `_wire_agent`, and the one place it lives —
        `Maintenance.deregister_agent` calls this rather than reaching for six
        dictionaries. An agent left in any of them keeps consuming its rate-limit
        and budget slots after it is gone.
        """
        self._agent_tools.pop(agent_id, None)
        self._source_overrides.pop(agent_id, None)
        self._agent_limits.pop(agent_id, None)
        if self._rate_limiter is not None:
            self._rate_limiter.reset(agent_id)
        self._session_budget.reset(agent_id)

    def tools_for(self, ctx: AgentContext) -> list[Tool]:
        """The tools this context can reach the gate's per-call layers with.

        Applies the gate's two *static* capability layers against the same
        effective profile check_tool_call resolves — L1 `allowed_tool_names`
        and L4 `allowed_tags` — so a subagent context returns the subagent's
        narrowed set, not the parent's. Returning the parent's set here would
        offer a subagent's model tools the gate denies on every call.

        This is a superset of what will actually be allowed, and deliberately
        so: argument rules, approvals, policy, signal correlation and arg
        scanning (L2, L3, L5, L6, L7) all depend on the call, not the agent,
        and cannot be answered without one. Use it to build a tool list for an
        LLM, never as a substitute for calling check_tool_call.

        Empty when the agent is not loaded, and when the context names a
        subagent the parent does not declare — both are cases where the gate
        allows nothing.

        Which source owns a tool is deliberately not exposed: that is the
        gate's business, and a caller routing on it would be dispatching
        around check_tool_call. Use gate.source_name from an allowed decision.
        """
        tools = [tool for _, tool in self._agent_tools.get(ctx.agent_id, {}).values()]
        if not tools:
            return []

        # Same effective-profile resolution as check_tool_call: a subagent is
        # gated by its own declaration, a parent by the agent's.
        try:
            agent_config = self._agent_registry.get(ctx.agent_id)
            effective: AgentConfig | SubAgentConfig = (
                agent_config.get_sub_agent(ctx.sub_agent_id)
                if ctx.sub_agent_id is not None else agent_config
            )
        except Exception:
            # Unregistered agent, or a subagent this agent does not declare.
            # The gate denies every call in both cases; report the same.
            return []

        allowed_names = set(effective.allowed_tool_names)
        # L4 intersects the profile's tags with the context's, neither widening
        # the other — see check_tool_call layer 4.
        capability_tags = set(effective.allowed_tags)
        if ctx.allowed_tags is not None:
            capability_tags &= set(ctx.allowed_tags)

        return [
            t for t in tools
            if t.name in allowed_names and not (set(t.tags) - capability_tags)
        ]

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
        #
        # A bus already attached means the previous turn on this context never
        # reached scan_output. Two causes, and the caller cannot be told apart
        # from here: an abandoned turn (the application raised mid-turn), or two
        # turns running concurrently through one shared context — which silently
        # merges their evidence. Replacing keeps Invariant 7 (per-turn signal
        # isolation) intact for the turn starting now; the log is what makes the
        # sharing case findable, since nothing else about it is observable.
        if ctx.turn_signals is not None:
            log.warning(
                "turn signals were still attached at scan_input — previous turn "
                "did not reach scan_output; if two turns share this "
                "AgentContext concurrently, derive one per conversation with "
                "ctx.for_conversation(id)",
                extra={"session_id": session_id, **ctx.to_log_fields()},
            )
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
            config=self._config.scan_input,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
        )

        # Record signals from the input scan
        ctx.turn_signals.record_input(verdict, text=text)

        # Accumulator record moved to scan_output — needs full turn context
        # for consolidated turn_risk. scan_input BLOCK short-circuits still
        # need to record; do that here for BLOCK only.
        if verdict.status == ScanStatus.BLOCK:
            if self._threat_accumulator is not None:
                categories = [f.category for f in verdict.findings]
                density = wiring._extract_density(verdict)
                turn_risk = ctx.turn_signals.compute_risk()
                await self._threat_accumulator.record(
                    session_id, text, verdict.status.value, categories,
                    density=density, turn_risk=turn_risk,
                )
            # Turn ends here — clear signals
            ctx._clear_signals()

        return verdict

    async def check_tool_call(
        self, name: str, args: dict[str, Any], ctx: AgentContext
    ) -> GateDecision:
        # R0: revocation — the kill switch. First, so a revoked agent consumes
        # no rate-limit or budget state on its way to being denied.
        if self._revocations.is_revoked(ctx.agent_id):
            return await self._deny_pre_gate(
                f"agent '{ctx.agent_id}' is revoked", name, ctx
            )

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

        # R3: MCP manifest onboarding approval — every call against an MCP
        # source is checked against the signed baseline store (see
        # harness.mcp.gate.McpBaselineGate). A no-op for local sources and
        # for a deployment with no mcp_manifests_dir configured.
        if self._mcp_baseline_gate is not None:
            approved, deny_reason = self._mcp_baseline_gate.check(source_name)
            if not approved:
                return await self._deny_pre_gate(deny_reason, name, ctx)

        gate = await run_gate(
            name, args, ctx,
            agent_config=agent_config,
            tools=tools,
            policy=self._policy,
            arg_scanners=self._arg_scanners,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            scan_args_for_tags=self._scan_args_for_tags,
            turn_signals=ctx.turn_signals,
            source_name=source_name,
            # The gate calls this only when it allows, and before it emits, so
            # token_id lands on the event that authorised the dispatch.
            issue_token=(
                (lambda: self._mint_dispatch_token(name, source_name, ctx))
                if self._connectivity.enabled and self._connectivity_secret
                else None
            ),
            approvals=self._approvals,
            normalization=self._config.normalization,
            scan_state=self._scan_state,
            manifest_rules=self._mcp_policy_rules.get(source_name),
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
            config=self._config.scan_file,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            state=self._scan_state,
            # No normalization *of the path*, which is the text this boundary
            # carries. De-obfuscating it produces views that are different
            # paths — a split on "AppData", a decoded base64-looking directory
            # — and FileScanner reports HIGH `file.not_found` for every one of
            # them, while both file scanners re-open the file once per view.
            #
            # Extracted content is a different string and is normalized:
            # FileContentScanner receives config.normalization at construction
            # (see wiring._build_file_scanners) and de-obfuscates each payload
            # it pulls out of the file. Passing it here instead would apply it
            # to the path.
            normalization=None,
            audit_tags=self._audit_tags_for(ctx),
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
            config=self._config.scan_tool_result,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
        )

        # Record signals from the tool result scan. The raw result is digested,
        # not the redacted form — a redacted span is still a span the tool put
        # into the turn, and an argument built from it is still ingested.
        if ctx.turn_signals is not None:
            ctx.turn_signals.record_tool_result(verdict, text=result)

        return verdict

    async def scan_output(self, text: str, ctx: AgentContext) -> ScanVerdict:
        session_id = ctx.conversation_id or ctx.agent_id

        # Option A: consolidated risk-based block. Even if no individual
        # scanner blocks, if the accumulated turn risk crosses RISK_HIGH,
        # block at scan_output — the last boundary with the full picture.
        # Computed from TurnSignals recorded by earlier boundaries, so it is
        # known before this call's own scan runs and can be folded into that
        # scan's single audit event rather than emitting a second one after
        # the fact (Invariant 1: exactly one event per boundary call).
        turn_risk = 0.0
        forced_block_reason: str | None = None
        forced_block_extra:  dict[str, Any] | None = None
        if ctx.turn_signals is not None:
            turn_risk = ctx.turn_signals.compute_risk()
            if turn_risk >= RISK_HIGH:
                forced_block_reason = (
                    f"consolidated turn risk {turn_risk:.2f} exceeds high "
                    f"threshold ({RISK_HIGH:.2f})"
                )
                forced_block_extra = {
                    "turn_risk":     round(turn_risk, 4),
                    "signal_source": "consolidated",
                }

        verdict = await run_scan(
            text, ctx,
            boundary=BoundaryName.OUTPUT_SCAN,
            scanners=self._output_scanners,
            config=self._config.scan_output,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            state=self._scan_state,
            normalization=self._config.normalization,
            audit_tags=self._audit_tags_for(ctx),
            forced_block_reason=forced_block_reason,
            forced_block_extra=forced_block_extra,
        )

        # Accumulator record — moved from scan_input to scan_output so the
        # session score reflects the full-turn consolidated risk, not just
        # the input scan verdict.
        if self._threat_accumulator is not None:
            categories = [f.category for f in verdict.findings]
            density = wiring._extract_density(verdict)
            await self._threat_accumulator.record(
                session_id, text, verdict.status.value, categories,
                density=density, turn_risk=turn_risk,
            )

        # Clear the turn signal bus — the turn ends here
        ctx._clear_signals()

        return verdict


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

    async def __aenter__(self) -> SHAI:
        """Enter a scope that closes the harness on exit.

            async with await SHAI.from_yaml("config/harness.yaml") as harness:
                await harness.register_tools([...])
                ...

        Preferred over calling `close()` by hand: the resources below are held
        for the life of the process otherwise, and a `finally` that someone
        forgets is how they leak.
        """
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        """Release every resource the harness holds. Call at process shutdown.

        Stays public, and is not something config can do for you: it releases
        the MCP sources' httpx clients, the audit sinks' file handles, and the
        threat accumulator's SQLite connection. The application owns the
        process, so it has to be able to say when those go — nothing inside
        SHAI knows when the last turn has run. `async with` (above) is the
        ergonomic form; this is here for applications that manage lifetime
        themselves.

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
        return self._source_registry.get(name)

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
            resolved[name] = (tool.source_name or "local", tool)

        # Apply enriched overrides — replaces registry entry for this agent only
        for name, tool in overrides.items():
            if name in agent_names:
                resolved[name] = (tool.source_name or "local", tool)

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

