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
from harness.adapters.scanners.mcp_metadata_scanner import MCPMetadataScanner
from harness.tools.registry import ToolRegistry
from harness.tools.source import LocalSource, MCPSource, SourceRegistry, ToolSource
from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import run_scan, run_file_scan, run_tool_result_scan
from harness.boundaries.check_tool_call import run as run_gate
from harness.core.types import BoundaryName, Decision, ScanAction, ScanStatus, Severity
from harness.config.loader import load_yaml
from harness.adapters.secrets.env import EnvVarProvider
from harness.config.schema import HarnessConfig
from harness.core.context import AgentContext

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
        # scan action configs
        scan_input_action: ScanAction,
        scan_input_scanner_actions: list[ScanAction | None],
        scan_input_redact_withs: list[str | None],
        scan_output_action: ScanAction,
        scan_output_scanner_actions: list[ScanAction | None],
        scan_output_redact_withs: list[str | None],
        scan_file_action: ScanAction,
        scan_file_scanner_actions: list[ScanAction | None],
        scan_file_redact_withs: list[str | None],
        scan_tool_result_action: ScanAction,
        tool_result_scanners: list,
        scan_tool_result_enabled: bool,
        tool_result_block_at: Severity,
        source_registry: SourceRegistry,
        connectivity_secret: bytes | None = None,
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
        self._scan_args_for_tags            = scan_args_for_tags
        self._scan_input_action             = scan_input_action
        self._scan_input_scanner_actions    = scan_input_scanner_actions
        self._scan_input_redact_withs       = scan_input_redact_withs
        self._scan_output_action            = scan_output_action
        self._scan_output_scanner_actions   = scan_output_scanner_actions
        self._scan_output_redact_withs      = scan_output_redact_withs
        self._scan_file_action              = scan_file_action
        self._scan_file_scanner_actions     = scan_file_scanner_actions
        self._scan_file_redact_withs        = scan_file_redact_withs
        self._scan_tool_result_action       = scan_tool_result_action
        self._rate_limiter              = rate_limiter
        self._tool_result_scanners      = tool_result_scanners
        self._scan_tool_result_enabled  = scan_tool_result_enabled
        self._tool_result_block_at      = tool_result_block_at
        self._mcp_metadata_scanners:    list = []
        self._scan_mcp_metadata_enabled = True
        self._mcp_metadata_block_at     = Severity.MEDIUM
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
        # Merged lookup: tool_name → True when manifest requires scan_tool_result.
        # Built at from_yaml() time from all sources with scan_tool_result_on.
        # Empty = scan all results (default). Non-empty = only listed tools scanned.
        self._scan_tool_result_on: set[str] = set()

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

        input_scanners  = _build_text_scanners(config.scan_input.scanners)
        output_scanners = _build_text_scanners(config.scan_output.scanners)
        arg_scanners    = _build_text_scanners(config.check_tool_call.arg_scanners)
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
            raw = config.connectivity.token_secret
            if raw.startswith("secret://"):
                raw = provider.resolve(raw[len("secret://"):]).value
            connectivity_secret = raw.encode()
            log.info("connectivity layer enabled — dispatch tokens will be issued")

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
        tool_result_scanners = (
            [_make_injection_doc_scanner()]
            if config.scan_tool_result.enabled else []
        )

        mcp_metadata_scanners = _build_text_scanners(config.scan_mcp_metadata.scanners)

        # Build shared registries first — source_registry needs tool_registry
        tool_registry   = ToolRegistry()
        agent_registry  = AgentRegistry()

        # Build SourceRegistry and register all declared sources
        source_registry = SourceRegistry(policy)
        for src_cfg in config.sources:
            # Resolve connector manifest if specified
            if src_cfg.connector:
                from harness.connectors import load_manifest, manifest_to_source_config_fields
                from harness.config.schema import SourceConfig as _SC
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
                # Resolve credential values (already resolved by loader pass)
                source = MCPSource(
                    name=src_cfg.name,
                    url=src_cfg.url,
                    credentials=dict(src_cfg.credentials),
                    tags=list(src_cfg.tags),
                    allowed_urls=list(src_cfg.allowed_urls),
                    allowed_methods=list(src_cfg.allowed_methods),
                )
                # Pass connectivity config + emitter so ShaiTransport
                # can be wired at _connect() time
                source._connectivity = config.connectivity
                source._emitter      = emitter
                source._tenant_id    = config.tenant_id
                # Wire connector manifest enforcement data
                source._connector_tool_specs = dict(src_cfg.connector_tool_specs)
                source._scan_tool_result_on  = set(src_cfg.scan_tool_result_on)
                # Wire MCP metadata scanner config
                source._mcp_metadata_scanners     = instance._mcp_metadata_scanners
                source._scan_mcp_metadata_enabled = instance._scan_mcp_metadata_enabled
                source._mcp_metadata_block_at     = instance._mcp_metadata_block_at
            else:
                # LOCAL — backed by the shared tool registry
                source = LocalSource(
                    name=src_cfg.name,
                    registry=tool_registry,
                    tool_names=list(src_cfg.tool_names) or None,
                    tags=list(src_cfg.tags),
                )
            await source_registry.register(source)

        def _scanner_meta(refs) -> tuple[list[ScanAction | None], list[str | None]]:
            """Extract per-scanner action and redact_with from AdapterRef list."""
            actions = [r.action for r in refs]
            redact_withs = [r.redact_with for r in refs]
            return actions, redact_withs

        inp_actions, inp_redacts     = _scanner_meta(config.scan_input.scanners)
        out_actions, out_redacts     = _scanner_meta(config.scan_output.scanners)
        file_actions, file_redacts   = _scanner_meta(config.scan_file.scanners)

        rl_cfg = config.check_tool_call.rate_limit
        rate_limiter = (
            RateLimiter(
                window_seconds=rl_cfg.window_seconds,
                max_calls_per_window=rl_cfg.max_calls_per_window,
                max_calls_per_tool=rl_cfg.max_calls_per_tool,
            )
            if rl_cfg.enabled else None
        )

        # Collect scan_tool_result_on across all connector sources
        scan_tool_result_on: set[str] = set()
        for _src_cfg in config.sources:
            scan_tool_result_on.update(_src_cfg.scan_tool_result_on)

        instance = cls(
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
            scan_input_action=config.scan_input.action,
            scan_input_scanner_actions=inp_actions,
            scan_input_redact_withs=inp_redacts,
            scan_output_action=config.scan_output.action,
            scan_output_scanner_actions=out_actions,
            scan_output_redact_withs=out_redacts,
            scan_file_action=config.scan_file.action,
            scan_file_scanner_actions=file_actions,
            scan_file_redact_withs=file_redacts,
            scan_tool_result_action=config.scan_tool_result.action,
            connectivity_secret=connectivity_secret,
        )
        instance._scan_tool_result_on        = scan_tool_result_on
        instance._mcp_metadata_scanners      = mcp_metadata_scanners
        instance._scan_mcp_metadata_enabled  = config.scan_mcp_metadata.enabled
        instance._mcp_metadata_block_at      = config.scan_mcp_metadata.block_at
        return instance

    # ── Startup ───────────────────────────────────────────────────────────

    async def register_tools(self, tools: "list[Tool | Any]") -> None:
        """Register tools and re-resolve all already-loaded agents.

        Accepts a list of:
          - Tool descriptors (plain harness.tools.tool.Tool)
          - ShaiTool instances from the @shai_tool decorator
            (SHAI metadata + implementation in one object)

        May be called before or after load_agent() — order does not matter.
        After registering, every loaded agent's tool set is refreshed so
        newly registered tools become immediately available.
        """
        from harness.integrations.base import ShaiTool, extract_shai_tools
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
            scanner_actions=self._scan_input_scanner_actions,
            scanner_redact_withs=self._scan_input_redact_withs,
            boundary_action=self._scan_input_action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_input_enabled,
            block_at=self._block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def scan_pii(self, text: str, ctx: AgentContext) -> ScanVerdict:
        """Run only the RegexPIIScanner on text.

        Runs the full scan pipeline (action, block_at, audit event) but with
        only the PII scanner — not the full input scanner stack.
        Useful when you need targeted PII detection on content that doesn't
        need injection scanning (e.g. a structured API response).
        """
        pii_scanners = [
            s for s in self._input_scanners
            if getattr(s, "name", "") == "regex_pii"
        ]
        if not pii_scanners:
            pii_scanners = self._input_scanners   # fallback: run all
        return await run_scan(
            text, ctx,
            boundary=BoundaryName.INPUT_SCAN,
            scanners=pii_scanners,
            scanner_actions=self._scan_input_scanner_actions[:len(pii_scanners)],
            scanner_redact_withs=self._scan_input_redact_withs[:len(pii_scanners)],
            boundary_action=self._scan_input_action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_input_enabled,
            block_at=self._block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def scan_injection(self, text: str, ctx: AgentContext) -> ScanVerdict:
        """Run only the InjectionScanner on text.

        Runs the full scan pipeline but with only the injection scanner.
        Useful for targeted injection detection on a specific input surface
        (e.g. a URL parameter, a tool name, a structured field).
        """
        inj_scanners = [
            s for s in self._input_scanners
            if getattr(s, "name", "").startswith("injection_scan")
        ]
        if not inj_scanners:
            inj_scanners = self._input_scanners   # fallback: run all
        return await run_scan(
            text, ctx,
            boundary=BoundaryName.INPUT_SCAN,
            scanners=inj_scanners,
            scanner_actions=[None] * len(inj_scanners),
            scanner_redact_withs=[None] * len(inj_scanners),
            boundary_action=self._scan_input_action,
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

        # Pre-gate: agent must be registered — deny with audit event on miss
        try:
            agent_config = self._agent_registry.get(ctx.agent_id)
        except Exception as e:
            from harness.core.events import AuditEvent, now_ms
            reason = f"agent '{ctx.agent_id}' is not registered in this harness"
            event = AuditEvent.build(
                boundary=BoundaryName.TOOL_CALL_GATE,
                decision=Decision.DENY,
                ctx=ctx,
                tenant_id=self._tenant_id,
                duration_ms=0,
                tool_name=name,
                deny_reason=reason,
                audit_tags={},
            )
            await self._emitter.emit(event)
            return GateDecision(allowed=False, deny_reason=reason)

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
        )

        # Issue dispatch token when gate allows and connectivity is enabled
        if gate.allowed and self._connectivity.enabled and self._connectivity_secret:
            from harness.connectivity.token import (
                sign_token, encode_token, default_allowed_urls,
            )
            tool_obj     = tools.get(name)
            source_cfg   = next(
                (s for s in self._config.sources if s.name == source_name),
                None,
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
                tool_name=name,
                source_name=source_name,
                allowed_urls=allowed_urls,
                allowed_methods=allowed_methods,
                secret=self._connectivity_secret,
                ttl_seconds=self._connectivity.token_ttl_seconds,
            )
            encoded = encode_token(token)
            # Rebuild GateDecision with token and source_name
            gate = GateDecision(
                allowed=True,
                redacted_args=gate.redacted_args,
                dispatch_token=encoded,
                source_name=source_name,
            )
            log.debug("dispatch token issued",
                      extra={"agent_id": ctx.agent_id, "tool": name,
                             "token_id": token.token_id,
                             "expires_at": token.expires_at.isoformat()})

        # Stamp source_name on the gate decision if not already set
        if gate.allowed and gate.source_name is None:
            gate = GateDecision(
                allowed=gate.allowed,
                deny_reason=gate.deny_reason,
                redacted_args=gate.redacted_args,
                dispatch_token=gate.dispatch_token,
                source_name=source_name,
            )
        return gate

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
            scanner_actions=self._scan_file_scanner_actions,
            scanner_redact_withs=self._scan_file_redact_withs,
            boundary_action=self._scan_file_action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_file_enabled,
            block_at=self._file_block_at,
            audit_tags=self._audit_tags_for(ctx),
        )

    async def scan_tool_result(
        self,
        result: str,
        ctx: AgentContext,
        *,
        tool_name: str | None = None,
    ) -> ScanVerdict:
        """Scan a tool return value before it re-enters the LLM context.

        tool_name: when provided and a connector manifest has declared
            scan_tool_result_on, only tools in that set are scanned.
            Tools not listed emit a disabled=True audit event and return
            ScanVerdict(allow). When tool_name is None or no manifest
            declares scan_tool_result_on, all results are scanned (safe default).
        """
        if (
            tool_name is not None
            and self._scan_tool_result_on
            and tool_name not in self._scan_tool_result_on
        ):
            log.debug(
                "scan_tool_result skipped — tool not in scan_tool_result_on",
                extra={"tool": tool_name, **ctx.to_log_fields()},
            )
            from harness.core.events import AuditEvent
            from harness.core.verdicts import ScanVerdict, ScanStatus
            event = AuditEvent.build(
                boundary=BoundaryName.TOOL_RESULT_SCAN,
                decision=Decision.ALLOW,
                ctx=ctx,
                tenant_id=self._tenant_id,
                duration_ms=0,
                disabled=True,
                adapters=["scan_tool_result_on"],
                audit_tags=self._audit_tags_for(ctx),
            )
            await self._emitter.emit(event)
            return ScanVerdict(status=ScanStatus.ALLOW)

        return await run_tool_result_scan(
            result, ctx,
            scanners=self._tool_result_scanners,
            scanner_actions=[],   # tool_result uses boundary_action only
            scanner_redact_withs=[],
            boundary_action=self._scan_tool_result_action,
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
            scanner_actions=self._scan_output_scanner_actions,
            scanner_redact_withs=self._scan_output_redact_withs,
            boundary_action=self._scan_output_action,
            emitter=self._emitter,
            tenant_id=self._tenant_id,
            enabled=self._scan_output_enabled,
            block_at=self._block_at,
            audit_tags=self._audit_tags_for(ctx),
        )


    @property
    def scanners(self) -> "dict[str, object]":
        """Return all active scanner instances keyed by name.

        Provides visibility into which scanners are running and their
        configuration. Useful for inspection, testing, and debugging.

        Returns a flat dict across all boundaries — scanners used in
        multiple boundaries appear once (the input_scanner instance).

            harness.scanners
            # {
            #   'regex_pii':          RegexPIIScanner(...),
            #   'injection_scan':     InjectionScanner(...),
            #   'injection_scan_doc': InjectionScanner(patterns_for_doc),
            #   'file_scanner':       FileScanner(...),
            #   'mcp_metadata_scan':  MCPMetadataScanner(...),
            #   'rate_limiter':       RateLimiter(...),
            # }
        """
        result: dict[str, object] = {}
        for scanner in (
            self._input_scanners
            + self._output_scanners
            + self._tool_result_scanners
            + self._file_scanners
            + self._arg_scanners
        ):
            name = getattr(scanner, "name", type(scanner).__name__)
            result[name] = scanner
        if self._rate_limiter is not None:
            result["rate_limiter"] = self._rate_limiter
        return result

    def collect_events(self):
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
    def _source_name_for_tool(self, tool_name: str, tool: "Tool") -> str:
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

    def _resolve_tools(self, cfg: AgentConfig) -> "dict[str, tuple[str, Tool]]":
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


# ── Module-level adapter builders ─────────────────────────────────────────
#
# Each scanner is a named, standalone class. _build_text_scanners resolves
# them from AdapterRef declarations in harness.yaml. The named factories
# below make the mapping explicit — no magic string dispatch.

def _make_pii_scanner(cfg: dict) -> RegexPIIScanner:
    """Build a RegexPIIScanner from an AdapterRef config dict."""
    return RegexPIIScanner(**cfg)


def _make_injection_scanner(cfg: dict) -> InjectionScanner:
    """Build an InjectionScanner from an AdapterRef config dict."""
    return InjectionScanner(**cfg)


def _make_injection_doc_scanner() -> InjectionScanner:
    """Build an InjectionScanner using patterns_for_doc.yaml.

    Used for tool_result scanning and file content scanning — tuned for
    structured content (lower false-positive rate than injection_patterns.yaml).
    """
    from pathlib import Path as _Path
    doc_patterns = _Path(__file__).parent.parent / "adapters/scanners/patterns_for_doc.yaml"
    return InjectionScanner(
        patterns_file=doc_patterns if doc_patterns.exists() else None,
        name="injection_scan_doc",
    )


# Named registry — explicit, no magic strings
_SCANNER_FACTORIES: dict[str, "Any"] = {
    "regex_pii":          _make_pii_scanner,
    "injection_scan":     _make_injection_scanner,
    "mcp_metadata_scan":  lambda cfg: MCPMetadataScanner(**cfg),
}


def _build_text_scanners(adapter_refs: list) -> list:
    """Build text scanners from AdapterRef declarations in harness.yaml.

    Built-in scanners (regex_pii, injection_scan) are resolved via the
    named factory table above. Custom scanners are resolved via entry points.
    """
    scanners = []
    for ref in adapter_refs:
        factory = _SCANNER_FACTORIES.get(ref.name)
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


# Keep _build_scanners as an alias for backward compatibility
# (used in test fixtures and any external code that calls it directly)
_build_scanners = _build_text_scanners


def _build_file_scanners(adapter_refs: list, *, max_size_mb: float) -> list:
    """Build file scanners — always includes FileScanner as the structural pass.

    FileScanner runs structural checks (MIME, size, extension, PDF JS, EXIF, ZIP,
    Office macros) then runs InjectionScanner on extracted text content.
    Additional scanners declared in config are appended after.
    """
    from harness.adapters.scanners.file_scanner import FileScanner

    text_scanner = _make_injection_doc_scanner()
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
