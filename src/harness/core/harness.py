"""Harness facade — the only public entry point of the SDK.

One Harness instance serves many concurrent agent turns safely.
Agent tools are resolved once at load_agent() time — no per-turn overhead.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.adapters.scanners.basic_injection import BasicInjectionScanner
from harness.tools.registry import ToolRegistry
from harness.agents.agent_config import AgentConfig
from harness.agents.registry import AgentRegistry
from harness.audit.emitter import AuditEmitter
from harness.boundaries._scan import run_scan, run_file_scan
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


class Harness:
    """Control-plane facade for production agents.

    Startup sequence:
        harness = Harness.from_yaml("config/harness.yaml")
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
        # Per-agent resolved tool sets — populated at load_agent() time
        # key: agent_id, value: {tool_name: Tool} for that agent
        self._agent_tools: dict[str, dict[str, Tool]] = {}

    # ── Construction ──────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Harness":
        """Load harness.yaml and construct a fully wired Harness instance.

        Secret resolution order:
          1. Build a SecretsProvider from config.secrets (default: EnvVarProvider).
          2. Re-parse YAML with the provider so secret:// URIs are resolved.
        """
        # First pass: resolve ${ENV_VAR} only (no provider yet)
        config_pre = load_yaml(path)

        # Build the secrets provider from config
        provider = _build_secrets_provider(config_pre.secrets)

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
        emitter = AuditEmitter(sinks)

        return cls(
            config=config,
            agent_registry=AgentRegistry(),
            tool_registry=ToolRegistry(),
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

        The tool set for this agent is resolved once here and stored.
        No per-turn registry lookup happens after this point.

        Returns AgentContext — pass it to scan_input, check_tool_call,
        scan_output on every turn.
        """
        cfg = await self._agent_registry.load(path)
        self._agent_tools[cfg.id] = self._resolve_tools(cfg)
        log.info("agent loaded",
                 extra={"agent_id": cfg.id,
                        "tools": len(self._agent_tools[cfg.id])})
        return AgentContext(agent_id=cfg.id)

    async def reload_agent(self, path: str | Path) -> AgentContext:
        """Reload an agent-xx.yaml and refresh its resolved tool set."""
        cfg = await self._agent_registry.reload(path)
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
        """Flush and close all audit sinks. Call at process shutdown."""
        await self._emitter.close()

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
                log.warning("scanner adapter not found — skipped",
                            extra={"name": ref.name, "error": str(e)})
    return scanners



def _build_secrets_provider(adapter_ref: object) -> "EnvVarProvider":
    """Build a SecretsProvider from an AdapterRef config entry.

    Currently only EnvVarProvider is supported in core.
    Enterprise providers (Vault, AWS, Azure, GCP) register via entry points.
    """
    name = getattr(adapter_ref, "name", "env")
    cfg  = getattr(adapter_ref, "config", {})

    if name == "env":
        return EnvVarProvider(
            prefix=cfg.get("prefix") or None,
        )

    # Enterprise provider via entry point
    try:
        from harness.adapters.discovery import resolve
        cls = resolve("harness.secrets", name)
        return cls(**cfg)
    except Exception as e:
        log.warning("secrets provider %r not found — falling back to EnvVarProvider: %s",
                    name, e)
        return EnvVarProvider()


def _build_file_scanners(adapter_refs: list, *, max_size_mb: float) -> list:
    """Build file scanners — always includes FileScanner as the structural pass.

    If no scanners are configured (scan_file disabled), returns [FileScanner]
    with a YamlRuleScanner(patterns_for_doc) pre-wired as the content scanner.
    Additional scanners in the config are appended after.
    """
    from harness.adapters.scanners.file_scanner import FileScanner
    from harness.adapters.scanners.yaml_rule_scanner import YamlRuleScanner
    from pathlib import Path as _Path

    patterns_for_doc = _Path(__file__).parent.parent / \
        "adapters/scanners/patterns_for_doc.yaml"

    text_scanner = YamlRuleScanner(
        patterns_file=patterns_for_doc if patterns_for_doc.exists() else None,
        name="yaml_rules_doc",
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
                        extra={"name": ref.name, "error": str(e)})
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
                            extra={"name": ref.name, "error": str(e)})
    if not sinks:
        log.warning("no audit sinks configured — falling back to stdout")
        sinks = [StdoutSink()]
    return sinks
