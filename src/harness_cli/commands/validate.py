"""harness validate — validate harness.yaml and all agent files."""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

from harness.agents.registry import AgentRegistry
from harness.config.loader import load_yaml
from harness.config.protected_paths import protected_paths
from harness.config.schema import HarnessConfig
from harness.core.errors import ConfigError, HarnessError
from harness.core.types import OnError, Transport
from harness.mcp.manifest import load_manifest_file, manifest_path_for
from harness_cli.console import console
from harness_cli.paths import agent_path_lines

# The boundaries that carry `on_error`; scan_mcp_metadata runs a fixed scanner
# set and has none.
_SCAN_BOUNDARIES = ("scan_input", "scan_file", "scan_output", "scan_tool_result")


def _risky_url_host(url: str) -> bool:
    """True for a host the allow-list matcher cannot mean what it says about.

    `*` in a host never globs (patterns take a trailing `/*` only), so such an
    entry matches no destination; an unspecified address is a destination the
    scope policy refuses on its own.
    """
    host = urlsplit(url).hostname or ""
    if "*" in host:
        return True
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False  # a name, not an IP literal


def _risk_warnings(config: HarnessConfig) -> list[str]:
    """Legal settings that weaken a control. Names the setting, never a value."""
    warnings: list[str] = []

    for name in _SCAN_BOUNDARIES:
        if getattr(config, name).on_error is OnError.FAIL_OPEN:
            warnings.append(f"{name}.on_error: fail_open")

    if config.connectivity.token_policy == "audit":
        warnings.append("connectivity.token_policy: audit")

    if config.mcp_manifests_dir:
        for src in config.sources:
            if src.transport is not Transport.MCP:
                continue
            path = manifest_path_for(src.name, config.mcp_manifests_dir)
            try:
                manifest = load_manifest_file(path)
            except ConfigError:
                # The error text quotes the parser's view of the file, which
                # can include a credentials entry; name the file, not the cause.
                warnings.append(f"manifest {src.name}: unreadable or invalid ({path})")
                continue
            bad = [i for i, u in enumerate(manifest.allowed_urls) if _risky_url_host(u)]
            if bad:
                warnings.append(
                    f"manifest {src.name}: allowed_urls entries at positions {bad} "
                    "have a wildcard or unspecified host"
                )

    return warnings


def cmd_validate(args: argparse.Namespace) -> int:
    config_path = Path(args.config)

    console.write(f"Validating {config_path} ...", end=" ")
    try:
        config = load_yaml(config_path)
        source_rules = config.policy.parsed_source_rules()
        console.write("OK")
    except (ConfigError, ValueError) as e:
        console.error(f"FAIL\nError: {e}")
        return 1

    console.write(f"  tenant_id:    {config.tenant_id}")
    console.write(f"  source_rules: {len(source_rules)}")
    for combo in config.policy.forbidden_tag_combinations:
        console.write(f"  forbidden_tags: {sorted(set(combo))}")
    console.write(f"  audit_sinks:  {[s.name for s in config.audit_sinks]}")

    norm = config.normalization
    console.write(f"  normalization: enabled={norm.enabled}" + (
        f"  decode={norm.decode}  max_depth={norm.max_depth}" if norm.enabled else ""
    ))

    sess = config.session
    console.write(f"  session:       enabled={sess.enabled}" + (
        f"  store={sess.store.name}  threshold={sess.escalation_threshold}"
        f"  window={sess.window_size}  on_escalation={sess.on_escalation}"
        if sess.enabled else ""
    ))
    console.write(f"  session_budget: store={config.session_budget.store.name}")
    approvals = config.check_tool_call.approvals
    console.write("  approvals:     " + (
        f"store={approvals.store.name}" if approvals.store else "not configured"
    ))

    console.write("  boundaries:")
    for boundary_name, boundary_cfg in [
        ("scan_input",       config.scan_input),
        ("scan_file",        config.scan_file),
        ("scan_output",      config.scan_output),
        ("scan_tool_result", config.scan_tool_result),
        ("scan_mcp_metadata", config.scan_mcp_metadata),
    ]:
        scanners = [s.name for s in getattr(boundary_cfg, "scanners", [])]
        console.write(
            f"    {boundary_name}: always on  block_at={boundary_cfg.block_at}"
            + (f"  scanners={scanners}" if scanners else "")
        )

    budget = config.check_tool_call.execution_budget
    active = []
    if budget.max_steps is not None:
        active.append(f"max_steps={budget.max_steps}")
    if budget.max_tool_calls_per_prompt is not None:
        active.append(f"fan_out={budget.max_tool_calls_per_prompt}")
    if budget.loop_detection_window > 0:
        active.append(f"loop_window={budget.loop_detection_window}")
    console.write(
        "  execution_budget: " + (", ".join(active) if active else "none configured")
    )

    protected = protected_paths(config, config_path=config_path, agents_dir=args.agents_dir)
    console.write(f"  protected_paths: {len(protected)}")
    for path in protected:
        console.write(f"    {path}")

    warnings = _risk_warnings(config)
    if warnings:
        console.write("  warnings:")
        for line in warnings:
            console.write(f"    {line}")

    if args.agents_dir is None:
        console.write(
            "\nAgent validation skipped; use --agents-dir DIR to include agent YAML files."
        )
        return 0

    agents_dir = Path(args.agents_dir)
    if not agents_dir.is_dir():
        console.error(f"\nError: agents directory not found: {agents_dir}")
        return 1

    agent_files = sorted(agents_dir.glob("*.yaml"))
    if not agent_files:
        console.write(f"\nNo agent YAML files found in {agents_dir}")
        return 0

    console.write(f"\nValidating agents in {agents_dir}:")

    async def _validate_agents() -> tuple[int, int]:
        reg = AgentRegistry(
            forbidden_tag_combinations=config.policy.forbidden_tag_sets(),
            protected_paths=protected,
        )
        ok = fail = 0
        for path in agent_files:
            console.write(f"  {path.name} ...", end=" ")
            try:
                cfg = await reg.load(path)
                subs = len(cfg.sub_agents)
                console.write(
                    f"OK  (tools={len(cfg.allowed_tool_names)}, sub_agents={subs})"
                )
                for line in agent_path_lines(cfg):
                    console.write(f"      {line}")
                ok += 1
            except HarnessError as e:
                console.error(f"FAIL\n    Error: {e}")
                fail += 1
        return ok, fail

    ok, fail = asyncio.run(_validate_agents())
    console.write(f"\nResult: {ok} OK, {fail} FAIL")
    return 0 if fail == 0 else 1
