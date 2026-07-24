"""harness validate — validate harness.yaml and all agent files."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from harness.agents.registry import AgentRegistry
from harness.config.loader import load_yaml
from harness.core.errors import ConfigError, HarnessError
from harness_cli.console import console


def cmd_validate(args: argparse.Namespace) -> int:
    config_path = Path(args.config)

    console.write(f"Validating {config_path} ...", end=" ")
    try:
        config = load_yaml(config_path)
        policy_rules = config.policy.parsed_rules()
        console.write("OK")
    except (ConfigError, ValueError) as e:
        console.error(f"FAIL\nError: {e}")
        return 1

    console.write(f"  tenant_id:    {config.tenant_id}")
    console.write(f"  policy_rules: {len(policy_rules)}")
    console.write(f"  audit_sinks:  {[s.name for s in config.audit_sinks]}")

    norm = config.normalization
    console.write(f"  normalization: enabled={norm.enabled}" + (
        f"  decode={norm.decode}  max_depth={norm.max_depth}" if norm.enabled else ""
    ))

    sess = config.session
    console.write(f"  session:       enabled={sess.enabled}" + (
        f"  backend={sess.backend}  threshold={sess.escalation_threshold}"
        f"  window={sess.window_size}  on_escalation={sess.on_escalation}"
        if sess.enabled else ""
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
            f"    {boundary_name}: enabled={boundary_cfg.enabled}"
            f"  block_at={boundary_cfg.block_at}"
            + (f"  scanners={scanners}" if scanners else "")
        )

    budget = config.check_tool_call.execution_budget
    active = []
    if budget.max_steps is not None:
        active.append(f"max_steps={budget.max_steps}")
    if budget.max_tokens_per_session is not None:
        active.append(f"max_tokens={budget.max_tokens_per_session}")
    if budget.max_tool_calls_per_prompt is not None:
        active.append(f"fan_out={budget.max_tool_calls_per_prompt}")
    if budget.loop_detection_window > 0:
        active.append(f"loop_window={budget.loop_detection_window}")
    console.write(
        "  execution_budget: " + (", ".join(active) if active else "none configured")
    )

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
        reg = AgentRegistry()
        ok = fail = 0
        for path in agent_files:
            console.write(f"  {path.name} ...", end=" ")
            try:
                cfg = await reg.load(path)
                subs = len(cfg.sub_agents)
                console.write(
                    f"OK  (tools={len(cfg.allowed_tool_names)}, sub_agents={subs})"
                )
                ok += 1
            except HarnessError as e:
                console.error(f"FAIL\n    Error: {e}")
                fail += 1
        return ok, fail

    ok, fail = asyncio.run(_validate_agents())
    console.write(f"\nResult: {ok} OK, {fail} FAIL")
    return 0 if fail == 0 else 1
