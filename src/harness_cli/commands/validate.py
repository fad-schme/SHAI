"""harness validate — validate harness.yaml and all agent files."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def cmd_validate(args: argparse.Namespace) -> int:
    config_path = Path(args.config)

    # ── 1. Validate harness.yaml ──────────────────────────────────────────
    print(f"Validating {config_path} ...", end=" ")
    try:
        from harness.config.loader import load_yaml
        config = load_yaml(config_path)
        print("OK")
    except FileNotFoundError:
        print(f"FAIL\nError: file not found: {config_path}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"FAIL\nError: {e}", file=sys.stderr)
        return 1

    print(f"  tenant_id:    {config.tenant_id}")
    print(f"  policy:       {config.policy.name}")
    print(f"  audit_sinks:  {[s.name for s in config.audit_sinks]}")

    # Normalization
    norm = config.normalization
    print(f"  normalization: enabled={norm.enabled}" + (
        f"  decode={norm.decode}  max_depth={norm.max_depth}" if norm.enabled else ""
    ))

    # Session accumulator
    sess = config.session
    print(f"  session:       enabled={sess.enabled}" + (
        f"  backend={sess.backend}  threshold={sess.escalation_threshold}"
        f"  window={sess.window_size}  on_escalation={sess.on_escalation}"
        if sess.enabled else ""
    ))

    # Scan boundaries — list configured scanners
    for boundary_name, boundary_cfg in [
        ("scan_input",  config.scan_input),
        ("scan_output", config.scan_output),
    ]:
        scanners = [s.name for s in getattr(boundary_cfg, "scanners", [])]
        print(f"  {boundary_name}: enabled={boundary_cfg.enabled}" + (
            f"  scanners={scanners}" if scanners else ""
        ))

    # ── 2. Validate agent files ───────────────────────────────────────────
    agents_dir: Path | None = None
    if args.agents_dir:
        agents_dir = Path(args.agents_dir)

    if agents_dir is None or not agents_dir.exists():
        print("\nNo agents directory configured or found — skipping agent validation.")
        return 0

    agent_files = sorted(agents_dir.glob("*.yaml"))
    if not agent_files:
        print(f"\nNo agent YAML files found in {agents_dir}")
        return 0

    print(f"\nValidating agents in {agents_dir}:")
    import asyncio
    from harness.agents.registry import AgentRegistry

    async def _validate_agents() -> tuple[int, int]:
        reg = AgentRegistry()
        ok = fail = 0
        for path in agent_files:
            print(f"  {path.name} ...", end=" ")
            try:
                cfg = await reg.load(path)
                subs = len(cfg.sub_agents)
                print(f"OK  (tools={len(cfg.allowed_tool_names)}, sub_agents={subs})")
                ok += 1
            except Exception as e:
                print(f"FAIL\n    Error: {e}", file=sys.stderr)
                fail += 1
        return ok, fail

    ok, fail = asyncio.run(_validate_agents())
    print(f"\nResult: {ok} OK, {fail} FAIL")
    return 0 if fail == 0 else 1
