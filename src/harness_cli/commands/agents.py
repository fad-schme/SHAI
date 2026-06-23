"""harness agents list — list agent files in a directory."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def cmd_agents_list(args: argparse.Namespace) -> int:
    agents_dir = Path(args.agents_dir) if args.agents_dir else None

    if agents_dir is None:
        print(
            "No agents directory specified. Use --agents-dir <path>.",
            file=sys.stderr,
        )
        return 1

    if not agents_dir.exists():
        print(f"Agents directory not found: {agents_dir}", file=sys.stderr)
        return 1

    agent_files = sorted(agents_dir.glob("*.yaml"))
    if not agent_files:
        print(f"No agent YAML files found in {agents_dir}")
        return 0

    async def _load() -> list:
        from harness.agents.registry import AgentRegistry
        reg = AgentRegistry()
        agents = []
        for path in agent_files:
            try:
                cfg = await reg.load(path)
                agents.append(cfg)
            except Exception as e:
                print(f"  Warning: could not load {path.name}: {e}", file=sys.stderr)
        return agents

    agents = asyncio.run(_load())

    if not agents:
        print("No agents loaded.")
        return 0

    col_id    = max(len(a.id) for a in agents)
    col_ver   = max(len(a.version or "-") for a in agents)
    col_tools = max(len(str(len(a.allowed_tool_names))) for a in agents)
    col_subs  = max(len(str(len(a.sub_agents))) for a in agents)

    header = (
        f"{'ID':<{col_id}}  "
        f"{'VERSION':<{col_ver}}  "
        f"{'TOOLS':>{col_tools}}  "
        f"{'SUBS':>{col_subs}}  "
        f"SOURCES"
    )
    print(header)
    print("-" * len(header))

    for a in agents:
        print(
            f"{a.id:<{col_id}}  "
            f"{(a.version or '-'):<{col_ver}}  "
            f"{len(a.allowed_tool_names):>{col_tools}}  "
            f"{len(a.sub_agents):>{col_subs}}  "
            f"{', '.join(a.sources) or '-'}"
        )
        for sub in a.sub_agents:
            print(
                f"  └─ {sub.id:<{col_id - 4}}  "
                f"{'':>{col_ver}}  "
                f"{len(sub.allowed_tool_names):>{col_tools}}  "
                f"{'':>{col_subs}}  "
                f"{', '.join(sub.sources) or '-'}"
            )

    print(f"\n{len(agents)} agent(s)")
    return 0
