"""harness agents list — list registered agents."""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path


def cmd_agents_list(args: argparse.Namespace) -> int:
    config_path = Path(args.config)

    try:
        from harness.config.loader import load_yaml
        config = load_yaml(config_path)
    except Exception as e:
        print(f"Error loading {config_path}: {e}", file=sys.stderr)
        return 1

    agents_dir: Path | None = None

    if agents_dir is None or not agents_dir.exists():
        print("No agents directory configured.", file=sys.stderr)
        return 1

    agent_files = sorted(agents_dir.glob("*.yaml"))
    if not agent_files:
        print("No agent files found.")
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

    # Table header
    col_id   = max(len(a.id) for a in agents)
    col_ver  = max(len(a.version or "-") for a in agents)
    col_tools = max(len(str(len(a.allowed_tool_names))) for a in agents)
    col_subs = max(len(str(len(a.sub_agents))) for a in agents)

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
