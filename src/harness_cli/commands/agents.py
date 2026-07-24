"""harness agents list — list agent files in a directory."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from harness.core.errors import HarnessError
from harness_cli.console import console


def cmd_agents_list(args: argparse.Namespace) -> int:
    agents_dir = Path(args.agents_dir)

    if not agents_dir.is_dir():
        console.error(f"Agents directory not found: {agents_dir}")
        return 1

    agent_files = sorted(agents_dir.glob("*.yaml"))
    if not agent_files:
        console.write(f"No agent YAML files found in {agents_dir}")
        return 0

    async def _load() -> list:
        from harness.agents.registry import AgentRegistry
        reg = AgentRegistry()
        agents = []
        for path in agent_files:
            try:
                cfg = await reg.load(path)
                agents.append(cfg)
            except HarnessError as e:
                console.error(f"Warning: could not load {path.name}: {e}")
        return agents

    agents = asyncio.run(_load())

    if not agents:
        console.write("No agents loaded.")
        return 0

    sub_labels = [f"  └─ {sub.id}" for agent in agents for sub in agent.sub_agents]
    tool_counts = [
        len(config.allowed_tool_names)
        for agent in agents
        for config in [agent, *agent.sub_agents]
    ]
    col_id = max([len("ID"), *(len(a.id) for a in agents), *(map(len, sub_labels))])
    col_ver = max(len("VERSION"), *(len(a.version or "-") for a in agents))
    col_tools = max(len("TOOLS"), *(len(str(count)) for count in tool_counts))
    col_subs = max(len("SUBS"), *(len(str(len(a.sub_agents))) for a in agents))

    header = (
        f"{'ID':<{col_id}}  "
        f"{'VERSION':<{col_ver}}  "
        f"{'TOOLS':>{col_tools}}  "
        f"{'SUBS':>{col_subs}}  "
        f"SOURCES"
    )
    console.write(header)
    console.write("-" * len(header))

    for a in agents:
        console.write(
            f"{a.id:<{col_id}}  "
            f"{(a.version or '-'):<{col_ver}}  "
            f"{len(a.allowed_tool_names):>{col_tools}}  "
            f"{len(a.sub_agents):>{col_subs}}  "
            f"{', '.join(a.sources) or '-'}"
        )
        for sub in a.sub_agents:
            sub_label = f"  └─ {sub.id}"
            console.write(
                f"{sub_label:<{col_id}}  "
                f"{'-':<{col_ver}}  "
                f"{len(sub.allowed_tool_names):>{col_tools}}  "
                f"{'-':>{col_subs}}  "
                f"{', '.join(sub.sources) or '-'}"
            )

    console.write(f"\n{len(agents)} agent(s)")
    return 0
