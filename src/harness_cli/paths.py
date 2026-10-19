"""Filesystem-path lines shared by `shai validate` and `shai harness inspect`."""
from __future__ import annotations

from harness.agents.agent_config import AgentConfig, AllowedPaths


def _grant_lines(allowed: AllowedPaths) -> list[str]:
    lines = [f"{mode}: {', '.join(entries)}"
             for mode, entries in (("read ", allowed.read), ("write", allowed.write)) if entries]
    return lines or ["filesystem: none"]


def agent_path_lines(agent: AgentConfig) -> list[str]:
    """What an agent and each of its subagents may read and write."""
    lines = _grant_lines(agent.allowed_paths)
    for sub in agent.sub_agents:
        lines += [f"subagent {sub.id}: {line}" for line in _grant_lines(sub.allowed_paths)]
    return lines
