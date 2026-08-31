"""shai harness inspect / graph — offline view of what a config wires up.

Both commands read harness.yaml (and optionally an agents directory). Neither
builds adapters, connects to an MCP server, or emits an audit event: what they
print is the declared topology, not a running process.

`sources:` declares both local and MCP sources by name (see
config.schema.SourceConfig) — an MCP entry's connection, tool set, and policy
come from its manifest file, resolved by convention at
`<mcp_manifests_dir>/<name>.yaml` and approved via `shai mcp onboard` (see
harness.mcp).

The runtime counterpart is the SYSTEM/STARTUP audit event, which additionally
carries source-file digests of the adapters actually instantiated.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from harness.agents.agent_config import AgentConfig
from harness.config.loader import load_yaml
from harness.config.schema import HarnessConfig, SourceConfig
from harness.core.attestation import build_config_attestation
from harness.core.errors import HarnessError
from harness_cli.console import console

# Scan boundaries only — check_tool_call has no `enabled` flag (the gate always
# runs) and is reported separately.
_SCAN_BOUNDARIES = (
    "scan_input",
    "scan_output",
    "scan_tool_result",
    "scan_file",
    "scan_mcp_metadata",
)


def _load(args: argparse.Namespace) -> tuple[HarnessConfig, list[SourceConfig], list[AgentConfig]] | None:
    """Load config, resolve sources, load agents. None on a fatal config error."""
    config_path = Path(args.config)
    try:
        config = load_yaml(config_path)
        sources = list(config.sources)
    except (HarnessError, ValueError) as e:
        console.error(f"Error: {e}")
        return None
    return config, sources, _load_agents(
        getattr(args, "agents_dir", None),
        config.policy.forbidden_tag_sets(),
    )


def _load_agents(
    agents_dir: str | None,
    forbidden_tags: list[frozenset[str]],
) -> list[AgentConfig]:
    if not agents_dir:
        return []
    directory = Path(agents_dir)
    if not directory.is_dir():
        console.error(f"Agents directory not found: {directory}")
        return []

    async def _read() -> list[AgentConfig]:
        from harness.agents.registry import AgentRegistry
        registry = AgentRegistry(forbidden_tag_combinations=forbidden_tags)
        loaded: list[AgentConfig] = []
        for path in sorted(directory.glob("*.yaml")):
            try:
                loaded.append(await registry.load(path))
            except HarnessError as e:
                console.error(f"Warning: could not load {path.name}: {e}")
        return loaded

    return asyncio.run(_read())


# ── inspect ────────────────────────────────────────────────────────────────

def cmd_harness_inspect(args: argparse.Namespace) -> int:
    loaded = _load(args)
    if loaded is None:
        return 1
    config, sources, agents = loaded
    att = build_config_attestation(config=config, sources=sources)

    console.write(f"SHAI {att['shai_version']}  |  tenant: {config.tenant_id}")
    console.write(f"config: {args.config}")

    console.write("\nboundaries:")
    for field in _SCAN_BOUNDARIES:
        cfg = getattr(config, field)
        scanners = [s.name for s in cfg.scanners]
        console.write(
            f"  {field:<18} enabled={cfg.enabled}  block_at={cfg.block_at}"
            + (f"  scanners={', '.join(scanners)}" if scanners else "")
        )
    gate = config.check_tool_call
    console.write(
        f"  {'check_tool_call':<18} always on"
        f"  rate_limit={gate.rate_limit.enabled}"
        + (f"  arg_scanners={', '.join(s.name for s in gate.scanners)}"
           if gate.scanners else "")
    )

    console.write(f"\naudit sinks:  {', '.join(s.name for s in config.audit_sinks)}"
                  f"   signing={config.audit_signing.enabled}")
    console.write(f"policy:       {att['policy']['source_rule_count']} source rules"
                  f"  digest={att['policy']['digest'][:12]}")

    db = att["patterns_db"]
    console.write("patterns db:  disabled" if db is None else
                  f"patterns db:  {db['path']} - {db['rule_count']} rules"
                  f"  digest={db['digest'][:12]}")

    if att["sources"]:
        console.write("\nsources:")
        for src in att["sources"]:
            console.write(
                f"  {src['name']:<16} {src['transport']:<6} "
                f"tags={','.join(src['tags']) or '-'}"
            )

    if att["mcp_manifests"]:
        console.write(f"\nmcp manifests ({config.mcp_manifests_dir}):")
        for m in att["mcp_manifests"]:
            console.write(f"  {m['id']:<16} {m['url'] or '-':<44} "
                          f"digest={m['digest'][:12]}")

    if agents:
        console.write("\nagents:")
        for agent in agents:
            console.write(
                f"  {agent.id:<16} tools={len(agent.allowed_tool_names):<3} "
                f"tags={','.join(agent.allowed_tags)}  "
                f"sources={','.join(agent.sources) or '-'}  "
                f"subagents={len(agent.sub_agents)}"
            )

    return 0


# ── graph ──────────────────────────────────────────────────────────────────

def _build_graph(sources: list[SourceConfig],
                 agents: list[AgentConfig],
                 config: HarnessConfig) -> dict[str, Any]:
    """Agent → source → tool → tag → policy-rule dependency graph.

    Tool names come from agent allow-lists — a `sources:` entry (local or
    MCP, see config.schema.SourceConfig) contributes no tool nodes of its
    own; MCP tool topology lives in the manifest file, outside this offline
    view.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def node(node_id: str, node_type: str, label: str, **attrs: Any) -> str:
        nodes.setdefault(node_id, {"id": node_id, "type": node_type,
                                   "label": label, **attrs})
        return node_id

    def edge(src: str, dst: str, kind: str) -> None:
        edges.append({"from": src, "to": dst, "type": kind})

    for src in sources:
        s_id = node(f"source:{src.name}", "source", src.name,
                    transport=str(src.transport))
        for tag in src.tags:
            edge(s_id, node(f"tag:{tag}", "tag", tag), "tagged")

    for agent in agents:
        a_id = node(f"agent:{agent.id}", "agent", agent.id)
        for name in agent.sources:
            edge(a_id, node(f"source:{name}", "source", name), "declares")
        for tool_name in agent.allowed_tool_names:
            edge(a_id, node(f"tool:{tool_name}", "tool", tool_name), "allows")
        for tag in agent.allowed_tags:
            edge(a_id, node(f"tag:{tag}", "tag", tag), "scoped_to")
        for sub in agent.sub_agents:
            sub_id = node(f"subagent:{agent.id}/{sub.id}", "subagent", sub.id)
            edge(a_id, sub_id, "delegates")
            for tool_name in sub.allowed_tool_names:
                edge(sub_id, node(f"tool:{tool_name}", "tool", tool_name), "allows")
            for tag in sub.allowed_tags:
                edge(sub_id, node(f"tag:{tag}", "tag", tag), "scoped_to")

    # Source-activation rules, then per-agent tool rules. Global policy no
    # longer arbitrates tool calls, so a rule with no owner governs which
    # sources activate, not which tools may be invoked.
    rules = [(None, r) for r in config.policy.parsed_source_rules()]
    rules += [(a.id, r) for a in agents for r in a.policy_rules]
    for owner, rule in rules:
        r_id = node(f"rule:{owner or 'global'}/{rule.id}", "rule",
                    f"{rule.id} ({rule.action})", scope=owner or "global",
                    action=rule.action)
        if owner:
            edge(f"agent:{owner}", r_id, "governed_by")
        for tool_name in rule.match.tool_names:
            edge(r_id, node(f"tool:{tool_name}", "tool", tool_name), "matches")
        for tag in rule.match.tool_tags:
            edge(r_id, node(f"tag:{tag}", "tag", tag), "matches")
        for tag in rule.match.source_tags:
            edge(r_id, node(f"tag:{tag}", "tag", tag), "matches")

    return {
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": edges,
    }


_DOT_SHAPES = {
    "agent":    "box",
    "subagent": "box",
    "source":   "component",
    "tool":     "ellipse",
    "tag":      "diamond",
    "rule":     "note",
}


def _to_dot(graph: dict[str, Any]) -> str:
    lines = ["digraph shai {", "  rankdir=LR;", '  node [fontname="sans-serif"];']
    for n in graph["nodes"]:
        lines.append(f'  "{n["id"]}" [label="{n["label"]}", '
                     f'shape={_DOT_SHAPES.get(n["type"], "box")}];')
    for e in graph["edges"]:
        lines.append(f'  "{e["from"]}" -> "{e["to"]}" [label="{e["type"]}"];')
    lines.append("}")
    return "\n".join(lines)


def cmd_harness_graph(args: argparse.Namespace) -> int:
    loaded = _load(args)
    if loaded is None:
        return 1
    config, sources, agents = loaded
    graph = _build_graph(sources, agents, config)

    console.write(json.dumps(graph, indent=2) if args.format == "json"
                  else _to_dot(graph))
    return 0
