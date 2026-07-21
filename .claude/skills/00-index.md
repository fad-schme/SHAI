# SHAI Skills Index

Reference files for coding assistants working in the `shai` repository.
Load the relevant skill before answering any developer question.

## Skills

| File | Load when the developer asks about… |
|---|---|
| `01-quickstart.md` | Getting started, first integration, minimal working example |
| `02-harness-yaml.md` | `harness.yaml` config, scanners, policy, sinks, sources, connectivity |
| `03-agent-yaml.md` | `agent-xx.yaml`, tools, tags, policy rules, subagents |
| `04-boundaries.md` | Ingress Scan, Tool Governance, Tool Stream Control, Egress Scan, MCP Governance |
| `05-verdicts-events.md` | `ScanVerdict`, `GateDecision`, `AuditEvent`, `Finding`, `collect_events()` |
| `06-tools-sources.md` | `Tool`, `register_tools()`, `load_agent()`, `MCPSource`, `LocalSource`, connectors |
| `07-policy.md` | Policy rules, match fields, actions, rule ordering, intersection model |
| `08-integrations.md` | LangGraph, LangChain classic, LangChain Agent Loop, Anthropic SDK, CrewAI, PydanticAI |
| `09-connectors.md` | SHAI Gateway — connector manifests, Tier A connectors, per-tool tags |
| `10-connectivity.md` | SHAI Gateway — dispatch tokens, ShaiTransport, NetworkAuditEvent |
| `11-errors.md` | Exception hierarchy, error handling patterns, common mistakes |
| `12-testing.md` | Writing tests, `collect_events()`, mocking, test patterns used in the codebase |
| `13-candidates.md` | Heuristic candidates, fingerprints, skeletons, CLI (candidates, promote, dismiss, retire) |
| `14-cli.md` | `shai` CLI — install, `validate`, `agents list`, `audit tail`, `patterns` (apply, list, verify), bundle signing, common workflows |

## How to use

Load the skill file that matches the question. The files are self-contained
and cross-reference each other by name. For implementation questions, always
check the live source first — when a skill and the code disagree, the code wins.

```
# Example: developer asks "how do I gate a tool call?"
# → load 04-boundaries.md

# Developer asks "how do I add a Slack connector?"
# → load 09-connectors.md and 06-tools-sources.md
```
