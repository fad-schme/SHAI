# SHAI Skills Index

Reference files for coding assistants working in the `shai` repository.
Load the relevant skill before answering any developer question.

## What's new since last docs update

Cross-cutting changes since the previous doc set. Load the linked file for
detail.

| Area | Change | Read |
|---|---|---|
| Boundaries | 7-layer gate (was 4). New signal correlation + tightened arg scanning driven by earlier boundary findings. | `04-boundaries.md` |
| Boundaries | `scan_output` now emits a **consolidated risk block** when cross-boundary turn_risk crosses `RISK_HIGH` — turn is blocked even when no individual scanner blocked. | `04-boundaries.md` |
| Boundaries | Scanner catalog additions: `jailbreak_scan`, `identity_spoof_scan`, `heuristic_scan` are first-class configurable scanners with their own catalogs. | `04-boundaries.md`, `02-harness-yaml.md` |
| Cross-boundary | `TurnSignals` bus lives on `AgentContext` for one turn — `scan_input` writes findings, `check_tool_call` reads them to tighten the gate, `scan_tool_result` reads them to tighten `block_at`, `scan_output` computes consolidated risk. | `04-boundaries.md`, `05-verdicts-events.md` |
| Config | `on_error` per boundary: `fail_closed` (default) / `fail_open` / `degrade`. Default flipped from implicit fail-open — existing configs relying on the old behavior must opt in explicitly. | `02-harness-yaml.md` |
| Config | `extended_patterns` block: signed pattern DB loaded into scanners at startup. Rules authored as catalog YAML, signed via CLI, applied via `shai patterns apply`. | `02-harness-yaml.md` |
| Audit | New boundary values: `system` (scanner degrade / circuit-breaker events). New decision: `degraded`. Consolidated risk block carries `extra.turn_risk` and `extra.signal_source`. | `05-verdicts-events.md` |
| Scanners | PII: Luhn-validated cards, structurally-validated SSNs, new categories `secret.private_key`, `secret.jwt`, `secret.aws_secret`, `secret.conn_string`, `secret.slack_webhook`. | `04-boundaries.md` |
| Scanners | Heuristic scanner adds a 5th sub-score: typoglycemia (scrambled-keyword detection via Damerau-Levenshtein ≤ 1). | `04-boundaries.md` |
| Scanners | File scanner: SVG script scanning, double-extension detection, expanded PDF markers, zip compression-ratio bombs, EXIF+XMP metadata routed through the full text-scanner chain. | `04-boundaries.md` |
| Ops | `shai patterns build/apply/verify` — signed pattern DB workflow. See `make_bundle.py` and `README.md` in the new-patterns delivery. | `02-harness-yaml.md` |
| Ops | Deployment: **do not stream `scan_output`.** Buffer to the boundary or disable `scan_output` and use a client-side CSP. | `04-boundaries.md` |

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
