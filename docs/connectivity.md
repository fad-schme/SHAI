# Connectivity layer

PLACEHOLDER FOR THE CODING AGENT.

## What goes here

The connectivity layer sits below the harness and enforces at the network
and process boundary. See CLAUDE.md §3.9 for the authoritative design.
This document expands it with implementation detail.

Sections:

1. **The bypass problem** — why the harness alone is insufficient, and
   which call paths escape check_tool_call (direct HTTP, subprocess exec,
   code execution output, raw sockets).

2. **Dispatch token** — the full DispatchToken schema, field semantics,
   HMAC signing, TTL policy, and how the harness constructs and issues it.
   How allowed_destinations is derived from ToolSource MCP config.
   How the shared secret is managed via SecretsProvider.

3. **Egress gateway** — token validation algorithm (HMAC verify →
   TTL check → destination check), deny path (log + block + emit audit
   event), rate limiting per (agent_id, tool_name), hot-reload contract.

4. **L7 network policy** — YAML policy schema, method + path matching,
   interaction with dispatch token (L7 policy is additive — both must
   allow), hot-reload mechanism, policy versioning.

5. **Process isolation** — one container per agent, filesystem namespace,
   seccomp syscall filter profile, privilege escalation prevention.
   What is locked at creation vs what can be updated.

6. **Inference router** — intercept pattern for LLM API calls, credential
   stripping and injection, model allowlist enforcement. The harness does
   not configure model routing — the connectivity layer does, independently.

7. **Audit correlation** — connectivity layer event schema, the agent_id
   + token correlation key, how connectivity events feed the same SIEM
   as harness AuditEvents, the combined audit chain.

8. **Policy domain summary** — static vs dynamic domains table.

9. **Implementation guidance** — the connectivity layer has no dependency
   on the harness Python codebase. Only the shared secret and the token
   format are required. Rust or Go are appropriate for the network path.
