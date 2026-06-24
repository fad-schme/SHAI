# SHAI Connectivity Layer

## The gap SHAI closes today — and the gap it does not

SHAI gates tool calls at the Python API boundary. Every tool call is
checked, every decision is audited. But once a call is allowed and
dispatched, the harness has no visibility into what happens next.

A tool — or LLM-generated code running inside a code-execution tool —
can make arbitrary outbound connections: raw HTTP, subprocess exec, direct
socket. The harness never sees these. An injected payload that survives
`scan_tool_result` can instruct a tool to POST secrets to an attacker's
server. SHAI's audit trail shows the tool was called; it cannot show what
the tool did on the wire.

This is the gap that `shai-connectivity` closes.

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│  Agent container  (one per agent — isolated namespace)              │
│                                                                     │
│  ┌──────────────┐    gate + token    ┌──────────────────────────┐  │
│  │  Agent code  │ ─────────────────► │  SHAI harness            │  │
│  │  (any        │ ◄──── GateDecision │  check_tool_call()       │  │
│  │  framework)  │   + DispatchToken  │  issues DispatchToken    │  │
│  └──────┬───────┘                    └──────────────────────────┘  │
│         │ tool dispatch                                             │
│         ▼                                                           │
│  ┌──────────────┐   all outbound     ┌──────────────────────────┐  │
│  │  Tool / MCP  │ ──── HTTP ────────►│  Egress gateway          │  │
│  │  client /    │   (via HTTP_PROXY  │  • validate DispatchToken │  │
│  │  code exec   │    or eBPF hook)   │  • enforce destinations  │  │
│  └──────────────┘                    │  • enforce HTTP methods  │  │
│                                      │  • L7 path/payload rules │  │
│                                      │  • emit network AuditEvent│  │
│                                      └──────────┬───────────────┘  │
│                                                 │                   │
└─────────────────────────────────────────────────┼───────────────────┘
                                                  │ validated traffic
                                                  ▼
                                      ┌──────────────────────────┐
                                      │  Inference router        │
                                      │  (LLM API calls only)    │
                                      │  • strip agent creds     │
                                      │  • inject backend creds  │
                                      │  • enforce model allow-  │
                                      │    list per agent        │
                                      └──────────┬───────────────┘
                                                 │
                                                 ▼
                                      External services
                                      (Slack MCP, OpenAI, etc.)
```

---

## Components

### 1. SHAI harness — dispatch token issuer

`check_tool_call` is the only place in SHAI where "this tool call is
allowed" is decided. That decision is the only legitimate authorisation
for an outbound network connection. The token is issued here.

`GateDecision` gains an optional `dispatch_token: str | None` field.
When the gate allows, the harness signs a token and includes it. When
the gate denies, no token is issued — there is nothing to present at
the network boundary.

The agent dispatch layer attaches the token to outbound calls:

```python
gate = await harness.check_tool_call(tool_name, args, ctx)
if gate.allowed:
    result = await source.call(
        tool_name,
        gate.redacted_args or args,
        dispatch_token=gate.dispatch_token,   # presented to egress gateway
    )
```

The token is not a bearer credential — it does not grant access to the
destination directly. It is a signed assertion that SHAI authorised this
specific call. The egress gateway validates the assertion against the
wire traffic.

### 2. Dispatch token

```python
@dataclass(frozen=True)
class DispatchToken:
    token_id:        str           # UUID — unique per gate decision
    agent_id:        str
    sub_agent_id:    str | None
    tenant_id:       str
    tool_name:       str
    source_name:     str           # which source owns this tool
    allowed_urls:    list[str]     # URL prefix patterns this call may reach
    allowed_methods: list[str]     # HTTP methods permitted (e.g. ["GET", "POST"])
    issued_at:       datetime
    expires_at:      datetime      # short TTL: 10–30 seconds
    nonce:           str           # prevents replay within TTL window
    signature:       str           # HMAC-SHA256 over all other fields
```

**`allowed_urls`** is derived from the tool's source config at
`from_yaml()` time. An MCP source declared with
`url: "https://mcp.slack.com/sse"` produces tokens whose `allowed_urls`
are scoped to `https://mcp.slack.com/*`. A local tool with no declared
URL gets `allowed_urls: []` — it may not make outbound calls at all.

**TTL** is short by design (10–30 seconds). A token is single-use in
practice: one gate decision, one dispatch, one network call. The nonce
prevents replay within the TTL window.

**Signature** covers all fields except `signature` itself, serialised
as deterministic JSON (`sort_keys=True`), HMAC-SHA256 with a shared
secret configured in `harness.yaml` under `connectivity.token_secret`.
The same shared secret is configured on the egress gateway.

### 3. Egress gateway

The gateway intercepts all outbound HTTP/HTTPS from the agent container.
It is the single enforcement point for network-level policy.

**Deployment (sidecar model):**

```
HTTP_PROXY=http://localhost:8080
HTTPS_PROXY=http://localhost:8080
```

The gateway runs as a sidecar container. The agent process's proxy
environment variables redirect all HTTP/HTTPS traffic through it.
No code changes required in the agent or tool implementations.

**eBPF/netfilter model (higher assurance):**

For higher-assurance deployments, the gateway uses an eBPF TC hook or
`netfilter` REDIRECT rule to intercept all outbound TCP from the agent's
network namespace — including raw sockets that bypass `HTTP_PROXY`. This
requires elevated privileges at container creation time but provides
stronger guarantees than the proxy model.

**Validation sequence per outbound connection:**

```
1. Extract DispatchToken from request header (X-Shai-Token)
2. Verify HMAC-SHA256 signature
3. Check expires_at — reject if expired
4. Check nonce — reject if seen before (short-lived nonce store)
5. Check request destination against allowed_urls
6. Check HTTP method against allowed_methods
7. Apply L7 policy rules (path restrictions, payload size)
8. If all checks pass: forward the request
9. Emit NetworkAuditEvent correlated by token_id → agent_id
10. If any check fails: reject with 403, emit NetworkAuditEvent(denied)
```

**No-token policy:**

Connections presented without a `X-Shai-Token` header are governed by
a configurable no-token policy:

- `block_all` (default) — reject any connection without a valid token.
  This is the secure default: only SHAI-gated calls reach the network.
- `allow_declared_urls` — allow connections to URLs declared in
  `harness.yaml` sources without a token. Use during migration.
- `audit_only` — allow all connections, log missing tokens. Use during
  initial rollout to understand traffic before enforcing.

### 4. L7 policy

Applied after token validation. Configurable per source and per agent.
Expressed as YAML rules, hot-reloadable without gateway restart.

```yaml
# Example L7 policy
- id: slack_read_only_for_research_sub
  match:
    source_name: slack_mcp
    sub_agent_id: research_sub
  rules:
    - method: POST
      action: deny
      reason: "research_sub is read-only"
    - path_prefix: /api/conversations.history
      action: allow
    - path_prefix: /
      action: deny
      reason: "only conversations.history permitted for research_sub"

- id: limit_llm_payload
  match:
    destination_prefix: "https://api.openai.com"
  rules:
    - max_request_body_bytes: 65536   # 64 KB — prevents bulk exfiltration
      action: deny_if_exceeded
```

### 5. Inference router

A specialised reverse proxy for LLM API calls. Sits in front of LLM
provider endpoints (OpenAI, Anthropic, local Ollama).

**Why it exists:** an agent that holds an OpenAI API key can make LLM
calls that bypass the inference router entirely. If a compromised tool
exfiltrates the key, the attacker has direct LLM access. The inference
router removes the key from the agent's environment entirely — the agent
calls a local endpoint, the router validates the call against the
agent's model allowlist, injects the real credential, and forwards.

**Enforcement:**

- **Model allowlist per agent** — declared in `agent-xx.yaml` under
  `allowed_models: ["gpt-4o-mini"]`. The router rejects calls to models
  outside the list.
- **Per-agent rate limits** — tokens/minute and requests/minute per
  agent, enforced at the router. Prevents runaway inference costs.
- **Credential isolation** — the agent process never holds a production
  LLM API key. Only the router has it, in a mounted secret.
- **Audit correlation** — every LLM call is logged with `agent_id`,
  model, token counts, correlated to the harness audit stream by
  `agent_id` + timestamp.

### 6. Container/process isolation

The outermost hard boundary. Static — set at container creation, not
configurable at runtime.

| Domain | Mechanism | What it prevents |
|---|---|---|
| Filesystem | Read-only root + explicit volume mounts | Agent writing to host FS |
| Process | `seccomp` syscall filter | Fork bombs, ptrace, raw socket creation |
| Network namespace | Isolated netns per agent | Cross-agent traffic |
| Privilege | `no-new-privileges`, non-root UID | Escalation after compromise |
| Code execution | Language-level sandbox (RustPython, Deno, Pyodide) | Arbitrary host exec from generated code |

Static isolation is set once and not hot-reloadable. Changes require
container restart. This is intentional — a running agent should not be
able to weaken its own isolation.

---

## Audit correlation

The connectivity layer emits `NetworkAuditEvent` records that correlate
with SHAI's `AuditEvent` records via `token_id` → `agent_id`.

```json
{
  "timestamp":    "2025-01-15T10:23:46.000Z",
  "event_type":   "network_egress",
  "token_id":     "uuid-of-dispatch-token",
  "agent_id":     "orchestrator_agent",
  "sub_agent_id": null,
  "tenant_id":    "platform-prod",
  "tool_name":    "search_docs",
  "source_name":  "slack_mcp",
  "destination":  "https://mcp.slack.com/api/search.messages",
  "method":       "POST",
  "status":       "allowed",
  "bytes_sent":   1240,
  "bytes_recv":   8820,
  "duration_ms":  142
}
```

Cross-referencing SHAI + network events gives the complete chain:

```
harness AuditEvent  →  SHAI decided to allow the tool call
network AuditEvent  →  the tool actually reached this destination
                        sent N bytes, received M bytes
```

Neither stream alone is sufficient. The SIEM query for a full turn:

```
SELECT h.*, n.*
FROM harness_audit h
JOIN network_audit n ON h.token_id = n.token_id
WHERE h.agent_id = 'orchestrator_agent'
  AND h.timestamp > now() - interval '1 hour'
ORDER BY h.timestamp
```

---

## SHAI interface changes for 0.2.x

### `GateDecision` gains `dispatch_token`

```python
@dataclass(frozen=True)
class GateDecision:
    allowed:        bool
    deny_reason:    str | None = None
    redacted_args:  dict | None = None
    dispatch_token: str | None = None   # new — signed JWT or HMAC token
```

### `HarnessConfig` gains `connectivity` block

```yaml
connectivity:
  enabled: false              # default off — opt-in
  token_secret: "secret://SHAI_TOKEN_SECRET"
  token_ttl_seconds: 15
  no_token_policy: block_all  # block_all | allow_declared_urls | audit_only
  gateway_url: "http://localhost:8080"
```

### `MCPSource.call()` attaches the token

When `connectivity.enabled`, `MCPSource.call()` adds
`X-Shai-Token: <signed_token>` to every outbound request. Local tools
receive the token via a context variable or a wrapper, not an HTTP header.

### `SourceConfig` gains `allowed_urls`

```yaml
sources:
  - name: slack_mcp
    transport: mcp
    url: "https://mcp.slack.com/sse"
    allowed_urls:
      - "https://mcp.slack.com/*"
      - "https://slack.com/api/*"
    allowed_methods: [GET, POST]
```

`allowed_urls` defaults to the source URL prefix when not specified.

---

## Threat coverage

| Threat | Without connectivity layer | With connectivity layer |
|---|---|---|
| T16 Data exfiltration | Partial — output scan catches LLM responses; raw tool HTTP not visible | Full — egress gateway blocks unapproved destinations |
| T17 Supply chain | Partial — source suppression, file scanner | Full — unsigned/untokenised connections blocked; model allowlist via inference router |
| T3 Uncontrolled actions | Partial — gate blocks disallowed tool calls | Full — gate + network enforcement; even a bypassed gate cannot reach the network |
| Credential exfiltration | Not covered | Inference router: agent never holds LLM API keys |
| Cross-agent traffic | Not covered | Network namespace isolation: one netns per agent |
| Runaway inference | Not covered | Inference router: per-agent token/request rate limits |

---

## Implementation phases

**Phase 1 — Token issuance (SHAI harness changes)**
- `DispatchToken` dataclass
- Token signing in `check_tool_call` when `connectivity.enabled`
- `GateDecision.dispatch_token` field
- `connectivity` block in `HarnessConfig`
- `allowed_urls` / `allowed_methods` on `SourceConfig`

**Phase 2 — Egress gateway (new package `shai-gateway`)**
- HTTP/HTTPS proxy with token validation
- Nonce store (Redis or in-memory with TTL)
- `NetworkAuditEvent` emission
- Configurable no-token policy

**Phase 3 — L7 policy**
- YAML rule engine in the gateway
- Hot-reload without restart
- Per-source, per-agent, per-subagent scoping

**Phase 4 — Inference router (new package `shai-inference-router`)**
- Reverse proxy for LLM providers
- Model allowlist per agent
- Per-agent rate limiting
- Credential isolation

**Phase 5 — eBPF enforcement (optional, higher assurance)**
- TC hook for raw socket interception
- Requires `CAP_NET_ADMIN` at container creation

---

## Current status

Not implemented. Phase 1 (token issuance) is the immediate next step.
It requires no new packages — only changes to `shai` itself.

Process isolation (recommended today) is described in `ARCHITECTURE.md`
under the connectivity section. It is the strongest available mitigation
until the gateway ships.
