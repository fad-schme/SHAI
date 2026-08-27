# Connectivity Reference

Network-layer enforcement for MCP tool calls.

---

## What it adds

Without connectivity: SHAI gates at the Python boundary. Once a call is
allowed, no visibility into what happens on the wire.

With connectivity: every allowed MCP call carries a signed `DispatchToken`.
`ShaiTransport` validates it on the wire — URL, method, source binding,
and one-time use.

---

## Enable

```yaml
# harness.yaml
connectivity:
  enabled: true
  token_secret: "secret://SHAI_TOKEN_SECRET"   # HMAC signing key
  token_ttl_seconds: 15                         # tokens expire in 15s
  no_token_policy: permissive                   # permissive | strict
```

`no_token_policy`:
- `permissive` — allows requests without a token (SSE, init, non-MCP calls)
- `strict` — rejects any request without a valid token

---

## DispatchToken

Issued by `check_tool_call` on every allowed decision when `enabled: true`.

```python
gate = await harness.check_tool_call(tool_name, args, ctx)

gate.dispatch_token  # str | None — encoded token, pass to source.call()
```

**What the token asserts:**
- `agent_id`, `sub_agent_id`, `tenant_id` — identity
- `tool_name`, `source_name` — exactly which tool on which source
- `allowed_urls`, `allowed_methods` — what the call may reach
- `expires_at` — short TTL (default 15 seconds)
- `token_id` — UUID, consumed as a one-time nonce

**Containment property.** Tokens are minted only on the gate's allow path, are
single-use, and expire in `token_ttl_seconds`. Stopping issuance for an agent —
`deregister_agent()`, a denying policy, any deny path — stops that agent's
outbound MCP traffic within one TTL, without the agent loop's cooperation
(enforcement is in `ShaiTransport`) and without affecting other agents (tokens
carry `agent_id`). `token_ttl_seconds` is therefore the containment latency.
Applies only when `connectivity.enabled` is true — it defaults to false — and
only to calls that dispatch through `ShaiTransport`.

**Passing the token to MCP dispatch:**
```python
if gate.allowed:
    source = await harness.get_source("slack_mcp")
    result = await source.call(
        tool_name,
        gate.redacted_args or args,
        dispatch_token=gate.dispatch_token,
    )
```

Hand-rolled dispatch is the only place you thread the token yourself. The
framework integrations route MCP tools to their source and attach the token
for you — `HarnessToolNode` for any tool without a local callable,
`gated_dispatch` when called without a `dispatch` argument. A call dispatched
without the token is refused under `no_token_policy: strict` and produces no
`NetworkAuditEvent` to correlate under `permissive`.

---

## ShaiTransport enforcement

`ShaiTransport` wraps the `httpx.AsyncClient` inside `MCPSource`.
Every outbound request passes through these checks in order:

```
1. URL enforcement    — request URL must match self._allowed_urls (transport config)
2. Method enforcement — request method must match self._allowed_methods
3. Token validation   — verify HMAC signature + expiry
   3a. Source binding  — token.source_name must match transport's source_name
   3b. URL binding     — request URL must match token.allowed_urls (token claim)
   3c. Method binding  — request method must match token.allowed_methods
   3d. Nonce check     — token_id must not have been used before
4. X-Shai-Token header injected
5. Forward to inner transport
6. Emit NetworkAuditEvent
```

**Both transport config AND token claims must pass.** The token is not
sufficient on its own — the transport enforces its own URL/method lists too.

---

## NetworkAuditEvent

Emitted per outbound request when a token is present. Written to the same
audit sinks as `AuditEvent`. Distinguished by `event_type="network_egress"`.

Written as one JSON object per line, keys sorted, nulls omitted:

```json
{
  "agent_id":    "orchestrator",
  "bytes_recv":  8820,
  "bytes_sent":  1240,
  "destination": "https://mcp.slack.com/api/search.messages",
  "duration_ms": 142,
  "event_type":  "network_egress",
  "method":      "POST",
  "signature":   "a3f2b1c4d5e6...",
  "source_name": "slack_mcp",
  "status":      "allowed",
  "tenant_id":   "acme",
  "timestamp":   "2026-07-27T12:00:00Z",
  "token_id":    "uuid-1234",
  "tool_name":   "search_messages"
}
```

`token_id` is the join key with the `check_tool_call` `AuditEvent`. `signature`
is present only when `audit_signing.enabled`. `sub_agent_id` and `deny_reason`
are omitted here because they are null on this event.

**Token_id joins gate + network events:**
```sql
SELECT h.tool_name, h.decision, n.destination, n.bytes_recv
FROM audit_events h
JOIN network_audit n ON h.token_id = n.token_id
WHERE h.agent_id = 'orchestrator'
```

**No NetworkAuditEvent for SSE or init** — those carry no token.

---

## Security properties

| Property | How enforced |
|---|---|
| Only SHAI-gated calls reach the network | Token required for tool calls |
| Token can't be reused | Nonce store, TTL window |
| Token can't be used on wrong source | `token.source_name == transport._source_name` |
| Token can't reach URLs outside its scope | `token.allowed_urls` cross-checked against request |
| Token can't use methods outside its scope | `token.allowed_methods` cross-checked |

---

## Components

Token issuance happens in the Python harness (`DispatchToken`,
`GateDecision.dispatch_token`, `ConnectivityConfig`). `ShaiTransport` enforces
it in-process at the httpx layer and emits `NetworkAuditEvent`; it is wired
into `MCPSource._connect()`.

---

## NetworkPolicyError

Raised by `ShaiTransport` when a request is blocked:

```python
from harness.core.errors import NetworkPolicyError

try:
    result = await source.call(tool_name, args)
except NetworkPolicyError as e:
    # Outbound request was blocked by ShaiTransport
    print(e)   # e.g. "token source_name 'github' does not match transport source 'slack_mcp'"
```

A `NetworkAuditEvent` with `status="denied"` is always emitted before the error is raised.
