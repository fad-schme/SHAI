# Connectivity (Planned)

The harness gates at the API level. A tool — or LLM-generated code running inside a code-execution tool — can still make raw outbound network calls that the harness never sees.

`shai-connectivity` (planned) will enforce at the network boundary:

1. `check_tool_call` issues a short-lived signed **dispatch token** on `allow`.
2. The token scopes allowed destinations, HTTP methods, and a TTL.
3. An egress proxy validates the token before forwarding.
4. Calls without a valid token are blocked at the network layer.

This closes the gap between application-level gating (what SHAI does today) and network-level enforcement (what is needed for full T16/T17 coverage).

**Current status:** not implemented. The interface is defined here for design continuity.

---

## Dispatch token (interface)

```python
@dataclass(frozen=True)
class DispatchToken:
    tool_name:    str
    agent_id:     str
    tenant_id:    str
    allowed_urls: list[str]     # URL patterns the tool may call
    issued_at:    datetime
    expires_at:   datetime
    signature:    str           # HMAC-SHA256
```

Tokens would be issued inside `check_tool_call` on allow, passed to the dispatch layer, and validated by the egress proxy before forwarding each outbound request.

---

## Process isolation (recommended today)

Until `shai-connectivity` ships, the strongest mitigation for T16 (data exfiltration) and T17 (supply chain) is process isolation:

- Run each agent in a container with no outbound network access except to declared tool endpoints
- Tools that make external calls run in separate processes with minimal permissions
- Code-execution tools run in sandboxes (e.g. Docker with `--network none` + volume mounts for specific paths only)

SHAI's audit trail provides visibility; process isolation provides the enforcement boundary.
