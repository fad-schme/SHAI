# Audit Event Schema

Every boundary call emits exactly one `AuditEvent`. No raw user text, LLM output, tool arguments, or scanner-matched substrings appear in any field.

---

## AuditEvent fields

| Field | Type | Always present | Description |
|---|---|---|---|
| `timestamp` | ISO 8601 datetime (UTC) | Yes | Wall-clock time of the event |
| `boundary` | string enum | Yes | `input_scan`, `tool_call_gate`, `tool_result_scan`, `output_scan`, `file_scan` |
| `decision` | string enum | Yes | `allow`, `deny`, `blocked`, `redact` |
| `disabled` | bool | Yes | `true` when the boundary is configured `enabled: false` |
| `duration_ms` | int | Yes | Wall-clock duration of the boundary call in milliseconds |
| `tenant_id` | string | Yes | From `harness.yaml` — identifies the deployment |
| `agent_id` | string | Yes | The top-level agent making the call |
| `sub_agent_id` | string | No | Set when `scope_context_for_subagent` is active |
| `tool_name` | string | No | Tool name for `tool_call_gate` events |
| `transport` | string | No | `local`, `mcp`, or `skill` for `tool_call_gate` events |
| `adapters` | list[string] | Yes | Scanner or policy adapter names that ran |
| `finding_count` | int | Yes | Number of findings (0 for gate and disabled events) |
| `max_severity` | string | No | Highest finding severity: `info`, `low`, `medium`, `high`, `critical` |
| `deny_reason` | string | No | Required when `decision=deny` |
| `audit_tags` | object | Yes | Operator-defined tags from agent-xx.yaml `audit_tags` |
| `extra` | object | Yes | Adapter-specific metadata |
| `signature` | string | No | HMAC-SHA256 hex digest when `audit_signing.enabled: true` |

---

## Decision values by boundary

| Decision | `input_scan` | `tool_call_gate` | `tool_result_scan` | `output_scan` | `file_scan` |
|---|---|---|---|---|---|
| `allow` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `deny` | — | ✓ | — | — | — |
| `blocked` | ✓ | — | ✓ | ✓ | ✓ |
| `redact` | — | ✓ | — | — | — |

`deny` is only used by the tool call gate. `blocked` is only used by scan boundaries. `redact` occurs on the gate when a policy rule has `action: redact`.

---

## Example events

**Input blocked (PII detected):**
```json
{
  "timestamp": "2025-01-15T10:23:45.123456+00:00",
  "boundary": "input_scan",
  "decision": "blocked",
  "disabled": false,
  "duration_ms": 3,
  "tenant_id": "platform-prod",
  "agent_id": "orchestrator_agent",
  "sub_agent_id": null,
  "adapters": ["regex_pii", "injection_scan"],
  "finding_count": 1,
  "max_severity": "high",
  "audit_tags": {"team": "platform", "env": "prod"}
}
```

**Tool call denied (policy):**
```json
{
  "timestamp": "2025-01-15T10:23:45.456789+00:00",
  "boundary": "tool_call_gate",
  "decision": "deny",
  "disabled": false,
  "duration_ms": 2,
  "tenant_id": "platform-prod",
  "agent_id": "orchestrator_agent",
  "sub_agent_id": "research_sub",
  "tool_name": "send_email",
  "transport": "local",
  "adapters": ["rules"],
  "finding_count": 0,
  "deny_reason": "research_sub is read-only",
  "audit_tags": {"team": "platform", "env": "prod"}
}
```

**Tool result scan — indirect injection detected:**
```json
{
  "timestamp": "2025-01-15T10:23:46.789012+00:00",
  "boundary": "tool_result_scan",
  "decision": "blocked",
  "disabled": false,
  "duration_ms": 5,
  "tenant_id": "platform-prod",
  "agent_id": "orchestrator_agent",
  "adapters": ["injection_scan_doc"],
  "finding_count": 2,
  "max_severity": "high",
  "audit_tags": {"team": "platform", "env": "prod"}
}
```

**Signed event:**
```json
{
  "timestamp": "2025-01-15T10:23:47.000000+00:00",
  "boundary": "tool_call_gate",
  "decision": "allow",
  "duration_ms": 1,
  "tenant_id": "platform-prod",
  "agent_id": "orchestrator_agent",
  "tool_name": "search_docs",
  "transport": "local",
  "adapters": ["rules"],
  "finding_count": 0,
  "audit_tags": {},
  "signature": "a3f2b1c4d5e6..."
}
```

---

## Verifying a signed event

```python
import hashlib, hmac, json

def verify(event: dict, secret: bytes) -> bool:
    expected = event.get("signature")
    if expected is None:
        return False
    payload = {k: v for k, v in event.items() if k != "signature" and v is not None}
    body = json.dumps(payload, sort_keys=True, default=str).encode()
    computed = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected)
```

The signature covers all non-null fields except `signature` itself, serialised as deterministic JSON (`sort_keys=True`). Use `hmac.compare_digest` for timing-safe comparison.

---

## SIEM query examples

All sinks emit JSONL (one JSON object per line). Standard queries:

```bash
# All denials in the last hour
jq 'select(.decision == "deny")' audit.jsonl

# Tool call gate events for a specific agent
jq 'select(.boundary == "tool_call_gate" and .agent_id == "orchestrator_agent")' audit.jsonl

# Subagent privilege escalation attempts
jq 'select(.decision == "deny" and .sub_agent_id != null)' audit.jsonl

# Indirect injection detections
jq 'select(.boundary == "tool_result_scan" and .decision == "blocked")' audit.jsonl

# Events missing a signature (audit signing not enabled or tampered)
jq 'select(.signature == null)' audit.jsonl

# High-severity findings on input
jq 'select(.boundary == "input_scan" and .max_severity == "high")' audit.jsonl
```
