# Verdicts, Events, and collect_events()

---

## ScanVerdict

Returned by `scan_input`, `scan_output`, `scan_tool_result`, `scan_file`.

```python
@dataclass
class ScanVerdict:
    status:        ScanStatus         # ALLOW | WARN | BLOCK
    findings:      list[Finding]      # empty when no findings
    redacted_text: str | None         # set when any scanner redacted content

    # Convenience properties
    @property
    def blocked(self) -> bool: ...    # status == BLOCK
    @property
    def warned(self) -> bool: ...     # status == WARN
    @property
    def finding_count(self) -> int:   # len(findings)
    @property
    def max_severity(self) -> Severity | None: ...
```

**Pattern:**
```python
verdict = await harness.scan_input(text, ctx)

if verdict.blocked:
    return "Rejected"

# Always use redacted_text when it's set — it's the safe version
safe = verdict.redacted_text or text
```

**`redacted_text` is `None` when nothing was redacted** — not an empty string.
Always use `or original` pattern.

---

## Finding

```python
@dataclass
class Finding:
    scanner:   str             # "regex_pii", "injection_scan"
    category:  str             # "pii.ssn", "prompt_injection", etc.
    severity:  Severity        # LOW | MEDIUM | HIGH
    detail:    str | None      # category name only — never the matched text
```

**`detail` never contains matched text.** This is intentional — matched PII
or injection payloads must not appear in logs.

```python
for f in verdict.findings:
    print(f.scanner, f.category, f.severity)
    # e.g.: "regex_pii", "pii.credit_card", Severity.HIGH
```

---

## GateDecision

Returned by `check_tool_call`.

```python
@dataclass
class GateDecision:
    allowed:        bool
    deny_reason:    str | None    # set when allowed=False
    redacted_args:  dict | None   # set when L4 arg scanning redacted args
    dispatch_token: str | None    # set when connectivity.enabled and allowed=True
```

**Pattern:**
```python
gate = await harness.check_tool_call(name, args, ctx)

if not gate.allowed:
    return gate.deny_reason   # always non-None when allowed=False

# Always use redacted_args when set
effective_args = gate.redacted_args or args
result = await dispatch(name, effective_args)
```

---

## AuditEvent

Emitted by every boundary call. Written to configured sinks (file, stdout).
Also collected by `collect_events()`.

```python
@dataclass(frozen=True)
class AuditEvent:
    # Identity
    timestamp:      datetime          # UTC
    boundary:       BoundaryName      # input_scan | tool_call_gate | ...
    decision:       Decision          # allow | deny | blocked | warn | redact
    disabled:       bool              # True when boundary is disabled in config
    duration_ms:    int

    # Context
    tenant_id:      str
    agent_id:       str
    sub_agent_id:   str | None
    audit_tags:     dict[str, str]    # from agent config

    # Adapters
    adapters:       list[str]         # scanner/policy names that ran
    finding_count:  int               # 0 when clean
    max_severity:   str | None        # highest finding severity

    # Tool call only
    tool_name:      str | None
    transport:      str | None

    # Deny only
    deny_reason:    str | None        # always set when decision=deny

    # Connectivity
    token_id:       str | None        # DispatchToken join key

    # Boundary-specific metadata (never raw text) — see "The extra dict" below
    extra:          dict[str, Any]    # e.g. { "turn_risk": 0.71, "signal_source": "consolidated" }

    # Signing (when audit_signing.enabled)
    signature:      str | None
```

**No raw text in any field.** Not in `deny_reason`, not in `detail`.

### Boundary names

| `boundary` | Boundary method |
|---|---|
| `input_scan` | `scan_input()` |
| `tool_call_gate` | `check_tool_call()` |
| `tool_result_scan` | `scan_tool_result()` |
| `output_scan` | `scan_output()` |
| `file_scan` | `scan_file()` |
| `mcp_metadata_scan` | MCP tool-registration metadata scan |
| `system` | Scanner degrade / circuit-breaker events — no direct call, emitted alongside a scan boundary when a scanner fails |

### Decision values

| `decision` | Meaning | Which boundaries |
|---|---|---|
| `allow` | Clean pass | All |
| `warn` | Flagged but passed | Scan boundaries |
| `blocked` | Hard block | Scan boundaries |
| `deny` | Gate denied | `tool_call_gate` only |
| `redact` | Content redacted | Scan boundaries |
| `degraded` | Scanner failure per `on_error: degrade`, or circuit-breaker trip | `system` (paired with the affected scan) |

### The `extra` dict

`AuditEvent.extra` is an open dict for boundary-specific metadata. Never
contains raw text or matched substrings. Well-known keys:

| Key | Where | Meaning |
|---|---|---|
| `turn_risk` | `output_scan` | Consolidated turn risk score (0.0–~0.99) from `TurnSignals.compute_risk()`. Present on every `output_scan` event when signals are active. |
| `signal_source` | `output_scan` (`blocked`) | `"consolidated"` when the block came from the risk-based aggregator, not an individual scanner. |
| `signals` | Various | List of subsystem-level signals that fired for the event, e.g. `["session_escalation"]` on an accumulator-driven block. |
| `scanner` | `system` | Which scanner degraded or tripped its circuit breaker. |
| `error` | `system` | Short string describing the underlying failure. |
| `circuit_state` | `system` | `"open"` / `"half_open"` for breaker-driven events. |
| `degraded` | `system` (`degraded`) | `True` when the event represents an `on_error: degrade` pass-through. |
| `normalization` | Scan boundaries | List of transform names that fired during de-obfuscation (`strip_invisible`, `unicode_fold`, `decode_base64`, …). Never the decoded text. |

Consumers should treat unknown `extra` keys as informational and forward-compatible.

---

## NetworkAuditEvent

Emitted by `ShaiTransport` for outbound MCP requests when `connectivity.enabled`.
Written to the same sinks. Distinguished by `event_type="network_egress"`.

```python
@dataclass(frozen=True)
class NetworkAuditEvent:
    event_type:   str        # "network_egress"
    token_id:     str | None # join key with AuditEvent
    source_name:  str
    agent_id:     str
    tool_name:    str | None  # None for SSE/init requests
    destination:  str
    method:       str
    status:       str        # "allowed" | "denied"
    deny_reason:  str | None
    bytes_sent:   int
    bytes_recv:   int
    duration_ms:  int
```

**SIEM join:**
```sql
SELECT h.*, n.*
FROM audit_events h
JOIN network_audit n ON h.token_id = n.token_id
WHERE h.agent_id = 'orchestrator_agent'
```

---

## collect_events()

Collects `AuditEvent` objects in-process without affecting sinks.

```python
# Wrap a full agent turn
with harness.collect_events() as events:
    verdict = await harness.scan_input(text, ctx)
    gate    = await harness.check_tool_call(name, args, ctx)
    tv      = await harness.scan_tool_result(result, ctx)
    ov      = await harness.scan_output(response, ctx)

# After the block, events is fully populated
allows = [e for e in events if str(e.decision) == "allow"]
denies = [e for e in events if str(e.decision) == "deny"]
gates  = [e for e in events if str(e.boundary) == "tool_call_gate"]
```

**Accessing fields:**
`AuditEvent` is a Pydantic model. Access fields as attributes, not dict keys.

```python
# Correct
ev.boundary      # BoundaryName enum
str(ev.boundary) # "tool_call_gate"
ev.decision      # Decision enum
ev.tool_name     # str | None
ev.finding_count # int

# Wrong
ev["boundary"]   # TypeError — not a dict
```

**Concurrent safety:** multiple `collect_events()` blocks are safe.
Each gets its own independent list.
