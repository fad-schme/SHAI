# Boundaries Reference

SHAI enforces security at four boundaries. Every call emits exactly one
`AuditEvent`. Boundaries never raise — they always return a verdict.

---

## Ingress Scan (`scan_input`)

```python
verdict = await harness.scan_input(user_text, ctx)

if verdict.blocked:
    return "Input rejected"

# Use redacted_text if the scanner redacted anything
safe_text = verdict.redacted_text or user_text
```

**Runs:** configured scanners (`regex_pii`, `injection_scan`) on the raw user text.
**Catches:** PII (T11), direct prompt injection (T5).
**Audit:** `boundary="input_scan"`, `decision` = allow/warn/blocked.

---

## Named scanner methods

Each scanner is also callable individually through the facade:

```python
from harness import SHAI, RegexPIIScanner, InjectionScanner, MCPMetadataScanner

# Run only PII detection — no injection scan overhead
verdict = await harness.scan_pii(text, ctx)

# Run only injection detection — targeted surface scanning
verdict = await harness.scan_injection(text, ctx)

# Inspect active scanners
print(harness.scanners)
# {
#   'regex_pii':          RegexPIIScanner,
#   'injection_scan':     InjectionScanner,
#   'injection_scan_doc': InjectionScanner(patterns_for_doc),
#   'file_scanner':       FileScanner,
#   'rate_limiter':       RateLimiter,
# }
```

`scan_input` still runs all configured scanners together — the named methods
are for cases where you need a single scanner on a specific surface.

## Tool Governance (`check_tool_call`)

```python
gate = await harness.check_tool_call(tool_name, tool_args, ctx)

if not gate.allowed:
    # Provide denial feedback to the LLM
    return f"Tool call denied: {gate.deny_reason}"

# gate.redacted_args is set when L4 arg scanning redacted something
args = gate.redacted_args or tool_args
result = await my_dispatch(tool_name, args)
```

**Four layers — first deny anywhere wins:**

| Layer | Check | Bypassable? |
|---|---|---|
| Pre-gate | Agent registered in harness? | No |
| L1 | `tool_name` in `allowed_tool_names`? | No |
| L2 | `tool.tags ⊆ ctx.allowed_tags`? (subagents only) | No |
| L3 | Policy rules (subagent → parent → global) | By design |
| L4 | Arg scanning for `sensitive`-tagged tools | Config |

**L1 is absolute.** Nothing can grant access to a tool not in `allowed_tool_names`.

**Rate limiter** fires before L1. Sliding-window token bucket per agent.
Two counters: global call budget + per-tool budget. Both must pass.

**Dispatch token** is issued when `connectivity.enabled: true`:
```python
gate.dispatch_token  # str | None — pass to source.call()
```

---

## Tool Stream Control (`scan_tool_result`)

```python
# Basic — always scans
tverdict = await harness.scan_tool_result(result, ctx)

# Better — with tool_name lets connector manifests skip non-risky tools
tverdict = await harness.scan_tool_result(result, ctx, tool_name="get_issue")

if tverdict.blocked:
    result = "Tool result blocked by security policy"
else:
    result = tverdict.redacted_text or result
```

**Runs:** `patterns_for_doc.yaml` (9 injection-pattern rules tuned for document content).
**Catches:** indirect prompt injection embedded in tool results (T6).

**`tool_name` parameter and `scan_tool_result_on`:**
When a connector manifest declares `scan_tool_result_on`, only those tools
are scanned. Tools not in the list emit a `disabled=True` audit event and
return `ScanVerdict(allow)` without running scanners.

When `tool_name` is `None` or no manifest is loaded, all results are scanned.
This is the safe default — backward compatible.

---

## Egress Scan (`scan_output`)

```python
out_verdict = await harness.scan_output(llm_response, ctx)

if out_verdict.blocked:
    return "[Response blocked by security policy]"

return out_verdict.redacted_text or llm_response
```

**Runs:** configured scanners (typically `regex_pii`) on the LLM response.
**Catches:** PII leakage in responses (T11), data exfiltration (T16 partial).
**Audit:** `boundary="output_scan"`.

---

## Ingress Scan — File (`scan_file`)

```python
verdict = await harness.scan_file("/tmp/upload.pdf", ctx)

if verdict.blocked:
    return "File rejected"
```

**Two passes:**
1. Structural: MIME type, extension, size gate, PDF JS, EXIF, ZIP macros
2. Content: extracted text through InjectionScanner

**Disabled by default** — set `scan_file.enabled: true` in harness.yaml.

---

## Error handling at scan boundaries (0.2.0)

Scanner failures are handled per the boundary's `on_error` config:

| `on_error` | Scanner failure behavior |
|---|---|
| `fail_closed` | Pipeline short-circuits → `ScanVerdict(BLOCK)`. Default. |
| `fail_open` | Empty findings, pipeline continues (pre-0.2 behavior). |
| `degrade` | `ScanVerdict(WARN)`, `degraded=True` in audit event. |

A per-scanner circuit breaker tracks consecutive failures. After 5 failures
the scanner is skipped entirely. After a recovery timeout (exponential
backoff, cap 5 min), one probe call is attempted. Every scanner failure and
circuit breaker trip emits a `boundary=system`, `decision=degraded` audit
event with the scanner name, error, and circuit state.

```yaml
scan_input:
  on_error: fail_closed    # scanner crash → block content
```

---

## Audit invariants (all boundaries)

- **One event per call, always** — even on pre-gate failure or exception.
- **No raw text** — no user input, LLM output, args, or matched substrings.
- `decision=deny` only on `tool_call_gate`.
- `decision=blocked` / `decision=warn` only on scan boundaries.
- `disabled=True` → `decision=allow`, scanners not run.
- `tenant_id` comes from config, never from the caller.

---

## Scanner catalog

| Class | Import | Catalog | Used in |
|---|---|---|---|
| `HeuristicScanner` | `harness.adapters.scanners.heuristic_scan` | Built-in heuristics | All scan boundaries (always on) |
| `RegexPIIScanner` | `harness.adapters.scanners.regex_pii` | Built-in patterns | `scan_input`, `scan_output`, arg scanning |
| `InjectionScanner` | `harness.adapters.scanners.injection_scan` | `injection_patterns.yaml` | `scan_input` |
| `InjectionScanner` (doc) | same class, different catalog | `patterns_for_doc.yaml` | `scan_tool_result`, `FileScanner` content pass |
| `FileScanner` | `harness.adapters.scanners.file_scanner` | structural + doc patterns | `scan_file` |
| `MCPMetadataScanner` | `harness.adapters.scanners.mcp_metadata_scanner` | `mcp_metadata_patterns.yaml` | MCP `tools/list` registration |
| `RateLimiter` | `harness.adapters.scanners.rate_limiter` | — (config-driven) | `check_tool_call` pre-gate |

**`HeuristicScanner` — always on (0.2.0):**
Prepended automatically to every scan boundary. Not configurable. Detects
structural anomalies that regex catalogs miss: high-entropy segments (base64
blobs, obfuscated payloads), instruction-dense text, abrupt register shifts,
and embedded LLM markup (`<|system|>`, `[INST]`, `{"role": "system"}`).
Four sub-scores (0–2 each), summed: ≥5 HIGH, ≥3 MEDIUM, ≥1 LOW.

**Ensemble severity promotion (0.2.0):**
After all scanners complete, findings are cross-checked. When 2+ different
scanners flag the same category and their combined severity weight crosses
a threshold, all findings in that category are promoted to HIGH. This means
a MEDIUM from `injection_scan` plus a MEDIUM from `heuristic_scan` for the
same category becomes HIGH — even though neither scanner alone would have
triggered a block at `block_at: high`. Always on, no configuration.

**`injection_patterns.yaml` vs `patterns_for_doc.yaml`:**
- `injection_patterns.yaml` — tuned for user text input. More sensitive, 17 rules.
  Used by `InjectionScanner` at `scan_input`.
- `patterns_for_doc.yaml` — tuned for document/structured content. Lower false-positive
  rate for code, PDF text, spreadsheet data. Used by `scan_tool_result` and `FileScanner`.
- `mcp_metadata_patterns.yaml` — tuned for MCP tool metadata. Most sensitive — almost
  nothing legitimate looks like an injection in a tool description.

## collect_events() — capture events in-process

```python
with harness.collect_events() as events:
    verdict = await harness.scan_input(text, ctx)
    gate    = await harness.check_tool_call(name, args, ctx)
    result  = await dispatch(name, args)
    tv      = await harness.scan_tool_result(result, ctx)

# events is list[AuditEvent], populated after the block
for ev in events:
    print(ev.boundary, ev.decision, ev.tool_name)
```

`collect_events()` doesn't affect configured sinks (file, stdout).
Multiple concurrent `collect_events()` blocks are safe — each gets its
own independent list.

→ See `05-verdicts-events.md` for `AuditEvent` field reference.
