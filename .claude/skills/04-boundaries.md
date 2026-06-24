# Boundaries Reference

SHAI enforces security at four boundaries. Every call emits exactly one
`AuditEvent`. Boundaries never raise — they always return a verdict.

---

## scan_input

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

## check_tool_call

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

## scan_tool_result

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

## scan_output

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

## scan_file

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

## Audit invariants (all boundaries)

- **One event per call, always** — even on pre-gate failure or exception.
- **No raw text** — no user input, LLM output, args, or matched substrings.
- `decision=deny` only on `tool_call_gate`.
- `decision=blocked` / `decision=warn` only on scan boundaries.
- `disabled=True` → `decision=allow`, scanners not run.
- `tenant_id` comes from config, never from the caller.

---

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
