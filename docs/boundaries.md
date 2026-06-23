# Boundaries

Four boundaries surround every agent turn. Each emits exactly one `AuditEvent` per call regardless of outcome. No raw text in any event field.

```
user text ──► scan_input ──► LLM ──► check_tool_call ──► tool ──► scan_tool_result ──► LLM ──► scan_output ──► response
```

---

## scan_input

Inspects user text before it reaches the LLM. Detects PII, prompt injection, and custom patterns.

| Behaviour | Detail |
|---|---|
| Disabled | Emits `AuditEvent(disabled=True, decision=allow)`. Returns `ScanVerdict(blocked=False)`. |
| Scanners | Run concurrently via `asyncio.gather`. Per-scanner exceptions are logged and treated as empty findings — pipeline never raises. |
| Block threshold | `block_at` severity (default `high`). Any finding at or above blocks. |
| Redaction | Last scanner's `redacted_text` wins. Use `verdict.redacted_text or original`. |

```python
verdict = await harness.scan_input(user_text, ctx)
if verdict.blocked:
    return "Input rejected"
safe_text = verdict.redacted_text or user_text
```

---

## check_tool_call

The mandatory gate. Cannot be disabled. Four layers in strict order. First deny anywhere wins. Exactly one `AuditEvent` per call.

### Pre-gate — agent registered?

`AgentRegistry.get(ctx.agent_id)` raises `AgentNotRegisteredError` if the agent was never loaded. Mapped to `GateDecision(allowed=False)`.

### L1 — allowed_tool_names

Hard pre-policy gate. `tool_name` must be in `AgentConfig.allowed_tool_names` (or the active `SubAgentConfig.allowed_tool_names`). No policy rule can override this. If the LLM requests a tool not in `allowed_tool_names`, L1 fires before policy runs.

### L2 — allowed_tags (subagent capability gate)

Active only when `ctx.allowed_tags is not None` (i.e. a subagent call scoped by `scope_context_for_subagent`). Every tag on the tool must be in `allowed_tags`. Prevents subagents from calling tools their parent never granted capability for.

### L3 — intersection policy

`PolicyEngine.evaluate(tool, args, ctx, rules=combined_rules)`.

`combined_rules` = subagent `policy_rules` + parent `policy_rules`. Engine evaluates these first, then its global rules (`rules_path`). First match wins. Default allow on no match.

Policy actions: `allow`, `deny`, `redact`.

### L4 — arg scanning (optional)

Fires only for tools tagged with any tag in `scan_args_for_tags` (default: `["sensitive"]`). Runs `arg_scanners` on the flattened args string. Any finding at `HIGH` or above denies.

```python
gate = await harness.check_tool_call(name, args, ctx)
if not gate.allowed:
    return f"Denied: {gate.deny_reason}"
effective_args = gate.redacted_args or args
result = await dispatch(name, effective_args)
```

---

## scan_tool_result

Scans tool return values before they re-enter the LLM context. Detects indirect prompt injection embedded in documents, search results, or API responses.

Uses `patterns_for_doc.yaml` — a 9-rule catalog tuned for document content. No configuration needed; the catalog is bundled.

```python
result  = await source.call(tool_name, args)
verdict = await harness.scan_tool_result(result, ctx)
if verdict.blocked:
    return "Tool result blocked — potential injection"
safe_result = verdict.redacted_text or result
```

Disabled by default. Enable in `harness.yaml`:

```yaml
scan_tool_result:
  enabled: true
  block_at: high
```

---

## scan_output

Identical structure to `scan_input`. Inspects the LLM's final response before it reaches the user. Catches accidental PII egress or data leakage in the response.

```python
verdict = await harness.scan_output(llm_response, ctx)
return verdict.redacted_text or llm_response
```

---

## Audit invariants

These hold on every code path, including error and disabled paths:

- Exactly **one** `AuditEvent` per boundary call
- `disabled=True` → `decision=allow`, `finding_count=0`
- `decision=deny` → `deny_reason` is non-null, only on `tool_call_gate`
- `decision=blocked` → only on scan boundaries (`input_scan`, `output_scan`, `tool_result_scan`, `file_scan`)
- `tenant_id` stamped from `HarnessConfig`, never from the caller
- No raw user text, LLM output, tool arguments, or scanner-matched substrings in any field

---

## scan_file

Inspects uploaded files. Structurally identical to `scan_input` — same pipeline, same audit invariants.

`FileScanner` is always included automatically and handles: size gate, MIME type verification, PDF JavaScript, EXIF metadata, ZIP/Office macros, and InjectionScanner on extracted text.

```yaml
scan_file:
  enabled: true
  block_at: high
  max_size_mb: 50
```

```python
verdict = await harness.scan_file("/path/to/upload.pdf", ctx)
if verdict.blocked:
    return "File rejected"
```
