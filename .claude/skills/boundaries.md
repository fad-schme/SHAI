# Boundaries Reference

SHAI enforces security at five boundaries. Every call emits exactly one
`AuditEvent`. Boundaries never raise — they always return a verdict.

---

## Input Scan (`scan_input`)

```python
verdict = await harness.scan_input(user_text, ctx)

if verdict.blocked:
    return "Input rejected"

# Use redacted_text if the scanner redacted anything
safe_text = verdict.redacted_text or user_text
```

**Runs:** the `scan_input.scanners` chain (typically `injection_scan`,
`jailbreak_scan`, `identity_spoof_scan`, `regex_pii`) plus the always-on
`heuristic_scan`. Scanner failures follow `on_error` (default `fail_closed`).
**Catches:** PII (T11), direct prompt injection (T5).
**Audit:** `boundary="input_scan"`, `decision` = allow/warn/blocked.

---

## Named scanner methods

There is no facade method that runs one named scanner. Which scanners run at a
surface is a `harness.yaml` decision: give the boundary a chain of exactly the
scanners it should run — `regex_pii` alone for a surface that needs only PII
detection. Scanners are selected by name in config, never imported and never
called directly.

```python
# Inspect active scanners
print(harness.maintenance.scanners)
# {
#   'regex_pii':          RegexPIIScanner,
#   'injection_scan':     InjectionScanner,
#   'injection_scan_doc': InjectionScanner(patterns_for_doc),
#   'file_scanner':       FileScanner,
#   'rate_limiter':       RateLimiter,
# }
```

## Tool Governance (`check_tool_call`)

```python
gate = await harness.check_tool_call(tool_name, tool_args, ctx)

if not gate.allowed:
    # Provide denial feedback to the LLM
    return f"Tool call denied: {gate.deny_reason}"

# gate.redacted_args is set when L7 arg scanning redacted something
args = gate.redacted_args or tool_args
result = await my_dispatch(tool_name, args)
```

**Seven layers — first deny anywhere wins:**

| Layer | Check | Bypassable? |
|---|---|---|
| Pre-gate | Revocation + rate limit + session execution budget + agent registered? + MCP manifest approval | No |
| L1 | `tool_name` in `allowed_tool_names`? | No |
| L2 | Argument rules (deterministic parameter constraints) | No |
| L3 | Irreversibility gate (SENSITIVE/IRREVERSIBLE require a quorum of signed `ApprovalGrant`s) | No |
| L4 | `tool.tags ⊆ allowed_tags`? (the agent's own, narrowed by subagent) | No |
| L5 | Policy rules (manifest denials → subagent → parent) | By design |
| L6 | Signal correlation — reads `TurnSignals` from earlier boundaries | No |
| L7 | Arg scanning — tools tagged in `scan_args_for_tags` (default `sensitive`) OR when L6 tightened | Config |

**L1 is absolute.** Nothing can grant access to a tool not in `allowed_tool_names`.

**L6 signal correlation** L6 is a no-op when `TurnSignals` is absent (e.g. a boundary called outside a
full turn cycle, or when the operator called `check_tool_call` directly with
`turn_signals=None`).

**Rate limiter** fires in the pre-gate. Sliding-window token bucket per agent.
Two counters: global call budget + per-tool budget. Both must pass.

**Dispatch token** is issued on every allowed decision — signed, single-use,
bound to the tool, agent, and source:
```python
gate.dispatch_token  # str | None — pass to source.call()
```
`ShaiTransport` checks it on every MCP request; a local tool checks it with
`verify_tool_dispatch` (`tool_dispatch_check` event).

---

## Tool Stream Control (`scan_tool_result`)

```python
tverdict = await harness.scan_tool_result(result, ctx)

if tverdict.blocked:
    result = "Tool result blocked by security policy"
else:
    result = tverdict.redacted_text or result
```

**Runs:** whichever scanners `scan_tool_result.scanners` names — the shipped
example uses `injection_scan` (`injection_common.yaml` + `injection_patterns.yaml`),
`identity_spoof_scan`, and `jailbreak_scan`, plus the always-on heuristic
backstop. `patterns_for_doc.yaml` is **not** loaded here; it reaches only
`scan_file`, via `_build_text_scanners(include_document_patterns=True)`.
**Catches:** indirect prompt injection embedded in tool results (T6), including
guardrail-integrity payloads — a retrieved document instructing the model to
discard its instructions is an indirect injection, not a user jailbreak.

**Signal-driven tightening.** When `TurnSignals` shows that the input scan
flagged injection and the gate allowed a specific tool this turn,
`scan_tool_result` steps `block_at` down one level for this call only
(HIGH → MEDIUM, MEDIUM → LOW, floored at LOW). Rationale: the attack chain
is in motion — treat lower-severity result findings as blocking evidence
they are not yet the top of the funnel. Transparent to the caller; the
audit event records the effective severity used.

Every result is scanned, with no per-tool exemption — a tool whose output
looks like control-plane data is exactly where an injection payload arrives
unnoticed.
---

## Egress Scan (`scan_output`)

```python
out_verdict = await harness.scan_output(llm_response, ctx)

if out_verdict.blocked:
    return "[Response blocked by security policy]"

return out_verdict.redacted_text or llm_response
```

**Runs:** configured scanners (typically `regex_pii`, optionally an output
prompt-leakage catalog loaded via `patterns_db`) on the LLM response.
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

## Ingress Scan — File (`scan_file`)

```python
verdict = await harness.scan_file("/tmp/upload.pdf", ctx)

if verdict.blocked:
    return "File rejected"
```

**Two independent scanners**, so a failure in one cannot discard the other's
findings and each is governed by `on_error` on its own. Audit events for this
boundary list both adapters, `file_scanner` and `file_content_scan`.

1. **Structural** (`FileScanner`) — MIME type, extension, size gate,
   double-extension disguise (`invoice.pdf.exe`), PDF marker set
   (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`,
   `/RichMedia`), SVG inspection, archive inspection, EXIF + XMP metadata
   extraction, Office macros.

   *SVG* — `.svgz` is decompressed first, so a gzipped payload is not invisible
   to the check. Byte patterns catch scripts, inline handlers and `javascript:`
   URIs; a tree pass over the parsed document then catches what a regex over XML
   structurally cannot — namespace-prefixed `<svg:script>`, CDATA-wrapped
   bodies, numeric character references. `<image>`/`<use>`/`<feImage>` pointing
   off-host is `file.svg_external_ref` — these fetch on render, making a hostile
   SVG an SSRF probe. A document declaring XML entities is reported
   (`file.svg_entity_decl`) rather than parsed. Stdlib `ElementTree`, no
   `defusedxml`: it retrieves no external DTDs and resolves no external
   entities, and refusing entity declarations closes expansion.

   *Archives* — the zip family judged from central-directory metadata without
   decompressing anything; `.gz`/`.bz2`/`.xz`/`.svgz` via a bounded
   decompression probe, since they declare no trustworthy uncompressed size;
   tar including compressed tars, plus path-traversal and symlink escapes; one
   bounded level of nesting, which catches a bomb whose outer container is
   stored uncompressed; `.7z`/`.rar` reported as uninspectable rather than
   passed silently.

2. **Content** (`FileContentScanner`) — extracted text AND image metadata routed through the
   `scan_file.scanners` chain, configured just like `scan_input.scanners` and
   subject to the same `on_error` policy. Declaring `jailbreak_scan` and
   `identity_spoof_scan` there checks a poisoned document for guardrail
   attacks and authority claims, not injection alone; with no `scanners` key a
   document-tuned injection scanner runs. Image-metadata hits are prefixed
   `file.image_metadata.*` in the audit trail so operators can distinguish
   document-body findings from EXIF/XMP findings without losing the
   underlying category.

   Text is extracted from `.pdf`, `.docx`, the plain-text family (`.txt`,
   `.md`, `.csv`, `.json`, `.xml`, `.html`, `.yaml`, `.yml`) and `.svg`/`.svgz`.
   Any other type reaches the chain with document text empty — the structural
   scanner is the whole control for it.

---

## Scanner catalog

| Class |  Catalog | Used in |
|---|---|---|---|
| `RegexPIIScanner` |  Built-in PII + secrets (Luhn-validated cards, structure-validated SSNs, `secret.private_key`, `secret.jwt`, `secret.aws_secret`, `secret.conn_string`, `secret.slack_webhook`) | `scan_input`, `scan_output`, arg scanning |
| `InjectionScanner` | `injection_common.yaml` + `injection_patterns.yaml` — direct injection, tool coercion, encoded payloads, delimiter smuggling (incl. KaTeX/LaTeX invisible text) | `scan_input`, `scan_tool_result` |
| `InjectionScanner` (doc) |  `patterns_for_doc.yaml` — tuned for document content, unioned with the common + input catalogs | `scan_file` only (`FileContentScanner` chain) |
| `JailbreakScanner` |  `jailbreak_patterns.yaml` — persona override, instruction control, safety deactivation, refusal suppression, mode activation, prompt extraction, hypothetical laundering | Any text boundary; recommended at `scan_input`, `scan_output` **and** `scan_tool_result` |
| `IdentitySpoofScanner` |  `identity_spoof_patterns.yaml` — claimed orchestrator/system authority, peer-privilege claims, tool-result authority | High value at `scan_tool_result` |
| `HeuristicScanner` |  Not YAML-driven. 5 sub-scores: entropy, instruction density, coherence, structural markers, **typoglycemia** (Damerau-Levenshtein-1 against an intent-space keyword list, with anagram-scramble fast path and prefix-relationship rejection so morphology like `ignored`, `filters`, `systems` is not scored) | Always on |
| `FileScanner`  | Not YAML-driven. Structural only — MIME, extension, size, filename, PDF markers, SVG, archives, EXIF, Office macros | `scan_file` |
| `FileContentScanner` |  Not YAML-driven. Runs the configured `scan_file.scanners` chain over extracted text and the image EXIF/XMP blob | `scan_file` |
| `CommandInjectionScanner` |  Not YAML-driven and **no l10n sibling** — shell syntax is language-independent. `bashlex` AST shapes: pipeline into an interpreter, `/dev/tcp` redirect, fetch-then-exec chain, inline interpreter code with an opaque payload | Any boundary, including `check_tool_call`. Requires the `shell` extra |
| `MCPMetadataScanner` |  `mcp_metadata_patterns.yaml` — tool names, descriptions, argument schemas | MCP `tools/list` registration, `shai mcp onboard` |
| `PromptDefenseScanner` |  `prompt_defense_patterns.yaml` — flags manifest tool text that lacks defensive language | `shai mcp onboard` only |
| `RateLimiter` |  — (config-driven) | `check_tool_call` pre-gate |

**Cross-turn.** `ThreatAccumulator` scores escalation spread across a
session's turns (crescendo attacks). Disabled by default.
