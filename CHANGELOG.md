# Changelog

All notable changes to SHAI are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Semver policy

- **PATCH**: bug fixes, pattern catalog updates, new scanners (additive)
- **MINOR**: new config fields with defaults, new boundaries, new integrations
- **BREAKING**: removing config fields, changing defaults, verdict/event schema changes

## [0.5.0] — 2026-07-29

### Changed
- **BREAKING**: `gated_dispatch` returns one of three things instead of two. It
  now scans the tool result after dispatch, so a result blocked as indirect
  injection comes back as a `ScanVerdict`, alongside the existing `GateDecision`
  on a gate deny and the tool result on allow. A caller testing only
  `isinstance(result, GateDecision)` will hand a blocked `ScanVerdict` to the
  model as though it were tool output — test for both, or pass either to
  `make_tool_result_from_denial()`. On a redacted result the return is the
  redacted string rather than the original object, since the unredacted value
  must not be handed back.
- **BREAKING**: `make_tool_result_from_denial()` accepts
  `GateDecision | ScanVerdict`. For a blocked result the model-facing message is
  fixed text rather than a reason string — findings describe matched content and
  are never echoed back. Its first parameter is renamed `gate` → `denial`, which
  affects keyword callers only.
- **BREAKING**: `ToolRegistry.register()` raises `ConfigError` where it
  previously returned `False`, when a tool of the same name differs in
  `description`, `argument_rules`, or `irreversibility`.
  `SHAI.register_tools()` propagates it. Re-registering a genuinely identical
  tool is still idempotent. Through `load_agent()` the raise is caught and the
  tool is kept as a per-agent override, so the agent resolves against the newer
  definition instead of silently retaining the older one.
- **BREAKING**: `SHAI.scan_injection()` honours a per-scanner `action:` declared
  on the scanner it selects, instead of forcing the boundary action onto it.
  Only configs that set `action:` on a scanner whose name starts with
  `injection_scan` are affected — for them this helper now agrees with
  `scan_input`, which already honoured the same declaration, so an
  `action: alert` that previously blocked here now warns.
- `Tool.tags` is sorted and de-duplicated at construction, so tag order no
  longer round-trips. Every consumer already read tags as a set; normalising
  keeps ordering from affecting tool equality now that equality is field-wise.
- `SHAI.__init__` takes keyword arguments only, and takes only the collaborators
  it cannot derive: the registries, emitter, scanner lists, policy, rate limiter
  and source registry. The per-boundary `enabled`, `block_at` and `action`
  values it used to mirror are read from the `HarnessConfig` it already holds.
  `SHAI.from_yaml()` is unchanged and remains the supported constructor.

### Fixed
- **Tool results were never scanned in the Anthropic SDK integration.**
  `gated_dispatch` gated the call and dispatched it, then returned the result
  untouched — no `scan_tool_result`, so no T6 indirect-injection protection for
  anyone using that helper or a `run_turn` loop built on it. The scan now runs
  between dispatch and return, matching what the LangChain and LangGraph
  integrations already did.
- **Weaker tool security metadata silently overwrote stronger.** `Tool.__eq__`
  compared only `name`, `transport`, and sorted `tags`, so `ToolRegistry`
  treated a re-registration carrying different `argument_rules` or a different
  `irreversibility` as idempotent and discarded the newer definition. Since the
  gate reads both off the `Tool` at L2 and L3, a tool could keep enforcing rules
  that had already been tightened elsewhere. Equality is now Pydantic's
  field-wise comparison, so every field is significant — a hand-maintained field
  list would only have drifted again.
- **`scan_output` ignored its own `block_at`.** The facade handed both text
  boundaries `scan_input.block_at`, so a `harness.yaml` that set
  `scan_output.block_at` got the input threshold instead — an output configured
  to block at `medium` only blocked at `high` when input was left at the
  default. Each boundary now reads its own threshold.
- **`run_turn` passed `llm_fn` the wrong type.** Agent tools were read straight
  from the registry, whose values became `tuple[str, Tool]` in an earlier
  refactor, while the `llm_fn` annotation promised `list[Tool]`. Callers written
  against the documented signature received tuples.

### Removed
- **BREAKING**: `scan_tool_result_on` — gone from `ConnectorManifest`,
  `SourceConfig`, and all eight bundled connector manifests. No integration ever
  passed `tool_name`, so the field was inert on every shipped code path and no
  deployment loses scanning; what it did do was tell operators they were scoping
  T6 scanning when they were not. It also collapsed every source's list into one
  global set, so a narrow list on one source would have suppressed scanning for
  another source's tools. Because `SourceConfig` forbids unknown keys, a stale
  `scan_tool_result_on:` in `harness.yaml` now fails validation at
  `from_yaml()` — delete the key.
- **BREAKING**: the `tool_name` parameter on `SHAI.scan_tool_result()`. The
  removed filter was its only consumer. Calls passing it now raise `TypeError`
  — drop the argument. The `disabled=True` audit event that a filtered tool
  produced is gone with it.

### Security
- Tool results reaching the model through `gated_dispatch` are scanned for
  indirect injection (T6). This closed a live gap, not a theoretical one:
  the Anthropic SDK integration had no result scanning at all, and the shipped
  reference documentation for it omitted the call entirely.
- Every tool result is scanned, with no per-tool opt-out. A tool whose output
  an operator classifies as control-plane data is exactly where an injection
  payload arrives unnoticed.
- `scan_output` enforces the threshold it was configured with. Deployments that
  set the output boundary stricter than the input one were scanning outputs at
  the looser input threshold.
- Tool equality covers the metadata the gate enforces, so argument rules and
  irreversibility classifications can no longer be downgraded by a same-name
  re-registration. The conflict error names which fields differ but never
  includes `description` or `argument_rules` values — a tool description is
  attacker-controlled MCP metadata and must not reach logs verbatim.

## [0.4.1] — 2026-07-28

### Added
- **SVG content reaches the `scan_file` content chain.** `.svg` and `.svgz`
  source now goes through the configured scanners, the same treatment `.xml`
  and `.html` already got. An injection or persona-override payload sitting in
  an SVG `<text>`, `<title>` or `<desc>` was previously invisible to
  `injection_scan` and `jailbreak_scan` — the file produced no content for them
  to read.
- **`file.svg_external_ref`** (MEDIUM) — `<image>`, `<use>` and `<feImage>`
  pointing at an external URL. These fetch when the file is rendered, which
  makes a hostile SVG an SSRF probe and an exfiltration channel. Fragment refs
  and `data:` URIs perform no fetch and are not flagged.
- **`file.svg_entity_decl`** (MEDIUM) — the SVG declares XML entities, so it is
  reported rather than parsed. Entity expansion is the one hostile-XML case a
  parser cannot be handed safely; this is the same call the scanner makes for a
  `.7z` it has no reader for. The ordinary SVG 1.1 doctype every drawing tool
  emits is not affected — an external DTD reference is never retrieved.

### Fixed
- **A script-carrying `.svgz` was indistinguishable from a benign one.** `.svgz`
  is gzip, so the SVG script patterns ran against compressed bytes and could
  never match. The source is now decompressed first, under the same bound the
  archive probe uses. Deployments running the default `block_at: high` are
  unaffected in allow/block terms — `.svg`/`.svgz` already earn a HIGH
  `file.suspicious_extension` on extension alone — but the audit trail now says
  *why*. Deployments that lowered `block_at` or dropped `.svg` from the
  suspicious-extension list will see these files start blocking.
- **SVG script detection no longer depends on byte patterns alone.** A tree pass
  over the parsed document catches what a regex over XML structurally cannot:
  namespace-prefixed elements (`<svg:script>`), CDATA-wrapped handler bodies,
  and numeric character references in a URI (`&#106;avascript:`). The byte
  patterns are retained as the floor — they still fire on a document too
  malformed for an XML parser, which a lenient HTML parser would render anyway.
  Detection is the union of both passes.

### Security
- SVG inspection uses stdlib `xml.etree.ElementTree` — **no new dependency**.
  ElementTree neither retrieves external DTDs nor resolves external entities, so
  there is no XXE surface; entity expansion is closed by refusing to parse any
  source carrying an entity declaration. The tree pass is bounded to 1 MB of
  source, since a parsed tree costs several times the bytes it came from and the
  structural pass has no size gate ahead of it.

## [0.4.0] — 2026-07-27

### Added
- `patterns_db` block in `harness.yaml` (`PatternsDBConfig`: `enabled`, `path`,
  `secret`). When enabled, `SHAI.from_yaml()` loads HMAC-SHA256 verified rules
  from the signed pattern DB and merges them into the `injection_scan`,
  `jailbreak_scan`, and `identity_spoof_scan` catalogs at startup. The row
  `catalog` column is the routing key. Disabled by default.
- **Verifiable audit trail** — a signed audit line can be checked with nothing
  but the log file and the signing key: parse the JSONL line, lift out
  `signature`, re-encode the remainder with sorted keys, compare the
  HMAC-SHA256. Sinks and the signer share one canonical encoding
  (`canonical_json` in `harness.core.events`), so the written line minus its
  signature is byte-identical to the payload that was signed.
- **`on_error` on every scanning boundary** — `fail_closed` (default),
  `fail_open`, or `degrade`, settable per boundary under `scan_input`,
  `scan_output`, `scan_tool_result`, and `scan_file`. The key was documented in
  0.3.0 but never existed in the schema, so a config that set it was rejected
  at startup; see Fixed. Selecting anything other than the default weakens the
  posture deliberately — `fail_open` lets content through when a scanner
  raises. `scan_mcp_metadata` has no `on_error`; it runs at connect time, not
  per turn.
- **Multi-scanner file content scanning** — `scan_file.scanners` is the content
  chain, so a poisoned document can be checked for guardrail attacks and
  identity spoofing, not injection alone. Declaring `jailbreak_scan` takes a
  persona-override payload buried in a document body from allowed to blocked.
  Image EXIF/XMP metadata goes through the same chain, prefixed
  `file.image_metadata.*` in the audit trail.
- **Archive inspection across container formats.** The zip family (`.zip`,
  `.docx`, `.xlsx`, `.pptx`, `.jar`) is judged from central-directory metadata
  without decompressing anything. Single-stream formats (`.gz`, `.bz2`, `.xz`,
  `.svgz`) get a bounded decompression probe on stdlib `gzip`/`bz2`/`lzma` —
  no new dependency — because they declare no trustworthy uncompressed size:
  gzip's is modulo 2³² and attacker-controlled, so measuring real output is the
  only honest test. Tar is covered including compressed tars. An archive nested
  inside an archive is inspected one bounded level deep, which catches a bomb
  whose outer container is stored uncompressed and therefore looks unremarkable
  to any metadata check. `.7z` and `.rar` have no stdlib reader and are
  reported as uninspectable rather than passed silently.

### Changed
- `patterns_db.path` now also backs the heuristic-candidate cache, which
  previously read a hardcoded `state/patterns.db`. Both tables resolve to one
  configured file. Deployments that kept the DB at the default path are
  unaffected.
- **BREAKING**: audit sink output (`file`, `stdout`) is derived from the event
  model instead of a hand-maintained field list. Every `AuditEvent` line gains
  `token_id` and `signature` when set — both were silently dropped before — JSON
  keys are sorted, and timestamps and enums render through Pydantic's JSON mode.
  Log consumers that pin an exact key set or field order must be updated.
- `NetworkAuditEvent` moved from `harness.connectivity.transport` to
  `harness.core.events`, alongside `AuditEvent`, and is now a Pydantic model
  rather than a dataclass. It remains re-exported from `harness.connectivity`,
  so existing imports keep working. Its hand-rolled `model_dump_json()` is gone
  — Pydantic supplies one.
- **BREAKING**: audit event signatures are computed over the same canonical JSON
  the sinks write, instead of a separately built Python-mode dump. The two
  encoders rendered timestamps differently (`2026-07-27 12:00:00+00:00` against
  `2026-07-27T12:00:00Z`), so a written line could never verify against the
  signature it carried. Signature **values** therefore differ from earlier
  builds for the same event; the written line content is unchanged. Stored log
  files are unaffected because no release before 0.4.0 wrote `signature` to
  disk, but a consumer that captured `event.signature` in process — via a custom
  sink or `collect_events()` — and kept it for later comparison must
  re-baseline.
- **BREAKING**: session execution budgets are keyed per conversation
  (`ctx.conversation_id`, falling back to `agent_id`) instead of collapsing onto
  a single per-agent bucket. `max_steps` is now a per-conversation ceiling. For a
  deployment running many conversations through one agent this is a
  **loosening** — the old single bucket capped that agent's traffic in
  aggregate, which was an accident of the broken session key rather than a
  designed limit. Leave `conversation_id` unset to keep the aggregate behaviour.
- Subagent contexts inherit their parent's `conversation_id`, so a delegated
  call shares the parent's budget and threat-accumulator session.
- **BREAKING**: an invalid `limits:` block in `agent-xx.yaml` is now rejected
  while parsing the file, instead of logging a warning and falling back to
  global defaults. The old behaviour discarded the block whole, so one bad key
  silently dropped the agent's *valid* limits too — an agent declaring
  `max_steps` could end up unbounded. `load_agent()` raises `ConfigError`
  before registering anything and `reload_agent()` keeps the previous
  definition, so a rejected config never leaves a partially loaded agent.
  Deployments carrying a malformed `limits:` block will fail to start until it
  is corrected.
- **BREAKING**: `scan_file.scanners` is the file's **content** chain — each
  scanner receives text extracted from the file and, for images, the EXIF/XMP
  blob. Previously `run_file_scan` handed those entries the file *path*, so a
  text scanner declared there could never match anything. Declared scanners are
  authoritative, as at every other boundary; with no `scanners` key a
  document-tuned injection scanner runs so an enabled boundary is never a
  no-op. `heuristic_scan` is still appended automatically as the always-on
  structural backstop. A config that already listed scanners there was getting
  nothing from them and will now get real verdicts — expect new denials on
  files that previously passed.
- **BREAKING**: per-scanner `action` and `redact_with` are rejected under
  `scan_file` with a `ConfigError`. The whole chain runs inside one content
  scanner, so the boundary has a single scanner to index overrides against and
  the keys were silently ignored. Use the boundary-level `action` instead, and
  remove them from any existing `scan_file` block or startup fails.
- **BREAKING**: the `file.zip_bomb` finding category is gone, replaced by
  `file.archive_bomb` — the scope is no longer zip. Policy rules matching the
  old name stop matching. Two categories join it: `file.archive_escape` (HIGH)
  for tar path traversal and symlink members, and `file.unscannable_archive`
  (MEDIUM) for a container with no available reader.
- **Archive uploads that previously passed will now be denied.** `.tar`,
  `.gz`, `.xz`, `.7z` and `.rar` produced no findings at all before this
  release, so any deployment accepting them should expect new denials on first
  upgrade. Scanning a single-stream archive also now costs up to 50 MB of
  bounded decompression where it previously cost nothing; the zip path still
  decompresses nothing.
- `scan_file` audit events list two adapters, `file_scanner` and
  `file_content_scan`, where they previously listed one. The structural pass
  and the content chain are now separate scanners at the boundary. Log
  consumers keying on the `adapters` array should expect both.

### Fixed
- Signed pattern rules applied with `shai patterns apply` are now read at
  runtime. `load_verified_rules()` had no caller and
  `InjectionScanner.extra_rules` was never populated, so applied rules reached
  the database but never a scanner. Rows failing signature verification are
  skipped and logged; a missing DB file or a key mismatch degrades to the
  bundled YAML catalog rather than failing startup.
- Network egress events now reach the audit sinks. `NetworkAuditEvent` was a
  dataclass while `AuditEmitter` and both sinks expect a Pydantic model, so
  every emission raised `AttributeError` and was swallowed by
  `ShaiTransport._emit`'s log-and-continue — no `network_egress` record had ever
  been written. Converting the event to a Pydantic model and deriving the sink
  serializer from the model fixes both halves.
- A failing audit sink is logged rather than masked. The failure handler in
  `AuditEmitter.emit` read `event.boundary` unconditionally, which raised
  `AttributeError` on a `NetworkAuditEvent` and buried the original sink error.
- A signing failure raises `AuditEmissionError` instead of surfacing a Pydantic
  serialization error on a boundary, preserving the rule that only
  `AuditEmissionError` escapes the audit path. An event that cannot be encoded
  is never emitted unsigned — a silent gap in a signed trail is the repudiation
  risk signing exists to close.
- `StdoutSink` and `FileSink` satisfy the `AuditSink` protocol. A stray
  `collect_events` definition had been pasted into the Protocol body, so neither
  reference sink structurally matched the interface it implements.
- Three of the four session budget controls never fired. `check_tool_call` read
  its session key from `getattr(ctx, "session_id", ...)` and its per-prompt key
  from `getattr(ctx, "prompt_id", None)`; `AgentContext` has neither field and
  ignores unknown ones, so both lookups were dead by construction. Every session
  collapsed onto one per-agent bucket and `max_tool_calls_per_prompt` never
  enforced at all. The session key now comes from `ctx.conversation_id or
  ctx.agent_id` — the key the threat accumulator already used — and the fan-out
  key from `TurnSignals.turn_id`, created at `scan_input` and cleared at
  `scan_output`, so a new user turn resets the counter without the caller
  tracking turn boundaries. Fan-out consequently requires `scan_input` to have
  run: a tool-only flow that never calls it gets no fan-out ceiling.
- A budget configured with only `loop_detection_window` never reached the
  enforcer. `ExecutionLimits.any_enabled()` tested the numeric limits and
  ignored loop detection, and callers gate the whole budget check on it.
- `on_error` now exists and takes effect. The key was documented in 0.3.0 but
  was never added to the config schema, so `BoundaryConfig`'s `extra="forbid"`
  rejected any config that set it — and the facade passed no value to any
  boundary, leaving all of them on the hardcoded `fail_closed` default. Every
  boundary now reads its own setting. Deployments that were unknowingly running
  `fail_closed` keep that behaviour, because it is still the default.
- A file content scanner that raised was caught and logged inside
  `FileScanner`, so the boundary saw a successful result and emitted
  `decision=allow` with no `SYSTEM` event — `on_error` never applied to the
  content chain. Exceptions now propagate so the boundary policy decides:
  `fail_closed` blocks, `fail_open` allows, `degrade` warns, each alongside a
  `SYSTEM` event recording the failure.
- A failing content scanner no longer disarms the structural pass. The two now
  run as independent scanners at the boundary, so a file carrying an embedded
  script is still blocked on its structural findings when the content chain
  raises — under `fail_open` and `degrade` such a file previously passed with
  no findings at all. Their circuit breakers are independent too: repeated
  content failures used to open the single file-scanner breaker and silently
  stop MIME, PDF-JavaScript and ZIP checks along with it.

### Removed
- **BREAKING**: `max_tokens_per_session` and `tool_cost_weights`, from
  `check_tool_call.execution_budget` in `harness.yaml` and from agent `limits:`
  blocks. SHAI does not own the agent loop and never observes the LLM call, so a
  token ceiling could only act on a figure self-reported by the process being
  governed — an assertion, not an enforceable control. Cap token spend at the
  model provider. `SessionBudget` is now three controls: step counter,
  per-prompt fan-out, loop detection.

  **Strip both keys from every config file before upgrading — agent files
  included.** A stale key raises `ConfigError` wherever it appears: at
  `SHAI.from_yaml()` for `harness.yaml`, at `load_agent()` for an agent's
  `limits:` block. Startup fails until the keys are gone; nothing is silently
  ignored.
- `SessionBudget.new_prompt()` — superseded. It could not make fan-out work on
  its own, because `check()` counts a call only when `prompt_id` is supplied.
- `FileScanner.__init__`'s singular `text_scanner` parameter — superseded by
  `text_scanners`. It existed to keep one internal call site working, and that
  call site now passes the chain.
- `scan_file_scanner_actions` and `scan_file_redact_withs` from `SHAI.__init__`,
  following the rejection of per-scanner overrides at that boundary. They could
  only ever carry `None`. `SHAI.from_yaml()` is the documented construction path
  and is unaffected.

### Security
- Detection rules distributed through the signed pattern DB now take effect at
  runtime. Operators who applied a bundle on 0.3.0 were running the bundled
  YAML catalog only — set `patterns_db.enabled` and restart to activate them.
- DB-sourced rules are additive: they extend a scanner's catalog and cannot
  disable, reorder, or suppress bundled rules. Trust in them is anchored solely
  in the HMAC-SHA256 signing key, verified per row with `hmac.compare_digest`.
- **BREAKING**: pattern row signatures are now HMAC-SHA256 over the canonical
  JSON encoding of `{rule_id, catalog, payload}` (`sort_keys=True`), matching
  how the audit emitter signs. The previous body concatenated the three fields
  with no delimiter, so `("x", "injection")` and `("xin", "jection")` signed
  identically. Because `catalog` now routes a rule to a scanner, that ambiguity
  let an actor with DB write access but no signing key re-split a signed row to
  move a rule onto a different scanner. **Bundles signed before 0.4.0 must be
  re-signed, and existing DB rows re-applied** — they will fail verification and
  be skipped until then. Check with
  `shai patterns verify --db state/patterns.db --secret PATTERNS_SIGNING_KEY`.
- The `token_id` join between a tool-call gate `AuditEvent` and the
  `NetworkAuditEvent` for the outbound request it authorised now works. Both
  sides were broken: network events never reached a sink at all, and `token_id`
  was absent from every written line. Correlating a gate decision with the
  egress it permitted is possible for the first time.
- `signature` is persisted to the audit trail, and the trail is verifiable from
  the file. The HMAC-SHA256 stamped when `audit_signing.enabled` was computed
  correctly but dropped by the sink serializer, so no signed trail was ever
  written to disk. Signing and writing now share one canonical encoding, so an
  operator holding only the JSONL file and the key can confirm every line —
  editing a recorded decision, or checking with the wrong key, fails
  verification.
- The T4 resource-overload controls enforce for the first time. `max_steps`,
  `max_tool_calls_per_prompt`, and loop detection were all reachable only by
  accident or not at all — a deployment carrying these limits in config was
  running without them. Expect new denials on first upgrade wherever they are
  configured.
- Step-limit bypass through delegation closed. `scope_subagent()` did not carry
  `conversation_id`, so a subagent keyed on a different budget bucket than its
  parent and received a fresh `max_steps` allowance — an agent that exhausted
  its budget could simply delegate to keep working. The same gap split
  threat-accumulator evidence across two session keys, so escalation stopped
  accumulating across a delegation.
- Uploaded documents are checked for more than injection. The file boundary's
  content chain accepted only one scanner in practice, so guardrail attacks and
  identity spoofing hidden in a document body or in image EXIF/XMP passed
  unexamined. Declaring the scanners under `scan_file.scanners` now runs them.
- `on_error` is enforceable at the file boundary for the first time. A content
  scanner that failed was silently skipped and the file allowed; under the
  default `fail_closed` such a file is now blocked, and under any policy the
  structural findings survive the failure.
- Structural file checks are no longer collateral damage when content scanning
  breaks. MIME, PDF `/JavaScript`, SVG script, archive-bomb and Office-macro
  detection now run in their own scanner with their own circuit breaker, so
  neither a raising content scanner nor a tripped content breaker can stop
  them.
- Compression bombs are detected outside zip. `.gz`, `.bz2`, `.xz`, `.tar`,
  `.7z` and `.rar` previously produced **no findings of any kind** — they were
  not merely missing bomb detection, they were invisible to the boundary. Tar
  archives are additionally checked for path traversal and symlink escapes,
  which is a distinct attack class: escaping the extraction root rather than
  exhausting resources.

  Two limitations worth knowing before enabling `scan_file` on untrusted
  uploads at volume. The bomb test requires a ratio above 100 **and** output
  above 50 MB, so a file with a merely healthy ratio passes and is then fully
  decompressed — a 3 MB `.tar.gz` expanding to 203 MB (63:1) is judged clean
  and all 203 MB is decompressed during member enumeration, which scales to
  roughly 5 GB at a 50 MB upload allowance. Requiring both conditions is
  deliberate, since legitimate archives do compress that well, but it means
  absolute expansion is unbounded below the ratio threshold. And the probe is
  blocking work inside an async scanner: one 29 KB `.xz` file stalled the event
  loop for 0.21 s, which every concurrent agent turn in the process shares.

## [0.3.0] — 2026-07-23

The 0.2 line was never released. This is the first tagged release since
`0.1.0` and consolidates the entire scanner-hardening, error-handling, and
audit-integrity workstream.

### Added
- `on_error` field on `BoundaryConfig` and `FileScanConfig` (`fail_closed` | `fail_open` | `degrade`)
- `CircuitBreaker` per scanner adapter — exponential backoff, cap 5 min
- `BoundaryName.SYSTEM` and `Decision.DEGRADED` for structured error events emitted to the audit trail
- `HeuristicScanner` — always on, entropy + instruction density + bigram coherence + structural markers + typoglycemia sub-score
- Ensemble severity promotion — cross-scanner findings promoted to HIGH when combined weight crosses threshold
- Signed pattern database (`patterns_db`) for incremental pattern distribution
- `shai patterns apply|list|verify` CLI commands
- `PatternsDBConfig` in `harness.yaml`
- `THREAT_MODEL.md` — explicit mapping from OWASP Agentic-AI threats to SHAI controls and tests, including known gaps
- Circuit breaker and promoted-candidate state moved onto the `SHAI` instance
  (removes module-level mutable state — safe for multiple instances per process)

### Changed
- **BREAKING**: default `on_error` is now `fail_closed` (was implicit fail-open).
  Existing configs that relied on the old behavior must add `on_error: fail_open` explicitly.
- `InjectionScanner` accepts `extra_rules` parameter for DB-sourced patterns
- README rewritten: honest positioning, prior-art section, threat-model link
- `docs/index.md` is a public documentation index (was a Claude Skills manifest)
- `docs/` and `.claude/skills/` consolidated: both folders have the same
  unnumbered topic set. `docs/` is tuned for humans, `.claude/skills/` for
  AI coding assistants.

### Fixed
- `from_yaml()` referenced `instance` before construction — crashed on any
  config with MCP sources.
- Removed duplicate `src/harness/connectivity/harness/` and
  `src/harness/connectivity/harness_cli/` trees left over from an earlier layout.
- Cleaned up historical `UMA` references in the injection-pattern catalogs.

## [0.1.0] — 2026-07-01

### Added
- Initial release: SHAI facade, five boundaries, six framework integrations
- Scanner adapters: regex_pii, injection_scan, jailbreak_scan, identity_spoof_scan
- Audit pipeline with HMAC-SHA256 signing
- MCP source support with ShaiTransport egress enforcement
- Session threat accumulator (SQLite-backed)
- CLI: `shai validate`, `shai audit tail`, `shai agents list`
