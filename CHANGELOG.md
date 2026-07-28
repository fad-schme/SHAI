# Changelog

All notable changes to SHAI are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Semver policy

- **PATCH**: bug fixes, pattern catalog updates, new scanners (additive)
- **MINOR**: new config fields with defaults, new boundaries, new integrations
- **BREAKING**: removing config fields, changing defaults, verdict/event schema changes

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
