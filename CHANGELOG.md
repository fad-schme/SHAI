# Changelog

All notable changes to SHAI are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Semver policy

- **PATCH**: bug fixes, pattern catalog updates, new scanners (additive)
- **MINOR**: new config fields with defaults, new boundaries, new integrations
- **BREAKING**: removing config fields, changing defaults, verdict/event schema changes

## [Unreleased]

### Security
- **BREAKING — `AgentContext.human_approved` is removed, replaced by
  `AgentContext.approvals`.** The old field was a plain bool on a
  caller-constructible context: any caller set it by assignment, one `True`
  covered every tool and every argument for a whole turn, and the allow path
  recorded no approver, no scope, and no expiry. Layer 3 gated on nothing.

  `approvals` carries encoded `ApprovalGrant`s (new module
  `harness.core.approval`), each HMAC-SHA256 signed and bound to one
  `(agent_id, tenant_id, tool_name, args_digest, approver_id, expiry)`. The gate
  verifies signature **and** binding offline — a grant for one tool cannot be
  replayed against another, and approving a $5 refund does not authorise a
  $50,000 one. SHAI never calls an authorization server; where the grant came
  from (CIBA, Auth0, WorkOS, a Slack button) is the integrator's choice.

  New `check_tool_call.approvals` config block with `secret`,
  `sensitive_quorum` (default 1) and `irreversible_quorum` (default 2). Quorum
  counts **distinct** `approver_id`s, so N-of-M approval is N grants from N
  people. **With no `secret` configured, every `SENSITIVE` and `IRREVERSIBLE`
  tool is denied** — there is deliberately no fallback to a weaker check.

  Approvers are recorded on the gate's allow event as `extra.approvers`, so the
  audit trail can answer who authorised an irreversible action.
  `scope_context_for_subagent()` does not copy `approvals` onto the child
  context, so a delegated call is approved on its own terms by default. A grant
  binds a tool name and an `args_digest`, never a caller role — what a subagent
  may invoke at all is decided earlier, by its `allowed_tool_names` and
  `allowed_tags`.

  *Migration:* set `check_tool_call.approvals.secret`, then issue grants with
  `sign_grant()` / `encode_grant()` and pass them on `ctx.approvals`. Callers
  that never used `human_approved` and register no `SENSITIVE`/`IRREVERSIBLE`
  tools are unaffected.

### Added
- **`shai audit verify --file PATH --secret ENV_VAR`** — verifies the
  HMAC-SHA256 signature on every record in a trail written with
  `audit_signing.enabled`. This closes the read side of signed auditing: the
  feature could sign a trail but shipped no supported way to check one, and
  `AuditSigningConfig` documented a `harness audit verify` command that had
  never existed — wrong binary name and a subcommand that was not implemented.
  Operators following it were left hand-rolling HMAC verification.

  Records are classified as verified, mismatched, unsigned, or malformed, and
  failing line numbers are reported. **Exit 0 only when every record verified**
  — unsigned and malformed records fail the run alongside mismatched ones,
  because a trail with a hole in it does not answer the question signing was
  enabled to answer. An empty file fails for the same reason. `--secret` names
  an environment variable rather than taking the key, matching `shai patterns`,
  so the key stays out of shell history and the process list.

  Verification canonicalises before hashing, so a record a log shipper
  reserialized with different key order still verifies. The primitive lives
  next to the signer (`harness.audit.emitter.verify_line`) so the two
  encodings cannot drift apart.

- **`AgentContext.for_conversation(id)`** — derives a context scoped to one
  conversation, preserving `agent_id`, `sub_agent_id`, `allowed_tags` and
  `approvals`. `load_agent()` returns the template to derive from; there was
  previously no supported way to set `conversation_id`, so callers either
  constructed `AgentContext` field-by-field — which the docs told them not to
  do — or left every conversation sharing one execution budget and one
  cross-turn threat score.

  This is also the fix for a **per-turn signal isolation** defect. A context
  carries the turn's `TurnSignals`: `scan_input` attaches it, `scan_output`
  clears it. Two turns running concurrently through the *same* context shared
  one bus — the second `scan_input` replaced the first turn's evidence, and
  whichever `scan_output` ran first cleared it for both. The first turn then
  reached its own `scan_output` with nothing recorded: its injection signal was
  gone, so gate layer 6 correlated against nothing and the consolidated
  turn-risk block could not fire. The documentation pointed both ways at once,
  telling callers not to share a context between turns and, three lines later,
  to hold the one from `load_agent()` for the agent's lifetime.

  Two turns presenting the same context are indistinguishable, so the harness
  cannot resolve this alone — `for_conversation()` is how a caller keeps them
  apart. `scan_input` now logs a warning when it finds a bus already attached,
  which is either a shared context or a turn that never reached `scan_output`.
  Sequential reuse of one context is unchanged and silent.

- **Agent kill switch** — `SHAI.revoke_agent()` / `restore_agent()` /
  `revoked_agents()`, plus `shai agents revoke|restore|revocations`. A revoked
  agent is denied at the gate's pre-gate, before the rate limiter, while every
  other agent in the process keeps running; the denial emits one `AuditEvent`
  like any other. New top-level `revocation` config block with `path` and
  `cache_ttl_seconds` (default 5, 0 = read every call). Empty `path` (the
  default) disables the feature, and calling `revoke_agent()` without it raises
  `ConfigError` rather than quietly doing nothing.

  Both surfaces write the same JSON file, because `shai` runs in its own
  process and cannot reach a running harness's memory — **`cache_ttl_seconds`
  is therefore the kill latency**, while the in-process API applies immediately.
  Revocations persist across restarts, and a read error keeps the last known
  set rather than resurrecting a revoked agent or denying every agent at once.
  Revocation stops actions, not conversation: the agent stays registered and the
  scan boundaries still run — `deregister_agent()` remains the full removal.

- **`command_injection_scan`** — new built-in scanner detecting shell command
  *composition* via `bashlex` AST shapes: a pipeline whose sink is an
  interpreter, a `/dev/tcp` redirect, fetch-then-execute chains, and inline
  interpreter code carrying an opaque payload. Declarable at every boundary
  (`scan_input`, `scan_output`, `scan_tool_result`, `scan_file`,
  `check_tool_call`) — a command can arrive in user input, a tool result, or a
  file body, and each boundary's own `block_at` decides what a severity means
  there. Findings are demoted one level when a statement reads as prose rather
  than an invocation, so text discussing a command reports MEDIUM while a line
  issuing it reports HIGH; padding a payload with prose lowers severity but
  never erases the finding. Carries `method_family: structural_command`, so it
  corroborates with `heuristic_scan` rather than collapsing into it.
  Commands wrapped in a tool call — `run_shell('curl … | sh')`,
  `{"command": "wget …"}` — are lifted out and parsed on their own, since that
  is the shape an agent emits; parsing only the enclosing line sees a quoted
  word and misses the pipeline inside it.

  Requires the new **`shell` extra** (`pip install 'shai-harness[shell]'`); declaring
  the scanner without it raises `ConfigError` at `SHAI.from_yaml()` rather than
  degrading silently.
- **`policy.forbidden_tag_combinations`** — tag sets no single agent may declare
  together, enforced when the agent is loaded rather than when it calls a tool.
  An agent whose `allowed_tags` is a superset of any configured entry raises
  `ConfigError` from `AgentRegistry.load()`, `register()`, and `reload()`, and is
  never registered. Each entry requires at least two distinct tags. Subagents are
  not checked separately — their tags are always a subset of their parent's.
  `shai validate` and `shai harness inspect` apply the same check. Defaults to
  empty, so existing configs are unaffected.
- **`SHAI.tools_for(ctx)`** — the `Tool` descriptors a context can reach, for
  building a tool list for an LLM call without re-parsing the agent YAML. It
  applies the gate's two *static* capability layers against the same effective
  profile `check_tool_call` resolves — L1 `allowed_tool_names` and L4
  `allowed_tags` — so **a subagent context returns the subagent's narrowed set,
  not the parent's**, and a tool the agent names but whose tags it does not hold
  is absent. Empty for an agent that is not loaded, and for a subagent the parent
  does not declare; the gate allows nothing in either case.

  Deliberately a superset of what will actually be allowed: argument rules,
  approvals, policy, signal correlation and arg scanning all depend on the call
  rather than the agent, and cannot be answered without one. Use it to build a
  tool list, never as a substitute for calling `check_tool_call`. Source
  ownership is not exposed — read `gate.source_name` off an allowed decision.
  Integrations no longer reach into `harness._agent_tools` for this, which
  `harness.integrations.anthropic_sdk.run_turn` previously did.

### Added
- **`SHAI` is an async context manager.** `async with await
  SHAI.from_yaml(path) as harness:` closes the harness on exit. `close()` stays
  public and unchanged for applications that manage lifetime themselves — it
  releases the MCP sources' httpx clients, the audit sinks' file handles and the
  threat accumulator's SQLite connection, and nothing inside SHAI knows when the
  last turn has run.

### Changed
- **BREAKING**: the operational surface moves off the `SHAI` facade to
  `harness.maintenance`. Seven members relocate — `reload_agent`,
  `deregister_agent`, `list_agents`, `revoke_agent`, `restore_agent`,
  `revoked_agents`, and the `scanners` property:

      harness.revoke_agent("billing_agent")     # before
      harness.maintenance.revoke_agent("billing_agent")   # after

  The facade now carries only the per-turn contract — the five enforcement
  boundaries plus what a turn needs to reach them — and drops from 22 public
  members to 16. Nothing else changed: the five boundaries stay public, because
  SHAI does not own the agent loop and an application with its own loop calls
  them directly.

  `scanners` moves for a second reason. Scanners are enabled by name in
  `harness.yaml` and resolved through the `harness.scanners` entry-point group;
  handing live scanner instances back out of the facade contradicted that, and
  inspection is what the maintenance surface is for.

  On the new surface, `async` follows the same rule as the registries — only
  `reload_agent` awaits, so `deregister_agent()` and `registered_agents()` are
  now synchronous. `harness.maintenance` needs no construction and no await.

  `list_agents()` is renamed **`registered_agents()`**, pairing with
  `revoked_agents()` on the same object. The old name read as the in-process
  twin of `shai agents list` and is not: the CLI scans a directory of agent YAML
  files offline and registers nothing, while this reflects live harness state.
  The CLI's own `--help` claimed it listed "registered agents" and now says what
  it does.

### Removed
- **BREAKING**: `SHAI.scan_pii()` and `SHAI.scan_injection()`, and with them
  `BoundaryName.NARROW_SCAN` and its `shai audit tail --boundary` choice.
  They were the only two entry points on the facade named after a *scanner*
  rather than a *boundary*. A scanner is enabled by name in `harness.yaml` and
  runs at the boundary that declares it; a method that reaches past the
  configured chain to run one scanner is a second way to answer a question
  config already answers.

  *Migration:* declare the scanner you want on the boundary that should run it.
  For a surface that needs only PII detection, give that boundary a chain of
  `regex_pii` alone — the verdict shape is unchanged. Audit consumers filtering
  on `boundary == "narrow_scan"` can drop the filter: no event carries it now.

- **BREAKING**: `harness.integrations.openai_agents.make_before_tool_hook()`.
  It gated a call and handed control back to the SDK, which dispatches the tool
  itself — so the hook never saw the result and `scan_tool_result` could not
  run. Tool output reached the model unscanned, with no T6 indirect-injection
  boundary, from a public entry point that otherwise looked equivalent to
  `wrap_tools()`. It was the only place in six integrations that ran part of
  the contract instead of all of it.

  *Migration:* `gated = await wrap_tools(tools, harness=harness, ctx=ctx)`,
  then pass `gated` to `Agent(...)`. This registers the tools and runs
  `check_tool_call` → dispatch → `scan_tool_result`, the same sequence every
  other integration runs.

### Changed
- **BREAKING**: `ToolRegistry`, `AgentRegistry` and `SourceRegistry` are
  `async` only where they await. `register`, `deregister`, `register_many`,
  `get` and `list` are now synchronous on all three — they are dict operations
  behind a `threading.Lock`, and marking them `async` made `ToolRegistry.list()`
  and `as_dict()` two spellings of one read. `AgentRegistry.load`/`reload`
  (YAML parsed off the event loop) and `SourceRegistry.activate`/`close`
  (concurrent source loading) stay async.

  These classes are internal — not exported from `harness` — so this reaches
  only code holding a registry directly. **The `SHAI` facade is unchanged**:
  `await harness.get_source(...)`, `await harness.register_tools(...)` and
  `await harness.list_agents()` keep their signatures. The facade is the
  published surface and stays uniformly async; the rule applies behind it.

- **The audit emitter stamps a copy instead of rewriting the event it was
  given.** Truncating an oversized `deny_reason` and applying the HMAC used
  `object.__setattr__` to write through `AuditEvent`'s frozen model, so a
  boundary that had already handed its event over found it altered afterwards.
  Sinks, `collect_events()`, the written bytes and the signature are all
  unchanged — the emitter produces the same record as before. What changes is
  that the caller's own object is left alone.
- **Startup attestation** now records `policy.forbidden_tag_combinations`. The
  control is enforced at agent load rather than by a policy rule, so the
  existing `policy.digest` would not have moved if an operator dropped it.

### Fixed
- **A policy `redact` rule no longer drops the arguments it does not name.**
  `RuleBasedPolicy` returned the rule's `redact:` dict as the complete
  `redacted_args`, and the gate assigned it to the effective arguments whole, so
  every argument the rule did not name was silently discarded before dispatch. A
  rule written as `redact: {amount: "***"}` turned a call carrying
  `{account, amount, currency}` into `{amount: "***"}`.

  The masking case was the mild one. The arguments a redact rule does not name
  are frequently the ones that *constrain* the call — a scope filter, a tenant
  id, a row limit — so a rule written to narrow a dispatch widened it instead.

  `redacted_args` is now `{**args, **rule.redact}`, which is what
  `docs/configuration.md` already documented ("named args are replaced") and
  what the gate's own layer-7 scanner redaction has always done. Behaviour
  changes for any deployment with a `redact` rule: unnamed arguments now reach
  the tool. A rule that relied on the old behaviour to strip arguments was
  relying on a bug — express it as a `deny` rule or a narrower tool contract.

- **THREAT_MODEL.md no longer claims audit events are signed with a rotating
  secret.** They are signed with a single operator-supplied key. Nothing in SHAI
  implements rotation: `audit_signing.secret` is one key, `AuditEvent` carries
  no key identifier, and `shai audit verify` takes one secret. An operator who
  rotated on the strength of that sentence would find every pre-rotation record
  reported as *mismatched* — indistinguishable from tampering — and
  `shai audit verify` exiting non-zero on that file permanently.

  No behaviour changed; the claim was wrong, and it was wrong in the document
  SHAI offers as its honest coverage claim. T10's residual risks now record the
  rotation limitation and the workaround (rotate at a file boundary, keep each
  retired key with the segment it covers), plus a second gap that was also
  unstated: audit rotation discards evidence beyond `max_bytes` ×
  `backup_count`, and signing says nothing about records that no longer exist.

- **Large text no longer stalls a boundary.** `HeuristicScanner` is the
  always-on backstop on every text boundary, and its internal URL regex left
  the URL scheme repeat unbounded. On text where `://` never arrives — ordinary
  prose, the common case — the engine re-scanned the remainder of the input
  from every start position, making the scan quadratic: roughly 0.5 s at 40 KB,
  30 s at 80 KB, and about 19 minutes for a 500 KB input, with the boundary
  blocked for the duration. Any caller could reach it by passing a large
  document to `scan_input` or `scan_output`, and a tool returning a large
  result reached it through `scan_tool_result` with no user action at all.

  The scheme repeat is now bounded at 63 characters, which makes the scan
  linear — 500 KB completes in 0.48 s. Detection is unchanged: the longest
  registered URI scheme is 36 characters, and a longer one is simply not
  treated as a URL, which preserves its separators and can only raise this
  scanner's suspicion, never lower it.

- **Per-character fragmentation is now detected.** A payload written
  `i g n o r e your previous instructions` passed every boundary. Two separate
  causes, both in the normalization layer that produces the views scanners
  match against.

  The repair fired on whole-text ratios — the proportion of short tokens and
  the density of separators — so padding a fragmented trigger phrase with
  ordinary prose drove both below threshold and switched the repair off
  entirely. Fragmenting three words inside a paragraph was enough. A run of
  four or more single-character tokens now fires it regardless of what
  surrounds them.

  And where the repair did fire, the view it produced for this shape had every
  separator stripped — `ignoreyourpreviousinstructions` — which no pattern
  anchored on a word boundary can match, and most patterns are. Runs of single
  characters are now joined in place, leaving surrounding words separate, so
  the recovered text reads `ignore your previous instructions`.

  Affects `scan_input`, `scan_output`, `scan_tool_result`, and argument scanning
  at the gate — anywhere normalization runs. No config or API change; text
  already detected stays detected.

- **Payloads glued to the text carrying them are now detected.** An indirect
  payload is concatenated onto the document that delivers it, and where no
  separator lands between them the trigger word loses its left word boundary:
  `…New York, NY 10001 USAIgnore your previous instructions` passed, while the
  same text one space later blocked. Most catalog patterns lead with a
  `\b`-anchored token and there is no `\b` between two word characters.

  Normalization now adds a view splitting at lower/digit → upper, acronym →
  capitalised word, and digit → letter. Glue between two lowercase words
  (`regardsignore`) is **not** covered — separating that needs a dictionary, not
  a character rule. camelCase identifiers in tool output are split in the added
  view, which is the accepted cost: the view is scan-only and additive.

- **`scan_file` no longer blocks files whose path normalization altered.** The
  boundary passed the file *path* through the normalization layer, and every
  scanner runs against every view — so a de-obfuscated view was a *different
  path*, and the structural scanner reported `file.not_found` at HIGH for each
  one. Any path containing a base64-looking segment, a `-/-` run, or (after the
  glue split above) an ordinary `C:/Users/…/AppData/…` could block a legitimate
  upload. Paths are no longer normalized; file content is unaffected, since it
  was never normalized here in the first place — it is scanned where it is
  extracted. One consequence worth knowing: the suspicious-filename check now
  sees the raw filename, so a homoglyph filename no longer folds before that
  check.

- **`reload_agent()` no longer promotes optional sources to required.**
  `load_agent()` passes each source's `required` flag from `harness.yaml` into
  source activation; `reload_agent()` — otherwise a copy of the same body — did
  not, and activation treats a missing flag as required. A source declared
  `required: false` was therefore optional at load and mandatory at reload, so an
  enrichment source that had gone down turned a reload into `ConfigError` where
  the original load had succeeded. Both paths now share one implementation.

  The divergence erred strict: it refused reloads, and never admitted a source
  that should have been skipped.

- **`harness.__version__` reports the real version again, and so does the
  startup attestation.** `__init__.py` read its version from a distribution
  named `shai`, but the distribution is `shai-harness`. A wrong name does not
  raise — `PackageNotFoundError` is caught and the source-tree sentinel is
  returned — so on a correct install `__version__` was `0.0.0+dev`, and every
  `boundary=system, decision=startup` event recorded
  `shai_version="0.0.0+dev"`. The signature over those events was valid; the
  version they attested was not the one running, which is the one question that
  record exists to answer. Contract tests now compare `__version__` against the
  distribution name declared in `pyproject.toml`, so a future rename fails
  loudly instead of restoring the sentinel.

- **`command_injection_scan` and `mcp_metadata_scan` are resolvable by name.**
  Both are selectable under a boundary's `scanners:` list, but neither was
  registered in the `harness.scanners` entry-point group, so
  `harness.adapters.discovery.resolve("harness.scanners", name)` raised
  `AdapterDiscoveryError` for them. That broke the migration this changelog
  published when the `MCPMetadataScanner` re-export was removed — it directs
  users to "resolve it by name through `harness.scanners` like every other
  scanner", which was the one name that could not be resolved that way.
  `harness.yaml` was never affected: `from_yaml()` builds bundled scanners from
  an internal table that always had all seven. A contract test now pins the two
  against each other.

## [0.7.0] — 2026-08-05

### Added
- **`policy.engine` selects the PolicyEngine by name.** Defaults to the
  built-in `rules` evaluator, so no existing config changes behaviour. Any
  other name resolves through the `harness.policy` entry-point group, which
  makes an OPA or Cedar engine wirable from `harness.yaml`:

  ```yaml
  policy:
    engine:
      name: opa
      config: {bundle_url: "${OPA_BUNDLE_URL}"}
  ```

  Unlike a scanner or sink that cannot be built, an engine that cannot be built
  is fatal — a harness with no policy engine has no gate. Inline `policy.rules`
  alongside a non-`rules` engine is rejected at load rather than silently
  ignored: those rules reach the built-in evaluator only.

- **`secrets:` selects the SecretsProvider by name.** Defaults to `env`
  (`EnvVarProvider`), matching what every config did implicitly before. Any
  other name resolves through the `harness.secrets` entry-point group, so a
  Vault or KMS provider is a config change rather than an application-code
  change:

  ```yaml
  secrets:
    name: vault
    config: {addr: "${VAULT_ADDR}"}
  ```

  The block is read before the rest of the config is validated, because this
  provider is what resolves the config's own `secret://` URIs. `${ENV_VAR}`
  expands inside it; a `secret://` inside it is rejected, since it would need
  the provider it is defining.

  Both groups were declared and resolvable but had no consumer: `from_yaml()`
  constructed `RuleBasedPolicy` and `EnvVarProvider` directly, so a package
  registering under either group could never be reached.

- **Startup attestation** — `SHAI.from_yaml()` emits one `boundary=system`,
  `decision=startup` `AuditEvent` before returning, recording what the process
  actually wired: SHAI version, every scanner/sink/policy adapter with its
  module path and source-file SHA256, connector manifest digests, pattern-DB
  rule count and digest, policy rule count and digest, and each declared source
  with its URL stripped of userinfo, query, and fragment. Signed like any other
  event when `audit_signing.enabled`. Adapters that are installed but not
  referenced by `harness.yaml` are deliberately absent — the event attests what
  runs, not what is available.

- **`startup` decision value** — new `Decision` member, accepted by
  `shai audit tail --decision startup`.

- **`shai harness inspect`** — offline listing of what a config declares:
  boundaries and scanners, sinks, policy digest, pattern-DB state, connector
  manifests, resolved sources, and agents from `--agents-dir`. Builds no
  adapters, opens no connections, emits no audit event.

- **`shai harness graph`** — the same topology as a graph: agent → source →
  tool → tag, with policy rules and subagents. `--format dot` (default) or
  `--format json`. Two sources whose URLs match once credentials and query
  strings are stripped are reported as a shadow-endpoint warning on stderr and
  in the JSON `warnings` list.

### Fixed
- **A malformed dispatch token could escape `ShaiTransport`'s denial path.**
  `verify_token()` documented `TokenError` as its only failure mode, but a
  token decoding to a JSON array raised `AttributeError` and one carrying a
  non-string timestamp raised `TypeError`. Neither is caught by the transport's
  `except TokenError`, so the request aborted on an unexpected exception
  *before* the `NetworkAuditEvent` with `status="denied"` was emitted — the one
  case where a refused request left no audit record. Both now raise
  `TokenError` and deny normally.

  The cause was duplication: `connectivity/token.py` and `core/approval.py` had
  grown two independent copies of the same signed envelope, and the grant copy
  already had both guards. They now share one implementation
  (`harness.core.signing`), so a hardening fix lands once. The wire format is
  byte-identical — signatures, encodings, and previously issued tokens and
  grants all verify unchanged.

- **Heuristic candidate matching worked only on exact duplicates.** The
  fingerprint's `lsh` field computed a 64-function MinHash over character
  bigrams and then compressed it with `sha256(signature)[:16]`; `lsh_jaccard`
  compared characters of that digest. SHA-256 is an avalanche hash, so a single
  differing minimum — which is what "these two texts are 95% similar" looks
  like — produced an unrelated digest. Measured, two prompts differing by one
  word scored **0.0**. Both consumers threshold at 0.7, so candidate
  deduplication never merged near-duplicates and promoted candidates never
  matched anything but a byte-identical replay. `hit_count` therefore stayed at
  1 and almost nothing reached the three-hit floor `shai patterns candidates`
  applies, leaving the review queue looking empty.

  `lsh` now holds the whole signature — 64 minima as fixed-width hex — and
  `lsh_jaccard` returns the fraction of minima that agree, which is the
  estimator MinHash is for. Near-duplicates now score 0.93–0.98 and unrelated
  texts ~0.20.

  *Operational note:* the stored format changed. Existing rows in
  `state/patterns.db` carry the old 16-char digest, and signatures of unequal
  length share nothing by definition, so **previously promoted candidates stop
  matching** until the pattern recurs and is promoted again. No migration is
  provided — the candidate table is a rebuildable discovery surface, not a
  system of record. Clear it with
  `sqlite3 state/patterns.db 'DELETE FROM heuristic_candidates'` to drop the
  dead rows; the signed `patterns` table is untouched and unaffected.

  This changes what is detected, not what is blocked: promoted-candidate
  findings remain MEDIUM, never enter the per-scanner results the action loop
  reads, and carry `structural_heuristic` — the same method family as
  `heuristic_scan` — so they still cannot reach HIGH through ensemble promotion
  or block on their own.

- **Manifest resolution no longer discards the manifest.** Resolving a source
  that names `connector:` treated every unset `SourceConfig` field as an
  operator override, so the model's own defaults — `transport: local`, empty
  `tags`, `allowed_urls`, `allowed_methods` — replaced the manifest's values.
  Only `url` and the per-tool specs survived, and the source was built as a
  local source rather than an MCP one. Overrides are now taken from the fields
  the operator actually wrote. A source with no `connector:` is unaffected and
  never touches the manifest registry.

### Changed
- **Every SHAI process now writes an audit event at construction.** Deployments
  with a `stdout` sink will see one additional JSON line per start; file and
  SIEM sinks gain one row per process.

### Security
- **The tool-call gate denies when the policy engine raises anything.** Layer 5
  caught `PolicyEvaluationError` only, which was sufficient while
  `RuleBasedPolicy` — which wraps its own failures in that type — was the only
  engine reachable. Now that `policy.engine` accepts an engine from outside the
  package, any other exception (a bundle fetch timing out, a bad duck-type)
  would have escaped `check_tool_call`, returning no verdict and emitting no
  audit event. Such a call is now denied with exactly one event, and the reason
  records the exception *type* only — a third-party message can quote the
  arguments it was evaluating.
- **`from_yaml()` fails when the startup event cannot be written.** If every
  configured sink rejects the emission, `AuditEmissionError` propagates and no
  harness is returned — a process that cannot record its own startup cannot
  record the decisions that follow. This is stricter than the best-effort
  `system`/`degraded` path.

## [0.6.1] — 2026-08-04

### Added
- **`role_boundary_forgery` rule (injection catalog)** — matches chat-template
  control tokens appearing in content the model did not generate: the ChatML
  family (`<|im_start|>`, `<|im_end|>`, `<|system|>`), Llama's `<<SYS>>` and
  `[INST]`, and other vendors' reserved turn markers. These tokens exist only
  to frame the model's own transcript, so one in a user turn, a tool result,
  or an uploaded document is categorical evidence rather than cumulative — a
  single match fires at `high`.

  Deliberately limited to reserved tokens. Generic role markup — `<system>`,
  `</document>`, `<s>` — was tried and removed: those are ordinary XML, config,
  and HTML-strikethrough elements, and matching them blocked legitimate
  documents. Content carrying real control tokens now blocks where it
  previously passed.

- **`instruction_override` extended to sixteen further languages** — Italian,
  Portuguese, Japanese, Korean, Arabic, Hindi, Russian, Turkish, Polish,
  Dutch, Norwegian, Swedish, Danish, Finnish, Greek, and Vietnamese, joining
  the existing `fr`/`es`/`de`/`zh`. Every pattern requires both an override
  verb and an instructions noun inside a bounded window; a bare verb is
  ordinary language in all of these locales.

  Only `instruction_override` is extended. The other nine rule kinds carried
  by `fr`/`es`/`de`/`zh` are unchanged, so coverage in the new languages is
  narrower than in the original four. Deployments handling non-English input
  will see override attempts blocked that previously passed.

- **Six further decoders in the normalization layer** — base32, ascii85
  (delimited `<~…~>` form only), binary octet runs, literal `\uXXXX` escape
  sequences, Morse, and reversed text. Each produces an additional scan view,
  so a payload obfuscated under any of them is now matched against the same
  catalogs as plaintext.

  Reversal and Morse are gated, because both "succeed" on arbitrary input:
  reversal surfaces a view only when it recovers more natural language than
  the input already had — the same guard rot13 uses — and Morse requires a run
  of at least five valid letters, so ellipses and dashes in prose do not
  qualify. Undelimited ascii85 is not attempted at all: it matches nearly any
  run of printable ASCII and would decode ordinary prose into noise.

### Fixed
- **The heuristic scanner now returns the same verdict for the same input.**
  `_match_fuzzy_class` iterated its target vocabulary — a `frozenset` — and took
  whichever fuzzy match appeared first. Set iteration order for strings varies
  with Python's per-process hash randomisation, so byte-identical input could be
  classified differently between processes: a request blocked before a restart
  and allowed after it, and a signed audit event that could not be reproduced.
  Targets are now iterated in a fixed order.

  The same loop also let a weak (same-length substitution) match suppress a
  strong one found later, which was arbitrary rather than a judgement. A strong
  match now wins wherever it appears. **This raises detection slightly**:
  tokens that fuzzy-match several vocabulary entries are now credited to the
  strongest, so some inputs that previously scored medium reach high. Measured
  on a third-party direct-injection corpus, blocks rose from a 27–29 spread to a
  stable 32 out of 1,040.

- **`collect_events()` no longer unsubscribes the wrong collector.** The
  context manager registered a list and removed it on exit with
  `list.remove()`, which compares by `==`. Two buckets holding the same events
  — most often two empty ones — are equal, so an exiting block could drop a
  *different* block's subscription. The consequences were a `ValueError:
  list.remove(x): x not in list` raised from the other block's `finally`
  (masking whatever that block was doing), and a collector that stayed
  attached after its `with` had exited, quietly accumulating events from the
  rest of the process.

  Removal is now by identity, so the documented guarantee that concurrent
  `collect_events()` calls are safe is true rather than aspirational. Callers
  running a single collector at a time were never affected. Anyone who wrapped
  concurrent boundary calls — a harness driven from several tasks, or a test
  helper collecting per-request — was.

### Security
- Detection surface widens in three places above. Each was measured against
  the available benign corpus with no new false positives, but that corpus is
  English-only: **the sixteen new languages have no benign coverage**, so
  their false-positive behaviour is argued from pattern construction rather
  than measured. Deployments handling significant non-English traffic should
  watch block rates after upgrading.

## [0.6.0] — 2026-07-31

### Added
- **`ArgumentRule.user_origin`** — declares that an argument's value must trace
  to the user's prompt rather than to text a tool returned during the same
  turn. Defaults `False`, so every existing tool is outside the control until
  it is declared. Intended for the arguments that route or authorise —
  recipient, path, url, amount — and not for free-text bodies, which
  legitimately carry content the agent just read.
- **Content provenance on `TurnSignals`** — `input_digests`,
  `tool_result_digests` and `arg_is_ingested()`. `record_input()` and
  `record_tool_result()` take a new keyword-only `text=`; boundaries pass the
  scanned text and it is stored as hashed tokens, never as spans. Both sets are
  capped per turn; past the cap the comparison under-matches rather than
  growing without bound.

### Fixed
- **`within_chars` proximity now answers correctly on long and on padded
  input.** The check behind every compound (`match.all`) rule was a backtracking
  walk whose worst case is the product of the group match counts, and its two
  guards each caused a defect. Spans were capped at 32 per signal group, so in a
  long document the occurrence that actually satisfied proximity could fall
  outside the cap and the rule stopped firing with nothing logged. The step
  budget guarding the walk failed closed, so input padded to exhaust it was
  *reported as a match*. Both are gone: the check is now a linear sweep, with no
  budget, no fail-closed path, and a per-group span limit that bounds memory
  rather than deciding outcomes.

  Two behaviour changes follow. Compound rules now fire on long documents where
  the matching signals sit far into the text — this affects the
  indirect-injection family most, which operates on retrieved documents and
  message bodies. And input crafted to exhaust the old budget no longer produces
  a finding; those were never verified matches, but a deployment counting them
  will see fewer.

### Changed
- **Localized `policy_evasion` and `escalation_phrases` no longer outrank their
  English base rules.** The `fr`/`es`/`de`/`zh` variants of both were
  `severity: high` against a `medium` base, and `has_high_rule` forces the whole
  scan to HIGH on a single high match — so the same phrasing blocked in four
  languages and only warned in English. All eight are now `medium`, matching the
  base rule. Deployments relying on the stricter non-English behaviour will see
  those inputs warn rather than block.
- **Gate layer 6 evaluates both denial patterns before the tighten.** A `WARN`
  input on a write-capable tool previously returned the tighten marker before
  any later pattern was considered, so additional evidence could produce the
  weaker outcome. Denials are now decided first. No existing configuration
  changes behaviour: the pattern this ordering matters for is opt-in.

### Security
- **Indirect-injection containment no longer depends on detecting the payload.**
  Gate layer 6 denies a call when an argument declared `user_origin` carries a
  value that entered the turn through a tool result and appears nowhere in the
  user's prompt. This holds regardless of whether any scanner flagged that tool
  result, which is the point: an indirect injection carrying no override
  language produces no findings, but it still has to supply the value it
  redirects the call to.

  Known cost: an agent that resolves a user-named entity through a read — a
  contact lookup turning a name into an address — trips this exactly as a
  poisoned document does, because by provenance the two are identical. Declare
  `user_origin` only on arguments the user names directly.

## [0.5.0] — 2026-07-29

### Added
- **French, Spanish, German and Mandarin pattern coverage for the last two
  English-only catalogs.** `injection_common.yaml` loads on every catalog
  scanner, and `mcp_metadata_patterns.yaml` reads tool descriptions written by
  whoever runs the MCP server — both were monolingual, which made "write the
  payload in another language" a free bypass on the two widest surfaces in the
  system. Every bundled catalog now ships a `.l10n.yaml` sibling, and a test
  fails if one is added without it. Localized rules are named
  `<lang>.<base_rule>` so a payload written in two languages scores as one piece
  of evidence rather than two.
- **`AuditEvent`, `NetworkAuditEvent` and `NetworkPolicyError` are exported.**
  All three are reachable through the public API — the first two are what
  `collect_events()` yields, the third can escape a source dispatch — and none
  was importable from `harness` directly.
- **`Finding.signals`** — the numeric sub-scores a scanner computed, by name.
  The heuristic scanner populates entropy, density, coherence, structural,
  fuzzy-intent and total on every finding it emits. Consumers read these instead
  of parsing them back out of the human-readable `detail` string.
- **`narrow_scan` boundary.** `scan_pii()` and `scan_injection()` emit under it
  rather than `input_scan`, so a consumer counting input scans per turn is not
  thrown off by a helper call, and `adapters` names the subset that actually
  ran. Filterable with `shai audit tail --boundary narrow_scan`.
- **The signed pattern DB feeds `mcp_metadata_scan`.** Its `mcp_metadata`
  catalog is now routed like the other three, and `MCPMetadataScanner` accepts
  `extra_rules` — operators extend MCP metadata detection the same way they
  extend every other catalog scanner.
- **`mcp_metadata_scan` boundary in the audit trail.** MCP tool metadata
  scanning now emits one `AuditEvent` per tool inspected, so
  `shai audit tail --boundary mcp_metadata_scan` returns rows instead of
  nothing — the CLI already offered that filter, but no `BoundaryName` value
  could produce it. Events carry `tool_name`, `transport`, `adapters`,
  `finding_count`, `max_severity` and `extra.source`. Note that existing sinks
  receive traffic they did not before: one event per tool in a source's
  `tools/list`, once per source per process at connect time. A consumer that
  validates `boundary` against a fixed set needs `mcp_metadata_scan` added to
  it.

### Changed
- **BREAKING**: an enabled scan boundary with no scanner configured now blocks.
  It returned ALLOW. "We inspected this and found nothing" and "nothing
  inspected this" were the same answer to the caller, which is the one thing a
  scan verdict must never be ambiguous about. Turning a boundary *off* is
  unchanged and still allows — that is an explicit decision, and the event
  carries `disabled: true` to say so. Reaching the new branch means the
  configuration asked for a scan it could not perform. The rule lives in the
  shared pipeline, so it covers every boundary rather than the case that
  prompted it.
- **BREAKING**: `check_tool_call.arg_scanners:` is now `check_tool_call.scanners:`.
  Every boundary spells the key the same way. Because the config models reject
  unknown keys, a stale `arg_scanners:` fails at `from_yaml()` rather than being
  quietly ignored — rename it in `harness.yaml`.
- **BREAKING**: `scan_pii()` and `scan_injection()` run only what is configured.
  When the scanner they name was absent from `scan_input.scanners`, they fell
  back to the *entire* input stack — so a call asking for targeted PII detection
  silently ran injection, jailbreak and the heuristic backstop under
  `scan_input`'s threshold and action. They now run the matching subset, and
  block when it is empty (see the entry above). An application calling
  `scan_pii()` without declaring `regex_pii` will start seeing blocks; it was
  previously getting a scan it never asked for, under the wrong threshold.
- **BREAKING**: a pattern catalog that cannot be loaded raises instead of
  loading empty. `InjectionScanner` returned an empty catalog on a missing file,
  invalid YAML, or a non-mapping document — and a scanner with no rules returns
  "no findings" for every input, indistinguishable from one that is working. A
  typo in a `patterns_file` path was a silent hole. It now raises `ValueError`
  at construction. An explicit `patterns: []` is still valid and still means
  what it says.
- **BREAKING**: `scan_mcp_metadata.action` is honoured. It was accepted and
  ignored, so the boundary was block-or-nothing with no observe-before-enforce
  path. `alert` now registers the tool and records the finding as `warn`;
  `block` refuses as before. `redact` is rejected at config load — a tool
  description is registered whole or not at all, and a partially redacted one
  still reaches the model.
- **BREAKING**: an agent's `allowed_tags:` now gates the agent's own tool calls.
  It never did. Layer 4 read only the capability set on the context, which is
  populated for subagents and left empty on a parent turn — so a top-level
  agent declaring `allowed_tags: [read]` got no enforcement from it at all, and
  the field's only effect was constraining that agent's subagents at load time.
  An operator reading their own config had every reason to believe otherwise.
  The declared set now binds the agent too, intersected with any narrower set
  the context carries: a hand-built `AgentContext` cannot widen what the config
  allows, and a deliberately narrowed one is still honoured. Semantics are
  unchanged and match what subagents always had — a tool's tags must be a
  *subset* of the allowed set, not merely overlap it.
  **Migration**: `allowed_tags` must list every tag carried by every tool the
  agent may call, or those calls are denied with `requires tags [...] not in
  agent capability set`. An agent allowing `[read]` and calling a tool tagged
  `[read, internal]` now fails until `internal` is added. Agents consuming MCP
  sources are most affected — those tools carry an `mcp` tag plus any
  source-level tags. Read the deny reasons in the audit trail to enumerate what
  each agent actually needs.
- **BREAKING**: `scan_file` can now block a document two techniques agree on.
  Neither of the boundary's scanners declared a detection technique, so every
  finding was labelled `unknown`, the whole boundary reported one technique,
  and the cross-method severity promotion that requires two could never fire
  there — the structural pass corroborating the content chain being exactly
  what it exists for. `FileScanner` now reports `structural_file` and the
  content chain's findings keep the technique of whichever scanner produced
  them. Consequence on an unchanged config: a document flagged `medium` in the
  same category by two different techniques in the chain — a catalog scanner
  and the always-on heuristic backstop, say — is promoted to `high` and blocks
  at the default `block_at: high`, where before it passed. Files that used to
  get through can now be rejected. Set `scan_file.block_at: critical` to keep
  the previous effective threshold while the new promotions are assessed.
- `verify_token()` names `sub_agent_id` when it is missing instead of failing
  with `signature mismatch`. The field was always part of the signed payload,
  so a token without it already failed — the error just did not say why. No
  valid token is affected.
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
- **The strongest heuristic detections recorded an empty fingerprint.** The
  scanner emits a second, higher-severity finding when it sees a compound
  typoglycemia attack, and that finding sorts first. The candidate database
  read sub-scores by parsing the first finding's `detail` text, and the compound
  finding's wording has no sub-score section — so entropy, density, coherence
  and structural all recorded as zero, precisely on the attacks worth learning
  from. Sub-scores are now carried as data on every finding (`Finding.signals`)
  rather than recovered from prose.
- **One malformed rule failed an entire signed bundle.** Signature verification
  already drops a single tampered row without taking down the rest, but the
  survivors were then compiled as one batch — so a single schema-invalid rule
  discarded every other rule in the bundle and failed startup with it. Rules
  from the database now compile one at a time: a bad rule costs that rule, is
  logged, and the others load.
- **A compound rule could be switched off by padding the input.** The
  `within_chars` proximity check walked one match per signal group with no
  ceiling, so its cost was the product of the per-group match counts — on text
  an attacker writes. It is now budgeted, and exhausting the budget counts the
  rule as *matched*: the alternative would have made "make the search expensive"
  a way to suppress detection.
- **Localized rules could inflate severity instead of corroborating.** Eight
  translated rules carried names that did not derive cleanly from the rule they
  mirror, so they scored as independent detections alongside their English
  counterpart rather than collapsing into one piece of evidence. Pinned with
  `meta.semantic_id`.
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
- **A `critical` finding in MCP tool metadata never blocked the tool.** The
  block decision ran off a local `[low, medium, high]` list and tested
  `if f.severity in severity_order` before comparing, so `critical` — the
  highest severity SHAI can represent — fell out of the comparison entirely and
  the tool registered cleanly at every configured `scan_mcp_metadata.block_at`.
  A compromised MCP server whose metadata payload scored `critical` was strictly
  safer scoring `high`. The decision now uses the same `Severity` comparison
  every other boundary uses. `critical` is the only severity whose outcome
  changes, and only from allow to block.
- **Refusing an MCP tool left no audit record.** A tool blocked for metadata
  injection was logged at WARNING and skipped, and nothing else. Because a
  blocked tool is never registered it never reaches the gate either, so the
  refusal appeared in no audit event anywhere — the one decision an operator
  most needs to review after connecting an untrusted source was the one the
  trail did not hold. Emission now happens on every path through the scan, so
  a clean tool is recorded as `allow` alongside the refusals; "all N tools from
  this source were scanned" is only provable from the trail if the clean ones
  are in it. A refusal's `deny_reason` names the threshold that fired and
  nothing else — the matched metadata is the payload being refused and is never
  echoed into the trail.
- **Signed pattern rules crashed startup for two of the three catalogs.**
  `patterns_db` routes `injection`, `jailbreak` and `identity_spoof` rules to
  their matching scanners, but `JailbreakScanner` and `IdentitySpoofScanner`
  each overrode `__init__` without forwarding `extra_rules` — so
  `SHAI.from_yaml()` raised `TypeError` the moment either catalog held a row
  and its scanner was declared in `harness.yaml`. An operator shipping a
  jailbreak bundle got a startup crash whose only workarounds were removing the
  scanner or emptying the catalog, so the feature was unreachable for two of
  the three families it exists to serve. Both overrides are gone: a subclass
  now declares `name` and `default_patterns` as class attributes and inherits
  one constructor, leaving no parameter to forget forwarding. Each subclass
  keeps its own catalog and name, and `name=` still overrides. One consequence
  for anyone subclassing `InjectionScanner` directly — an instance built with
  no `name=` argument now takes the subclass's `name` class attribute instead
  of defaulting to `"injection_scan"`.
- **A circuit breaker that reopened after `reset()` did so silently.**
  `reset()` assigned a misspelled attribute, so the log-once guard stayed set
  and the "circuit breaker open — adapter skipped" warning was suppressed on
  every subsequent trip. The breaker still worked; the operator just got no
  signal that a scanner had been taken out of the pipeline.
- **`scan_file` findings report the technique that produced them.** Both of
  the boundary's scanners omitted `method_family`, which the `Scanner` protocol
  requires, so every finding was stamped `unknown`. Audit events at this
  boundary now carry the real technique, and `structural_file` joins the
  vocabulary. See the `Changed` entry above for the verdict consequence.
- **`AuditEvent.token_id` was always null, so the documented SIEM join had only
  one side.** The field exists to correlate a gate decision with the
  `NetworkAuditEvent` its dispatch produced, and the schema documentation shows
  the join — but the gate emitted its allow event first and the dispatch token
  was minted afterwards, so nothing ever filled it in. The token is now issued
  before the event is built, on the allow path only, and its id is stamped on
  the event. A denied call still mints no token. Correlating gate decisions
  against outbound requests works for the first time.
- **A secret whose value began with `secret://` resolved twice.** After the
  config loader resolved a reference, `from_yaml()` tested the *result* for the
  same prefix and resolved again — so an operator whose signing key, dispatch
  token secret, or pattern-DB secret happened to start with `secret://` got a
  second lookup and a different key than the one they set. The second pass is
  gone; the loader's resolved value is used as-is.

### Removed
- **BREAKING**: fifteen names are no longer exported from the `harness`
  top-level namespace. `SHAI` is the API; everything still exported is a shape
  one of its method signatures uses — what you pass in, what you get back, or
  what can escape as an exception. The rest were exported because they were
  useful internally: `ToolRegistry`, `LocalSource`, `MCPSource`,
  `SourceRegistry`, `SubAgentConfig`, `RuleConfig`, `ConnectivityConfig`,
  `DispatchToken`, `TokenError`, `ScanAction`, `AdapterDiscoveryError`,
  `PolicyEvaluationError`, `ArgumentViolationError`, `IrreversibleActionError`,
  `ToolNotRegisteredError`. The four exception types among them never escape a
  public method — the gate reports its refusals as `GateDecision(allowed=False)`,
  so catching them was already dead code.
  **Migration**: each remains importable from its own module — for example
  `from harness.tools.source import MCPSource`, `from harness.connectivity import
  DispatchToken`. Anything outside `__all__` is now explicitly an implementation
  detail and may change without deprecation.
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
- **BREAKING**: `MCPMetadataScanner.should_block()` and its `block_at_severity`
  constructor parameter. The scanner carried a second, independent threshold
  that nothing supplied and no shipped code path consulted — the real decision
  was made against `scan_mcp_metadata.block_at`, and the two implementations had
  already diverged (see Fixed). The scanner now only produces findings and the
  boundary applies the threshold, which is the split every other scanner
  follows. Set the threshold in `harness.yaml` under `scan_mcp_metadata.block_at`;
  a `config: {block_at_severity: ...}` on the scanner's `AdapterRef` now fails at
  `from_yaml()`.
- **BREAKING**: the `MCPMetadataScanner` re-export from
  `harness.adapters.scanners`. It was the only one of seven bundled scanners
  the package exported, making it a partial second public surface alongside the
  entry-point group, and which one got exported was arbitrary. Import it from
  `harness.adapters.scanners.mcp_metadata_scanner`, or resolve it by name
  through `harness.scanners` like every other scanner.
- The `harness.sources` entry-point group. It advertised `local`, `skill` and
  `mcp` as pluggable source adapters, but the group was never in the set
  `resolve()` accepts, and the `skill` entry pointed at a class that was never
  written — so nothing could load any of it. Sources are selected by the
  `transport:` field on a source in `harness.yaml`, which is unchanged. A
  package registering under this group was never being consulted, so there is
  nothing to migrate. Contract tests now assert that every declared group is
  resolvable and every entry-point target imports, so a decorative group cannot
  be added back unnoticed.

### Security
- A scan that cannot run fails closed. The combination of a boundary enabled
  with no scanners, a catalog that would not load, and helper methods that
  silently substituted a different scanner set meant several ways to end up
  believing content had been inspected when nothing had inspected it. Each now
  either blocks or refuses to start.
- Non-English payloads no longer bypass the two widest detection surfaces.
  Language was a free bypass on the shared rule catalog and on MCP tool
  metadata — the latter written by whoever runs the server, and handed to the
  model as trusted schema context.
- Only the scanners an operator declared will run. The narrow-scan helpers
  substituting the full input stack meant the set of scanners actually applied
  to content did not match the configuration, in either direction.
- A denial-of-service against pattern matching cannot suppress a rule. The
  bounded proximity search resolves exhaustion as a match, so making the search
  expensive costs the attacker a detection rather than earning them a bypass.
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
- MCP tool metadata is gated across the full severity ladder. `critical`
  findings were silently exempt from the block decision, so the strongest signal
  the scanner could raise was the one that let a tool through — an inversion an
  attacker benefits from by making a payload more obviously malicious, not less.
- One threshold governs MCP metadata blocking. The scanner's own severity
  setting is gone, so `scan_mcp_metadata.block_at` is the only thing that
  decides, and there is no second copy left to drift from it.
- Tools refused at connect time are recorded. A compromised MCP server whose
  tool metadata carried an injection payload was turned away silently, leaving
  an operator no way to tell from the audit trail that a source had tried it —
  or to correlate the attempt with anything else. Registration refusals are now
  first-class audit events.
- A total audit-sink outage fails source connection rather than proceeding.
  `AuditEmissionError` propagates out of the metadata scan, so `load_agent()`
  raises instead of connecting a source whose refusals could not be written.
- Least privilege applies to the agent that declared it, not only to its
  children. A deployment that scoped a top-level agent to `[read]` was running
  it unscoped; the capability set is now enforced where an operator would
  expect it, and cannot be widened by the calling code.
- Gate decisions correlate with the network requests they authorised. Without
  `token_id` on the gate event, an outbound request could be traced back to a
  token but not to the decision that issued it — the half of the audit trail
  that answers "what authorised this egress" was missing.
- Corroborating techniques raise severity at `scan_file` as they already do at
  every other scan boundary. Two independent techniques agreeing on a category
  is the strongest signal the ensemble has, and it was structurally unreachable
  for uploaded files — the one surface where a payload arrives inside a
  container the content scanners have to be told how to read.
- A scanner taken out of the pipeline by its circuit breaker is visible again.
  After any `reset()`, later trips logged nothing, so a deployment could run
  with a scanner permanently skipped and no warning in the log to say so.
- Signed jailbreak and identity-spoof rules reach their scanners. Operators who
  applied a bundle to either catalog were running without those rules entirely:
  the harness could not start with them loaded, so the working configuration
  was always the one where they were absent. Only the `injection` catalog ever
  took effect.

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
