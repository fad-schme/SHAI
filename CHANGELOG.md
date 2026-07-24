# Changelog

All notable changes to SHAI are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Semver policy

- **PATCH**: bug fixes, pattern catalog updates, new scanners (additive)
- **MINOR**: new config fields with defaults, new boundaries, new integrations
- **BREAKING**: removing config fields, changing defaults, verdict/event schema changes

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
