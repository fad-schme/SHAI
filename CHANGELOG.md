# Changelog

All notable changes to SHAI are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Semver policy

- **PATCH**: bug fixes, pattern catalog updates, new scanners (additive)
- **MINOR**: new config fields with defaults, new boundaries, new integrations
- **BREAKING**: removing config fields, changing defaults, verdict/event schema changes

## [0.2.0] — Unreleased

### Added
- `on_error` field on `BoundaryConfig` and `FileScanConfig` (fail_closed | fail_open | degrade)
- `CircuitBreaker` for scanner adapters — exponential backoff, cap 5 min
- `BoundaryName.SYSTEM` and `Decision.DEGRADED` for structured error events
- `HeuristicScanner` — always on, entropy + instruction density + coherence + structural markers
- Ensemble severity promotion — cross-scanner findings promoted to HIGH when combined weight crosses threshold
- Signed pattern database (`patterns_db`) for incremental pattern distribution
- `shai patterns apply|list|verify` CLI commands
- `PatternsDBConfig` in harness.yaml

### Changed
- **BREAKING**: default `on_error` is now `fail_closed` (was implicit fail-open).
  Add `on_error: fail_open` to restore pre-0.2 behavior.
- `InjectionScanner` accepts `extra_rules` parameter for DB-sourced patterns

### Fixed
- `from_yaml()` referenced `instance` before construction — crashed on any
  config with MCP sources.

## [0.1.0] — 2026-07-01

### Added
- Initial release: SHAI facade, five boundaries, six framework integrations
- Scanner adapters: regex_pii, injection_scan, jailbreak_scan, identity_spoof_scan
- Audit pipeline with HMAC-SHA256 signing
- MCP source support with ShaiTransport egress enforcement
- Session threat accumulator (SQLite-backed)
- CLI: `shai validate`, `shai audit tail`, `shai agents list`
