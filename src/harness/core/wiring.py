"""Adapter construction for SHAI.from_yaml().

Scanner, sink, and policy engine builders — turning AdapterRef declarations
from harness.yaml into constructed instances. Split out of core/harness.py
so the facade module holds only the public SHAI surface; this is where
wiring decisions live.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

from harness.adapters.audit_sinks.stdout import StdoutSink
from harness.adapters.scanners.base import ConfiguredScanner
from harness.adapters.scanners.heuristic_scan import HeuristicScanner
from harness.adapters.scanners.injection_scan import InjectionScanner
from harness.adapters.scanners.mcp_metadata_scanner import MCPMetadataScanner
from harness.adapters.scanners.regex_pii import RegexPIIScanner
from harness.core.errors import ConfigError
from harness.policy.rules import RuleBasedPolicy

if TYPE_CHECKING:
    from harness.config.schema import NormalizationConfig, PolicyConfig
    from harness.policy.engine import PolicyEngine

log = logging.getLogger(__name__)


# ── Module-level adapter builders ─────────────────────────────────────────
#
# Each scanner is a named, standalone class. _build_text_scanners resolves
# them from AdapterRef declarations in harness.yaml. The named factories
# below make the mapping explicit — no magic string dispatch.

def _extract_density(verdict) -> float:
    """Instruction-density sub-score from the heuristic scanner, or 0.0.

    Reads Finding.signals rather than parsing Finding.detail — the detail
    string is for humans and rewording it must not change what the threat
    accumulator scores.
    """
    for f in verdict.findings:
        if f.scanner == "heuristic_scan" and "density" in f.signals:
            return f.signals["density"]
    return 0.0


def _make_file_injection_scanner(cfg: dict) -> InjectionScanner:
    """Build the common + input + document catalog union for file content."""
    doc_patterns = Path(__file__).parent.parent / "adapters/scanners/l10n/patterns_for_doc.yaml"
    return InjectionScanner(
        additional_patterns_files=(doc_patterns,),
        **cfg,
    )


# Signed-DB catalog name per injection-family scanner. Explicit rather than
# derived from the scanner name: the catalog names are an operator-facing
# contract in the bundle format and must not shift if a scanner is renamed.
# Only InjectionScanner and its subclasses appear here — they share one
# __init__, so every name in this table accepts extra_rules. A subclass that
# overrides __init__ without forwarding the kwarg breaks that and is rejected
# by test_db_catalog_scanners_accept_extra_rules.
_DB_CATALOG_FOR_SCANNER: dict[str, str] = {
    "injection_scan":      "injection",
    "jailbreak_scan":      "jailbreak",
    "identity_spoof_scan": "identity_spoof",
    "mcp_metadata_scan":   "mcp_metadata",
}


# Named registry — explicit, no magic strings
_SCANNER_FACTORIES: dict[str, Any] = {
    "regex_pii":           lambda cfg: RegexPIIScanner(**cfg),
    "injection_scan":      lambda cfg: InjectionScanner(**cfg),
    "heuristic_scan":      lambda cfg: HeuristicScanner(**cfg),
    "mcp_metadata_scan":   lambda cfg: MCPMetadataScanner(**cfg),
    "jailbreak_scan":      lambda cfg: __import__(
        "harness.adapters.scanners.jailbreak_scan", fromlist=["JailbreakScanner"]
    ).JailbreakScanner(**cfg),
    "identity_spoof_scan": lambda cfg: __import__(
        "harness.adapters.scanners.identity_spoof_scan", fromlist=["IdentitySpoofScanner"]
    ).IdentitySpoofScanner(**cfg),
    "command_injection_scan": lambda cfg: __import__(
        "harness.adapters.scanners.command_injection_scan",
        fromlist=["CommandInjectionScanner"],
    ).CommandInjectionScanner(**cfg),
}


def _build_text_scanners(
    adapter_refs: list,
    *,
    extra_rules: dict[str, list] | None = None,
    include_document_patterns: bool = False,
) -> list[ConfiguredScanner]:
    """Build text scanners from AdapterRef declarations in harness.yaml.

    Scanners are resolved via the named factory table above, which is the
    whole set.

    Each scanner is paired with the action / redact_with of the ref that
    produced it, so overrides cannot shift from one scanner onto another.

    extra_rules maps scanner name → compiled rules from the signed pattern DB
    (see _DB_CATALOG_FOR_SCANNER). Only injection-family names appear in it, so
    scanners that do not accept extra_rules never receive the kwarg.

    HeuristicScanner is the always-on structural backstop: appended here with
    no override (the boundary action governs it) unless an explicit
    `heuristic_scan` ref already placed it. Declaring it in harness.yaml only
    controls its position and per-scanner action.
    """
    scanners: list[ConfiguredScanner] = []
    for ref in adapter_refs:
        factory = _SCANNER_FACTORIES.get(ref.name)
        if factory:
            cfg = ref.config
            if extra_rules and ref.name in extra_rules:
                # Copy: ref.config is shared across every boundary's build call.
                cfg = {**cfg, "extra_rules": extra_rules[ref.name]}
            scanner = (
                _make_file_injection_scanner(cfg)
                if include_document_patterns and ref.name == "injection_scan"
                else factory(cfg)
            )
        else:
            # _SCANNER_FACTORIES is the whole set — SHAI Core has no scanner
            # extension surface, so an unknown name can never resolve to
            # anything. NOTE: skipping it leaves the boundary running one
            # fewer inspection than the operator declared, announced only in a
            # warning log. That fail-open is tracked separately; this branch
            # preserves the prior behaviour rather than changing it here.
            log.warning("unknown scanner — skipped",
                        extra={"adapter_name": ref.name})
            continue
        scanners.append(ConfiguredScanner(scanner, ref.action, ref.redact_with))
    if not any(getattr(c.scanner, "name", "") == HeuristicScanner.name for c in scanners):
        scanners.append(ConfiguredScanner(HeuristicScanner()))
    return scanners


def _build_file_scanners(
    adapter_refs: list, *, max_size_mb: float,
    normalization: NormalizationConfig | None = None,
) -> list[ConfiguredScanner]:
    """Build the scan_file scanner list.

    Two independent scanners, so a failing content scanner cannot discard the
    structural findings and each is governed by on_error on its own:

      FileScanner        — structural pass (MIME, size, extension, PDF JS, SVG,
                           EXIF, ZIP, Office macros)
      FileContentScanner — the configured chain over extracted text and image
                           metadata

    `scan_file.scanners` is that content chain and is authoritative, exactly as
    `scan_input.scanners` is for input — declared scanners are what run over
    extracted content.
    """
    from harness.adapters.scanners.file_scanner import (
        FileContentScanner,
        FileScanner,
    )

    refs = [r for r in adapter_refs if r.name != "file_scanner"]
    # The content chain runs inside FileContentScanner, which calls the
    # scanners directly — FileScanConfig rejects per-scanner overrides, so
    # only the instances travel down.
    text_scanners = [
        c.scanner
        for c in _build_text_scanners(refs, include_document_patterns=True)
    ]
    return [
        ConfiguredScanner(FileScanner(max_size_mb=max_size_mb)),
        ConfiguredScanner(
            FileContentScanner(
                text_scanners=text_scanners,
                max_size_mb=max_size_mb,
                # Content only. The structural scanner above takes none:
                # it reads the path, and a de-obfuscated path is a
                # different path.
                normalization=normalization,
            )
        ),
    ]


def _build_policy(cfg: PolicyConfig) -> PolicyEngine:
    """Build the PolicyEngine named by `policy.engine`.

    RuleBasedPolicy is the only engine SHAI Core has; any other name is a
    config error. A harness with no policy engine has no gate at all and
    allows every tool call, so a construction failure is fatal too.
    """
    if cfg.engine.name != RuleBasedPolicy.name:
        raise ConfigError(
            f"unknown policy engine {cfg.engine.name!r}. "
            f"Valid engines: [{RuleBasedPolicy.name!r}]",
            op="from_yaml",
        )
    return RuleBasedPolicy(source_rules=cfg.parsed_source_rules())


def _build_sinks(adapter_refs: list) -> list:
    sinks = []
    for ref in adapter_refs:
        if ref.name == "stdout":
            sinks.append(StdoutSink())
        elif ref.name == "file":
            from harness.adapters.audit_sinks.file import FileSink
            sinks.append(FileSink(**ref.config))
        else:
            # stdout and file are the whole set. NOTE: as with scanners, an
            # unknown name is skipped, and an emptied list then falls back to
            # stdout below — a typo silently moves the audit trail. Tracked
            # separately; not changed by the discovery removal.
            log.warning("unknown audit sink — skipped",
                        extra={"adapter_name": ref.name})
    if not sinks:
        log.warning("no audit sinks configured — falling back to stdout")
        sinks = [StdoutSink()]
    return sinks
