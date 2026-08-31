"""prompt_defense_scanner.py — absence-of-defense scanner for MCP manifest
onboarding.

Every other catalog scanner in this package fires a finding when a pattern
MATCHES the scanned text — evidence of an attack. This one inverts that:
a finding fires for a defense category when NONE of that category's patterns
match — the manifest's declared tool text never says the tool refuses an
instruction-override attempt, never says it withholds data from external
destinations, and so on. Absence of defensive language is the signal.

Reuses the same YAML catalog compiler every other scanner uses
(harness.adapters.scanners.injection_scan._compile_catalog_with_l10n) — same
lint, same meta.category/match/strings shape, same five-locale convention —
but does its own presence check instead of InjectionScanner's scoring model,
since "did any pattern in this category match" has no severity ladder to
climb.

Runs inside `shai mcp onboard` (harness.mcp.onboard) against the manifest's
own declared tool name/description text — never a live server response.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from pathlib import Path
from typing import Any

from harness.adapters.scanners.base import ScanResult
from harness.adapters.scanners.injection_scan import (
    _compile_catalog_with_l10n,
    _CompiledRule,
    _normalize,
)
from harness.core.types import Severity
from harness.core.verdicts import Finding

log = logging.getLogger(__name__)

_PATTERNS_FILE = Path(__file__).parent / "l10n" / "prompt_defense_patterns.yaml"


def _rule_matches(rule: _CompiledRule, normalized_text: str) -> bool:
    """True if any signal group in this rule matches the (already-normalized)
    text — presence, not scoring; a defense category needs just one hit."""
    for group in rule.signal_groups:
        for cp in group.patterns:
            try:
                if cp.kind == "hex":
                    if cp.value in normalized_text:
                        return True
                elif cp.value.search(normalized_text):
                    return True
            except Exception as e:  # nosec B112 — malformed pattern, skip it
                log.debug("prompt_defense pattern match error: %s", e)
                continue
    return False


class PromptDefenseScanner:
    """Flags MCP manifest tool text carrying no defensive language for a
    given attack category. Stateless — safe for concurrent use.
    """

    name = "prompt_defense"
    method_family = "regex_catalog"

    def __init__(
        self,
        patterns_file: Path | None = None,
        extra_rules: list[_CompiledRule] | None = None,
    ) -> None:
        primary = patterns_file or _PATTERNS_FILE
        catalog = _compile_catalog_with_l10n(Path(primary))
        if extra_rules:
            catalog = catalog + extra_rules

        # Group by category — the primary (English) rule and its l10n
        # siblings share one category and defend it together: a match in
        # any locale satisfies the category, so grouping (not per-rule) is
        # the unit "does this manifest show this defense" is evaluated at.
        by_category: dict[str, list[_CompiledRule]] = defaultdict(list)
        for rule in catalog:
            by_category[rule.category].append(rule)
        self._categories: dict[str, list[_CompiledRule]] = dict(by_category)
        log.debug("PromptDefenseScanner initialised",
                  extra={"patterns_file": str(primary),
                         "categories": len(self._categories)})

    async def scan_tool(
        self,
        mcp_tool: dict[str, Any],
        *,
        source_name: str = "unknown",
    ) -> ScanResult:
        """Scan one manifest-declared tool dict ({"name", "description"}).

        Never raises — a malformed pattern is skipped, logged, and treated as
        non-matching (see _rule_matches).
        """
        name = str(mcp_tool.get("name") or "").strip()
        description = str(mcp_tool.get("description") or "").strip()
        text = " ".join(part for part in (name, description) if part)
        if not text:
            return ScanResult()

        normalized = _normalize(text)
        findings: list[Finding] = []
        for category, rules in self._categories.items():
            if any(_rule_matches(r, normalized) for r in rules):
                continue
            representative = rules[0]
            findings.append(Finding(
                scanner=self.name,
                category=category,
                severity=Severity(representative.severity),
                # Names only the category — never the scanned text (Invariant 3).
                detail=f"no defensive language found for category: {category}",
                method_family=self.method_family,
            ))

        if findings:
            log.debug("prompt defense findings",
                      extra={"source": source_name, "tool": name,
                             "categories": [f.category for f in findings]})
        return ScanResult(findings=findings)
