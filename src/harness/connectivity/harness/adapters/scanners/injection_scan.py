"""injection_scan.py — YAML-driven injection-pattern scanner.

Replaces the earlier basic_injection and yaml_rule_scanner implementations.
Default pattern catalog: injection_patterns.yaml (ships with harness).
Alternate catalog for document content: patterns_for_doc.yaml.

Catalog is compiled once at scanner construction — never per call.
Rule functions are only invoked when at least one regex in the rule matched,
so clean text pays only the regex cost with no scoring-function overhead.

Severity is declared per-rule in the YAML catalog (meta.severity).
The numeric score is used as a tiebreaker when multiple rules fire, and
to emit a meaningful Finding.detail. It is not the primary severity signal.

Severity thresholds (score-based override — any matching high-severity rule
also forces severity=high regardless of numeric total):
  score >= 6.0  → HIGH
  score >= 3.0  → MEDIUM
  score >= 1.0  → LOW

Pattern file format
-------------------
patterns:
  - name: rule_name
    meta:
      severity:     high | medium | low
      category:     prompt_injection | tool_injection | obfuscation | …
      threat_level: 1-5
    strings:
      key_a: '(?i)regex pattern'
      key_b: '{hex bytes in braces}'
    functions:              # optional — called only when strings matched
      - intent_score
      - obfuscation_score
"""
from __future__ import annotations

import logging
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

log = logging.getLogger(__name__)

_DEFAULT_PATTERNS = Path(__file__).parent / "l10n" / "injection_patterns.yaml"

# ── Compiled catalog types ────────────────────────────────────────────────

@dataclass(frozen=True)
class _CompiledPattern:
    key:   str
    kind:  str   # "regex" | "hex"
    value: Any   # compiled re.Pattern | hex-string


@dataclass(frozen=True)
class _CompiledRule:
    name:           str
    severity:       str    # "low" | "medium" | "high"
    category:       str
    threat_level:   int
    patterns:       tuple  # tuple[_CompiledPattern]
    function_names: tuple  # tuple[str]


# ── Scoring function registry ─────────────────────────────────────────────

_FUNCTION_WEIGHTS: dict[str, float] = {
    "intent_score":             1.5,
    "structure_score":          1.0,
    "encoding_score":           1.0,
    "persona_score":            1.2,
    "cumulative_soft_triggers": 1.0,
    "token_score":              0.5,  # nosec B105 — scoring weight, not a password
    "obfuscation_score":        1.2,
    "invisible_text":           1.0,
}


def _load_scoring_functions() -> dict[str, Any]:
    try:
        from harness.adapters.scanners.rule_functions import (
            intent_score, structure_score, encoding_score, persona_score,
            cumulative_soft_triggers, token_score, obfuscation_score,
            invisible_text,
        )
        return {
            "intent_score":             intent_score,
            "structure_score":          structure_score,
            "encoding_score":           encoding_score,
            "persona_score":            persona_score,
            "cumulative_soft_triggers": cumulative_soft_triggers,
            "token_score":              token_score,
            "obfuscation_score":        obfuscation_score,
            "invisible_text":           invisible_text,
        }
    except ImportError:
        log.debug("rule_functions not available — scoring functions disabled")
        return {}


# ── Severity helpers ──────────────────────────────────────────────────────

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}

_SHAI_SEVERITY: dict[str, Severity] = {
    "low":    Severity.LOW,
    "medium": Severity.MEDIUM,
    "high":   Severity.HIGH,
}

def _score_to_severity(score: float) -> str:
    if score >= 6.0:
        return "high"
    if score >= 3.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "low"


# ── Catalog compilation ───────────────────────────────────────────────────

def _compile_catalog(path: Path) -> list[_CompiledRule]:
    import re
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        log.error("failed to load pattern file %s: %s", path, e)
        return []

    compiled: list[_CompiledRule] = []
    for rule in data.get("patterns", []):
        meta     = rule.get("meta", {})
        strings  = rule.get("strings", {})
        patterns: list[_CompiledPattern] = []

        for key, pat in strings.items():
            if not isinstance(pat, str):
                continue  # skip word-list values (content-safety rules)
            pat = pat.strip()
            if pat.startswith("{") and pat.endswith("}"):
                hex_str = pat.strip("{} ").replace(" ", "").lower()
                patterns.append(_CompiledPattern(key=key, kind="hex", value=hex_str))
            else:
                try:
                    patterns.append(_CompiledPattern(
                        key=key, kind="regex",
                        value=re.compile(pat, re.MULTILINE),
                    ))
                except re.error:
                    log.warning("bad pattern in rule %s key %s — skipped",
                                rule.get("name"), key)

        compiled.append(_CompiledRule(
            name=rule["name"],
            severity=str(meta.get("severity", "medium")),
            category=str(meta.get("category", "unknown")),
            threat_level=int(meta.get("threat_level", 1)),
            patterns=tuple(patterns),
            function_names=tuple(rule.get("functions", [])),
        ))

    log.info("injection_scan compiled %d rules from %s", len(compiled), path)
    return compiled


def compile_rules_from_dicts(rules: list[dict]) -> list[_CompiledRule]:
    """Compile raw rule dicts (from pattern DB) into _CompiledRule objects.

    Same compilation logic as _compile_catalog but takes dicts instead of
    reading a YAML file. Called by from_yaml() after DB verification.
    """
    import re as _re
    compiled: list[_CompiledRule] = []
    for rule in rules:
        meta    = rule.get("meta", {})
        strings = rule.get("strings", {})
        patterns: list[_CompiledPattern] = []
        for key, pat in strings.items():
            if not isinstance(pat, str):
                continue
            pat = pat.strip()
            if pat.startswith("{") and pat.endswith("}"):
                hex_str = pat.strip("{} ").replace(" ", "").lower()
                patterns.append(_CompiledPattern(key=key, kind="hex", value=hex_str))
            else:
                try:
                    patterns.append(_CompiledPattern(
                        key=key, kind="regex",
                        value=_re.compile(pat, _re.MULTILINE),
                    ))
                except _re.error:
                    log.warning("bad pattern in DB rule %s key %s — skipped",
                                rule.get("name"), key)
        compiled.append(_CompiledRule(
            name=rule["name"],
            severity=str(meta.get("severity", "medium")),
            category=str(meta.get("category", "unknown")),
            threat_level=int(meta.get("threat_level", 1)),
            patterns=tuple(patterns),
            function_names=tuple(rule.get("functions", [])),
        ))
    if compiled:
        log.info("compiled %d rules from pattern DB", len(compiled))
    return compiled


# ── Text normalisation ────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """NFKC-normalise, lowercase, collapse whitespace. Called once per scan."""
    text = unicodedata.normalize("NFKC", text)
    text = text.lower()
    return " ".join(text.split())


# ── Scanner ───────────────────────────────────────────────────────────────

# ── L10N catalog merge ────────────────────────────────────────────────────

def _compile_catalog_with_l10n(path: Path) -> list[_CompiledRule]:
    """Load the primary catalog and auto-merge its .l10n.yaml sibling when present.

    The sibling file is derived by inserting '.l10n' before '.yaml':
        injection_patterns.yaml → injection_patterns.l10n.yaml

    Both files must live in the same directory (the l10n/ folder). The merged
    catalog is the primary rules first, then the multilingual rules appended.
    If no sibling exists the primary catalog is returned unchanged.
    """
    rules = _compile_catalog(path)
    l10n_path = path.parent / (path.stem + ".l10n.yaml")
    if l10n_path.exists():
        l10n_rules = _compile_catalog(l10n_path)
        rules = rules + l10n_rules
        log.info(
            "l10n catalog merged: %d additional rules from %s",
            len(l10n_rules), l10n_path.name,
        )
    return rules


class InjectionScanner:
    """YAML-driven injection-pattern scanner.

    Satisfies the Scanner Protocol structurally.
    Catalog compiled once at construction — never per call.
    Scoring functions only called when at least one regex matched.
    """

    name = "injection_scan"

    def __init__(
        self,
        patterns_file: str | Path | None = None,
        extra_rules: list[_CompiledRule] | None = None,
        name: str = "injection_scan",
    ) -> None:
        self.name        = name
        self._path       = Path(patterns_file) if patterns_file else _DEFAULT_PATTERNS
        self._catalog    = _compile_catalog_with_l10n(self._path)
        if extra_rules:
            self._catalog = self._catalog + extra_rules
        self._functions  = _load_scoring_functions()

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not self._catalog or not text or not text.strip():
            return ScanResult()

        normalized       = _normalize(text)
        text_bytes_hex   = text.encode("utf-8", errors="ignore").hex()

        matched_rules:      list[str] = []
        matched_categories: list[str] = []
        regex_score    = 0.0
        function_score = 0.0
        has_high_rule  = False

        for rule in self._catalog:
            n_matched = 0
            for cp in rule.patterns:
                try:
                    if cp.kind == "hex":
                        if cp.value in text_bytes_hex:
                            n_matched += 1
                    else:
                        if cp.value.search(normalized):
                            n_matched += 1
                except Exception as pat_err:  # nosec B112 — malformed pattern; skip rule, do not abort scan
                    log.debug("pattern match error in rule scan: %s", pat_err)
                    continue

            if n_matched == 0:
                continue

            regex_score += 2.0 * n_matched
            matched_rules.append(rule.name)
            matched_categories.append(rule.category)
            if rule.severity == "high":
                has_high_rule = True

            # Scoring functions — only because this rule's regex matched
            for fn_name in rule.function_names:
                fn = self._functions.get(fn_name)
                if fn is None:
                    continue
                try:
                    contribution = float(fn(text))
                    function_score += contribution * _FUNCTION_WEIGHTS.get(fn_name, 1.0)
                except Exception as fn_err:  # nosec B110 — scoring fn failure degrades gracefully; score stays at 0
                    log.debug("scoring function '%s' failed: %s", fn_name, fn_err)

        if not matched_rules:
            return ScanResult()

        category_bonus = float(len(set(matched_categories)))
        total_score    = regex_score + function_score + category_bonus

        # Severity: rule-declared high overrides numeric total
        if has_high_rule or total_score >= 6.0:
            severity_str = "high"
        elif total_score >= 3.0:
            severity_str = "medium"
        else:
            severity_str = "low"

        shai_severity = _SHAI_SEVERITY.get(severity_str, Severity.LOW)

        # One Finding per unique category — keeps audit events compact
        findings: list[Finding] = []
        seen: set[str] = set()
        for rule_name, category in zip(matched_rules, matched_categories):
            if category not in seen:
                seen.add(category)
                findings.append(Finding(
                    scanner=self.name,
                    category=category,
                    severity=shai_severity,
                    detail=f"{category} — matched rule: {rule_name}",
                ))

        return ScanResult(findings=findings)
