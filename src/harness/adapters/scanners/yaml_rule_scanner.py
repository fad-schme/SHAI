"""YamlRuleScanner — YAML-driven rule engine for text scanning.

Loads pattern rules from a YAML file and runs regex + scoring-function
checks against each prompt. More comprehensive than basic_injection —
intended as a step-up scanner for deployments that need broader coverage.

Pattern files ship with SHAI:
  patterns.yaml          — general prompt injection, jailbreak, PII-adjacent
  patterns_for_doc.yaml  — document-content injection (used by FileScanner)

Rule format (per rule in the YAML):
  name:      identifier
  meta:
    category:      e.g. "prompt_injection"
    threat_level:  int 1-5 (maps to Severity)
  strings:
    a: regex or hex pattern
    b: ...
  functions:         # optional — scoring function names
    - intent_score
    - obfuscation_score

Composite threat score per rule:
  regex matches:  +2 per match
  hex matches:    +1 per match
  function calls: weighted sum (see rule_functions.py)

Severity mapping (total score across all rules):
  ≥ 20 → CRITICAL
  ≥  9 → HIGH
  ≥  5 → MEDIUM
  ≥  2 → LOW
  <  2 → INFO (no block)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

log = logging.getLogger(__name__)

_DEFAULT_PATTERNS = Path(__file__).parent / "patterns.yaml"

# Threshold → Severity
_SEVERITY_LEVELS = [
    (20, Severity.CRITICAL),
    (9,  Severity.HIGH),
    (5,  Severity.MEDIUM),
    (2,  Severity.LOW),
    (0,  Severity.INFO),
]

# Weighted scoring for function contributions
_FUNCTION_WEIGHTS: dict[str, float] = {
    "intent_score":             1.5,
    "structure_score":          1.0,
    "encoding_score":           1.0,
    "persona_score":            1.2,
    "cumulative_soft_triggers": 1.0,
    "token_score":              1.0,
    "obfuscation_score":        1.2,
    "invisible_text":           1.0,
}


def _load_scoring_functions() -> dict[str, Any]:
    """Import rule_functions if available. Returns empty dict on miss."""
    try:
        from harness.adapters.scanners.rule_functions import (
            intent_score,
            structure_score,
            encoding_score,
            persona_score,
            cumulative_soft_triggers,
            token_score,
            obfuscation_score,
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
        log.warning("rule_functions not available — scoring functions disabled")
        return {}


def _severity_for_score(score: float) -> Severity:
    for threshold, sev in _SEVERITY_LEVELS:
        if score >= threshold:
            return sev
    return Severity.INFO


def _normalize(text: str) -> str:
    """Lowercase, collapse whitespace. Matches basescanner.normalize_prompt."""
    import string
    text = text.lower()
    text = text.translate(str.maketrans("", "", string.punctuation))
    return " ".join(text.split())


class YamlRuleScanner:
    """YAML-driven text scanner.

    Satisfies Scanner Protocol structurally.
    Loads pattern rules from a YAML file at construction time.
    No external dependencies beyond PyYAML (already required by harness).
    """

    name = "yaml_rules"

    def __init__(
        self,
        patterns_file: str | Path | None = None,
        name: str = "yaml_rules",
    ) -> None:
        self.name = name
        self._patterns_file = Path(patterns_file) if patterns_file else _DEFAULT_PATTERNS
        self._patterns: list[dict] = []
        self._functions = _load_scoring_functions()
        self._load()

    def _load(self) -> None:
        try:
            with open(self._patterns_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            self._patterns = data.get("patterns", [])
            log.info("yaml_rule_scanner loaded %d patterns from %s",
                     len(self._patterns), self._patterns_file)
        except Exception as e:
            log.error("failed to load pattern file %s: %s", self._patterns_file, e)
            self._patterns = []

    # ── Pattern compilation ───────────────────────────────────────────────

    def _compile(self, entry: dict) -> dict[str, dict]:
        """Compile string patterns for one rule. Returns {key: {type, pattern}}."""
        compiled: dict[str, dict] = {}
        strings = entry.get("strings", {})

        # Handle both dict-style {a: pattern} and list-style content safety words
        if isinstance(strings, dict):
            for key, val in strings.items():
                if not isinstance(val, str):
                    continue  # skip list values (content safety word lists)
                val = val.strip()
                try:
                    if val.startswith("{") and val.endswith("}"):
                        hex_str = val.strip("{} ").replace(" ", "")
                        compiled[key] = {"type": "hex", "pattern": bytes.fromhex(hex_str)}
                    else:
                        compiled[key] = {"type": "regex",
                                         "pattern": re.compile(val, re.IGNORECASE)}
                except Exception as exc:
                    log.debug("pattern compile error in rule %s key %s: %s",
                              entry.get("name"), key, exc)
        return compiled

    def _match(
        self, text: str, text_bytes: bytes, compiled: dict[str, dict]
    ) -> list[str]:
        matched = []
        for key, item in compiled.items():
            try:
                if item["type"] == "regex" and item["pattern"].search(text):
                    matched.append(key)
                elif item["type"] == "hex" and item["pattern"] in text_bytes:
                    matched.append(key)
            except Exception:
                pass
        return matched

    # ── Word-list matching (content safety rules) ─────────────────────────

    def _match_word_lists(
        self, text: str, entry: dict
    ) -> tuple[int, str | None]:
        """Check severity-graded word lists (profanity, hate speech, etc.).

        Returns (score, highest_severity_label | None).
        """
        strings = entry.get("strings", {})
        severity_weights = {"mild": 1, "moderate": 3, "severe": 5}
        best: str | None = None
        total = 0

        for level, weight in severity_weights.items():
            words = strings.get(level, [])
            if not isinstance(words, list):
                continue
            for word in words:
                if re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE):
                    total += weight
                    best = level

        return total, best

    # ── Core scan ─────────────────────────────────────────────────────────

    def _run(self, raw_text: str) -> list[dict]:
        """Run all rules. Returns list of match dicts."""
        normalized = _normalize(raw_text)
        text_bytes = raw_text.encode("utf-8", errors="ignore")
        results = []
        regex_score = 0.0
        func_score  = 0.0

        for entry in self._patterns:
            rule_name = entry.get("name", "unknown")
            category  = entry.get("meta", {}).get("category", "unknown")
            strings   = entry.get("strings", {})

            # Word-list style (content safety)
            if any(isinstance(v, list) for v in strings.values()):
                score, level = self._match_word_lists(normalized, entry)
                if score > 0:
                    regex_score += score
                    results.append({
                        "rule_name": rule_name,
                        "category":  category,
                        "score":     score,
                        "detail":    f"{category} ({level})",
                    })
                continue

            # Regex/hex style
            compiled     = self._compile(entry)
            matched_keys = self._match(normalized, text_bytes, compiled)

            if matched_keys:
                rule_score = sum(
                    2 if compiled[k]["type"] == "regex" else 1
                    for k in matched_keys
                )
                regex_score += rule_score
                results.append({
                    "rule_name": rule_name,
                    "category":  category,
                    "score":     rule_score,
                    "detail":    f"{category} pattern matched",
                })

            # Scoring functions
            for fname in entry.get("functions", []):
                fn = self._functions.get(fname)
                if fn is None:
                    continue
                try:
                    contribution = fn(normalized)
                    if isinstance(contribution, (int, float)) and contribution > 0:
                        weighted = contribution * _FUNCTION_WEIGHTS.get(fname, 1.0)
                        func_score += weighted
                        results.append({
                            "rule_name": fname,
                            "category":  "function_score",
                            "score":     weighted,
                            "detail":    f"scoring function {fname}",
                        })
                except Exception as exc:
                    log.debug("scoring function %s failed: %s", fname, exc)

        return results

    # ── Public interface ──────────────────────────────────────────────────

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not self._patterns:
            return ScanResult()

        matches = self._run(text)
        if not matches:
            return ScanResult()

        total_score = sum(m["score"] for m in matches)
        categories  = {m["category"] for m in matches}
        # Category diversity bonus — breadth of attack surface
        score = total_score + len(categories)

        severity = _severity_for_score(score)

        # One Finding per unique category, not per pattern match —
        # keeps audit events compact and never includes matched text
        findings: list[Finding] = []
        seen: set[str] = set()
        for match in matches:
            cat = match["category"]
            if cat not in seen:
                seen.add(cat)
                findings.append(Finding(
                    scanner=self.name,
                    category=cat,
                    severity=severity,
                    detail=match["detail"],
                ))

        return ScanResult(findings=findings)
