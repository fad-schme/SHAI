"""injection_scan.py — YAML-driven injection-pattern scanner.

Default pattern catalog: injection_patterns.yaml (ships with harness).
Shared rules live in injection_common.yaml. File content additionally loads
the patterns_for_doc.yaml overlay.

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
    match:
      all:
        - name: action
          any: [key_a]
        - name: target
          any: [key_b]
    functions:              # optional — called only when strings matched
      - intent_score
      - obfuscation_score
"""
from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from typing import Any

import yaml

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

log = logging.getLogger(__name__)

_DEFAULT_PATTERNS = Path(__file__).parent / "l10n" / "injection_patterns.yaml"
_COMMON_PATTERNS = Path(__file__).parent / "l10n" / "injection_common.yaml"

# ── Compiled catalog types ────────────────────────────────────────────────

@dataclass(frozen=True)
class _CompiledPattern:
    key:   str
    kind:  str   # "regex" | "hex"
    value: Any   # compiled re.Pattern | hex-string


@dataclass(frozen=True)
class _CompiledSignalGroup:
    """One semantic evidence group.

    A ``match: any`` rule has one group per string. A compound rule has one
    group per ``match.all`` item and only matches when every group fires.
    Multiple regex alternatives inside one group contribute one evidence unit,
    preventing synonyms and translations from inflating the score.
    """

    name:       str
    patterns:   tuple  # tuple[_CompiledPattern]


@dataclass(frozen=True)
class _CompiledRule:
    name:           str
    semantic_name:  str
    severity:       str    # "low" | "medium" | "high"
    category:       str
    threat_level:   int
    signal_groups:  tuple  # tuple[_CompiledSignalGroup]
    match_mode:     str    # "any" | "all"
    within_chars:   int | None
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
            cumulative_soft_triggers,
            encoding_score,
            intent_score,
            invisible_text,
            obfuscation_score,
            persona_score,
            structure_score,
            token_score,
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


_SHAI_SEVERITY: dict[str, Severity] = {
    "low":    Severity.LOW,
    "medium": Severity.MEDIUM,
    "high":   Severity.HIGH,
}


# ── Catalog compilation ───────────────────────────────────────────────────

_LOCALE_PREFIX_RE = re.compile(r"^[a-z]{2}(?:-[a-z]{2})?\.", re.IGNORECASE)
_LOCALE_SUFFIX_RE = re.compile(r"_(?:fr|es|de|zh)$", re.IGNORECASE)


def _canonical_semantic_name(value: str) -> str:
    """Return a stable evidence name across localized catalog variants."""
    canonical = _LOCALE_PREFIX_RE.sub("", value.strip())
    if canonical.startswith("doc."):
        canonical = canonical[4:]
    canonical = _LOCALE_SUFFIX_RE.sub("", canonical)
    canonical = re.sub(r"[^a-z0-9_.-]+", "_", canonical.lower()).strip("_.-")
    return canonical or "unnamed"


def _compile_signal_groups(
    rule: dict,
    patterns: list[_CompiledPattern],
) -> tuple[tuple[_CompiledSignalGroup, ...], str]:
    """Compile the required explicit ``any`` or AND-of-ORs expression."""
    match = rule.get("match")
    if match == "any":
        return (
            tuple(
                _CompiledSignalGroup(
                    name=_canonical_semantic_name(pattern.key),
                    patterns=(pattern,),
                )
                for pattern in patterns
            ),
            "any",
        )

    all_groups = match["all"]
    by_key = {pattern.key: pattern for pattern in patterns}
    groups: list[_CompiledSignalGroup] = []
    for index, raw_group in enumerate(all_groups, start=1):
        references = raw_group["any"]
        referenced_patterns = tuple(by_key[reference] for reference in references)
        explicit_name = raw_group.get("name")
        if explicit_name:
            group_name = _canonical_semantic_name(explicit_name)
        else:
            semantic_references = sorted(
                {
                    _canonical_semantic_name(reference)
                    for reference in references
                    if isinstance(reference, str)
                }
            )
            group_name = "_or_".join(semantic_references) or f"group_{index}"
        groups.append(_CompiledSignalGroup(name=group_name, patterns=referenced_patterns))

    return tuple(groups), "all"


def compile_rules_from_dicts(rules: list[dict]) -> list[_CompiledRule]:
    """Compile raw rule dicts into _CompiledRule objects.

    The one compiler for both rule sources: the bundled YAML catalogs (via
    _compile_catalog) and the signed pattern DB, where from_yaml() calls this
    after load_verified_rules() has dropped rows failing HMAC verification.

    Rules are validated before compilation. Invalid metadata, regexes, match
    expressions, or signal references raise ValueError; development catalogs
    and signed rules use the same strict schema.
    """
    from harness.adapters.scanners.catalog_lint import lint_catalog

    issues = lint_catalog({"patterns": rules})
    if issues:
        message = "\n".join(str(issue) for issue in issues)
        raise ValueError(f"invalid pattern catalog:\n{message}")

    compiled: list[_CompiledRule] = []
    for rule in rules:
        meta     = rule["meta"]
        strings  = rule["strings"]
        patterns: list[_CompiledPattern] = []

        for key, pat in strings.items():
            pat = pat.strip()
            if pat.startswith("{") and pat.endswith("}"):
                hex_str = pat.strip("{} ").replace(" ", "").lower()
                patterns.append(_CompiledPattern(key=key, kind="hex", value=hex_str))
            else:
                patterns.append(_CompiledPattern(
                    key=key, kind="regex",
                    value=re.compile(pat, re.MULTILINE),
                ))

        signal_groups, match_mode = _compile_signal_groups(rule, patterns)
        match = rule["match"]
        within_chars = match.get("within_chars") if isinstance(match, dict) else None
        semantic_id = meta.get("semantic_id")
        semantic_name = (
            semantic_id
            if isinstance(semantic_id, str) and semantic_id.strip()
            else str(rule["name"])
        )

        compiled.append(_CompiledRule(
            name=rule["name"],
            semantic_name=_canonical_semantic_name(semantic_name),
            severity=meta["severity"],
            category=meta["category"],
            threat_level=meta["threat_level"],
            signal_groups=signal_groups,
            match_mode=match_mode,
            within_chars=within_chars,
            function_names=tuple(rule.get("functions", [])),
        ))
    return compiled


def compile_rules_incrementally(
    rules: list[dict], *, source: str
) -> list[_CompiledRule]:
    """Compile rules one at a time, dropping and logging the invalid ones.

    For rule sets that arrive incrementally and partially trusted — the signed
    pattern DB, where operators add rules over time. HMAC verification already
    drops a tampered row without failing the rest; compiling the survivors as
    one batch would undo that, letting a single malformed rule take down every
    other rule in the bundle along with startup. A bad rule costs that rule.

    Bundled catalogs use compile_rules_from_dicts instead and fail loud — see
    _compile_catalog.
    """
    compiled: list[_CompiledRule] = []
    dropped = 0
    for rule in rules:
        name = rule.get("name", "<unnamed>") if isinstance(rule, dict) else "<not-a-mapping>"
        try:
            compiled.extend(compile_rules_from_dicts([rule]))
        except (ValueError, KeyError, TypeError, re.error) as e:
            dropped += 1
            log.warning(
                "pattern rule rejected — skipped",
                extra={"op": "compile_db_rules", "source": source,
                       "rule": name, "error": str(e)},
            )
    if dropped:
        log.warning("%d of %d rules from %s were rejected",
                    dropped, len(rules), source)
    return compiled


def _compile_catalog(path: Path) -> list[_CompiledRule]:
    """Read a bundled YAML catalog and compile its `patterns` list.

    Fails loud on every kind of broken: unreadable, unparseable, not a mapping,
    or lint-rejected. These files ship inside the package, so a broken one is a
    build error, not a runtime condition to degrade around.

    The alternative — returning [] and carrying on — is worse than it looks: a
    scanner with an empty catalog returns ScanResult() for every input and is
    indistinguishable from one that is working and finding nothing. Silently
    scanning nothing is the failure mode this boundary exists to prevent.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"cannot load pattern catalog {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"pattern catalog {path} must contain a YAML mapping, "
            f"got {type(data).__name__}"
        )

    if "patterns" not in data:
        raise ValueError(
            f"pattern catalog {path} has no 'patterns' key — an empty catalog "
            f"must say so explicitly with 'patterns: []'"
        )

    # `patterns: []` is allowed and means what it says. The failure this guards
    # against is a catalog that *should* have rules and silently loaded none;
    # an explicitly empty one is a deliberate base for extra_rules to build on.
    compiled = compile_rules_from_dicts(data["patterns"])
    log.info("compiled %d rules from %s", len(compiled), path.name)
    return compiled


# ── Text normalisation ────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """NFKC-normalise, lowercase, collapse whitespace. Called once per scan.

    Not redundant with core.normalize.canonicalize, despite the overlap. That
    runs inside run_scan, and two callers reach this scanner without it:
    MCPMetadataScanner (tool metadata at connect time) and FileContentScanner
    (text extracted from a document). On those paths this is the only folding
    the catalog gets, so removing it would reopen the homoglyph and
    whitespace-padding bypass exactly where the content is least trusted.
    """
    text = unicodedata.normalize("NFKC", text)
    text = text.lower()
    return " ".join(text.split())


# Ceiling on the proximity search below. The search is a backtracking walk over
# one span per signal group, so its worst case is the product of the group span
# counts — on text an attacker writes. Groups are visited fewest-spans-first and
# a partial window wider than within_chars prunes immediately, so real payloads
# settle in a handful of steps; this bounds the pathological ones.
_WITHIN_SEARCH_BUDGET = 20_000


def _groups_fit_within(
    spans_by_group: list[list[tuple[int, int]]],
    within_chars: int,
) -> bool:
    """Return whether one match from every group fits in a bounded window.

    Fails **closed** on budget exhaustion — an input crafted to blow up the
    search counts as satisfying the proximity constraint, so the rule still
    fires and the finding is still reported. Failing open would turn the
    budget into a bypass: pad the text until the search gives up and the
    compound rule stops matching.
    """
    ordered = sorted(spans_by_group, key=len)
    budget = _WITHIN_SEARCH_BUDGET

    def visit(index: int, start: int | None, end: int | None) -> bool:
        nonlocal budget
        if index == len(ordered):
            return True
        for span_start, span_end in ordered[index]:
            budget -= 1
            if budget <= 0:
                log.debug(
                    "within_chars proximity search exhausted its budget — "
                    "treating the rule as matched",
                    extra={"groups": len(ordered), "within_chars": within_chars},
                )
                return True
            next_start = span_start if start is None else min(start, span_start)
            next_end = span_end if end is None else max(end, span_end)
            if next_end - next_start > within_chars:
                continue
            if visit(index + 1, next_start, next_end):
                return True
        return False

    return visit(0, None, None)


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

    Subclassing: a scanner that differs only in catalog and name sets the
    `name` and `default_patterns` class attributes and inherits this
    `__init__`. Do not override it to swap the catalog — an override has to
    forward every constructor parameter by hand, and forgetting one is how
    `extra_rules` from the signed pattern DB came to raise `TypeError` on the
    two subclasses that had one.
    """

    name = "injection_scan"
    method_family = "regex_catalog"
    default_patterns: Path = _DEFAULT_PATTERNS
    common_patterns: tuple[Path, ...] = (_COMMON_PATTERNS,)

    def __init__(
        self,
        patterns_file: str | Path | None = None,
        additional_patterns_files: tuple[str | Path, ...] = (),
        extra_rules: list[_CompiledRule] | None = None,
        name: str | None = None,
    ) -> None:
        self.name        = name or type(self).name
        primary          = (Path(patterns_file) if patterns_file
                            else type(self).default_patterns)
        # Every catalog this scanner reads, in load order. Shared rules first
        # (skipped when the caller names an explicit primary — that call is
        # asking for one specific catalog), then the primary, then any overlay.
        self._paths      = (
            *(type(self).common_patterns if patterns_file is None else ()),
            primary,
            *(Path(path) for path in additional_patterns_files),
        )
        self._catalog    = [
            rule
            for path in self._paths
            for rule in _compile_catalog_with_l10n(path)
        ]
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
        matched_signal_groups: list[tuple[str, ...]] = []
        semantic_evidence: set[tuple[str, str]] = set()
        scored_functions: set[tuple[str, str]] = set()
        regex_score    = 0.0
        function_score = 0.0
        has_high_rule  = False

        for rule in self._catalog:
            matched_groups: list[str] = []
            group_evidence: list[tuple[str, str]] = []
            group_spans: list[list[tuple[int, int]]] = []
            for group in rule.signal_groups:
                group_matched = False
                spans: list[tuple[int, int]] = []
                for cp in group.patterns:
                    try:
                        if cp.kind == "hex":
                            group_matched = cp.value in text_bytes_hex
                            if group_matched and rule.within_chars is not None:
                                byte_index = text_bytes_hex.find(cp.value) // 2
                                spans.append((byte_index, byte_index + len(cp.value) // 2))
                        else:
                            if rule.within_chars is None:
                                group_matched = cp.value.search(normalized) is not None
                            else:
                                spans.extend(
                                    match.span()
                                    for match in islice(cp.value.finditer(normalized), 32)
                                )
                                group_matched = bool(spans)
                    except Exception as pat_err:  # nosec B112 — malformed pattern; skip signal, do not abort scan
                        log.debug("pattern match error in rule scan: %s", pat_err)
                        continue
                    if group_matched:
                        break

                if group_matched:
                    matched_groups.append(group.name)
                    group_evidence.append((rule.semantic_name, group.name))
                    group_spans.append(spans)
                elif rule.match_mode == "all":
                    matched_groups = []
                    group_evidence = []
                    break

            if (
                matched_groups
                and rule.match_mode == "all"
                and rule.within_chars is not None
                and not _groups_fit_within(group_spans, rule.within_chars)
            ):
                matched_groups = []
                group_evidence = []

            if not matched_groups:
                continue

            new_evidence = set(group_evidence) - semantic_evidence
            regex_score += 2.0 * len(new_evidence)
            semantic_evidence.update(new_evidence)
            matched_rules.append(rule.name)
            matched_categories.append(rule.category)
            matched_signal_groups.append(tuple(matched_groups))
            if rule.severity == "high":
                has_high_rule = True

            # Scoring functions — only because this rule's regex matched
            for fn_name in rule.function_names:
                function_key = (rule.semantic_name, fn_name)
                if function_key in scored_functions:
                    continue
                fn = self._functions.get(fn_name)
                if fn is None:
                    continue
                try:
                    contribution = float(fn(text))
                    function_score += contribution * _FUNCTION_WEIGHTS.get(fn_name, 1.0)
                    scored_functions.add(function_key)
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
        category_matches: dict[str, dict[str, Any]] = {}
        for rule_name, category, signal_groups in zip(
            matched_rules,
            matched_categories,
            matched_signal_groups,
        ):
            record = category_matches.setdefault(
                category,
                {"rule_name": rule_name, "signal_groups": []},
            )
            for signal_group in signal_groups:
                if signal_group not in record["signal_groups"]:
                    record["signal_groups"].append(signal_group)

        for category, record in category_matches.items():
            findings.append(Finding(
                scanner=self.name,
                category=category,
                severity=shai_severity,
                detail=(
                    f"{category} — matched rule: {record['rule_name']}; "
                    f"signal groups: {', '.join(record['signal_groups'])}"
                ),
            ))

        return ScanResult(findings=findings)
