"""heuristic_scan.py — structural anomaly scanner.

Always on — appended by _build_text_scanners when not explicitly declared.
Declaring it in harness.yaml only controls its position and per-scanner action.
Catches patterns regex catalogs miss: obfuscated payloads, instruction-dense
text, register shifts, and embedded markup in natural language.

Four sub-scores (each 0–2). Sum ≥ 5 → HIGH, ≥ 3 → MEDIUM, ≥ 1 → LOW.
No dependencies. No ML.
"""
from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass

from harness.adapters.scanners.base import ScanResult
from harness.core.context import AgentContext
from harness.core.types import Severity
from harness.core.verdicts import Finding

# Raised from 4.5 → 4.8: natural dense English (code comments, tables, URLs)
# brushes 4.5 over a 64-char window and produced low-grade false positives.
# base64/hex payloads sit well above 5.0, so recall on real obfuscation is
# unaffected.
_ENTROPY_THRESHOLD = 4.8
_ENTROPY_WINDOW = 64
_DENSITY_THRESHOLD = 0.08

_CONTROL_TOKENS = frozenset({
    # imperative / override verbs
    "ignore", "override", "forget", "disregard", "bypass", "skip",
    "instead", "always", "never", "must", "execute", "run", "call",
    "output", "print", "reveal", "repeat", "respond", "pretend",
    # agentic action verbs — tool coercion and exfiltration surface
    "invoke", "fetch", "download", "upload", "send", "forward", "export",
    "delete", "disable", "enable", "grant", "escalate", "elevate",
    "leak", "exfiltrate", "transmit", "post", "curl", "wget",
    # instruction-framing tokens
    "system", "assistant", "instructions", "prompt", "act", "simulate",
})

_STRUCTURAL_RE = re.compile(
    r"<\|(?:system|user|assistant|im_start|im_end)\|>"
    r"|\[/?INST\]"
    r"|<<SYS>>|<</SYS>>"
    r"|\[(?:system|assistant|user)\]\s*[:>]"
    r"|### (?:Instruction|System|Response)"
    r"|```(?:system|tool_call)"
    r"|</?(?:system|tool_use|function_call|result)>"
    r"|\{\"(?:role|function|tool_calls)\":",
    re.IGNORECASE,
)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _entropy_score(text: str) -> float:
    """0–2: sliding window entropy over the text."""
    if len(text) < _ENTROPY_WINDOW:
        e = _shannon_entropy(text)
        return min(2.0, max(0.0, (e - _ENTROPY_THRESHOLD) * 2.0)) if e > _ENTROPY_THRESHOLD else 0.0
    max_e = 0.0
    for i in range(0, len(text) - _ENTROPY_WINDOW + 1, _ENTROPY_WINDOW // 2):
        e = _shannon_entropy(text[i : i + _ENTROPY_WINDOW])
        if e > max_e:
            max_e = e
    if max_e <= _ENTROPY_THRESHOLD:
        return 0.0
    return min(2.0, (max_e - _ENTROPY_THRESHOLD) * 2.0)


def _instruction_density_score(text: str) -> float:
    """0–2: ratio of control tokens to total tokens."""
    tokens = text.lower().split()
    if len(tokens) < 5:
        return 0.0
    hits = sum(1 for t in tokens if t.rstrip(".:,;!?") in _CONTROL_TOKENS)
    density = hits / len(tokens)
    if density <= _DENSITY_THRESHOLD:
        return 0.0
    return min(2.0, (density - _DENSITY_THRESHOLD) / _DENSITY_THRESHOLD * 2.0)


def _coherence_score(text: str) -> float:
    """0–2: bigram divergence between first and second half."""
    normalized = unicodedata.normalize("NFKC", text).lower()
    if len(normalized) < 40:
        return 0.0
    mid = len(normalized) // 2
    first = Counter(normalized[i : i + 2] for i in range(mid - 1))
    second = Counter(normalized[i : i + 2] for i in range(mid, len(normalized) - 1))
    all_bg = set(first) | set(second)
    if not all_bg:
        return 0.0
    intersection = sum(min(first[b], second[b]) for b in all_bg)
    union = sum(max(first[b], second[b]) for b in all_bg)
    divergence = 1.0 - (intersection / union if union else 1.0)
    if divergence < 0.6:
        return 0.0
    return min(2.0, (divergence - 0.6) * 5.0)


def _structural_score(text: str) -> float:
    """0–2: count of embedded markup patterns."""
    matches = _STRUCTURAL_RE.findall(text)
    if not matches:
        return 0.0
    return min(2.0, len(matches) * 0.7)


# ── Typoglycemia sub-score ────────────────────────────────────────────────
# OWASP LLM Prompt Injection Prevention cheat sheet lists typoglycemia as a
# distinct attack class (arxiv.org/abs/2410.01677): scrambled keywords like
# "ignroe / prevoius / delte / revael" that literal regex catalogs cannot see
# because they compare against exact spellings. Handled here as a heuristic
# sub-score so it runs on every text regardless of catalog match.
#
_TYPO_ACTIONS = frozenset({
    "ignore", "override", "bypass", "reveal", "disable", "delete", "exfiltrate",
    "exfil", "disregard", "forget", "expose", "leak", "escalate", "elevate",
    "cancel", "remove", "eliminate", "circumvent", "suspend", "deactivate",
    "grant", "forward", "execute", "turn",
})

_TYPO_PROTECTED_OBJECTS = frozenset({
    "instruction", "instructions", "prompt", "system", "safety", "filter",
    "filters", "restriction", "restrictions", "credential", "credentials",
    "admin", "guardrail", "guardrails", "security", "policy", "password",
    "passwords", "secret", "secrets", "alignment", "context",
    "programming", "conversation", "transcript", "transcripts",
})

_TYPO_EXECUTION_DESTINATIONS = frozenset({
    "attacker", "external", "email", "webhook", "shell", "account", "url",
})

_LEETSPEAK_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
})

_FRAGMENTED_TOKEN_RE = re.compile(r"\b(?:[a-z0-9][.-]){3,}[a-z0-9]\b")
_SEPARATOR_CHAIN_RE = re.compile(r"\b(?:[a-z0-9]{3,}[.-]){3,}[a-z0-9]{3,}\b")
_RAW_FUZZY_TOKEN_RE = re.compile(r"[a-z0-9]{4,}")
_FUZZY_TOKEN_RE = re.compile(r"[a-z]{4,}")


@dataclass(frozen=True)
class _FuzzyIntent:
    score: float
    actions: frozenset[str]
    protected_objects: frozenset[str]
    execution_destinations: frozenset[str]
    has_obfuscation: bool

    @property
    def is_compound_attack(self) -> bool:
        return bool(self.actions and self.protected_objects and self.has_obfuscation)


def _bounded_dl_distance(a: str, b: str, limit: int) -> int | None:
    """Bounded optimal-string-alignment distance, including transpositions."""
    if abs(len(a) - len(b)) > limit:
        return None

    previous_previous: list[int] | None = None
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        row_min = i
        for j, char_b in enumerate(b, start=1):
            cost = 0 if char_a == char_b else 1
            distance = min(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + cost,
            )
            if (
                previous_previous is not None
                and i > 1
                and j > 1
                and char_a == b[j - 2]
                and a[i - 2] == char_b
            ):
                distance = min(distance, previous_previous[j - 2] + 1)
            current.append(distance)
            row_min = min(row_min, distance)
        if row_min > limit:
            return None
        previous_previous, previous = previous, current

    return previous[-1] if previous[-1] <= limit else None


def _typoglycemia_match_kind(word: str, target: str) -> str | None:
    """Return ``strong`` or ``weak`` when word is a bounded fuzzy variant.

    Anagram-style scramble (same length, same first + last letter, sorted
    middle equal) OR bounded Damerau-Levenshtein distance with the additional
    constraint that neither word is a prefix of the other. The prefix check
    rejects English morphological forms — every real typoglycemia example
    changes the middle of the word (`ignroe`, `delte`, `ovverride`,
    `securty`), while every morphological variant appends at the end
    (`ignored`, `filters`, `systems`, `disabled`). Rejecting prefix pairs
    eliminates a whole class of false positives without weakening the
    attack signal.

    Word must be at least length 4 to reduce noise on short tokens.
    """
    if len(word) < 4 or len(target) < 4:
        return None
    if word == target:
        return None
    # Anagram scramble — cheap, catches the OWASP-cited pattern
    if (len(word) == len(target)
            and word[0] == target[0] and word[-1] == target[-1]
            and sorted(word[1:-1]) == sorted(target[1:-1])):
        return "strong"
    distance_limit = 2 if min(len(word), len(target)) >= 7 else 1
    if _bounded_dl_distance(word, target, distance_limit) is None:
        return None
    # Prefix-relationship rejection: one is the other + trailing chars →
    # morphological form, not typoglycemia.
    if word.startswith(target):
        return None
    # Insertions/deletions are strong obfuscation evidence. Same-length
    # substitutions can collide with ordinary words ("peak" → "leak",
    # "content" → "context"), so they are weak and need corroborating fuzzy
    # evidence from both the action and object classes.
    return "strong" if len(word) != len(target) else "weak"


def _normalize_fuzzy_text(text: str) -> tuple[list[str], frozenset[str]]:
    normalized = unicodedata.normalize("NFKC", text).lower()
    transformed_tokens: set[str] = set()

    for original_token in re.findall(r"[A-Za-z]{4,}", text):
        uppercase_count = sum(char.isupper() for char in original_token)
        lowercase_count = sum(char.islower() for char in original_token)
        if uppercase_count >= 2 and lowercase_count >= 2:
            transformed_tokens.add(original_token.lower())

    def join_fragment(match: re.Match[str]) -> str:
        joined = match.group(0).replace(".", "").replace("-", "")
        translated_joined = joined.translate(_LEETSPEAK_TRANSLATION)
        transformed_tokens.add(translated_joined)
        return joined

    joined = _FRAGMENTED_TOKEN_RE.sub(join_fragment, normalized)
    for chain in _SEPARATOR_CHAIN_RE.findall(joined):
        transformed_tokens.update(
            part.translate(_LEETSPEAK_TRANSLATION)
            for part in re.split(r"[.-]+", chain)
        )

    for raw_token in _RAW_FUZZY_TOKEN_RE.findall(joined):
        translated_token = raw_token.translate(_LEETSPEAK_TRANSLATION)
        if translated_token != raw_token:
            transformed_tokens.add(translated_token)

    translated = joined.translate(_LEETSPEAK_TRANSLATION)
    separated = re.sub(r"(?<=[a-z0-9])[.-]+(?=[a-z0-9])", " ", translated)
    return _FUZZY_TOKEN_RE.findall(separated), frozenset(transformed_tokens)


def _match_fuzzy_class(
    tokens: list[str],
    targets: frozenset[str],
    transformed_tokens: frozenset[str],
) -> tuple[frozenset[str], bool, bool, int]:
    matched: set[str] = set()
    fuzzy_targets: set[str] = set()
    fuzzy = False
    strong = False
    for token in tokens:
        if token in targets:
            matched.add(token)
            if token in transformed_tokens:
                fuzzy = True
                strong = True
                fuzzy_targets.add(token)
            continue
        for target in targets:
            if abs(len(token) - len(target)) > 2:
                continue
            match_kind = _typoglycemia_match_kind(token, target)
            if match_kind is not None:
                matched.add(target)
                fuzzy = True
                strong = strong or match_kind == "strong"
                fuzzy_targets.add(target)
                break
    return frozenset(matched), fuzzy, strong, len(fuzzy_targets)


def _fuzzy_intent(text: str) -> _FuzzyIntent:
    """Classify fuzzy action, protected-object, and destination evidence."""
    tokens, transformed_tokens = _normalize_fuzzy_text(text)
    actions, fuzzy_actions, strong_actions, action_fuzzy_count = _match_fuzzy_class(
        tokens,
        _TYPO_ACTIONS,
        transformed_tokens,
    )
    protected, fuzzy_protected, strong_protected, protected_fuzzy_count = _match_fuzzy_class(
        tokens,
        _TYPO_PROTECTED_OBJECTS,
        transformed_tokens,
    )
    destinations, fuzzy_destinations, strong_destinations, destination_fuzzy_count = (
        _match_fuzzy_class(
            tokens,
            _TYPO_EXECUTION_DESTINATIONS,
            transformed_tokens,
        )
    )
    fuzzy_target_count = (
        action_fuzzy_count
        + protected_fuzzy_count
        + destination_fuzzy_count
    )
    has_obfuscation = (
        strong_actions
        or strong_protected
        or strong_destinations
        or (fuzzy_actions and fuzzy_protected)
        or fuzzy_target_count >= 2
    )
    fuzzy_evidence_count = sum((fuzzy_actions, fuzzy_protected, fuzzy_destinations))
    score = min(2.0, fuzzy_evidence_count * 0.8)
    if actions and protected and has_obfuscation:
        score = max(score, 2.0)
    return _FuzzyIntent(
        score=score,
        actions=actions,
        protected_objects=protected,
        execution_destinations=destinations,
        has_obfuscation=has_obfuscation,
    )


def _fuzzy_intent_score(text: str) -> float:
    """Return the fuzzy-intent contribution to the anomaly score."""
    return _fuzzy_intent(text).score


class HeuristicScanner:
    """Structural anomaly scanner. Always on. Satisfies Scanner Protocol."""

    name = "heuristic_scan"
    method_family = "structural_heuristic"

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not text or not text.strip():
            return ScanResult()

        s1 = _entropy_score(text)
        s2 = _instruction_density_score(text)
        s3 = _coherence_score(text)
        s4 = _structural_score(text)
        fuzzy_intent = _fuzzy_intent(text)
        s5 = fuzzy_intent.score

        # Coherence (bigram register-shift) is the weakest sub-score and fires
        # on benign transitions (prose → code block, English → citation). It is
        # only trustworthy as corroboration, so it contributes only when at
        # least one stronger signal is already nonzero.
        if s1 == 0.0 and s2 == 0.0 and s4 == 0.0 and s5 == 0.0:
            s3 = 0.0

        total = s1 + s2 + s3 + s4 + s5

        if total < 1.0 and not fuzzy_intent.is_compound_attack:
            return ScanResult()

        if total >= 5.0:
            severity = Severity.HIGH
        elif total >= 3.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        # The authoritative copy of the sub-scores. `detail` below renders the
        # same numbers for a human; consumers read these. Every finding this
        # scanner emits carries them, so a consumer never has to pick the right
        # one out of the list to get a complete picture.
        signals = {
            "entropy":      s1,
            "density":      s2,
            "coherence":    s3,
            "structural":   s4,
            "fuzzy_intent": s5,
            "total":        total,
        }

        parts = []
        if s1 > 0:
            parts.append(f"entropy={s1:.1f}")
        if s2 > 0:
            parts.append(f"density={s2:.1f}")
        if s3 > 0:
            parts.append(f"coherence={s3:.1f}")
        if s4 > 0:
            parts.append(f"structural={s4:.1f}")
        if s5 > 0:
            parts.append(f"fuzzy_intent={s5:.1f}")

        findings: list[Finding] = []
        if fuzzy_intent.is_compound_attack:
            action_names = ",".join(sorted(fuzzy_intent.actions))
            object_names = ",".join(sorted(fuzzy_intent.protected_objects))
            detail = f"fuzzy compound: actions={action_names}; protected_objects={object_names}"
            if fuzzy_intent.execution_destinations:
                destinations = ",".join(sorted(fuzzy_intent.execution_destinations))
                detail += f"; execution_destinations={destinations}"
            findings.append(Finding(
                scanner=self.name,
                category="typoglycemia_compound",
                severity=Severity.HIGH,
                detail=detail,
                signals=signals,
            ))

        if total >= 1.0:
            findings.append(Finding(
                scanner=self.name,
                category="heuristic_anomaly",
                severity=severity,
                detail=f"total={total:.1f} ({', '.join(parts)})",
                signals=signals,
            ))

        return ScanResult(findings=findings)
