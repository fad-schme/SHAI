"""heuristic_scan.py — structural anomaly scanner.

Always on. Not configurable — prepended by _build_text_scanners.
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
# Keywords are the intent-space of injection: override verbs plus their
# common objects (system, prompt, filter, credentials). Kept small to keep
# the O(tokens × keywords) loop cheap and to limit false positives.
_TYPOGLYCEMIA_KEYWORDS = frozenset({
    "ignore", "override", "forget", "disregard", "bypass", "reveal", "delete",
    "execute", "invoke", "escalate", "elevate", "disable", "expose", "leak",
    "system", "instructions", "prompt", "filter", "filters", "restriction",
    "restrictions", "guardrail", "guardrails", "safety", "security",
    "password", "credential", "credentials", "secret", "admin", "root",
})


def _dl_distance_le_1(a: str, b: str) -> bool:
    """True iff the Damerau-Levenshtein distance between a and b is ≤ 1.

    Faster and simpler than computing the full distance matrix — we only need
    to know whether it clears the threshold. Covers one substitution, one
    insertion, one deletion, or one adjacent transposition. Falls back to
    equality when lengths make distance > 1 impossible.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if a == b:
        return True
    if la == lb:
        # Try one substitution OR one adjacent transposition
        diffs = [i for i in range(la) if a[i] != b[i]]
        if len(diffs) == 1:
            return True                              # single substitution
        if len(diffs) == 2 and diffs[1] == diffs[0] + 1:
            i, j = diffs
            return a[i] == b[j] and a[j] == b[i]     # adjacent transposition
        return False
    # Length differs by 1 — try one insertion (the longer is a with one extra char)
    if la > lb:
        a, b = b, a
        la, lb = lb, la
    # a is shorter; walk both, allow exactly one skip in b
    i = j = 0
    skipped = False
    while i < la and j < lb:
        if a[i] == b[j]:
            i += 1; j += 1
        elif skipped:
            return False
        else:
            skipped = True; j += 1
    return True


def _is_typoglycemia_variant(word: str, target: str) -> bool:
    """True if word is a typoglycemia variant of target.

    Anagram-style scramble (same length, same first + last letter, sorted
    middle equal) OR Damerau-Levenshtein distance ≤ 1 with the additional
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
        return False
    if word == target:
        return False                     # exact match is handled by regex
    # Anagram scramble — cheap, catches the OWASP-cited pattern
    if (len(word) == len(target)
            and word[0] == target[0] and word[-1] == target[-1]
            and sorted(word[1:-1]) == sorted(target[1:-1])):
        return True
    if not _dl_distance_le_1(word, target):
        return False
    # Prefix-relationship rejection: one is the other + trailing chars →
    # morphological form, not typoglycemia.
    if word.startswith(target) or target.startswith(word):
        return False
    return True


_ALPHA_TOKEN_RE = re.compile(r"[A-Za-z]{4,}")


def _fuzzy_intent_score(text: str) -> float:
    """0–2: count of distinct injection-intent keywords present as
    typoglycemia variants in the text. Exact matches and English
    morphological forms contribute nothing — those are the regex catalog's
    responsibility.

    Score curve: 1 distinct variant → 0.8, 2 → 1.6, ≥ 3 → 2.0.
    """
    lower = text.lower()
    tokens = _ALPHA_TOKEN_RE.findall(lower)
    if len(tokens) < 2:
        return 0.0
    matched: set[str] = set()
    for token in tokens:
        if token in _TYPOGLYCEMIA_KEYWORDS:
            continue                     # exact match — regex will handle it
        tl = len(token)
        for kw in _TYPOGLYCEMIA_KEYWORDS:
            if abs(tl - len(kw)) > 1:
                continue
            if _is_typoglycemia_variant(token, kw):
                matched.add(kw)
                break
    return min(2.0, len(matched) * 0.8)


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
        s5 = _fuzzy_intent_score(text)

        # Coherence (bigram register-shift) is the weakest sub-score and fires
        # on benign transitions (prose → code block, English → citation). It is
        # only trustworthy as corroboration, so it contributes only when at
        # least one stronger signal is already nonzero.
        if s1 == 0.0 and s2 == 0.0 and s4 == 0.0 and s5 == 0.0:
            s3 = 0.0

        total = s1 + s2 + s3 + s4 + s5

        if total < 1.0:
            return ScanResult()

        if total >= 5.0:
            severity = Severity.HIGH
        elif total >= 3.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

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

        return ScanResult(findings=[Finding(
            scanner=self.name,
            category="heuristic_anomaly",
            severity=severity,
            detail=f"total={total:.1f} ({', '.join(parts)})",
        )])
