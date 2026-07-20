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

_ENTROPY_THRESHOLD = 4.5
_ENTROPY_WINDOW = 64
_DENSITY_THRESHOLD = 0.08

_CONTROL_TOKENS = frozenset({
    "ignore", "override", "forget", "disregard", "bypass", "skip",
    "instead", "always", "never", "must", "execute", "run", "call",
    "output", "print", "reveal", "repeat", "respond", "pretend",
})

_STRUCTURAL_RE = re.compile(
    r"<\|(?:system|user|assistant|im_start|im_end)\|>"
    r"|\[/?INST\]"
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


class HeuristicScanner:
    """Structural anomaly scanner. Always on. Satisfies Scanner Protocol."""

    name = "heuristic_scan"

    async def scan(self, text: str, ctx: AgentContext) -> ScanResult:
        if not text or not text.strip():
            return ScanResult()

        s1 = _entropy_score(text)
        s2 = _instruction_density_score(text)
        s3 = _coherence_score(text)
        s4 = _structural_score(text)
        total = s1 + s2 + s3 + s4

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

        return ScanResult(findings=[Finding(
            scanner=self.name,
            category="heuristic_anomaly",
            severity=severity,
            detail=f"total={total:.1f} ({', '.join(parts)})",
        )])
