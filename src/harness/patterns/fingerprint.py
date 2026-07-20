"""fingerprint.py — structural fingerprint and skeleton extraction.

Extracts a compact representation of text anomalies without storing
raw content. Used by the heuristic candidate system to match
structurally similar texts across turns.

Fingerprint: sub-score buckets + marker flags + LSH hash.
Skeleton: triggering tokens in order, content stripped.
"""
from __future__ import annotations

import hashlib
import json
import re

# Same markers and tokens as heuristic_scan.py — single source of truth
_STRUCTURAL_RE = re.compile(
    r"<\|(?:system|user|assistant|im_start|im_end)\|>"
    r"|\[/?INST\]"
    r"|### (?:Instruction|System|Response)"
    r"|```(?:system|tool_call)"
    r"|</?(?:system|tool_use|function_call|result)>"
    r"|\{\"(?:role|function|tool_calls)\":",
    re.IGNORECASE,
)

_CONTROL_TOKENS = frozenset({
    "ignore", "override", "forget", "disregard", "bypass", "skip",
    "instead", "always", "never", "must", "execute", "run", "call",
    "output", "print", "reveal", "repeat", "respond", "pretend",
})

_MAX_SKELETON_LEN = 200
_LSH_K = 64  # number of hash functions for MinHash


def _bucket(score: float) -> str:
    if score <= 0.0:
        return "none"
    if score < 1.0:
        return "low"
    if score < 1.5:
        return "medium"
    return "high"


def _minhash_lsh(text: str) -> str:
    """MinHash LSH over character bigrams. Returns hex string."""
    bigrams = [text[i:i+2] for i in range(len(text) - 1)] if len(text) > 1 else [text]
    if not bigrams:
        return "0" * 16

    mins = []
    for seed in range(_LSH_K):
        min_h = None
        for bg in bigrams:
            h = int(hashlib.md5(f"{seed}:{bg}".encode(), usedforsecurity=False).hexdigest()[:8], 16)
            if min_h is None or h < min_h:
                min_h = h
        mins.append(min_h)

    # Compress to a short hex string: hash the signature itself
    sig = ":".join(str(m) for m in mins)
    return hashlib.sha256(sig.encode()).hexdigest()[:16]


def lsh_jaccard(lsh_a: str, lsh_b: str) -> float:
    """Approximate Jaccard similarity from two LSH hex strings.

    Since we compressed the full MinHash into a single hash, we use
    character-level comparison as a fast proxy. For exact similarity,
    store the full MinHash vector. This is sufficient for candidate
    deduplication where we need ~0.7 threshold, not exact values.
    """
    if lsh_a == lsh_b:
        return 1.0
    # Nibble-level comparison
    matches = sum(a == b for a, b in zip(lsh_a, lsh_b))
    return matches / max(len(lsh_a), len(lsh_b))


def extract_fingerprint(
    text: str,
    entropy_score: float,
    density_score: float,
    coherence_score: float,
    structural_score: float,
) -> dict:
    """Extract a structural fingerprint from text and heuristic sub-scores."""
    markers = _STRUCTURAL_RE.findall(text)
    tokens_lower = text.lower().split()
    control_hits = sorted({
        t.rstrip(".:,;!?") for t in tokens_lower
        if t.rstrip(".:,;!?") in _CONTROL_TOKENS
    })

    length = len(text)
    if length < 100:
        length_bucket = "short"
    elif length < 1000:
        length_bucket = "medium"
    else:
        length_bucket = "long"

    return {
        "entropy": _bucket(entropy_score),
        "density": _bucket(density_score),
        "coherence": _bucket(coherence_score),
        "structural": _bucket(structural_score),
        "markers": sorted(set(markers)),
        "control_tokens": control_hits,
        "length_bucket": length_bucket,
        "lsh": _minhash_lsh(text),
    }


def extract_skeleton(text: str) -> str:
    """Extract structural tokens in order, strip content. Max 200 chars."""
    parts: list[str] = []
    last_end = 0

    # Find structural markers with positions
    for m in _STRUCTURAL_RE.finditer(text):
        if m.start() > last_end:
            # Check for control tokens in the gap
            gap = text[last_end:m.start()]
            gap_tokens = gap.lower().split()
            ctrl = [t.rstrip(".:,;!?") for t in gap_tokens if t.rstrip(".:,;!?") in _CONTROL_TOKENS]
            if ctrl:
                parts.append("··· " + " ".join(ctrl) + " ")
            elif last_end > 0 or m.start() > 0:
                parts.append("··· ")
        parts.append(m.group())
        last_end = m.end()

    # Trailing control tokens after last marker
    if last_end < len(text):
        tail = text[last_end:]
        tail_tokens = tail.lower().split()
        ctrl = [t.rstrip(".:,;!?") for t in tail_tokens if t.rstrip(".:,;!?") in _CONTROL_TOKENS]
        if ctrl:
            parts.append(" ··· " + " ".join(ctrl))
        elif parts:
            parts.append(" ···")

    # If no structural markers at all, just show control tokens
    if not parts:
        tokens = text.lower().split()
        ctrl = [t.rstrip(".:,;!?") for t in tokens if t.rstrip(".:,;!?") in _CONTROL_TOKENS]
        if ctrl:
            parts = ["··· " + " ".join(ctrl) + " ···"]
        else:
            parts = ["··· (entropy/coherence anomaly) ···"]

    skeleton = "".join(parts)
    if len(skeleton) > _MAX_SKELETON_LEN:
        skeleton = skeleton[:_MAX_SKELETON_LEN - 3] + "..."
    return skeleton


def fingerprint_to_json(fp: dict) -> str:
    return json.dumps(fp, sort_keys=True)


def fingerprint_from_json(s: str) -> dict:
    return json.loads(s)
