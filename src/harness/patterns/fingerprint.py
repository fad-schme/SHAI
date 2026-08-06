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
_LSH_K = 64      # number of hash functions for MinHash
_LSH_WIDTH = 8   # hex chars per minimum — md5 digest is sliced to 8


def _bucket(score: float) -> str:
    if score <= 0.0:
        return "none"
    if score < 1.0:
        return "low"
    if score < 1.5:
        return "medium"
    return "high"


def _minhash_lsh(text: str) -> str:
    """MinHash signature over character bigrams.

    Returns the _LSH_K minima concatenated as fixed-width hex — the whole
    signature, not a digest of it. The estimator only works because minima
    survive independently: two texts sharing most bigrams share most minima.
    Hashing the signature down to one value destroys exactly that, since an
    avalanche hash turns a single differing minimum into an unrelated digest,
    and every non-identical pair then scored ~0 through lsh_jaccard.
    """
    bigrams = {text[i:i+2] for i in range(len(text) - 1)} if len(text) > 1 else {text}

    mins = [
        min(
            int(hashlib.md5(f"{seed}:{bg}".encode(), usedforsecurity=False).hexdigest()[:8], 16)
            for bg in bigrams
        )
        for seed in range(_LSH_K)
    ]
    return "".join(f"{m:0{_LSH_WIDTH}x}" for m in mins)


# Score at or above which two signatures are treated as the same pattern.
# One threshold for the whole candidate system: the write path merges a hit
# into an existing candidate at exactly the score the read path matches a
# promoted one, so a text that would increment a candidate is a text that
# candidate would fire on. Two spellings of this number let those drift apart.
LSH_MATCH_THRESHOLD = 0.7


def lsh_jaccard(lsh_a: str, lsh_b: str) -> float:
    """Estimated Jaccard similarity: the fraction of MinHash minima that agree.

    Signatures of unequal length do not correspond position-for-position, so
    they share nothing — a stale candidate written under an older signature
    format scores 0.0 and is superseded rather than matched.
    """
    if not lsh_a or len(lsh_a) != len(lsh_b):
        return 0.0
    agree = sum(
        lsh_a[i:i + _LSH_WIDTH] == lsh_b[i:i + _LSH_WIDTH]
        for i in range(0, len(lsh_a), _LSH_WIDTH)
    )
    return agree / (len(lsh_a) / _LSH_WIDTH)


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
