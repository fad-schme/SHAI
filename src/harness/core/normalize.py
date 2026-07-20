"""Canonicalize text so pattern scanners cannot be bypassed by obfuscation.

Responsibilities: produce a set of plaintext *views* of an input string — the
raw text plus any decoded/de-obfuscated forms — so the scan pipeline can match
signatures against every view instead of only the surface form.

Not responsible for: deciding whether content is malicious (that is a
Scanner's job), emitting audit events (the boundary does that), or mutating
the text the agent ultimately sees (views are for scanning only, never
substituted back into the conversation).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import math
import re
import unicodedata
from dataclasses import dataclass, field

# Confusables that regularly appear in homoglyph attacks. Kept as an explicit,
# auditable map rather than the full Unicode TR39 table: the long tail adds
# little coverage against real payloads and a lot of surface to reason about.
# Extend deliberately, not exhaustively.
_CONFUSABLES = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0501": "d", "\u04bb": "h", "\u0261": "g", "\u1d0f": "o",
    "\u0399": "I", "\u039f": "O", "\u0410": "A", "\u0412": "B",
    "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
}

# Zero-width and formatting characters used to fragment or hide tokens.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x2060, 0x00AD, 0x180E], None
)

_WS_RUN = re.compile(r"\s+")
# Separators used to fragment a payload between characters or words: runs of
# whitespace and common punctuation delimiters attackers interleave.
_FRAGMENT_SEP = re.compile(r"[\s\-/_.|~*]+")
# A fragmentation delimiter is punctuation that is either surrounded by spaces
# (" | ", " -/- ") or is a run of two or more punctuation chars ("--", "::").
# Ordinary hyphenation ("state-of-the-art") is a single punct char with no
# flanking spaces, so it does not match.
_ODD_DELIM = re.compile(r"(?:\s[\-/_.|~*]+\s|[\-/_.|~*]{2,})")
# base64 candidate: a long run of the base64 alphabet, optionally padded.
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# hex candidate: a long run of hex digits with even length.
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# percent-encoding presence check.
_PCT = re.compile(r"%[0-9a-fA-F]{2}")


@dataclass
class NormalizationResult:
    """Views of an input plus a record of which transforms actually fired.

    ``views`` always contains the folded surface form as its first entry and
    never contains duplicates. ``transforms`` names the transforms that changed
    the content — this is what the audit event records (transform names only,
    never the text itself).
    """

    views: list[str]
    transforms: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        """True when de-obfuscation produced anything beyond the folded form."""
        return len(self.views) > 1 or bool(self.transforms)


def _shannon_entropy(s: str) -> float:
    """Bits-per-character entropy. Used to skip low-entropy base64 look-alikes
    (ordinary prose matches the base64 alphabet but carries little entropy)."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _reassemble(text: str) -> list[tuple[str, str]]:
    """Return reassembled views when ``text`` looks fragmented.

    Two fragmentation styles need two different repairs, so this may yield two
    views:

    - separators collapsed to single spaces — repairs word-level fragmentation
      ("ignore -/- previous" -> "ignore previous"), preserving word boundaries
      that space-delimited signatures rely on;
    - separators removed entirely — repairs per-character fragmentation
      ("i g n o r e" -> "ignore").

    Fires only when the text looks fragmented: many short tokens once split on
    separators, or separators appearing between the majority of characters.
    Returns an empty list for ordinary prose so it is never destructured.
    """
    tokens = [t for t in _FRAGMENT_SEP.split(text) if t]
    if len(tokens) < 3:
        return []
    short_ratio = sum(1 for t in tokens if len(t) <= 2) / len(tokens)
    # Separator density: separators as a fraction of all characters.
    seps = sum(1 for ch in text if _FRAGMENT_SEP.match(ch))
    dense = seps / max(len(text), 1) > 0.3
    # Repeated multi-character punctuation delimiters ("-/-", "|", "::") between
    # words are a strong fragmentation tell — they effectively never occur two
    # or more times in ordinary prose.
    odd_delims = len(_ODD_DELIM.findall(text)) >= 2
    if short_ratio < 0.6 and not dense and not odd_delims:
        return []

    views: list[tuple[str, str]] = []
    spaced = _FRAGMENT_SEP.sub(" ", text).strip()
    if spaced and spaced != text:
        views.append(("reassemble_fragments", spaced))
    stripped = _FRAGMENT_SEP.sub("", text)
    if stripped and stripped != text and stripped != spaced:
        views.append(("reassemble_fragments", stripped))
    return views


def _fold(text: str) -> tuple[str, list[str]]:
    """Apply the always-on surface transforms: unicode fold, confusable
    mapping, invisible-character removal, whitespace collapse.

    Returns the folded string and the names of transforms that changed it.
    """
    fired: list[str] = []

    mapped = text.translate(_INVISIBLE)
    if mapped != text:
        fired.append("strip_invisible")

    folded = unicodedata.normalize("NFKC", mapped)
    confused = folded.translate(str.maketrans(_CONFUSABLES))
    if confused != mapped:
        # NFKC and confusable mapping both target lookalike/compatibility
        # glyphs; report them under one transform name to keep the audit
        # vocabulary small.
        fired.append("unicode_fold")

    collapsed = _WS_RUN.sub(" ", confused).strip()
    if collapsed != confused:
        fired.append("collapse_whitespace")

    return collapsed, fired


# A small set of very common English words. Enough to tell "recovered natural
# language" from "rotated gibberish" without shipping a full dictionary. This
# gates rot13 (see _decode_candidates); it is a signal, not a language model.
_COMMON_WORDS = frozenset(
    ["the", "a", "an", "and", "or", "but", "if", "then", "to", "of", "in", "on", "at", "by", "for", "with", "from", "as", "is", "are", "was", "were", "be", "been", "being", "do", "does", "did", "you", "your", "i", "we", "they", "it", "he", "she", "this", "that", "these", "those", "not", "no", "yes", "can", "will", "would", "should", "could", "ignore", "previous", "instruction", "instructions", "system", "prompt", "now", "please", "tell", "show", "me", "my", "all", "any"]
)
_WORD = re.compile(r"[a-z]+")


def _word_score(text: str) -> int:
    """Count tokens that are common English words. Used to decide whether a
    speculative rot13 decode actually recovered natural language."""
    return sum(1 for w in _WORD.findall(text.lower()) if w in _COMMON_WORDS)


def _decode_candidates(text: str, entropy_threshold: float) -> list[tuple[str, str]]:
    """Return (transform_name, decoded_text) for every substring that decodes
    cleanly under a supported scheme. Speculative: a failed decode yields
    nothing, and callers scan both the decoded output and the original."""
    out: list[tuple[str, str]] = []

    for m in _B64_CANDIDATE.finditer(text):
        chunk = m.group(0)
        if _shannon_entropy(chunk) < entropy_threshold:
            continue  # ordinary text that happens to be base64-legal
        try:
            raw = base64.b64decode(chunk, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(("base64", decoded))

    for m in _HEX_CANDIDATE.finditer(text):
        chunk = m.group(0)
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(("hex", decoded))

    if _PCT.search(text):
        try:
            from urllib.parse import unquote

            decoded = unquote(text)
            if decoded != text:
                out.append(("url", decoded))
        except (ValueError, UnicodeDecodeError):
            pass

    # rot13 is whole-string, not substring. Applied unconditionally it produces
    # a garbage view for every ordinary input (all alphabetic text "decodes"),
    # inflating scan work and audit noise. Only surface it when rotation makes
    # the text look *more* like natural language than it started — i.e. it
    # recovered real words that were not already present.
    rotated = codecs.decode(text, "rot13")
    if rotated != text and _word_score(rotated) > _word_score(text):
        out.append(("rot13", rotated))

    return out


def canonicalize(
    text: str,
    *,
    decode: bool = True,
    max_depth: int = 2,
    entropy_threshold: float = 3.5,
    max_bytes: int = 262144,
) -> NormalizationResult:
    """Produce scan views of ``text``.

    The first view is always the folded surface form. When ``decode`` is on,
    additional views are appended for each substring that decodes under a
    supported scheme, recursing up to ``max_depth`` to catch double-encoding.

    Views are de-duplicated preserving order. Work is bounded by ``max_bytes``
    (oversized input is folded but not decoded) so a hostile payload cannot
    force unbounded decoding.

    Raises: nothing. This is a pure, total function — an undecodable or
    malformed input simply yields fewer views.
    """
    folded, transforms = _fold(text)
    views = [folded]
    seen = {folded}

    reassembled = _reassemble(folded)
    for name, view in reassembled:
        if view not in seen:
            views.append(view)
            seen.add(view)
            if name not in transforms:
                transforms.append(name)

    if decode and len(folded.encode("utf-8", "ignore")) <= max_bytes:
        frontier = list(views)
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: list[str] = []
            for candidate in frontier:
                for name, decoded in _decode_candidates(candidate, entropy_threshold):
                    if decoded in seen:
                        continue
                    seen.add(decoded)
                    views.append(decoded)
                    next_frontier.append(decoded)
                    if name not in transforms:
                        transforms.append(name)
            frontier = next_frontier
            depth += 1

    return NormalizationResult(views=views, transforms=transforms)
