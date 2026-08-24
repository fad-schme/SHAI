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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.config.schema import NormalizationConfig

# Confusables that regularly appear in homoglyph attacks. Kept as an explicit,
# auditable map rather than the full Unicode TR39 table: the long tail adds
# little coverage against real payloads and a lot of surface to reason about.
# Extend deliberately, not exhaustively.
_CONFUSABLES = {
    # Cyrillic lowercase → Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i",
    "\u0501": "d", "\u04bb": "h", "\u0261": "g", "\u1d0f": "o",
    "\u0431": "b", "\u0442": "t", "\u043a": "k", "\u043c": "m",
    "\u043d": "h", "\u0432": "b", "\u0455": "s", "\u0458": "j",
    # Cyrillic uppercase → Latin
    "\u0410": "A", "\u0412": "B",
    "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u0405": "S", "\u0406": "I", "\u0408": "J", "\u041e": "O",
    "\u0411": "b", "\u0413": "r", "\u0417": "3",
    # Greek → Latin (lowercase then uppercase)
    "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03b9": "i",
    "\u03c1": "p", "\u03c5": "u", "\u03bd": "v", "\u03c7": "x",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
    # Armenian / Latin-extended lookalikes commonly used in homoglyph payloads
    "\u0578": "n", "\u057c": "n", "\u0585": "o",
    # Fullwidth Latin letters (NFKC folds most, but map the frequent ones
    # defensively in case NFKC is bypassed by a partial view)
    "\uff41": "a", "\uff45": "e", "\uff49": "i", "\uff4f": "o",
}

# Zero-width and formatting characters used to fragment or hide tokens.
# Includes bidi controls (embed/override/isolate) and the Unicode Tag block:
# both are live invisible-instruction smuggling vectors — the Tag block can
# encode a full ASCII payload that renders as nothing.
_INVISIBLE = dict.fromkeys(
    [
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x2060, 0x00AD, 0x180E,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,          # bidi embed / override / pop
        0x2066, 0x2067, 0x2068, 0x2069,                  # bidi isolates
        *range(0xE0000, 0xE0080),                        # Unicode Tag block (invisible ASCII)
    ],
    None,
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
# Consecutive single-character tokens needed before a run counts as
# per-character fragmentation. Four is short enough to catch a fragmented
# trigger word and long enough that initials, table cells, and "a b c" in prose
# do not qualify.
_MIN_CHAR_RUN = 4
# Transitions that reveal a word glued to what precedes it with no separator.
# Deliberately not letter → digit: "UK12345678901234567890" splits into noise
# and no bypass needs it.
_GLUED_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])"      # fooBar, 10001Ignore
    r"|(?<=[A-Z])(?=[A-Z][a-z])"   # USAIgnore
    r"|(?<=[0-9])(?=[A-Za-z])"     # 10001ignore
)
# base64 candidate: a long run of the base64 alphabet, optionally padded.
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
# hex candidate: a long run of hex digits with even length.
_HEX_CANDIDATE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
# percent-encoding presence check.
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
# base32 candidate: RFC 4648 alphabet, optionally padded. Uppercase-only, so
# it cannot collide with the base64 candidate above on ordinary mixed-case text.
_B32_CANDIDATE = re.compile(r"[A-Z2-7]{16,}={0,6}")
# ascii85 candidate: only the delimited form. Undelimited ascii85 is nearly any
# run of printable ASCII, which would decode ordinary prose into noise.
_A85_CANDIDATE = re.compile(r"<~.{8,}?~>", re.DOTALL)
# binary candidate: four or more space-separated octets.
_BINARY_CANDIDATE = re.compile(r"(?:[01]{8}[ \t]*){4,}")
# literal \uXXXX escape sequences, two or more in a row.
_UESC_CANDIDATE = re.compile(r"(?:\\u[0-9a-fA-F]{4}){2,}")
# morse candidate: a run of morse letters separated by spaces. Requires five
# letters so ellipses, em-dashes, and "..." in prose cannot qualify.
_MORSE_CANDIDATE = re.compile(r"(?:[.\-]{1,6}[ /]+){4,}[.\-]{1,6}")

# International Morse, letters and digits only. Static data, no punctuation:
# punctuation codes overlap common prose separators and buy nothing.
_MORSE_TABLE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}


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


def _split_glued(text: str) -> str:
    """Insert a boundary where a word was glued to what precedes it.

    An indirect payload is concatenated onto the document that carries it, and
    if no separator lands between them the trigger word loses its left word
    boundary: "…New York, NY 10001 USAIgnore your previous instructions". Most
    catalog patterns lead with a ``\\b``-anchored token, and there is no ``\\b``
    between ``usa`` and ``ignore`` — both are word characters — so the payload
    passes while the identical text one space later blocks.

    Splits at the three transitions that survive: lower/digit → upper,
    acronym → capitalised word ("USAIgnore"), and digit → letter
    ("10001Ignore"). **Glue between two lowercase words is not recoverable
    here** — "regardsignore" has no transition to split on, and separating it
    needs a dictionary rather than a character rule.

    Returns "" when nothing was split, so the caller adds no view.
    """
    split = _GLUED_BOUNDARY.sub(" ", text)
    return split if split != text else ""


def _longest_char_run(tokens: list[str]) -> int:
    """Length of the longest run of consecutive single-character tokens."""
    longest = run = 0
    for token in tokens:
        run = run + 1 if len(token) == 1 else 0
        longest = max(longest, run)
    return longest


def _join_char_runs(tokens: list[str]) -> str:
    """Join runs of single-character tokens, leaving whole words spaced.

    "i g n o r e your previous" -> "ignore your previous".

    This is the view the catalogs can actually match. Removing every separator
    instead yields "ignoreyourprevious", where the word boundaries are gone —
    and most catalog patterns lead with a ``\\b``-anchored token, so they match
    neither the fragmented text nor that repair of it.
    """
    out: list[str] = []
    joined = False
    i = 0
    while i < len(tokens):
        if len(tokens[i]) > 1:
            out.append(tokens[i])
            i += 1
            continue
        j = i
        while j < len(tokens) and len(tokens[j]) == 1:
            j += 1
        if j - i >= _MIN_CHAR_RUN:
            out.append("".join(tokens[i:j]))
            joined = True
        else:
            out.extend(tokens[i:j])
        i = j
    return " ".join(out) if joined else ""


def _reassemble(text: str) -> list[tuple[str, str]]:
    """Return reassembled views when ``text`` looks fragmented.

    Three fragmentation styles need three different repairs, so this may yield
    three views:

    - separators collapsed to single spaces — repairs word-level fragmentation
      ("ignore -/- previous" -> "ignore previous"), preserving word boundaries
      that space-delimited signatures rely on;
    - single-character runs joined in place — repairs per-character
      fragmentation while keeping the surrounding words separate
      ("i g n o r e your previous" -> "ignore your previous");
    - separators removed entirely — repairs per-character fragmentation
      ("i g n o r e" -> "ignore").

    Fires when the text looks fragmented anywhere: a long enough run of
    single-character tokens, many short tokens once split on separators, or
    separators appearing between the majority of characters. The run test is
    what makes this local — the ratio tests are computed over the whole string,
    so fragmenting three words inside an ordinary paragraph dilutes both below
    threshold and the repair would never fire on ratios alone.

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
    # Local tell: an unbroken run of single-character tokens. Dilution-proof,
    # because it does not average over the rest of the document.
    char_run = _longest_char_run(tokens) >= _MIN_CHAR_RUN
    if not char_run and short_ratio < 0.6 and not dense and not odd_delims:
        return []

    views: list[tuple[str, str]] = []
    spaced = _FRAGMENT_SEP.sub(" ", text).strip()
    if spaced and spaced != text:
        views.append(("reassemble_fragments", spaced))
    rejoined = _join_char_runs(tokens)
    if rejoined and rejoined != text and rejoined != spaced:
        views.append(("reassemble_fragments", rejoined))
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

    for m in _B32_CANDIDATE.finditer(text):
        chunk = m.group(0)
        if _shannon_entropy(chunk) < entropy_threshold:
            continue  # SHOUTED prose matches the base32 alphabet too
        try:
            decoded = base64.b32decode(chunk, casefold=False).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(("base32", decoded))

    for m in _A85_CANDIDATE.finditer(text):
        try:
            decoded = base64.a85decode(m.group(0), adobe=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(("ascii85", decoded))

    for m in _BINARY_CANDIDATE.finditer(text):
        bits = m.group(0).split()
        try:
            decoded = bytes(int(b, 2) for b in bits).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(("binary", decoded))

    for m in _UESC_CANDIDATE.finditer(text):
        try:
            decoded = codecs.decode(m.group(0), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable():
            out.append(("unicode_escape", decoded))

    for m in _MORSE_CANDIDATE.finditer(text):
        letters = [t for t in re.split(r"[ /]+", m.group(0)) if t]
        if len(letters) < 5 or any(t not in _MORSE_TABLE for t in letters):
            continue  # partial morse is more likely punctuation than a payload
        out.append(("morse", "".join(_MORSE_TABLE[t] for t in letters)))

    if _PCT.search(text):
        try:
            from urllib.parse import unquote

            decoded = unquote(text)
            if decoded != text:
                out.append(("url", decoded))
        except (ValueError, UnicodeDecodeError):
            pass

    # Reversal, like rot13 below, is whole-string and always "succeeds" — every
    # input reverses into something. Gate it the same way: surface the view only
    # when reversing recovered natural language that was not already there.
    reversed_text = text[::-1]
    if reversed_text != text and _word_score(reversed_text) > _word_score(text):
        out.append(("reversed", reversed_text))

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

    within_budget = len(folded.encode("utf-8", "ignore")) <= max_bytes

    # Bounded by max_bytes for the same reason decoding is: this is a full-size
    # substitution producing a full-size extra view, and every scanner runs over
    # every view. A glued payload hidden inside an oversized document is
    # therefore still missed — the same residual the decode bound already has.
    if within_budget:
        unglued = _split_glued(folded)
        if unglued and unglued not in seen:
            views.append(unglued)
            seen.add(unglued)
            transforms.append("split_glued")

    if decode and within_budget:
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


def canonicalize_config(text: str, config: NormalizationConfig) -> NormalizationResult:
    """canonicalize() driven directly by a NormalizationConfig.

    Every boundary that normalizes text reads the same four fields off its
    NormalizationConfig one at a time; this is that projection in one place
    instead of copied at each call site.
    """
    return canonicalize(
        text,
        decode=config.decode,
        max_depth=config.max_depth,
        entropy_threshold=config.entropy_threshold,
        max_bytes=config.max_bytes,
    )
