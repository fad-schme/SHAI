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

# Characters that render as nothing. One inserted mid-word costs an attacker
# nothing and destroys the word boundary that catalog patterns anchor on:
# `ig<U+FE0F>nore` is invisible to a reader and does not match `\bignore\b`.
#
# Membership rule, so extending this stays a decision rather than a habit: a
# codepoint measured to survive folding, plus the rest of its block where that
# block is homogeneous in function. Whole blocks are listed as ranges because
# half a block is an arbitrary line an attacker picks the other side of. This
# is still not the full Unicode default-ignorable set — that adds a long tail
# with no measured payloads behind it and a lot of surface to reason about.
#
# Stripping runs *before* NFKC (see _fold) so that an invisible inserted
# between two composable characters cannot block their composition. That order
# is only safe while the set is closed under folding: U+3164 and U+FFA0 both
# NFKC-fold to U+1160, so all three are listed. Nothing else in Unicode folds
# into this set — verified, not assumed — so one pass before the fold suffices.
_INVISIBLE = dict.fromkeys(
    [
        0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF, 0x00AD,
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,          # bidi embed / override / pop
        0x2066, 0x2067, 0x2068, 0x2069,                  # bidi isolates
        0x061C,                                          # Arabic letter mark (bidi)
        0x034F,                                          # combining grapheme joiner
        0x2800,                                          # Braille blank pattern
        *range(0x2060, 0x2065),                          # word joiner + invisible operators
        *range(0x180B, 0x1810),                          # Mongolian FVS 1-4 + vowel separator
        *range(0xFE00, 0xFE10),                          # variation selectors 1-16
        *range(0xE0100, 0xE01F0),                        # variation selectors 17-256
        0x115F, 0x1160, 0x3164, 0xFFA0,                  # Hangul fillers (see fold note)
        0x17B4, 0x17B5,                                  # Khmer inherent vowels
        *range(0xFFF9, 0xFFFC),                          # interlinear annotation
        *range(0x1D173, 0x1D17B),                        # musical format controls
        *range(0xE0000, 0xE0080),                        # Unicode Tag block (invisible ASCII)
    ],
    None,
)

_WS_RUN = re.compile(r"\s+")
# Separators used to fragment a payload between characters or words: runs of
# whitespace and common punctuation delimiters attackers interleave.
_FRAGMENT_SEP_CLASS = r"[\s\-/_.|~*]+"
_FRAGMENT_SEP = re.compile(_FRAGMENT_SEP_CLASS)
# The same separator, capturing. Splitting on it keeps the separator runs, and
# their *width* is what tells a gap between two characters of one word from a
# gap between two words — see _join_char_runs.
_FRAGMENT_SPLIT = re.compile(f"({_FRAGMENT_SEP_CLASS})")
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


def _join_char_runs(text: str) -> str:
    """Join runs of single-character tokens, leaving whole words spaced.

    "i g n o r e your previous" -> "ignore your previous".

    This is the view the catalogs can actually match. Removing every separator
    instead yields "ignoreyourprevious", where the word boundaries are gone —
    and most catalog patterns lead with a ``\\b``-anchored token, so they match
    neither the fragmented text nor that repair of it.

    A fragmented span covering several words is one unbroken run, so joining it
    whole would produce that same useless output. Separator width is what
    separates the two cases: an attacker fragmenting text puts a wider gap
    between words than between the characters of one word. Within each run the
    narrowest gap is therefore the character separator, and anything wider ends
    a word. When every gap in a run is the same width the input carries no
    boundary information at all, and the run joins as one word — the
    single-word case above.
    """
    parts = _FRAGMENT_SPLIT.split(text)
    tokens = parts[0::2]
    # gaps[i] is the separator that follows tokens[i]; the last token has none.
    gaps = parts[1::2] + [""]
    # A leading or trailing separator splits into an empty token; drop both
    # sides together so the two lists stay aligned.
    while tokens and not tokens[0]:
        tokens.pop(0)
        gaps.pop(0)
    while tokens and not tokens[-1]:
        tokens.pop()
        gaps.pop()

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
            narrowest = min(len(g) for g in gaps[i:j - 1])
            word = tokens[i]
            for k in range(i + 1, j):
                if len(gaps[k - 1]) > narrowest:
                    out.append(word)
                    word = tokens[k]
                else:
                    word += tokens[k]
            out.append(word)
            joined = True
        else:
            out.extend(tokens[i:j])
        i = j
    return " ".join(out) if joined else ""


def _reassemble(text: str, uncollapsed: str) -> list[tuple[str, str]]:
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

    ``uncollapsed`` is ``text`` with its whitespace runs intact. Detection and
    the separator-substitution views run on ``text`` — the collapsed form the
    rest of the pipeline works in — while the rejoin reads separator width off
    ``uncollapsed``, which is the only place it still exists.

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
    rejoined = _join_char_runs(uncollapsed)
    if rejoined and rejoined != text and rejoined != spaced:
        views.append(("reassemble_fragments", rejoined))
    stripped = _FRAGMENT_SEP.sub("", text)
    if stripped and stripped != text and stripped != spaced:
        views.append(("reassemble_fragments", stripped))
    return views


def _fold(text: str) -> tuple[str, str, list[str]]:
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

    # The pre-collapse form is returned alongside it because fragment
    # reassembly needs separator width, which collapsing destroys.
    return collapsed, confused.strip(), fired


# Frequent English letter trigrams. Two whole-string transforms (rot13 and
# reversal below) always "succeed" mechanically, so they cannot use "did it
# decode" as an admission test; they need a way to ask whether the result reads
# as language. A word list cannot answer that — an attacker writes the payload
# around it, which is exactly how the previous gate was evaded — but the letter
# statistics of English are not something a legible English sentence can avoid.
# Palindromic trigrams and reverse-pairs are excluded so the table stays
# directional: reversed English must not score like English.
_ENGLISH_TRIGRAMS = frozenset([
    "ent", "ing", "ion", "tio", "ver", "con", "ate", "hat", "tha", "ect", "pro", "the",
    "est", "ted", "ati", "age", "ter", "res", "can", "und", "all", "rea", "ith", "men",
    "too", "ool", "her", "wit", "sca", "oun", "gen", "rat", "com", "ont", "our", "ers",
    "thi", "nte", "red", "cti", "cal", "ann", "bou", "ity", "ons", "ery", "tur", "che",
    "ess", "sta", "nne", "tch", "tes", "rce", "for", "str", "den", "rom", "nda", "ins",
    "ign", "ile", "tin", "pat", "dar", "ame", "sha", "ist", "int", "din", "man", "ner",
    "dec", "ary", "atc", "ies", "sig", "ext", "hai", "ain", "ove", "tte", "sti", "rit",
    "nts", "att", "rec", "nce", "act", "out", "lic", "nst", "han", "app", "whe", "ntr",
    "ore", "ail", "ten", "ule", "tor", "ide", "mat", "cla", "rul", "ure", "era", "tri",
    "sed", "sou", "urc", "dit", "oth", "tra", "ode", "ble", "hin", "ine", "ead", "cat",
])

# A token counts as word-like when this share of its trigrams is in the table.
# Ordinary prose clears it comfortably; rotated or reversed prose does not.
_TRIGRAM_HIT_RATIO = 0.2

# Below this many recovered word-like tokens the result is noise, not language.
# One token flipping is well within chance for short or non-prose input.
_MIN_RECOVERED_TOKENS = 2

_TOKEN = re.compile(r"[a-z]{4,}")


def _language_score(text: str) -> int:
    """Count word-like tokens — vocabulary-free, from letter trigrams alone.

    Tokens shorter than four letters carry too little signal to judge, so they
    are ignored on both sides of the comparison rather than counted as noise.

    Runs on inputs up to the normalizer's size limit, so it stops scoring a
    token as soon as the verdict is settled and remembers repeated ones — a
    document is mostly the same few hundred words over and over.
    """
    score = 0
    seen: dict[str, bool] = {}
    for word in _TOKEN.findall(text.lower()):
        word_like = seen.get(word)
        if word_like is None:
            trigrams = len(word) - 2
            needed = math.ceil(_TRIGRAM_HIT_RATIO * trigrams)
            hits = 0
            for i in range(trigrams):
                if word[i:i + 3] in _ENGLISH_TRIGRAMS:
                    hits += 1
                    if hits >= needed:
                        break
            word_like = hits >= needed
            seen[word] = word_like
        score += word_like
    return score


def _recovered_language(before_score: int, after: str) -> bool:
    """True when a whole-string transform turned non-language into language.

    The comparison against the untransformed input, not the absolute score, is
    what admits the view: a payload embedded in a carrier sentence ("Reverse
    this: ...") reads partly as English either way, and only the gain
    distinguishes the transform that recovered it. Both transforms score the
    same input, so the caller passes its score in rather than recomputing it.
    """
    after_score = _language_score(after)
    return after_score >= _MIN_RECOVERED_TOKENS and after_score > before_score


# Whitespace that occurs in ordinary documents. `str.isprintable()` is False for
# all three, so it cannot serve as the admission test on its own — see _is_text.
_TEXT_WHITESPACE = dict.fromkeys([0x09, 0x0A, 0x0D], None)


def _is_text(decoded: str) -> bool:
    """True when a speculative decode produced something that reads as text.

    Admission has to reject the binary soup that decoding ordinary prose under a
    guessed scheme produces: every admitted view is scanned by every scanner at
    every boundary, so a permissive test multiplies work across the whole
    pipeline for nothing.

    `str.isprintable()` was that test and rejected too much. It is False for
    newline and tab, so a decoded payload spanning more than one line was
    dropped and the encoded form reached the scanners only in its opaque surface
    form — and multi-line is the ordinary shape of an injected instruction
    block, not an exotic one. Ignoring the three whitespace characters that
    appear in real documents keeps the rejection (NUL and the other C0/C1
    controls still disqualify a decode) and drops the false one.

    A decode that is *only* whitespace is rejected: it carries no signal, and
    admitting it would add a view that every scanner scans at every boundary for
    nothing.

    The printable case is tested first because it is the common one and costs no
    allocation. `str.translate` builds a new string, and a decoded candidate is
    not small once the size gate on decoding is lifted — paying for a full copy
    on every successful decode would work against the memory bound the rest of
    the pipeline is trying to hold.
    """
    if decoded.isprintable():
        return True
    stripped = decoded.translate(_TEXT_WHITESPACE)
    return bool(stripped) and stripped.isprintable()


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    """Return (transform_name, decoded_text) for every substring that decodes
    cleanly under a supported scheme. Speculative: a failed decode yields
    nothing, and callers scan both the decoded output and the original."""
    out: list[tuple[str, str]] = []

    for m in _B64_CANDIDATE.finditer(text):
        chunk = m.group(0)
        if len(chunk) % 4:
            continue  # cannot be well-formed base64, so do not attempt it
        try:
            raw = base64.b64decode(chunk, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _is_text(decoded):
            out.append(("base64", decoded))

    for m in _HEX_CANDIDATE.finditer(text):
        chunk = m.group(0)
        try:
            decoded = bytes.fromhex(chunk).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_text(decoded):
            out.append(("hex", decoded))

    for m in _B32_CANDIDATE.finditer(text):
        chunk = m.group(0)
        if len(chunk) % 8:
            continue  # cannot be well-formed base32, so do not attempt it
        try:
            decoded = base64.b32decode(chunk, casefold=False).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _is_text(decoded):
            out.append(("base32", decoded))

    for m in _A85_CANDIDATE.finditer(text):
        try:
            decoded = base64.a85decode(m.group(0), adobe=True).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _is_text(decoded):
            out.append(("ascii85", decoded))

    for m in _BINARY_CANDIDATE.finditer(text):
        bits = m.group(0).split()
        try:
            decoded = bytes(int(b, 2) for b in bits).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _is_text(decoded):
            out.append(("binary", decoded))

    for m in _UESC_CANDIDATE.finditer(text):
        try:
            decoded = codecs.decode(m.group(0), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            continue
        if _is_text(decoded):
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

    # Both whole-string transforms score against the same untransformed input.
    base_score = _language_score(text)

    # Reversal, like rot13 below, is whole-string and always "succeeds" — every
    # input reverses into something. Gate it the same way: surface the view only
    # when reversing recovered language that was not already there.
    reversed_text = text[::-1]
    if reversed_text != text and _recovered_language(base_score, reversed_text):
        out.append(("reversed", reversed_text))

    # rot13 is whole-string, not substring. Applied unconditionally it produces
    # a garbage view for every ordinary input (all alphabetic text "decodes"),
    # inflating scan work and audit noise. Only surface it when rotation makes
    # the text read *more* like language than it started — i.e. it recovered
    # word-like text that was not already present.
    rotated = codecs.decode(text, "rot13")
    if rotated != text and _recovered_language(base_score, rotated):
        out.append(("rot13", rotated))

    return out


def canonicalize(
    text: str,
    *,
    decode: bool = True,
    max_depth: int = 2,
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
    folded, uncollapsed, transforms = _fold(text)
    views = [folded]
    seen = {folded}

    reassembled = _reassemble(folded, uncollapsed)
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
                for name, decoded in _decode_candidates(candidate):
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

    Every boundary that normalizes text reads the same fields off its
    NormalizationConfig one at a time; this is that projection in one place
    instead of copied at each call site. Deliberately not `**config`: the
    config carries `enabled`, which the boundary acts on rather than the
    normalizer.
    """
    return canonicalize(
        text,
        decode=config.decode,
        max_depth=config.max_depth,
        max_bytes=config.max_bytes,
    )
