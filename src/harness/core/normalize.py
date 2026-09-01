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
import hashlib
import math
import re
import unicodedata
from collections.abc import Iterator
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

    # ── Extended deliberately, from measurement ──────────────────────────
    # An evasion campaign found Cherokee, Coptic and the rarer Cyrillic letters
    # only partly covered while the common scripts above blocked. These three
    # are ordinary alphabetic scripts with full Latin-lookalike inventories, not
    # long-tail curiosities, so a payload written in them survived folding
    # intact. Every entry below is a single-character confusable taken from the
    # Unicode TR39 confusables data (17.0.0) and named by its codepoint, so a
    # reviewer can check any line against the standard rather than against a
    # judgement about glyph shapes. The map stays hand-maintained: this is one
    # deliberate extension, not a generated table.

    # Cherokee — a large syllabary whose letters read as Latin capitals.
    "\u13a0": "D",   # CHEROKEE LETTER A
    "\u13a1": "R",   # CHEROKEE LETTER E
    "\u13a2": "T",   # CHEROKEE LETTER I
    "\u13a5": "i",   # CHEROKEE LETTER V
    "\u13a9": "Y",   # CHEROKEE LETTER GI
    "\u13aa": "A",   # CHEROKEE LETTER GO
    "\u13ab": "J",   # CHEROKEE LETTER GU
    "\u13ac": "E",   # CHEROKEE LETTER GV
    "\u13b3": "W",   # CHEROKEE LETTER LA
    "\u13b7": "M",   # CHEROKEE LETTER LU
    "\u13bb": "H",   # CHEROKEE LETTER MI
    "\u13bd": "Y",   # CHEROKEE LETTER MU
    "\u13c0": "G",   # CHEROKEE LETTER NAH
    "\u13c2": "h",   # CHEROKEE LETTER NI
    "\u13c3": "Z",   # CHEROKEE LETTER NO
    "\u13cf": "b",   # CHEROKEE LETTER SI
    "\u13d2": "R",   # CHEROKEE LETTER SV
    "\u13d4": "W",   # CHEROKEE LETTER TA
    "\u13d5": "S",   # CHEROKEE LETTER DE
    "\u13d9": "V",   # CHEROKEE LETTER DO
    "\u13da": "S",   # CHEROKEE LETTER DU
    "\u13de": "L",   # CHEROKEE LETTER TLE
    "\u13df": "C",   # CHEROKEE LETTER TLI
    "\u13e2": "P",   # CHEROKEE LETTER TLV
    "\u13e6": "K",   # CHEROKEE LETTER TSO
    "\u13e7": "d",   # CHEROKEE LETTER TSU
    "\u13f3": "G",   # CHEROKEE LETTER YU
    "\u13f4": "B",   # CHEROKEE LETTER YV
    "\uab75": "i",   # CHEROKEE SMALL LETTER V
    "\uab81": "r",   # CHEROKEE SMALL LETTER HU
    "\uab83": "w",   # CHEROKEE SMALL LETTER LA
    "\uab93": "z",   # CHEROKEE SMALL LETTER NO
    "\uaba9": "v",   # CHEROKEE SMALL LETTER DO
    "\uabaa": "s",   # CHEROKEE SMALL LETTER DU
    "\uabaf": "c",   # CHEROKEE SMALL LETTER TLI

    # Coptic — Greek-derived letterforms, hence Latin lookalikes.
    "\u03ed": "o",   # COPTIC SMALL LETTER SHIMA
    "\u2c82": "B",   # COPTIC CAPITAL LETTER VIDA
    "\u2c85": "r",   # COPTIC SMALL LETTER GAMMA
    "\u2c8e": "H",   # COPTIC CAPITAL LETTER HATE
    "\u2c92": "l",   # COPTIC CAPITAL LETTER IAUDA
    "\u2c93": "i",   # COPTIC SMALL LETTER IAUDA
    "\u2c94": "K",   # COPTIC CAPITAL LETTER KAPA
    "\u2c98": "M",   # COPTIC CAPITAL LETTER MI
    "\u2c9a": "N",   # COPTIC CAPITAL LETTER NI
    "\u2c9e": "O",   # COPTIC CAPITAL LETTER O
    "\u2c9f": "o",   # COPTIC SMALL LETTER O
    "\u2ca2": "P",   # COPTIC CAPITAL LETTER RO
    "\u2ca3": "p",   # COPTIC SMALL LETTER RO
    "\u2ca4": "C",   # COPTIC CAPITAL LETTER SIMA
    "\u2ca5": "c",   # COPTIC SMALL LETTER SIMA
    "\u2ca6": "T",   # COPTIC CAPITAL LETTER TAU
    "\u2ca8": "Y",   # COPTIC CAPITAL LETTER UA
    "\u2ca9": "y",   # COPTIC SMALL LETTER UA
    "\u2cac": "X",   # COPTIC CAPITAL LETTER KHI
    "\u2cbd": "w",   # COPTIC SMALL LETTER CRYPTOGRAMMIC NI
    "\u2cce": "P",   # COPTIC CAPITAL LETTER OLD COPTIC HA
    "\u2ccf": "p",   # COPTIC SMALL LETTER OLD COPTIC HA
    "\u2cd0": "L",   # COPTIC CAPITAL LETTER L-SHAPED HA

    # Cyrillic, the rarer letters. The common ones are above.
    "\u0423": "Y",   # CYRILLIC CAPITAL LETTER U
    "\u042c": "b",   # CYRILLIC CAPITAL LETTER SOFT SIGN
    "\u0433": "r",   # CYRILLIC SMALL LETTER GHE
    "\u0448": "w",   # CYRILLIC SMALL LETTER SHA
    "\u0461": "w",   # CYRILLIC SMALL LETTER OMEGA
    "\u0474": "V",   # CYRILLIC CAPITAL LETTER IZHITSA
    "\u0475": "v",   # CYRILLIC SMALL LETTER IZHITSA
    "\u04ae": "Y",   # CYRILLIC CAPITAL LETTER STRAIGHT U
    "\u04af": "y",   # CYRILLIC SMALL LETTER STRAIGHT U
    "\u04bd": "e",   # CYRILLIC SMALL LETTER ABKHASIAN CHE
    "\u04c0": "l",   # CYRILLIC LETTER PALOCHKA
    "\u04cf": "l",   # CYRILLIC SMALL LETTER PALOCHKA
    "\u050c": "G",   # CYRILLIC CAPITAL LETTER KOMI SJE
    "\u051b": "q",   # CYRILLIC SMALL LETTER QA
    "\u051c": "W",   # CYRILLIC CAPITAL LETTER WE
    "\u051d": "w",   # CYRILLIC SMALL LETTER WE

    # Latin blocks: letters that render as another Latin letter without being
    # an accented form of it. Accented characters are deliberately absent —
    # folding "é" to "e" would corrupt ordinary French and Spanish, and NFKC
    # already handles the compatibility forms.
    "\u0131": "i",   # LATIN SMALL LETTER DOTLESS I
    "\u0184": "b",   # LATIN CAPITAL LETTER TONE SIX
    "\u018d": "g",   # LATIN SMALL LETTER TURNED DELTA
    "\u0192": "f",   # LATIN SMALL LETTER F WITH HOOK
    "\u0196": "l",   # LATIN CAPITAL LETTER IOTA
    "\u01a6": "R",   # LATIN LETTER YR
    "\u01bd": "s",   # LATIN SMALL LETTER TONE FIVE
    "\u01bf": "p",   # LATIN LETTER WYNN
    "\u01c0": "l",   # LATIN LETTER DENTAL CLICK
    "\u0251": "a",   # LATIN SMALL LETTER ALPHA
    "\u0263": "y",   # LATIN SMALL LETTER GAMMA
    "\u0269": "i",   # LATIN SMALL LETTER IOTA
    "\u026a": "i",   # LATIN LETTER SMALL CAPITAL I
    "\u026f": "w",   # LATIN SMALL LETTER TURNED M
    "\u028b": "u",   # LATIN SMALL LETTER V WITH HOOK
    "\u028f": "y",   # LATIN LETTER SMALL CAPITAL Y
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
    # True when production stopped at the expansion budget, so the views above
    # are a prefix of what this input would have produced. A partly examined
    # document must never be indistinguishable from a fully examined one.
    budget_exhausted: bool = False

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


def _digest(view: str) -> str:
    """Identity of a view for de-duplication, without holding the view.

    De-duplicating on the strings themselves would keep every view resident for
    the length of the call, which is the memory the streaming generator exists
    to avoid.
    """
    return hashlib.sha256(view.encode("utf-8", "ignore")).hexdigest()


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


# Frequent letter trigrams, per language, for the four the pattern catalogs
# carry. Two whole-string transforms (rot13 and reversal below) always "succeed"
# mechanically, so they cannot use "did it decode" as an admission test; they
# need a way to ask whether the result reads as language. A word list cannot
# answer that — an attacker writes the payload around it, which is how the
# original gate was evaded — but the letter statistics of a language are not
# something a legible sentence in it can avoid.
#
# One table per language, scored independently, rather than one merged table:
# text has to look like *a* language, not like the union of four. Merging was
# measured and rejected — with 390 trigrams drawn from four languages almost any
# letter sequence hits something, and a base64 blob scored as prose. Each table
# is also directional on its own terms (palindromes and reverse-pairs excluded),
# which merging destroys, since a French trigram is often the reverse of an
# English one.
#
# Measured on 240 sentence-length samples per direction: 98-100% recovery in all
# four languages, one false view in 480, none on base64, hex or padding. The
# English-only table this replaced recovered 60% of Spanish and 73% of German.
#
# Chinese is deliberately absent. Reversal of a Han string leaves its character
# distribution untouched and rot13 does not touch non-Latin script at all, so
# neither transform is detectable by this mechanism; an approximation here would
# be worse than the honest gap.
_LANGUAGE_TRIGRAMS: dict[str, frozenset[str]] = {
    "en": frozenset([
        "act", "age", "ail", "ain", "all", "ame", "ann", "app", "ary", "atc", "ate", "ati",
        "att", "ble", "bou", "cal", "can", "cat", "che", "cla", "com", "con", "cti", "dar",
        "dec", "den", "din", "dit", "ead", "ect", "ent", "era", "ers", "ery", "ess", "est",
        "ext", "for", "gen", "hai", "han", "hat", "her", "hin", "ide", "ies", "ign", "ile",
        "ine", "ing", "ins", "int", "ion", "ist", "ith", "ity", "lic", "man", "mat", "men",
        "nce", "nda", "ner", "nne", "nst", "nte", "ntr", "nts", "ode", "ons", "ont", "ool",
        "ore", "oth", "oun", "our", "out", "ove", "pat", "pro", "rat", "rce", "rea", "rec",
        "red", "res", "rit", "rom", "rul", "sca", "sed", "sha", "sig", "sou", "sta", "sti",
        "str", "tch", "ted", "ten", "ter", "tes", "tha", "the", "thi", "tin", "tio", "too",
        "tor", "tra", "tri", "tte", "tur", "ule", "und", "urc", "ure", "ver", "whe", "wit",
    ]),
    "fr": frozenset([
        "age", "agr", "ain", "air", "ais", "ale", "ali", "ans", "ant", "ati", "aux", "ces",
        "cha", "col", "com", "con", "cti", "cul", "dan", "ent", "erm", "ers", "eur", "gri",
        "ico", "icu", "ign", "ill", "ime", "ine", "ins", "ion", "iqu", "ire", "iss", "ite",
        "ité", "ive", "les", "lis", "lle", "ltu", "lus", "men", "mes", "mis", "mme", "nce",
        "nes", "nne", "nta", "nte", "nts", "odu", "ole", "onn", "ons", "ont", "ort", "our",
        "par", "plu", "pou", "pro", "que", "ran", "res", "ric", "rie", "rmi", "rod", "son",
        "sse", "tai", "ter", "tes", "teu", "tio", "tiq", "tiv", "tre", "tur", "ues", "uit",
        "ult", "ure", "urs", "ver", "ère", "ées",
    ]),
    "es": frozenset([
        "aci", "ade", "ado", "agr", "ale", "ali", "ant", "ari", "cci", "cia", "cio", "ció",
        "col", "com", "con", "cos", "cto", "cul", "das", "des", "dos", "duc", "ent", "era",
        "ero", "err", "esa", "est", "gra", "gri", "grí", "ial", "icu", "ida", "ien", "ier",
        "ina", "ion", "ist", "iza", "ión", "las", "les", "liz", "lla", "ltu", "men", "nci",
        "ndo", "nes", "nta", "nte", "nto", "ntr", "odu", "ola", "ona", "one", "ort", "par",
        "per", "pro", "ran", "ras", "rec", "res", "ria", "ric", "rod", "rra", "ríc", "sta",
        "sti", "str", "tal", "tan", "tas", "ter", "tes", "tic", "tie", "tiv", "tor", "tos",
        "tra", "tri", "tur", "ult", "ura", "íco",
    ]),
    "de": frozenset([
        "abe", "ach", "alt", "and", "arc", "auc", "aus", "auw", "bau", "ben", "ber", "bes",
        "bäu", "cha", "che", "chi", "cht", "den", "der", "ebä", "ech", "eic", "ein", "eis",
        "eit", "ekt", "end", "ens", "ent", "erk", "ers", "ert", "est", "eut", "for", "geb",
        "gen", "ges", "hei", "hen", "her", "hit", "ich", "iel", "ier", "ige", "ine", "ion",
        "isc", "ist", "ite", "kte", "kti", "ktu", "len", "lic", "lle", "men", "nde", "ner",
        "nge", "nis", "nst", "nte", "rch", "rde", "rte", "run", "sch", "sei", "sen", "sic",
        "sta", "ste", "sti", "tal", "tek", "ten", "ter", "the", "tio", "tun", "tur", "uch",
        "ude", "ung", "ver", "wei", "wer", "äud",
    ]),
}

# trigram -> bitmask of the languages whose table contains it. Derived from the
# tables above so they stay the readable, auditable source; the mask keeps
# scoring to one dict lookup per trigram rather than one per language.
_TRIGRAM_LANGS: dict[str, int] = {}
for _bit, _table in enumerate(_LANGUAGE_TRIGRAMS.values()):
    for _tri in _table:
        _TRIGRAM_LANGS[_tri] = _TRIGRAM_LANGS.get(_tri, 0) | (1 << _bit)

# A token counts as word-like when this share of its trigrams is in one
# language's table. Ordinary prose clears it comfortably; rotated or reversed
# prose does not.
_TRIGRAM_HIT_RATIO = 0.2

# Below this many recovered word-like tokens the result is noise, not language.
# One token flipping is well within chance for short or non-prose input.
_MIN_RECOVERED_TOKENS = 2

# Five letters, not four: a four-letter token has two trigrams, so one stray
# hit makes it word-like, and with four language tables a stray hit is four
# times as likely as it was with one. Measured, that single relaxation was the
# whole difference between zero false views on the benign controls and one.
#
# Includes the accented letters ordinary French, Spanish and German prose uses:
# without them a French word splits at every accent and scores as fragments.
_TOKEN = re.compile(r"[a-z\u00e0-\u00f6\u00f8-\u00ff]{5,}")

_LANG_COUNT = len(_LANGUAGE_TRIGRAMS)


def _language_score(text: str) -> int:
    """Count word-like tokens — vocabulary-free, from letter trigrams alone.

    Scored per language and reported as the best single language's count, not
    the sum: a payload is written in one language, and a token that hits three
    tables one trigram each is noise rather than evidence.

    Tokens shorter than five letters carry too little signal to judge, so they
    are ignored on both sides of the comparison rather than counted as noise.

    Runs on inputs up to the normalizer's expansion budget, so it remembers
    repeated tokens — a document is mostly the same few hundred words over and
    over.
    """
    scores = [0] * _LANG_COUNT
    seen: dict[str, int] = {}
    for word in _TOKEN.findall(text.lower()):
        word_like = seen.get(word)
        if word_like is None:
            trigrams = len(word) - 2
            needed = math.ceil(_TRIGRAM_HIT_RATIO * trigrams)
            hits = [0] * _LANG_COUNT
            for i in range(trigrams):
                mask = _TRIGRAM_LANGS.get(word[i:i + 3], 0)
                if mask:
                    for bit in range(_LANG_COUNT):
                        if mask & (1 << bit):
                            hits[bit] += 1
            word_like = 0
            for bit, count in enumerate(hits):
                if count >= needed:
                    word_like |= 1 << bit
            seen[word] = word_like
        if word_like:
            for bit in range(_LANG_COUNT):
                if word_like & (1 << bit):
                    scores[bit] += 1
    return max(scores)


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


# Total bytes of non-surface views one call may produce. The surface form is
# not expansion — it exists whatever happens — so only repaired, unglued and
# decoded views count. Ordinary prose expands to roughly three to four times its
# own size, so this completes any document up to about 2 MB and truncates the
# tail of anything larger, saying so when it does.
_DEFAULT_EXPANSION_BUDGET = 8 * 1024 * 1024


class ViewStream:
    """Views produced one at a time, and whether production was cut short.

    Read ``budget_exhausted`` after iterating: it is False until the generator
    stops early, and a caller that reports it lets an operator tell a partly
    de-obfuscated document from a fully de-obfuscated one. The flag lives on the
    stream rather than in the yielded tuples because it is a property of the
    production as a whole, not of any one view.
    """

    __slots__ = ("budget_exhausted", "_views")

    def __init__(
        self,
        text: str,
        *,
        decode: bool,
        max_depth: int,
        max_expansion_bytes: int,
    ) -> None:
        self.budget_exhausted = False
        self._views = _iter_views(
            text,
            decode=decode,
            max_depth=max_depth,
            max_expansion_bytes=max_expansion_bytes,
            stream=self,
        )

    def __iter__(self) -> Iterator[tuple[str, list[str]]]:
        return self._views


def _iter_views(
    text: str,
    *,
    decode: bool,
    max_depth: int,
    max_expansion_bytes: int,
    stream: ViewStream,
) -> Iterator[tuple[str, list[str]]]:
    """Yield ``(view, transform_names)`` in production order, under a budget.

    The canonical implementation of view production; ``canonicalize`` is the
    consumer that materialises it and the boundaries are the consumer that
    streams it. Views are yielded as they are produced so a caller scanning one
    at a time never holds more than one, which is what bounds peak memory for a
    boundary call over a large document.

    Coverage is not size-gated: candidates are detected and decoded anywhere in
    the document, at any size. What is bounded is *expansion* — the total volume
    of non-surface views produced. Every step that produces a view is charged
    against the same budget, so there is one account of what limits expansion
    rather than one rule for decoding and another for everything else.

    ``seen`` holds view *digests* rather than the views themselves: holding the
    strings for de-duplication would keep every view resident and defeat the
    streaming the generator exists for.
    """
    folded, uncollapsed, fold_transforms = _fold(text)
    seen = {_digest(folded)}
    yield folded, fold_transforms

    remaining = max_expansion_bytes

    def _charge(view: str) -> bool:
        """Spend a view's bytes against the budget. False when it does not fit."""
        nonlocal remaining
        cost = len(view.encode("utf-8", "ignore"))
        if cost > remaining:
            stream.budget_exhausted = True
            return False
        remaining -= cost
        return True

    produced = [folded]
    for name, view in _reassemble(folded, uncollapsed):
        digest = _digest(view)
        if digest in seen:
            continue
        if not _charge(view):
            return
        seen.add(digest)
        produced.append(view)
        yield view, [name]

    unglued = _split_glued(folded)
    if unglued and _digest(unglued) not in seen:
        if not _charge(unglued):
            return
        seen.add(_digest(unglued))
        produced.append(unglued)
        yield unglued, ["split_glued"]

    if decode:
        # Breadth-first, so view order does not depend on how deeply any one
        # candidate nests. The frontier is the one place views are still held in
        # bulk — a depth level's worth — and every view in it was charged
        # against the same budget, so it is bounded by it too.
        frontier = produced
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: list[str] = []
            for candidate in frontier:
                for name, decoded in _decode_candidates(candidate):
                    digest = _digest(decoded)
                    if digest in seen:
                        continue
                    if not _charge(decoded):
                        return
                    seen.add(digest)
                    next_frontier.append(decoded)
                    yield decoded, [name]
            frontier = next_frontier
            depth += 1


def canonicalize(
    text: str,
    *,
    decode: bool = True,
    max_depth: int = 2,
    max_expansion_bytes: int = _DEFAULT_EXPANSION_BUDGET,
) -> NormalizationResult:
    """Produce scan views of ``text``.

    The first view is always the folded surface form. When ``decode`` is on,
    additional views are appended for each substring that decodes under a
    supported scheme, recursing up to ``max_depth`` to catch double-encoding.

    Views are de-duplicated preserving order. Every view beyond the surface form
    is charged against ``max_expansion_bytes``; when that is spent production
    stops and ``budget_exhausted`` says so. Document size does not limit what is
    examined — only how much may be produced from it.

    Materialises `ViewStream`. A caller that scans view by view should stream it
    instead — see `canonicalize_iter_config` — since a materialised list is
    resident whether or not the caller still needs it.

    Raises: nothing. This is a pure, total function — an undecodable or
    malformed input simply yields fewer views.
    """
    stream = ViewStream(
        text,
        decode=decode,
        max_depth=max_depth,
        max_expansion_bytes=max_expansion_bytes,
    )
    views: list[str] = []
    transforms: list[str] = []
    for view, fired in stream:
        views.append(view)
        for name in fired:
            if name not in transforms:
                transforms.append(name)
    return NormalizationResult(
        views=views, transforms=transforms, budget_exhausted=stream.budget_exhausted
    )


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
        max_expansion_bytes=config.max_expansion_bytes,
    )


def canonicalize_iter_config(text: str, config: NormalizationConfig) -> ViewStream:
    """`_iter_views` driven by a NormalizationConfig — the streaming projection.

    For callers that scan each view and release it. `canonicalize_config` is the
    same production for callers that need the whole list.
    """
    return ViewStream(
        text,
        decode=config.decode,
        max_depth=config.max_depth,
        max_expansion_bytes=config.max_expansion_bytes,
    )
