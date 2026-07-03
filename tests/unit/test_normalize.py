"""Acceptance tests for canonicalize(), using RedQuest's five converters as the
oracle.

The contract under test: for every converter RedQuest applies to an attack
payload, at least one of the views returned by canonicalize() must contain the
original marker string that a scanner signature would match. If the marker
survives obfuscation in some view, the scan pipeline catches it.

The converters here reproduce the behaviour described in RedQuest's
attacks/converters.py (base64, rot13, whitespace, unicode_lookalike, fragment).
Keeping our own copy makes the test hermetic and turns "SHAI defeats the
converters" into a red/green signal.
"""

from __future__ import annotations

import base64
import codecs

import pytest

from harness.core.normalize import canonicalize

# A canonical injection marker. Real scanners match richer patterns; this
# stand-in is enough to prove de-obfuscation surfaces the payload.
MARKER = "ignore previous instructions"


def _contains_marker(result) -> bool:
    """A converter is defeated if the marker appears in any view. Matching is
    whitespace-insensitive, mirroring how a signature engine normalizes spacing
    before matching — the reassembly views may collapse or drop separators."""
    target = MARKER.replace(" ", "")
    return any(target in view.lower().replace(" ", "") for view in result.views)


# --- RedQuest converter reconstructions -------------------------------------

def conv_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def conv_rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def conv_whitespace(text: str) -> str:
    # Inject zero-width spaces between characters and pad with runs of spaces.
    return "   ".join(ch + "\u200b" for ch in text)


def conv_unicode_lookalike(text: str) -> str:
    swap = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441",
            "p": "\u0440", "x": "\u0445", "i": "\u0456"}
    return "".join(swap.get(ch, ch) for ch in text)


def conv_fragment(text: str) -> str:
    # Split tokens with interleaved separators, as fragmentation attacks do.
    return text.replace(" ", " -/- ")


CONVERTERS = {
    "base64": conv_base64,
    "rot13": conv_rot13,
    "whitespace": conv_whitespace,
    "unicode_lookalike": conv_unicode_lookalike,
    "fragment": conv_fragment,
}


# --- Tests ------------------------------------------------------------------

@pytest.mark.parametrize("name,convert", CONVERTERS.items())
def test_converter_is_defeated(name, convert):
    obfuscated = convert(MARKER)
    # Sanity: the converter actually hid the marker from a naive substring scan.
    if name not in ("fragment",):
        assert MARKER not in obfuscated.lower(), f"{name} did not obfuscate the marker"
    result = canonicalize(obfuscated)
    assert _contains_marker(result), (
        f"{name}: marker not recovered in any view; views={result.views!r}"
    )
    assert result.transforms or _contains_marker(result)


def test_double_encoding_recovered():
    # base64 wrapped around rot13 — the max_depth=2 recursion must peel both.
    obfuscated = conv_base64(conv_rot13(MARKER))
    result = canonicalize(obfuscated)
    assert _contains_marker(result)


def test_clean_text_yields_single_view_and_no_transforms():
    clean = "what is the capital of france?"
    result = canonicalize(clean)
    assert result.views == [clean]
    assert result.transforms == []
    assert result.changed is False


def test_legitimate_base64_is_decoded_not_blocked():
    # canonicalize never blocks — it only produces views. A benign base64 blob
    # decodes to a view; the scanner (not us) decides it is harmless.
    blob = base64.b64encode(b"just some binary config data here").decode()
    result = canonicalize(blob)
    assert "base64" in result.transforms
    assert not _contains_marker(result)


def test_low_entropy_base64_lookalike_is_skipped():
    # Long lowercase prose is base64-legal but low entropy; must not be decoded
    # into a garbage view that could cause false matches.
    prose = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    result = canonicalize(prose)
    assert result.transforms == [] or "base64" not in result.transforms


def test_views_are_deduplicated():
    result = canonicalize(MARKER)
    assert len(result.views) == len(set(result.views))


def test_oversized_input_is_folded_not_decoded():
    big = conv_base64(MARKER) + "A" * 300000
    result = canonicalize(big, max_bytes=1024)
    # Folded surface view exists; no decode work was attempted.
    assert len(result.views) == 1


def test_rot13_does_not_fire_on_clean_prose():
    # Clean alphabetic prose must not spawn a spurious rot13 view.
    result = canonicalize("please summarize this document for me")
    assert "rot13" not in result.transforms
    assert len(result.views) == 1


def test_benign_inputs_produce_no_extra_views():
    benign = [
        "Can you summarize this quarterly report for me?",
        "The state-of-the-art model achieves 92% accuracy.",
        "Email me at john.doe@example.com when ready.",
        "See https://example.com/docs/api?v=2 for details",
        "She said: wait... what? I do not understand.",
    ]
    for text in benign:
        result = canonicalize(text)
        assert len(result.views) == 1, f"unexpected extra views for: {text!r}"


def test_is_a_total_function_on_garbage():
    for junk in ["", "\x00\x01\x02", "%%%", "=" * 40, "\u200b\u200b"]:
        result = canonicalize(junk)
        assert isinstance(result.views, list) and result.views
