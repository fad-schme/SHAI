"""Cost and completeness of the fuzzy-match candidate lookup.

`_match_fuzzy_class` finds the targets a token can fuzzy-match by lookup —
the token's short-deletion forms and its scramble key — then decides with
`_typoglycemia_match_kind` exactly as before. The lookup is only allowed to
remove work: every pair the full scan over the vocabulary would match must
still be found.
"""
from __future__ import annotations

import itertools

import pytest

import harness.adapters.scanners.heuristic_scan as heuristic
from harness.adapters.scanners.heuristic_scan import (
    _TYPO_ACTIONS,
    _TYPO_EXECUTION_DESTINATIONS,
    _TYPO_PROTECTED_OBJECTS,
    _match_fuzzy_class,
    _typoglycemia_match_kind,
)

_CLASSES = [_TYPO_ACTIONS, _TYPO_PROTECTED_OBJECTS, _TYPO_EXECUTION_DESTINATIONS]
_ALPHABET = "abcdefghijklmnopqrstuvwxyz"


def _reference(token: str, targets: frozenset[str]) -> tuple[str | None, str | None]:
    """The full scan over the sorted vocabulary — the behaviour being preserved."""
    best_target = best_kind = None
    for target in sorted(targets):
        kind = _typoglycemia_match_kind(token, target)
        if kind == "strong":
            return target, "strong"
        if kind is not None and best_target is None:
            best_target, best_kind = target, kind
    return best_target, best_kind


def _edits(word: str, alphabet: str = _ALPHABET) -> set[str]:
    """Every single substitution, insertion, deletion and adjacent transposition."""
    splits = [(word[:i], word[i:]) for i in range(len(word) + 1)]
    return (
        {a + b[1:] for a, b in splits if b}
        | {a + b[1] + b[0] + b[2:] for a, b in splits if len(b) > 1}
        | {a + c + b[1:] for a, b in splits if b for c in alphabet}
        | {a + c + b for a, b in splits for c in alphabet}
    )


def _variants(target: str) -> set[str]:
    one = _edits(target)
    # Distance 2 is allowed from seven letters up. Every edit kind appears at
    # both steps; the substitution/insertion alphabet is narrowed so the
    # brute-force reference stays fast.
    two = (
        {v2 for v in _edits(target, "x") for v2 in _edits(v, "e")}
        if len(target) >= 7 else set()
    )
    scrambles = {
        target[0] + "".join(p) + target[-1]
        for p in itertools.islice(itertools.permutations(target[1:-1]), 50)
    }
    return one | two | scrambles


@pytest.mark.parametrize("targets", _CLASSES, ids=["actions", "protected", "destinations"])
def test_lookup_finds_every_match_the_full_scan_finds(targets: frozenset[str]):
    tokens = {v for target in targets for v in _variants(target)}
    tokens |= {"content", "attached", "gmail", "peak", "vacation", "password"}
    mismatches = []
    for token in tokens:
        matched, fuzzy, strong, count = _match_fuzzy_class([token], targets, frozenset())
        target, kind = _reference(token, targets)
        expected = (
            frozenset({token}) if token in targets else frozenset({target}) if target else frozenset(),
            token not in targets and target is not None,
            token not in targets and kind == "strong",
            0 if token in targets or target is None else 1,
        )
        if (matched, fuzzy, strong, count) != expected:
            mismatches.append(token)
    assert not mismatches, mismatches[:20]


def test_repeated_word_is_matched_once(monkeypatch):
    """Cost follows distinct words, not word count: 500 copies of `content`
    (one substitution from `context`) cost one fuzzy decision, not 500."""
    calls = 0
    original = heuristic._typoglycemia_match_kind

    def counting(word: str, target: str) -> str | None:
        nonlocal calls
        calls += 1
        return original(word, target)

    monkeypatch.setattr(heuristic, "_typoglycemia_match_kind", counting)
    _match_fuzzy_class(["content"] * 500, _TYPO_PROTECTED_OBJECTS, frozenset())
    assert calls <= 2


def test_word_is_matched_once_across_the_passages_of_a_document(monkeypatch):
    """Passages overlap and repeat words; a word's match depends on the word
    alone, so 500 copies spread over two dozen passages still cost one fuzzy
    decision."""
    calls = 0
    original = heuristic._typoglycemia_match_kind

    def counting(word: str, target: str) -> str | None:
        nonlocal calls
        calls += 1
        return original(word, target)

    monkeypatch.setattr(heuristic, "_typoglycemia_match_kind", counting)
    heuristic._fuzzy_intent(" ".join(["content"] * 500))
    assert calls <= 2


def test_token_longer_than_any_target_is_never_compared(monkeypatch):
    """A token past the longest target by more than the edit bound cannot
    match, so it is rejected before its deletion forms are built — a single
    attacker-sized token must not cost quadratic work."""
    monkeypatch.setattr(
        heuristic, "_typoglycemia_match_kind",
        lambda word, target: pytest.fail("compared an unmatchable token"),
    )
    assert _match_fuzzy_class(["a" * 50_000], _TYPO_ACTIONS, frozenset()) == (
        frozenset(), False, False, 0,
    )
