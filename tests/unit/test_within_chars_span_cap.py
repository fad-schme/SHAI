"""Proximity search for `within_chars` compounds (R4).

A compound rule matches only if one span from every signal group fits inside a
window of `within_chars`. That is "smallest window covering k groups", and
`_groups_fit_within` sweeps it linearly.

It used to backtrack over one span per group, and all three of R4's defects
followed from that: the worst case is the product of the group span counts, so
it needed a step budget; the budget had to fail **closed** or padding would be a
bypass, which meant adversarial padding reported a match; and the per-group span
cap had to stay small enough to keep the budget out of reach, which silently
dropped real matches in long documents.

These tests pin the three behaviours that changed, plus an exhaustive
equivalence check against a brute-force oracle — the sweep is the kind of code
that is easy to get subtly wrong on window boundaries.
"""
from __future__ import annotations

import random
from itertools import product

from harness.adapters.scanners.injection_scan import (
    _MAX_SPANS_PER_GROUP,
    _groups_fit_within,
)


def brute_force(spans_by_group, within_chars) -> bool:
    """Definition of the predicate, tried exhaustively. Only for small inputs."""
    if not spans_by_group:
        return True
    if any(not s for s in spans_by_group):
        return False
    for combo in product(*spans_by_group):
        if max(e for _, e in combo) - min(s for s, _ in combo) <= within_chars:
            return True
    return False


class TestAgreesWithTheDefinition:

    def test_random_small_cases_match_brute_force(self):
        rng = random.Random(20260731)
        for _ in range(3_000):
            k = rng.randint(1, 4)
            groups = []
            for _ in range(k):
                n = rng.randint(1, 5)
                spans = []
                for _ in range(n):
                    start = rng.randint(0, 80)
                    spans.append((start, start + rng.randint(1, 12)))
                groups.append(spans)
            within = rng.randint(0, 60)
            assert _groups_fit_within(groups, within) == brute_force(groups, within), (
                groups, within)

    def test_boundary_is_inclusive(self):
        """width == within_chars fits; one more does not."""
        assert _groups_fit_within([[(0, 5)], [(8, 10)]], 10) is True
        assert _groups_fit_within([[(0, 5)], [(8, 10)]], 9) is False

    def test_empty_group_cannot_be_covered(self):
        assert _groups_fit_within([[(0, 5)], []], 1_000) is False

    def test_no_groups_is_vacuously_satisfied(self):
        assert _groups_fit_within([], 10) is True

    def test_single_group(self):
        assert _groups_fit_within([[(0, 5)]], 5) is True
        assert _groups_fit_within([[(0, 50)]], 5) is False


class TestDefectsThatAreNowGone:
    """One test per R4 failure path. Each fails on the backtracking version."""

    def test_late_satisfying_pair_is_found(self):
        """Silent false negative: the only in-window pair is the 150th occurrence.

        The old fixed cap of 32 never collected it, so the compound stopped
        matching with nothing logged. Long retrieved documents are exactly where
        the indirect-injection family operates.
        """
        group_a = [(i * 1_000, i * 1_000 + 10) for i in range(200)]
        group_b = [(150 * 1_000 + 20, 150 * 1_000 + 30)]
        assert _groups_fit_within([group_a, group_b], 100) is True

    def test_very_late_pair_is_also_found(self):
        """No residual ceiling: the 5,000th occurrence works the same way."""
        group_a = [(i * 100, i * 100 + 5) for i in range(10_000)]
        group_b = [(5_000 * 100 + 10, 5_000 * 100 + 15)]
        assert _groups_fit_within([group_a, group_b], 50) is True

    def test_dense_padding_no_longer_reports_a_match(self):
        """False positive: padding used to exhaust the budget, which failed closed.

        Two dense interleaved groups and a third far away — no window covers all
        three. The backtracking search burned its budget on the A×B product and
        returned "matched". The sweep answers correctly.
        """
        wide_a = [(i * 2, i * 2 + 1) for i in range(2_000)]
        wide_b = [(i * 2 + 1, i * 2 + 2) for i in range(2_000)]
        far_c = [(i * 2 + 1_000_000, i * 2 + 1_000_001) for i in range(2_000)]
        assert _groups_fit_within([wide_a, wide_b, far_c], 4) is False

    def test_dense_two_group_no_match_terminates_honestly(self):
        wide_a = [(i * 4, i * 4 + 1) for i in range(5_000)]
        far_b = [(i * 4 + 900_000, i * 4 + 900_001) for i in range(5_000)]
        assert _groups_fit_within([wide_a, far_b], 8) is False


class TestScale:

    def test_large_dense_input_is_linear(self):
        """40k spans across 3 groups resolves without a budget. Would not terminate
        in any practical time under the old product-of-counts walk."""
        a = [(i * 3, i * 3 + 1) for i in range(15_000)]
        b = [(i * 3 + 1, i * 3 + 2) for i in range(15_000)]
        c = [(i * 3 + 2, i * 3 + 3) for i in range(15_000)]
        assert _groups_fit_within([a, b, c], 6) is True

    def test_memory_bound_is_generous_not_load_bearing(self):
        """The cap exists to bound memory, not to decide matches."""
        assert _MAX_SPANS_PER_GROUP >= 10_000
